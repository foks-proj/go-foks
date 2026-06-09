package librt

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/chains"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	"github.com/foks-proj/go-foks/proto/lib"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type RTParty struct {
	sync.RWMutex
	plcn *libclient.PLCNode
}

func (k *RTParty) TeamID() (*proto.TeamID, error) {
	tmp := k.PLCNode().FQParty().FQTeam()
	if tmp == nil {
		return nil, core.InternalError("nil teamID for RTParty in Stage 1a")
	}
	ret := tmp.Team
	return &ret, nil
}

func (k *RTParty) SetPLCNode(n *libclient.PLCNode) {
	k.Lock()
	defer k.Unlock()
	k.plcn = n
}

func (k *RTParty) PLCNode() *libclient.PLCNode {
	k.RLock()
	defer k.RUnlock()
	return k.plcn
}

var _ libclient.BaseMinderNoder = (*RTParty)(nil)

type Minder struct {
	sync.Mutex
	base *libclient.BaseMinder[RTParty, *RTParty]
	au   *libclient.UserContext

	localCliMu sync.Mutex
	localCli   *rem.RealTimeClient
}

func NewMinder(au *libclient.UserContext) *Minder {
	if au == nil {
		panic("nil active user")
	}
	ret := &Minder{au: au}
	ret.base = libclient.NewBaseMinder(
		au,
		func(n *RTParty) {},
	)
	return ret
}

type MakeChannelTestHooks struct {
	PrePostDelayHook func()
	HitRaceHook      func(i int)
}

func (d *Minder) MakeChannel(
	m MetaContext,
	team *proto.FQTeamParsed,
	appId proto.RTAppID,
	nm proto.RTChannelName,
	desc proto.RTChannelDesc,
	roles proto.RolePairOpt,
) (
	*proto.RTChannelID,
	error,
) {
	return d.MakeChannelWithTestHooks(m, team, appId, nm, desc, roles, nil)
}

func (d *Minder) MakeChannelWithTestHooks(
	m MetaContext,
	team *proto.FQTeamParsed,
	appId proto.RTAppID,
	nm proto.RTChannelName,
	desc proto.RTChannelDesc,
	roles proto.RolePairOpt,
	test *MakeChannelTestHooks,
) (
	*proto.RTChannelID,
	error,
) {
	sleepDur := time.Millisecond
	numTries := 5
	for i := range numTries {
		ret, err := d.makeChannelOneAttempt(m, team, appId, nm, desc, roles, test)
		if err == nil {
			return ret, nil
		}
		var raceErr core.RTRaceError
		if !errors.As(err, &raceErr) || i == numTries-1 {
			return nil, err
		}

		// Report any races we hit to the testing framework
		if test != nil && test.HitRaceHook != nil {
			test.HitRaceHook(i)
		}

		m.Warnw("race condition on team metadata update", "iter", i, "sleep", sleepDur)
		time.Sleep(sleepDur)
		sleepDur *= 2
	}
	return nil, core.RTRaceError{Which: "channels"}
}

func (d *Minder) makeChannelOneAttempt(
	m MetaContext,
	team *proto.FQTeamParsed,
	appId proto.RTAppID,
	nm proto.RTChannelName,
	desc proto.RTChannelDesc,
	roles proto.RolePairOpt,
	test *MakeChannelTestHooks,
) (
	*proto.RTChannelID,
	error,
) {
	if team == nil {
		return nil, core.InternalError("team is required to make channel in Stage 1a")
	}
	rtp, err := d.base.GetParty(m.Base(), team)
	if err != nil {
		return nil, err
	}
	chlst, err := d.listAllChannelsForTeam(m, rtp, appId)
	if err != nil {
		return nil, err
	}

	type chKey struct {
		name  proto.RTChannelName
		klass proto.RTChannelClass
	}
	chMap := make(map[chKey]struct{})
	for _, chmd := range chlst.Channels {
		chMap[chKey{name: chmd.Name, klass: chmd.Klass}] = struct{}{}
	}

	// A note on roles, which are tricky. If no roles were specified, we use
	// the user's current dest role in the team as the default. If that is not
	// available (since the user isn't a direct member of the team), then we
	// default to DefaultRole.
	//
	// There is a rub. We'll encrypt the channel description with this role,
	// which can vary across all the roles. However, the name field will be encrypted
	// at one of two roles -- either the RTMin role, for readers; and at the Admin
	// role for everything admin and above. This way we don't wind up with
	// 10 different channels named "#general" per team, once for each Member viz level.
	// We'll have at most 2 channels named "#general", one for the plebs, and one
	// for the admins (and above).
	newChClass := proto.RTChannelClass_Bottom
	readRole := roles.Read
	nameRole := proto.MinRTRole

	if readRole == nil {
		readRole = rtp.PLCNode().DirectDstRole()
	}
	if readRole == nil {
		tmp := proto.DefaultRole
		readRole = &tmp
	}
	if readRole == nil {
		return nil, core.InternalError("could not determine role for channel creation")
	}

	isAdmin, err := readRole.IsAdminOrAbove()
	if err != nil {
		return nil, err
	}
	if isAdmin {
		newChClass = proto.RTChannelClass_Admin
		nameRole = proto.AdminRole
	}

	if _, found := chMap[chKey{name: nm, klass: newChClass}]; found {
		return nil, core.RTChannelExistsError{}
	}
	nameKeySeq, err := rtp.PLCNode().SKM().PrivateKeysForRole(m.Base(), nameRole)
	if err != nil {
		return nil, err
	}
	nameKeyCurr := nameKeySeq.Current()
	nameKeyMgr, err := NewKeyMgr(nameKeyCurr, appId)
	if err != nil {
		return nil, err
	}

	namePlain := proto.NewRTChannelNamePlaintextWithUtf8v1(nm)
	nameEnc, err := nameKeyMgr.SealIntoSecretBox(proto.RTKeyType_ChannelName, &namePlain)
	if err != nil {
		return nil, err
	}
	var update rem.RTChannelMetadata
	update.NameBox = *nameEnc

	if !desc.IsEmpty() {
		descRole := *readRole
		descKeySeq, err := rtp.PLCNode().SKM().PrivateKeysForRole(m.Base(), descRole)
		if err != nil {
			return nil, err
		}
		descKeyCurr := descKeySeq.Current()
		descKeyMgr, err := NewKeyMgr(descKeyCurr, appId)
		if err != nil {
			return nil, err
		}
		descPlain := proto.NewRTChannelDescPlaintextWithUtf8v1(desc)
		descEnc, err := descKeyMgr.SealIntoSecretBox(proto.RTKeyType_ChannelDesc, &descPlain)
		if err != nil {
			return nil, err
		}
		update.DescBox = descEnc
	}

	id, err := proto.NewRTChannelID()
	if err != nil {
		return nil, err
	}
	teamId, err := rtp.TeamID()
	if err != nil {
		return nil, err
	}

	wRole := roles.Write
	if wRole == nil {
		wRole = readRole
	}
	if wRole == nil {
		return nil, core.InternalError("nil write role unexpected")
	}

	update.Id = *id
	update.ParentTeam = *teamId
	update.AppID = appId
	update.Seqno = 1
	update.Roles = proto.RolePair{
		Read:  *readRole,
		Write: *wRole,
	}
	update.UpdatedAt = chlst.Vers + 1
	update.Klass = newChClass

	arg := rem.RtNewChannelArg{
		Md:      update,
		SetVers: chlst.Vers + 1,
	}

	_, cli, err := d.clientLocal(m.Base(), d.au)
	if err != nil {
		return nil, err
	}

	// In test, allow us to force a race, so we can test that the retry mechanism works.
	if test != nil && test.PrePostDelayHook != nil {
		test.PrePostDelayHook()
	}

	err = cli.RtNewChannel(m.Ctx(), arg)
	if err != nil {
		return nil, err
	}

	return &update.Id, nil
}

func (k *Minder) clientLocal(
	m libclient.MetaContext,
	au *libclient.UserContext,
) (
	*chains.Probe,
	*rem.RealTimeClient,
	error,
) {
	cert, err := au.ClientCert(m)
	if err != nil {
		return nil, nil, err
	}
	pr := au.HomeServer()
	if pr == nil {
		return nil, nil, core.HomeError("no home server")
	}

	k.localCliMu.Lock()
	defer k.localCliMu.Unlock()

	if k.localCli != nil {
		return pr, k.localCli, nil
	}

	gcli, err := pr.RPCClient(m, proto.ServerType_RealTime, cert)
	if err != nil {
		return nil, nil, err
	}
	ret := core.NewRealTimeClient(gcli, m)
	k.localCli = &ret
	return pr, &ret, nil
}

func (r *RTParty) keysAtRoleGen(
	m MetaContext,
	app proto.RTAppID,
	rg proto.RoleAndGen,
) (
	*KeyMgr,
	error,
) {
	seq, err := r.PLCNode().SKM().PrivateKeysForRole(m.Base(), rg.Role)
	if err != nil {
		return nil, err
	}
	key := seq.At(rg.Gen)
	if key == nil {
		return nil, core.KeyNotFoundError{Which: "SKM at role/gen in chat"}
	}
	mgr, err := NewKeyMgr(key, app)
	if err != nil {
		return nil, err
	}
	return mgr, nil
}

func (k *Minder) decryptChannelName(
	m MetaContext,
	rtp *RTParty,
	appID proto.RTAppID,
	enc proto.RTBoxRG,
) (
	proto.RTChannelName,
	error,
) {
	var zed proto.RTChannelName
	kmgr, err := rtp.keysAtRoleGen(m, appID, enc.Rg)
	if err != nil {
		return zed, err
	}
	cnk, err := kmgr.ChannelNameKey()
	if err != nil {
		return zed, err
	}
	var tmp proto.RTChannelNamePlaintext
	err = core.OpenSecretBoxInto(&tmp, enc.Box, cnk)
	if err != nil {
		return zed, err
	}
	t, err := tmp.GetT()
	if err != nil {
		return zed, err
	}
	if t != proto.RTChannelNameType_Utf8v1 {
		return zed, core.VersionNotSupportedError("channel name type unknown")
	}
	return tmp.Utf8v1(), nil
}

func (k *Minder) decryptChannelDesc(
	m MetaContext,
	rtp *RTParty,
	appID proto.RTAppID,
	enc *proto.RTBoxRG,
) (
	*proto.RTChannelDesc,
	error,
) {
	if enc == nil {
		return nil, nil
	}
	kmgr, err := rtp.keysAtRoleGen(m, appID, enc.Rg)
	if err != nil {
		return nil, err
	}
	cnk, err := kmgr.ChannelDescKey()
	if err != nil {
		return nil, err
	}
	var tmp proto.RTChannelDescPlaintext
	err = core.OpenSecretBoxInto(&tmp, enc.Box, cnk)
	if err != nil {
		return nil, err
	}
	t, err := tmp.GetT()
	if err != nil {
		return nil, err
	}
	if t != proto.RTChannelDescType_Utf8v1 {
		return nil, core.VersionNotSupportedError("channel name type unknown")
	}
	ret := tmp.Utf8v1()
	return &ret, nil
}

func (k *Minder) decryptChannelMetadata(
	m MetaContext,
	rtp *RTParty,
	chmdenc rem.RTChannelMetadata,
) (
	*lcl.RTChannelMetadataPlaintext,
	error,
) {
	var ret lcl.RTChannelMetadataPlaintext

	nm, err := k.decryptChannelName(m, rtp, chmdenc.AppID, chmdenc.NameBox)
	if err != nil {
		return nil, err
	}
	desc, err := k.decryptChannelDesc(m, rtp, chmdenc.AppID, chmdenc.DescBox)
	if err != nil {
		return nil, err
	}

	ret.Name = nm
	ret.Desc = desc
	ret.Id = chmdenc.Id
	ret.ParentTeam = chmdenc.ParentTeam
	ret.AppID = chmdenc.AppID
	ret.Roles = chmdenc.Roles
	ret.Klass = chmdenc.Klass
	ret.UpdatedAt = chmdenc.UpdatedAt

	return &ret, nil
}

func (k *Minder) ListAllChannelsForTeam(
	m MetaContext,
	tm *proto.FQTeamParsed,
	appID proto.RTAppID,
) (
	*lcl.RTChannelSetForTeam,
	error,
) {
	rtp, err := k.base.GetParty(m.Base(), tm)
	if err != nil {
		return nil, err
	}
	ret, err := k.listAllChannelsForTeam(m, rtp, appID)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(
		ret.Channels,
		func(a lcl.RTChannelMetadataPlaintext, b lcl.RTChannelMetadataPlaintext) int {
			if a.Klass != b.Klass {
				if a.Klass == proto.RTChannelClass_Admin &&
					b.Klass == proto.RTChannelClass_Bottom {
					return -1
				}
				return 1
			}
			return strings.Compare(string(a.Name), string(b.Name))
		},
	)
	return ret, nil
}

func (k *Minder) listAllChannelsForTeam(
	m MetaContext,
	rtp *RTParty,
	appID proto.RTAppID,
) (
	*lcl.RTChannelSetForTeam,
	error,
) {
	_, cli, err := k.clientLocal(m.Base(), k.au)
	if err != nil {
		return nil, err
	}
	fqt := rtp.plcn.FQParty().FQTeam()
	if fqt == nil {
		return nil, core.InternalError("teamID of chat party was inexpectedly nil")
	}
	encList, err := cli.RtListAllChannelsForTeam(m.Ctx(),
		rem.RtListAllChannelsForTeamArg{
			Team:  fqt.Team,
			AppID: appID,
		},
	)
	if err != nil {
		return nil, err
	}

	var out lcl.RTChannelSetForTeam
	for _, chmdenc := range encList.Lst {
		chmdpt, err := k.decryptChannelMetadata(m, rtp, chmdenc)
		if err != nil {
			return nil, err
		}
		out.Channels = append(out.Channels, *chmdpt)
	}
	out.Vers = encList.Vers
	out.Team = fqt.Team
	out.AppID = appID

	return &out, nil
}

// ThreadMessage is a single decrypted message, as returned by GetThread.
type ThreadMessage struct {
	Seq                      proto.RTMsgSeq
	Typ                      proto.RTMsgType
	Sender                   *proto.PartyID
	SenderFurtherAttribution *proto.UID
	SentAtTime               proto.Time
	InsertTime               proto.Time
	Body                     []byte // decrypted plaintext (RTMsgType_Basic)
}

// resolveChannel finds a channel in `team` by name. A name can exist in more
// than one class (e.g. an admin and a bottom "#general"); pass a non-nil klass
// to disambiguate. With klass==nil, an ambiguous name returns
// RTAmbiguousChannelError so the caller (or a UI) can retry with a class.
func (d *Minder) resolveChannel(
	m MetaContext,
	rtp *RTParty,
	appID proto.RTAppID,
	name proto.RTChannelName,
	klass *proto.RTChannelClass,
) (
	*lcl.RTChannelMetadataPlaintext,
	error,
) {
	lst, err := d.listAllChannelsForTeam(m, rtp, appID)
	if err != nil {
		return nil, err
	}
	var found *lcl.RTChannelMetadataPlaintext
	for i := range lst.Channels {
		ch := &lst.Channels[i]
		if ch.Name != name {
			continue
		}
		if klass != nil && ch.Klass != *klass {
			continue
		}
		if found != nil {
			// Only reachable when klass==nil; a (name, class) pair is unique.
			return nil, core.RTAmbiguousChannelError{Name: string(name)}
		}
		found = ch
	}
	if found == nil {
		return nil, core.RTNotFoundError(fmt.Sprintf("channel '%s'", string(name)))
	}
	return found, nil
}

func cookNonce(noncer *proto.RTMsgNoncer) (*proto.DomainSeparatedNaclNonce, error) {
	nonce, err := core.PrefixedHash(noncer)
	if err != nil {
		return nil, err
	}
	// convert to a 24-byte nacl nonce
	nn := nonce.DomainSeparatedNaclNonce()
	return nn, nil
}

// sealMessage encrypts the message body under the channel's read role at the
// current generation, so every reader of the channel can decrypt it.
func (d *Minder) sealMessage(
	m MetaContext,
	rtp *RTParty,
	appID proto.RTAppID,
	readRole proto.Role,
	noncer *proto.RTMsgNoncer,
	body []byte,
) (
	*proto.RTMsgBox,
	error,
) {

	nn, err := cookNonce(noncer)
	if err != nil {
		return nil, err
	}
	keySeq, err := rtp.PLCNode().SKM().PrivateKeysForRole(m.Base(), readRole)
	if err != nil {
		return nil, err
	}
	keyMgr, err := NewKeyMgr(keySeq.Current(), appID)
	if err != nil {
		return nil, err
	}
	msgbody := proto.NewRTMsgBodyWithBasic(
		proto.RTMsgPlaintextBasic(body),
	)
	return keyMgr.SealMsgWithNonce(&msgbody, nn)
}

// SendTestHooks lets tests perturb a send to exercise server-side validation.
type SendTestHooks struct {
	// EncryptRoleOverride encrypts the body at this role instead of the
	// channel's read role, to test the server's encryption-role check.
	EncryptRoleOverride *proto.Role
}

// Send encrypts and sends a basic message into the named channel of a team.
// klass disambiguates when a name exists in more than one class; pass nil when
// the name is unique.
func (d *Minder) Send(
	m MetaContext,
	team *proto.FQTeamParsed,
	appID proto.RTAppID,
	channelName proto.RTChannelName,
	klass *proto.RTChannelClass,
	body []byte,
) (
	*rem.RTSendRes,
	error,
) {
	return d.SendWithTestHooks(m, team, appID, channelName, klass, body, nil)
}

// SendWithTestHooks is Send with optional test perturbations.
func (d *Minder) SendWithTestHooks(
	m MetaContext,
	team *proto.FQTeamParsed,
	appID proto.RTAppID,
	channelName proto.RTChannelName,
	klass *proto.RTChannelClass,
	body []byte,
	test *SendTestHooks,
) (
	*rem.RTSendRes,
	error,
) {
	if team == nil {
		return nil, core.InternalError("team is required to send in Stage 1a")
	}
	rtp, err := d.base.GetParty(m.Base(), team)
	if err != nil {
		return nil, err
	}
	ch, err := d.resolveChannel(m, rtp, appID, channelName, klass)
	if err != nil {
		return nil, err
	}
	encryptRole := ch.Roles.Read
	if test != nil && test.EncryptRoleOverride != nil {
		encryptRole = *test.EncryptRoleOverride
	}
	typ := proto.RTMsgType_Basic

	// TODO !! Fill in prev's
	md := proto.RTMsgMetadata{
		SendTime: proto.ExportTime(m.G().Now()),
		Typ:      typ,
	}

	err = core.RandomFill(md.MsgID[:])
	if err != nil {
		return nil, err
	}

	noncer := proto.RTMsgNoncer{
		Md:     md,
		Sender: d.au.UID().ToPartyID(),
		AppID:  appID,
		Team:   rtp.PLCNode().FQParty().Party,
		Chid:   ch.Id,
	}

	box, err := d.sealMessage(m, rtp, appID, encryptRole, &noncer, body)
	if err != nil {
		return nil, err
	}
	_, cli, err := d.clientLocal(m.Base(), d.au)
	if err != nil {
		return nil, err
	}
	mw := proto.NewRTMsgWrapperWithEncrypted(*box)
	res, err := cli.RtSend(m.Ctx(), rem.RTSendArg{
		Md:   md,
		Mw:   mw,
		Chid: ch.Id.Short(),
	})
	if err != nil {
		return nil, err
	}
	err = dbPutMsgToOutbox(
		m,
		d.au,
		proto.RTMsgCached{
			Md: noncer,
			Mw: mw,
		},
	)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (d *Minder) openMessageWithRTMsg(
	m MetaContext,
	rtp *RTParty,
	appID proto.RTAppID,
	msg rem.RTMsg,
	ch proto.RTChannelID,
) (
	[]byte,
	*proto.RTMsgCached,
	error,
) {
	return d.openMessage(m, rtp, appID,
		msg.Md, msg.Mw, msg.Sender, msg.InsertTime, ch,
	)
}

// openMessage decrypts a message body fetched from the server, using the key at
// the role+gen stamped on the box.
func (d *Minder) openMessage(
	m MetaContext,
	rtp *RTParty,
	appID proto.RTAppID,
	md proto.RTMsgMetadata,
	mw proto.RTMsgWrapper,
	sender *proto.PartyID,
	serverInsertTime proto.Time,
	ch proto.RTChannelID,
) (
	[]byte,
	*proto.RTMsgCached,
	error,
) {
	team := rtp.PLCNode().FQParty().Party
	noncer := proto.RTMsgNoncer{
		Md:    md,
		AppID: appID,
		Team:  team,
		Chid:  ch,
	}
	if sender != nil {
		noncer.Sender = *sender
	}
	nn, err := cookNonce(&noncer)
	if err != nil {
		return nil, nil, err
	}
	typ, err := mw.GetT()
	if err != nil {
		return nil, nil, err
	}
	if typ != proto.MsgBodyType_Encrypted {
		return nil, nil, core.VersionNotSupportedError("only encrypted message bodies are supported")
	}
	box := mw.Encrypted()

	kmgr, err := rtp.keysAtRoleGen(m, appID, box.Rg)
	if err != nil {
		return nil, nil, err
	}
	var body proto.RTMsgBody
	err = kmgr.OpenMsgWithNonce(&body, box.Ctext, nn)
	if err != nil {
		return nil, nil, err
	}
	pt, err := body.GetT()
	if err != nil {
		return nil, nil, err
	}
	if pt != proto.RTMsgType_Basic {
		return nil, nil, core.VersionNotSupportedError("only basic messages are supported")
	}
	basic := body.Basic()
	cm := proto.RTMsgCached{
		Md:  noncer,
		Mw:  mw,
		Sit: serverInsertTime,
	}
	return basic.Bytes(), &cm, nil
}

// GetThread fetches and decrypts a page of messages from the named channel.
// klass disambiguates when a name exists in more than one class; pass nil when
// the name is unique.
//
// Here is the overall algorithm:
//   - fecth from local DB
//   - fetch from server after the max (or min) message, and plug in any holes
//   - check that prev pointers align with server sequencing.
//   - cache any newly downloaded messages
func (d *Minder) GetThread(
	m MetaContext,
	team *proto.FQTeamParsed,
	appID proto.RTAppID,
	channelName proto.RTChannelName,
	klass *proto.RTChannelClass,
	start proto.RTMsgSeq,
	dir proto.RTThreadDir,
	max uint64,
) (
	[]ThreadMessage,
	bool,
	error,
) {
	if team == nil {
		return nil, false, core.InternalError("team is required to read in Stage 1a")
	}
	rtp, err := d.base.GetParty(m.Base(), team)
	if err != nil {
		return nil, false, err
	}
	ch, err := d.resolveChannel(m, rtp, appID, channelName, klass)
	if err != nil {
		return nil, false, err
	}

	_, cli, err := d.clientLocal(m.Base(), d.au)
	if err != nil {
		return nil, false, err
	}
	page, err := cli.RtGetThread(m.Ctx(), proto.RTThreadQuery{
		ChannelID: ch.Id,
		Start:     start,
		Dir:       dir,
		Max:       max,
	})
	if err != nil {
		return nil, false, err
	}
	out, err := d.decodeAndCacheMsgs(m, rtp, appID, ch.Id, page.Msgs)
	if err != nil {
		return nil, false, err
	}
	return out, page.Final, nil
}

func (d *Minder) decodeMsgs(
	m MetaContext,
	rtp *RTParty,
	appID proto.RTAppID,
	chid proto.RTChannelID,
	msgs []lib.RTMsgCachedWithSeq,
) (
	[]ThreadMessage,
	error,
) {
	out := make([]ThreadMessage, 0, len(msgs))
	for _, msg := range msgs {
		body, cm, err := d.openMessage(m, rtp, appID,
			msg.Cm.Md.Md, msg.Cm.Mw, &msg.Cm.Md.Sender, msg.Cm.Sit, chid)
		if err != nil {
			return nil, err
		}
		out = append(out, ThreadMessage{
			Seq:                      msg.Seq,
			Typ:                      cm.Md.Md.Typ,
			Sender:                   &cm.Md.Sender,
			SenderFurtherAttribution: cm.Md.Md.FurtherUserAttribution,
			SentAtTime:               cm.Md.Md.SendTime,
			InsertTime:               cm.Sit,
			Body:                     body,
		})
	}
	return out, nil
}

// decodeAndCacheMsgs decrypts each server message into a ThreadMessage for the
// caller and writes the decrypted bodies into the local cache. Shared by
// GetThread (paged range) and GetMsgs (arbitrary set of seqs).
func (d *Minder) decodeAndCacheMsgs(
	m MetaContext,
	rtp *RTParty,
	appID proto.RTAppID,
	chid proto.RTChannelID,
	msgs []rem.RTMsg,
) (
	[]ThreadMessage,
	error,
) {
	out := make([]ThreadMessage, 0, len(msgs))
	cachePuts := make([]proto.RTMsgCachedWithSeq, 0, len(msgs))
	for _, msg := range msgs {
		body, cm, err := d.openMessageWithRTMsg(m, rtp, appID, msg, chid)
		if err != nil {
			return nil, err
		}
		out = append(out, ThreadMessage{
			Seq:                      msg.Seq,
			Typ:                      msg.Md.Typ,
			Sender:                   msg.Sender,
			SenderFurtherAttribution: msg.Md.FurtherUserAttribution,
			SentAtTime:               msg.Md.SendTime,
			InsertTime:               msg.InsertTime,
			Body:                     body,
		})
		cachePuts = append(cachePuts, proto.RTMsgCachedWithSeq{
			Cm:  *cm,
			Seq: msg.Seq,
		})
	}
	err := dbPutMsgs(m, d.au, cachePuts)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetMsgs fetches and decrypts an arbitrary set of messages from the named
// channel by seq. Used to fill holes between locally-cached messages and a
// paged GetThread fetch. Only messages that exist server-side are returned
// (each carries its own Seq); requested seqs with no message are omitted, so
// the result may be shorter than `seqs` and in unspecified order. klass
// disambiguates when a name exists in more than one class; pass nil when the
// name is unique.
func (d *Minder) GetMsgs(
	m MetaContext,
	team *proto.FQTeamParsed,
	appID proto.RTAppID,
	channelName proto.RTChannelName,
	klass *proto.RTChannelClass,
	seqs []proto.RTMsgSeq,
) (
	[]ThreadMessage,
	error,
) {
	if team == nil {
		return nil, core.InternalError("team is required to read in Stage 1a")
	}
	rtp, err := d.base.GetParty(m.Base(), team)
	if err != nil {
		return nil, err
	}
	ch, err := d.resolveChannel(m, rtp, appID, channelName, klass)
	if err != nil {
		return nil, err
	}
	_, cli, err := d.clientLocal(m.Base(), d.au)
	if err != nil {
		return nil, err
	}
	res, err := cli.RtGetMsgs(m.Ctx(), rem.RTGetMsgsArg{
		ChannelID: ch.Id,
		Seqs:      seqs,
	})
	if err != nil {
		return nil, err
	}
	return d.decodeAndCacheMsgs(m, rtp, appID, ch.Id, res.Msgs)
}
