package librt

import (
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

	// Always-on instrumentation counters; read via Metrics(). Useful for tests
	// and debugging (e.g. asserting a read was served entirely from cache).
	serverThreadReads atomic.Int64
	serverRecentReads atomic.Int64

	msgIDCache *LRU[proto.RTMsgID, proto.RTMsgSeq]

	// usernameCache memoizes UID -> display-name resolutions (each a full user
	// chain load), which would otherwise be issued per message-sender on every
	// thread read. Entries expire after a jittered ~6h TTL; see usernameCacheTTL.
	usernameMu    sync.Mutex
	usernameCache map[proto.UID]usernameCacheEntry

	testHooks *MinderTestHooks
}

type usernameCacheEntry struct {
	name      proto.NameUtf8
	expiresAt time.Time
}

const (
	// usernameCacheTTLBase is the central lifetime of a cached UID->name entry;
	// usernameCacheTTLJitter is the random spread added on top so a burst of
	// entries cached together don't all expire at once and stampede the server.
	usernameCacheTTLBase   = 6 * time.Hour
	usernameCacheTTLJitter = 2 * time.Hour
)

// jitteredUsernameTTL returns a lifetime uniformly in
// [base - jitter/2, base + jitter/2), centered on base (~6h).
func jitteredUsernameTTL() time.Duration {
	return usernameCacheTTLBase - usernameCacheTTLJitter/2 +
		time.Duration(rand.Int63n(int64(usernameCacheTTLJitter)))
}

// MinderTestHooks lets tests perturb a Minder. A nil Minder.testHooks, or a nil
// individual hook, is a no-op. The intended use is to simulate a malicious or
// buggy server by rewriting its responses in place before the client decodes
// and verifies them.
type MinderTestHooks struct {
	// MutateReadRes, if set, rewrites each RtGetThread response.
	MutateReadRes func(*rem.RTThreadPage)
	// MutateRecentsRes, if set, rewrites each RtGetThreadRecents response.
	MutateRecentsRes func(*rem.RTMsgList)
}

// SetTestHooks installs (or, with nil, clears) test hooks on the Minder.
func (d *Minder) SetTestHooks(h *MinderTestHooks) { d.testHooks = h }

func (d *Minder) hookReadRes(p *rem.RTThreadPage) {
	if d.testHooks != nil && d.testHooks.MutateReadRes != nil {
		d.testHooks.MutateReadRes(p)
	}
}

func (d *Minder) hookRecentsRes(l *rem.RTMsgList) {
	if d.testHooks != nil && d.testHooks.MutateRecentsRes != nil {
		d.testHooks.MutateRecentsRes(l)
	}
}

// MinderMetrics is a snapshot of a Minder's instrumentation counters.
type MinderMetrics struct {
	// ServerThreadReads counts RtGetThread RPCs issued (bookended ranges and/or
	// explicit seq fills). A read served entirely from the local cache does not
	// increment this.
	ServerThreadReads int64
	// ServerRecentReads counts RtGetThreadRecents RPCs issued.
	ServerRecentReads int64
}

// Metrics returns a snapshot of the Minder's instrumentation counters.
func (d *Minder) Metrics() MinderMetrics {
	return MinderMetrics{
		ServerThreadReads: d.serverThreadReads.Load(),
		ServerRecentReads: d.serverRecentReads.Load(),
	}
}

func NewMinder(au *libclient.UserContext) *Minder {
	if au == nil {
		panic("nil active user")
	}
	ret := &Minder{
		au:            au,
		msgIDCache:    NewLRU[proto.RTMsgID, proto.RTMsgSeq](10_000),
		usernameCache: make(map[proto.UID]usernameCacheEntry),
	}
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
	if nm.Eq(proto.RTGeneralChannel) {
		return nil, core.RTGenericError("cannot make channel named #general")
	}
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
		chMap[chKey{name: chmd.Name.Normalize(), klass: chmd.Klass}] = struct{}{}
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

	if _, found := chMap[chKey{
		name:  nm.Normalize(),
		klass: newChClass,
	}]; found {
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
	// PrivateKeysForRole returns (nil, nil) when we hold no private keys for the
	// role, i.e. we aren't a member at or above the channel's role. Without those
	// keys we can decrypt neither the channel name/description nor its messages,
	// so this is a read-permission failure -- not an internal error or a panic on
	// the nil sequence below.
	if seq == nil {
		return nil, core.PermissionError("no read access to channel at this role")
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
	ret.Unreadable = chmdenc.Unreadable

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
	// Drop channels the server flagged as unreadable for us (role below the read
	// role). They're returned so name-collision detection in MakeChannel can see
	// them, but they have no decryptable content, so we hide them from the inbox.
	ret.Channels = slices.DeleteFunc(
		ret.Channels,
		func(c lcl.RTChannelMetadataPlaintext) bool {
			return c.Unreadable
		},
	)
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
	MsgID                    proto.RTMsgID  // this message's random id
	PrevID                   proto.RTMsgID  // id the sender chained off of (zero if none)
	PrevSeq                  proto.RTMsgSeq // seq the sender chained off of (0 if none)
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
	spc lcl.RTChannelSpecifier,
) (
	*lcl.RTChannelMetadataPlaintext,
	error,
) {
	lst, err := d.listAllChannelsForTeam(m, rtp, appID)
	if err != nil {
		return nil, err
	}

	t, err := spc.GetT()
	if err != nil {
		return nil, err
	}

	var searchID *proto.RTChannelID
	var searchName proto.RTChannelName
	var searchClass proto.RTChannelClass

	switch t {
	case lcl.RTChannelSpecifierType_None:
		/* noop */
	case lcl.RTChannelSpecifierType_Name:
		searchName = spc.Name().Name
		searchClass = spc.Name().Klass
	case lcl.RTChannelSpecifierType_ID:
		tmp := spc.Id()
		searchID = &tmp
	default:
		return nil, core.InternalError("unexpected channel specifier type")
	}

	var found *lcl.RTChannelMetadataPlaintext
	for i := range lst.Channels {
		ch := &lst.Channels[i]

		// If specified by channel, then first match wins
		if searchID != nil {
			if searchID.Eq(ch.Id) {
				return ch, nil
			}
			continue
		}

		if !ch.Name.Eq(searchName) {
			continue
		}
		if searchClass != proto.RTChannelClass_None && ch.Klass != searchClass {
			continue
		}
		if found != nil {
			// Only reachable when klass==nil; a (name, class) pair is unique.
			return nil, core.RTAmbiguousChannelError{Name: searchName}
		}
		found = ch
	}
	if found == nil {
		return nil, core.RTNotFoundError(
			fmt.Sprintf("channel '%s'", spc.String()),
		)
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
	channel lcl.RTChannelSpecifier,
	body []byte,
) (
	*rem.RTSendRes,
	error,
) {
	return d.SendWithTestHooks(m, team, appID, channel, body, nil)
}

func (d *Minder) cacheMsgID(
	q proto.RTMsgSeq,
	i proto.RTMsgID,
) error {
	existing := d.msgIDCache.Put(i, q)
	if existing != nil && *existing != q {
		return core.RTMsgOrderError(fmt.Sprintf("conflicting msgIDs for sequence %d", q))
	}
	return nil
}

// SendWithTestHooks is Send with optional test perturbations.
func (d *Minder) SendWithTestHooks(
	m MetaContext,
	team *proto.FQTeamParsed,
	appID proto.RTAppID,
	channel lcl.RTChannelSpecifier,
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
	ch, err := d.resolveChannel(m, rtp, appID, channel)
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

	lastMsg, err := dbGetLastMsg(m, d.au, ch.Id)
	if err != nil {
		return nil, err
	}
	var prevSeq proto.RTMsgSeq
	if lastMsg != nil {
		md.PrevSeq = lastMsg.Seq
		md.PrevID = lastMsg.Cm.Md.Md.MsgID
		prevSeq = md.PrevSeq
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

	msgCached := proto.RTMsgCached{
		Md: noncer,
		Mw: mw,
	}

	err = dbPutMsgToOutbox(
		m,
		d.au,
		msgCached,
	)
	if err != nil {
		return nil, err
	}

	res, err := cli.RtSend(m.Ctx(), rem.RTSendArg{
		Md:   md,
		Mw:   mw,
		Chid: ch.Id.Short(),
	})
	if err != nil {
		return nil, err
	}

	// The server assigns the insert time; record it so the cached copy matches
	// what a server-fetched read would carry.
	msgCached.Sit = res.InsertTime
	msgCachedSeq := proto.RTMsgCachedWithSeq{
		Cm:  msgCached,
		Seq: res.Seq,
	}

	if prevSeq.IsValid() && res.Seq <= prevSeq {
		return nil, core.RTMsgOrderError(
			fmt.Sprintf(
				"sent message has sequence (%d) <= last seen (%d)",
				res.Seq.Int(), prevSeq.Int(),
			),
		)
	}

	err = d.dbPutMsgs(m, []proto.RTMsgCachedWithSeq{msgCachedSeq})
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

func merge(
	left []ThreadMessage,
	right []ThreadMessage,
	inc int, // -1 for descending, 1 for ascending
) []ThreadMessage {
	ret := make([]ThreadMessage, len(left)+len(right))
	var i, l, r int
	for l < len(left) || r < len(right) {
		if l == len(left) {
			ret[i] = right[r]
			r++
		} else if r == len(right) {
			ret[i] = left[l]
			l++
		} else {
			leftLess := (left[l].Seq < right[r].Seq)
			if (leftLess && inc > 0) || (!leftLess && inc < 0) {
				ret[i] = left[l]
				l++
			} else {
				ret[i] = right[r]
				r++
			}
		}
		i++
	}
	return ret

}

// findHoles returns the seqs missing from v, where v is a run of messages that
// must be strictly monotonic (sorted, no duplicates) in either direction. A run
// that isn't strictly monotonic is rejected as bad server data.
func findHoles(
	v []ThreadMessage,
) (
	[]proto.RTMsgSeq,
	error,
) {
	if len(v) <= 1 {
		return nil, nil
	}

	signMatch := func(a, b int) bool {
		return (a < 0) == (b < 0)
	}

	start := int(v[0].Seq)
	end := int(core.Last(v).Seq)
	inc := 1
	if end < start {
		inc = -1
	}

	// Validate the run is strictly monotonic in `inc`'s direction (and that
	// every seq is valid) up front, so the hole walk below can trust it. This
	// catches duplicates (delta 0) and out-of-order seqs.
	for i, msg := range v {
		if !msg.Seq.IsValid() {
			return nil, core.BadServerDataError("msg with invalid seqno")
		}
		if i == 0 {
			continue
		}
		d := msg.Seq.Int() - v[i-1].Seq.Int()
		if d == 0 || !signMatch(inc, d) {
			return nil, core.BadServerDataError("non-monotonic thread msg sequence")
		}
	}

	// Walk start..end inclusive; any index not present in v is a hole. v is
	// monotonic, so a single forward cursor tracks the next present seq.
	var ret []proto.RTMsgSeq
	var ptr int
	for i := start; i != end; i += inc {
		if v[ptr].Seq.Int() == i {
			ptr++
		} else {
			ret = append(ret, proto.RTMsgSeq(i))
		}
	}
	return ret, nil
}

func (d *Minder) initReq(
	m MetaContext,
	team *proto.FQTeamParsed,
	appID proto.RTAppID,
	channel lcl.RTChannelSpecifier,
) (
	*RTParty,
	*lcl.RTChannelMetadataPlaintext,
	*rem.RealTimeClient,
	error,
) {
	if team == nil {
		return nil, nil, nil, core.InternalError("team is required to read in Stage 1a")
	}
	rtp, err := d.base.GetParty(m.Base(), team)
	if err != nil {
		return nil, nil, nil, err
	}
	ch, err := d.resolveChannel(m, rtp, appID, channel)
	if err != nil {
		return nil, nil, nil, err
	}
	_, cli, err := d.clientLocal(m.Base(), d.au)
	if err != nil {
		return nil, nil, nil, err
	}
	return rtp, ch, cli, nil
}

// TeamViewToken returns the team's view bearer token, used for AsLocalTeam user
// loads. The agent uses it to resolve message-sender UIDs to usernames: in
// closed viewership mode, co-members can only load each other mediated through
// the shared team, not directly. Returns nil if the team carries no view token
// (e.g. it was loaded as self/owner); callers should treat name resolution as
// best-effort and tolerate a nil token.
func (d *Minder) TeamViewToken(
	m MetaContext,
	team *proto.FQTeamParsed,
) (
	*rem.TeamVOBearerToken,
	error,
) {
	if team == nil {
		return nil, core.InternalError("team is required")
	}
	rtp, err := d.base.GetParty(m.Base(), team)
	if err != nil {
		return nil, err
	}
	return rtp.PLCNode().ViewTok(), nil
}

// usernameCacheGet returns a cached, unexpired display name for uid, if any.
func (d *Minder) usernameCacheGet(m MetaContext, uid proto.UID) (proto.NameUtf8, bool) {
	d.usernameMu.Lock()
	defer d.usernameMu.Unlock()
	ent, ok := d.usernameCache[uid]
	if !ok {
		return "", false
	}
	if !m.G().Now().Before(ent.expiresAt) {
		delete(d.usernameCache, uid)
		return "", false
	}
	return ent.name, true
}

// usernameCacheSet records uid -> name with a fresh jittered TTL.
func (d *Minder) usernameCacheSet(m MetaContext, uid proto.UID, nm proto.NameUtf8) {
	d.usernameMu.Lock()
	defer d.usernameMu.Unlock()
	d.usernameCache[uid] = usernameCacheEntry{
		name:      nm,
		expiresAt: m.G().Now().Add(jitteredUsernameTTL()),
	}
}

// ResolveSenderNames maps each distinct user-sender UID in msgs to its display
// name. Resolutions are memoized (see usernameCache) since each cache miss is a
// full user-chain load; in closed viewership mode the load is mediated through
// the shared team, so a team view bearer token (tok) is presented. Best-effort:
// a sender that can't be loaded is omitted from the result rather than failing.
func (d *Minder) ResolveSenderNames(
	m MetaContext,
	tok *rem.TeamVOBearerToken,
	msgs []ThreadMessage,
) map[proto.UID]proto.NameUtf8 {
	ret := make(map[proto.UID]proto.NameUtf8)
	for i := range msgs {
		sender := msgs[i].Sender
		if sender == nil || !sender.IsUser() {
			continue
		}
		uid, err := sender.UID()
		if err != nil {
			continue
		}
		if _, ok := ret[uid]; ok {
			continue
		}
		if nm, ok := d.resolveSenderName(m, tok, uid); ok {
			ret[uid] = nm
		}
	}
	return ret
}

// resolveSenderName returns the display name for a single sender UID -- from the
// cache if present, otherwise via a (team-mediated) user-chain load whose result
// is then cached. Returns false if the user can't be loaded.
func (d *Minder) resolveSenderName(
	m MetaContext,
	tok *rem.TeamVOBearerToken,
	uid proto.UID,
) (proto.NameUtf8, bool) {
	if nm, ok := d.usernameCacheGet(m, uid); ok {
		return nm, true
	}
	uw, err := libclient.LoadUser(m.Base(), libclient.LoadUserArg{
		Uid:               uid,
		LoadMode:          libclient.LoadModeOthers,
		TeamVOBearerToken: tok,
	})
	if err != nil {
		m.Warnw("resolveSenderName", "uid", uid, "err", err)
		return "", false
	}
	nm := uw.Name()
	d.usernameCacheSet(m, uid, nm)
	return nm, true
}

// if inc > 1, sort ascending
// if inc < 1, sort descending
func sortMsgs(v []ThreadMessage, inc int) error {
	if inc == 0 {
		return core.InternalError("bad sort direction")
	}
	slices.SortFunc(v,
		func(a, b ThreadMessage) int {
			return (a.Seq.Int() - b.Seq.Int()) * inc
		},
	)
	return nil
}

type msgSession struct {
	idMap map[proto.RTMsgID]proto.RTMsgSeq
}

func newMsgSession() *msgSession {
	return &msgSession{
		idMap: make(map[proto.RTMsgID]proto.RTMsgSeq),
	}
}

// GetThreadBookened fetches and decrypts a page of messages from the named channel.
// klass disambiguates when a name exists in more than one class; pass nil when
// the name is unique.
//
// The limits are given by inclusive bookends. The direction is infered from the
// ordering of the bookends.
//
// Here is the overall algorithm:
//   - fecth from local DB
//   - fetch from server after the max (or min) message, and plug in any holes
//   - check that prev pointers align with server sequencing.
//   - cache any newly downloaded messages
func (d *Minder) GetThreadBookended(
	m MetaContext,
	team *proto.FQTeamParsed,
	appID proto.RTAppID,
	channel lcl.RTChannelSpecifier,
	start proto.RTMsgSeq,
	end proto.RTMsgSeq,
) (
	[]ThreadMessage,
	bool,
	error,
) {
	if team == nil {
		return nil, false, core.InternalError("team is required to read in Stage 1a")
	}

	sess := newMsgSession()

	// Direction is implied by the ordering of the bookends; the request is
	// authoritative. Cached rows come back in this same order (DBRange.Get
	// orders by start vs end), so cached[0] is the `start` side throughout.
	// Bookends are inclusive, so start==end is a well-defined single-message
	// request; direction is moot there, and ascending (the default) is fine.
	inc := 1
	if end < start {
		inc = -1
	}

	rtp, ch, cli, err := d.initReq(m, team, appID, channel)
	if err != nil {
		return nil, false, err
	}

	cachedMsgsEnc, err := dbGetMsgs(
		m, d.au,
		ch.Id,
		start,
		end,
	)
	if err != nil {
		return nil, false, err
	}

	cached, err := d.decodeMsgs(
		m,
		rtp,
		appID,
		ch.Id,
		cachedMsgsEnc,
	)
	if err != nil {
		return nil, false, err
	}
	holes, err := findHoles(cached)
	if err != nil {
		return nil, false, err
	}

	var bookends []rem.RTThreadRangeBookends
	if len(cached) > 0 {

		cachedStart := cached[0].Seq
		cachedEnd := core.Last(cached).Seq

		// We had everything in cache! Cached messages were validated when they
		// were first ingested, so by the trust model we don't re-verify here.
		if len(holes) == 0 && start == cachedStart && end == cachedEnd {
			return cached, false, nil
		}

		if start != cachedStart {
			bookends = append(bookends,
				rem.RTThreadRangeBookends{
					Start: start,
					End:   proto.RTMsgSeq(int(cachedStart) - inc),
				},
			)
		}
		if cachedEnd != end {
			bookends = append(bookends,
				rem.RTThreadRangeBookends{
					Start: proto.RTMsgSeq(int(cachedEnd) + inc),
					End:   end,
				},
			)
		}
	} else {
		bookends = []rem.RTThreadRangeBookends{{Start: start, End: end}}
		cached = []ThreadMessage{}
	}

	d.serverThreadReads.Add(1)
	page, err := cli.RtGetThread(m.Ctx(), rem.RTThreadQuery{
		ChannelID: ch.Id,
		Bookends:  bookends,
		Seqs:      holes,
	})
	if err != nil {
		return nil, false, err
	}
	d.hookReadRes(&page)

	err = sess.loadFromServer(extractAllSeqIDPairsFromRTThreadPage(&page))
	if err != nil {
		return nil, false, err
	}

	ret := cached
	for _, r := range page.RangeMsgs {
		tmp, err := d.decodeAndCacheServerMsgs(m, sess, rtp, appID, ch.Id, r.Lst)
		if err != nil {
			return nil, false, err
		}
		ret = merge(ret, tmp, inc)
	}

	tmp, err := d.decodeAndCacheServerMsgs(m, sess, rtp, appID, ch.Id, page.SeqMsgs)
	if err != nil {
		return nil, false, err
	}

	// we have to sort these messages as they come back randomly from the server.
	// since we are going to merge them just below
	err = sortMsgs(tmp, inc)
	if err != nil {
		return nil, false, err
	}

	ret = merge(ret, tmp, inc)

	// "final" means there's nothing more in the paging direction: we failed to
	// reach the far (`end`) edge, so the thread ran out before it. After the sort
	// Last(ret) is always the `end` side (smallest seq when descending, largest
	// when ascending). A short read at the `start` side instead just means
	// `start` overshot the live head, which isn't final. Empty => nothing in
	// range, so final.
	isFinal := len(ret) == 0 ||
		(inc > 0 && core.Last(ret).Seq < end) ||
		(inc < 0 && core.Last(ret).Seq > end)

	return ret, isFinal, nil
}

// GetThreadPage fetches up to num messages, newest-first, ending just before the
// cursor `before` (exclusive). With before==0 it returns the most recent page
// (the live head). It also reports atBeginning: true when the page reaches seq 1,
// i.e. there are no older messages to page back to. To walk backwards through a
// thread, pass the oldest seq of the previous page as the next `before`.
func (d *Minder) GetThreadPage(
	m MetaContext,
	team *proto.FQTeamParsed,
	appID proto.RTAppID,
	channel lcl.RTChannelSpecifier,
	before proto.RTMsgSeq,
	num uint,
) (
	[]ThreadMessage,
	bool,
	error,
) {
	if num == 0 {
		num = 128
	}

	// before==0: start from the live head.
	if before == 0 {
		msgs, err := d.GetThreadRecentMsgs(m, team, appID, channel, num)
		if err != nil {
			return nil, false, err
		}
		atBeginning := len(msgs) == 0 || core.Last(msgs).Seq <= 1
		return msgs, atBeginning, nil
	}

	// Page backwards, newest-first, over the inclusive seq window [lo, hi].
	// `before` is exclusive, so the window's top is hi = before-1. Bookends are
	// inclusive, so [lo, hi] holds exactly hi-lo+1 messages; with seqs contiguous
	// from 1 we size it to `num` (lo = hi-num+1, clamped at 1) and know we're at
	// the beginning once the window reaches seq 1.
	hi := int(before) - 1
	if hi < 1 {
		return nil, true, nil
	}
	lo := hi - int(num) + 1
	if lo < 1 {
		lo = 1
	}
	atBeginning := lo <= 1

	// Inclusive bookends: start=hi (newest), end=lo (oldest) ⇒ descending page.
	// hi==lo (a single trailing message) is fine -- bookends are inclusive.
	msgs, _, err := d.GetThreadBookended(m, team, appID, channel,
		proto.RTMsgSeq(hi), proto.RTMsgSeq(lo))
	if err != nil {
		return nil, false, err
	}
	return msgs, atBeginning, nil
}

// GetThreadView fetches a page (see GetThreadPage) and returns it as a decrypted,
// app-layer RTThreadView: message bodies plus sender display names resolved from
// their UIDs. Name resolution is team-mediated (closed viewership only lets
// co-members load each other through the shared team) and best-effort -- a sender
// that can't be loaded simply has a nil name rather than failing the read.
func (d *Minder) GetThreadView(
	m MetaContext,
	team *proto.FQTeamParsed,
	appID proto.RTAppID,
	channel lcl.RTChannelSpecifier,
	before proto.RTMsgSeq,
	num uint,
) (
	*lcl.RTThreadView,
	error,
) {
	msgs, atBeginning, err := d.GetThreadPage(m, team, appID, channel, before, num)
	if err != nil {
		return nil, err
	}
	tok, err := d.TeamViewToken(m, team)
	if err != nil {
		return nil, err
	}
	names := d.ResolveSenderNames(m, tok, msgs)

	ret := lcl.RTThreadView{AtBeginning: atBeginning}
	for i := range msgs {
		ret.Msgs = append(ret.Msgs, threadMessageToView(&msgs[i], names))
	}
	return &ret, nil
}

// threadMessageToView converts a decrypted ThreadMessage to the app-layer
// RTMsgView, attaching the sender's display name from names if resolved.
func threadMessageToView(
	msg *ThreadMessage,
	names map[proto.UID]proto.NameUtf8,
) lcl.RTMsgView {
	ret := lcl.RTMsgView{
		Seq:        msg.Seq,
		MsgID:      msg.MsgID,
		PrevID:     msg.PrevID,
		PrevSeq:    msg.PrevSeq,
		Typ:        msg.Typ,
		Sender:     msg.Sender,
		SentAtTime: msg.SentAtTime,
		InsertTime: msg.InsertTime,
		Body:       msg.Body,
	}
	if msg.Sender != nil && msg.Sender.IsUser() {
		if uid, err := msg.Sender.UID(); err == nil {
			if nm, ok := names[uid]; ok {
				ret.SenderName = &nm
			}
		}
	}
	return ret
}

// Get the num most recent messages that we don't already have.
func (d *Minder) GetThreadRecentMsgs(
	m MetaContext,
	team *proto.FQTeamParsed,
	appID proto.RTAppID,
	channel lcl.RTChannelSpecifier,
	num uint,
) (
	[]ThreadMessage,
	error,
) {
	if num == 0 {
		num = 128
	}
	inc := -1
	rtp, ch, cli, err := d.initReq(m, team, appID, channel)
	if err != nil {
		return nil, err
	}

	sess := newMsgSession()

	cachedMsgsEnc, err := dbGetRecentMsgs(
		m,
		d.au,
		ch.Id,
		num,
	)
	if err != nil {
		return nil, err
	}
	cached, err := d.decodeMsgs(
		m,
		rtp,
		appID,
		ch.Id,
		cachedMsgsEnc,
	)
	if err != nil {
		return nil, err
	}
	var stopAt proto.RTMsgSeq
	if len(cached) > 0 {
		stopAt = cached[0].Seq
	}
	d.serverRecentReads.Add(1)
	fresh, err := cli.RtGetThreadRecents(
		m.Ctx(),
		rem.RtGetThreadRecentsArg{
			Ch:     ch.Id,
			StopAt: stopAt,
			Lim:    uint64(num),
		},
	)
	if err != nil {
		return nil, err
	}
	d.hookRecentsRes(&fresh)
	err = sess.loadFromServer(extractAllSeqIDPairsFromMsgList(fresh.Lst))
	if err != nil {
		return nil, err
	}
	freshPlain, err := d.decodeAndCacheServerMsgs(m, sess, rtp, appID, ch.Id, fresh.Lst)
	if err != nil {
		return nil, err
	}

	// All of the fresh messages fill up the window, so can just return here.
	if len(freshPlain) >= int(num) {
		return freshPlain, nil
	}

	// in order, but with holes
	combined := append(freshPlain, cached...)
	holes, err := findHoles(combined)
	if err != nil {
		return nil, err
	}
	if len(holes) == 0 {
		end := min(int(num), len(combined))
		return combined[0:end], nil
	}

	d.serverThreadReads.Add(1)
	fillers, err := cli.RtGetThread(
		m.Ctx(),
		rem.RTThreadQuery{
			ChannelID: ch.Id,
			Seqs:      holes,
		},
	)
	if err != nil {
		return nil, err
	}
	d.hookReadRes(&fillers)
	// Same session as the recents fetch above (additive, no reset), so the
	// fillers are cross-checked against the recents page: equivocation between
	// the two batches and prev pointers from a filler into a recents message are
	// both caught here.
	err = sess.loadFromServer(extractAllSeqIDPairsFromRTThreadPage(&fillers))
	if err != nil {
		return nil, err
	}

	fillerPlain, err := d.decodeAndCacheServerMsgs(m, sess, rtp, appID, ch.Id, fillers.SeqMsgs)
	if err != nil {
		return nil, err
	}
	// we have to sort these messages as they come back randomly from the server.
	// since we are going to merge them just below
	err = sortMsgs(fillerPlain, inc)
	if err != nil {
		return nil, err
	}
	ret := merge(combined, fillerPlain, inc)
	// Trim to the requested window, matching the no-holes path above.
	end := min(int(num), len(ret))
	return ret[0:end], nil
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
			MsgID:                    cm.Md.Md.MsgID,
			PrevID:                   cm.Md.Md.PrevID,
			PrevSeq:                  cm.Md.Md.PrevSeq,
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

func (d *Minder) validateMetadata(
	m MetaContext,
	sess *msgSession,
	chid proto.RTChannelID,
	q proto.RTMsgSeq,
	prevSeq proto.RTMsgSeq,
	prevID proto.RTMsgID,
) error {
	if !prevSeq.IsValid() {
		return nil
	}
	if q <= prevSeq {
		return core.RTMsgOrderError(
			fmt.Sprintf("server returned msg @%d <= prev @%d", q, prevSeq),
		)
	}
	if prevID.IsZero() {
		return core.RTMsgOrderError("need a prevID if prev sequence is specified")
	}
	found, ok := sess.idMap[prevID]
	if ok && found != prevSeq {
		s, err := prevID.RTID().StringErr()
		if err != nil {
			s = "msg error: " + err.Error()
		}
		return core.RTMsgOrderError(
			fmt.Sprintf("disagreement for id=%s; %d != %d", s, found, prevSeq),
		)
	}
	err := d.validateMsgSeqToIDMapping(m, chid, prevSeq, prevID)
	if err != nil {
		return err
	}
	return nil
}

func (d *Minder) decodeAndVerifyMsg(
	m MetaContext,
	sess *msgSession,
	rtp *RTParty,
	appID proto.RTAppID,
	chid proto.RTChannelID,
	msg rem.RTMsg,
) (
	*ThreadMessage,
	*proto.RTMsgCached,
	error,
) {
	body, cm, err := d.openMessageWithRTMsg(m, rtp, appID, msg, chid)
	if err != nil {
		return nil, nil, err
	}
	err = d.validateMetadata(m, sess, chid, msg.Seq, msg.Md.PrevSeq, msg.Md.PrevID)
	if err != nil {
		return nil, nil, err
	}
	ret := ThreadMessage{
		Seq:                      msg.Seq,
		MsgID:                    msg.Md.MsgID,
		PrevID:                   msg.Md.PrevID,
		PrevSeq:                  msg.Md.PrevSeq,
		Typ:                      msg.Md.Typ,
		Sender:                   msg.Sender,
		SenderFurtherAttribution: msg.Md.FurtherUserAttribution,
		SentAtTime:               msg.Md.SendTime,
		InsertTime:               msg.InsertTime,
		Body:                     body,
	}
	return &ret, cm, nil
}

// decodeAndCacheServerMsgs decrypts each server message into a ThreadMessage for the
// caller and writes the decrypted bodies into the local cache. Shared by
// GetThread (paged range) and GetMsgs (arbitrary set of seqs).
func (d *Minder) decodeAndCacheServerMsgs(
	m MetaContext,
	sess *msgSession,
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
		tm, cm, err := d.decodeAndVerifyMsg(m, sess, rtp, appID, chid, msg)
		if err != nil {
			return nil, err
		}
		out = append(out, *tm)
		cachePuts = append(cachePuts, proto.RTMsgCachedWithSeq{
			Cm:  *cm,
			Seq: msg.Seq,
		})
	}
	err := d.dbPutMsgs(m, cachePuts)
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
	channel lcl.RTChannelSpecifier,
	seqs []proto.RTMsgSeq,
) (
	[]ThreadMessage,
	error,
) {
	if team == nil {
		return nil, core.InternalError("team is required to read in Stage 1a")
	}
	sess := newMsgSession()
	rtp, err := d.base.GetParty(m.Base(), team)
	if err != nil {
		return nil, err
	}
	ch, err := d.resolveChannel(m, rtp, appID, channel)
	if err != nil {
		return nil, err
	}
	_, cli, err := d.clientLocal(m.Base(), d.au)
	if err != nil {
		return nil, err
	}
	d.serverThreadReads.Add(1)
	page, err := cli.RtGetThread(m.Ctx(), rem.RTThreadQuery{
		ChannelID: ch.Id,
		Seqs:      seqs,
	})
	if err != nil {
		return nil, err
	}
	d.hookReadRes(&page)
	err = sess.loadFromServer(extractAllSeqIDPairsFromRTThreadPage(&page))
	if err != nil {
		return nil, err
	}
	return d.decodeAndCacheServerMsgs(m, sess, rtp, appID, ch.Id, page.SeqMsgs)
}

func (d *Minder) dbPutMsgs(
	m MetaContext,
	v []proto.RTMsgCachedWithSeq,
) error {
	for _, x := range v {
		err := d.cacheMsgID(x.Seq, x.Cm.Md.Md.MsgID)
		if err != nil {
			return err
		}
	}
	return dbPutMsgs(m, d.au, v)
}

func (d *Minder) validateMsgSeqToIDMapping(
	m MetaContext,
	chid proto.RTChannelID,
	q proto.RTMsgSeq,
	i proto.RTMsgID,
) error {
	tmp, ok := d.msgIDCache.Get(i)

	if ok {
		if tmp == q {
			return nil
		}
		s, err := i.RTID().StringErr()
		if err != nil {
			s = "msg encode error: " + err.Error()
		}
		return core.RTMsgOrderError(
			fmt.Sprintf(
				"bad mapping: expected %s -> %d but got %d",
				s, i, tmp,
			))
	}

	msgs, err := dbGetMsgs(m, d.au, chid, q, q)
	if err != nil {
		return err
	}
	if len(msgs) == 0 {
		// We don't have the prev message anywhere we can consult (this page, the
		// id-cache, or the local DB), so we can't check that prevID maps to
		// prevSeq -- accept it. Known gap: the message is then cached as
		// "validated", and per the trust model (cached == already-validated) we
		// never recheck it, even if we later learn the prev's seq->id mapping and
		// could retroactively catch a lie.
		// TODO(chat): revisit prev pointers when their target later becomes known.
		return nil
	}
	if len(msgs) != 1 {
		return core.RTMsgOrderError(fmt.Sprintf("too many rows for seq=%d", q))
	}
	msg := msgs[0]
	if !msg.Cm.Md.Md.MsgID.Eq(i) {
		return core.RTMsgOrderError(fmt.Sprintf("msg ID clash for seq=%d", q))
	}
	return nil
}

type seqIDPair struct {
	id  proto.RTMsgID
	seq proto.RTMsgSeq
}

func (s *msgSession) loadFromServer(v []seqIDPair) error {
	for _, x := range v {
		existing, ok := s.idMap[x.id]
		if ok && existing != x.seq {
			s, err := x.id.RTID().StringErr()
			if err != nil {
				s = "id error: " + err.Error()
			}
			return core.RTMsgOrderError(
				fmt.Sprintf("conflicting sequence numbers for msg ID %s", s),
			)
		}
		s.idMap[x.id] = x.seq
	}
	return nil
}

func extractAllSeqIDPairsFromMsgList(l []rem.RTMsg) []seqIDPair {
	ret := make([]seqIDPair, 0, len(l))
	for _, m := range l {
		ret = append(ret, seqIDPair{seq: m.Seq, id: m.Md.MsgID})
	}
	return ret

}

func extractAllSeqIDPairsFromRTThreadPage(p *rem.RTThreadPage) []seqIDPair {
	var ret []seqIDPair
	for _, r := range p.RangeMsgs {
		tmp := extractAllSeqIDPairsFromMsgList(r.Lst)
		ret = append(ret, tmp...)
	}
	tmp := extractAllSeqIDPairsFromMsgList(p.SeqMsgs)
	ret = append(ret, tmp...)
	return ret
}
