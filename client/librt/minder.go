package librt

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/chains"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
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
		if !errors.Is(err, core.RTChannelRaceError{}) || i == numTries-1 {
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
	return nil, core.RTChannelRaceError{}
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
	enc proto.RTMetadataSecretBox,
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
	enc *proto.RTMetadataSecretBox,
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
