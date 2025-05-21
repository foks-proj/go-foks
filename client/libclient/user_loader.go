// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"context"
	"crypto/x509"
	"errors"
	"slices"
	"time"

	"github.com/foks-proj/go-foks/lib/chains"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type LoadMode int

const (
	LoadModeNone       LoadMode = 0
	LoadModeSelf       LoadMode = 1
	LoadModeDeadSelf   LoadMode = 2
	LoadModeOthers     LoadMode = 3
	LoadModeOpenOthers LoadMode = 4
)

func (m LoadMode) IsSelf() bool {
	return m == LoadModeSelf || m == LoadModeDeadSelf
}

// UserChainRPCLoader must resolve usernames to UIDs in addition
// to loading chainlinks for a given UIDs.
type UserChainRPCLoader interface {
	LoadUserChain(ctx context.Context, a rem.LoadUserChainArg) (rem.UserChain, error)
	ResolveUsername(ctx context.Context, a rem.ResolveUsernameArg) (proto.UID, error)
}

func ChainLoaderGenericError(s string) error {
	return core.ChainLoaderError{Err: errors.New(s)}
}

type UserLoader struct {
	BaseChainLoader
	arg             LoadUserArg
	probe           *chains.Probe
	rpcLoader       UserChainRPCLoader
	existing        *lcl.UserSigchainState
	newState        *lcl.UserSigchainState
	raw             rem.UserChain
	msess           *merkle.Session
	odcs            [](*core.OpenDeviceChangeRes)
	keys            map[proto.FQEntityFixed]core.PublicSuiterWithSeqno
	devInfo         map[proto.FQEntityFixed][]proto.DeviceInfo
	puks            map[core.RoleKeyAndGen]core.SharedPublicSuite
	puksByRole      map[core.RoleKey][]core.SharedPublicSuite
	pukGens         map[core.RoleKey]proto.Generation
	allMerkleLeaves []proto.MerkleLeaf
	uncs            []proto.Commitment
	unseq           proto.NameSeqno
	dnIdx           int // index into raw.Devicenames
	deviceOrder     []proto.FQEntityFixed
	sctlsc          *proto.TreeLocationCommitment
	res             *UserWrapper
	hepks           *core.HEPKSet
	stalePUKs       *StaleKeys
}

func (u *UserLoader) Existing() *lcl.UserSigchainState {
	return u.existing
}

type PartyWrapper interface {
	Hostname() proto.Hostname
	Name() proto.NameUtf8
	TeamMemberKeys(r core.RoleKey) (*proto.TeamMemberKeys, *proto.HEPK, error)
	CheckTeamIndexRange(targetTeam core.RationalRange, joinReqIndexRange *proto.RationalRange) error
}

type UserWrapper struct {
	prot      *lcl.UserSigchainState
	hostAddr  proto.TCPAddr
	keys      map[proto.FQEntityFixed]core.PublicSuiterWithSeqno
	DevInfo   map[proto.FQEntityFixed][]proto.DeviceInfo
	pukGens   map[core.RoleKey]proto.Generation
	puks      map[core.RoleKey][]core.SharedPublicSuite
	fqu       proto.FQUser
	Hepks     *core.HEPKSet
	stalePUKs *StaleKeys
}

var _ PartyWrapper = (*UserWrapper)(nil)

func (u *UserWrapper) Hostname() proto.Hostname { return u.hostAddr.Hostname() }
func (u *UserWrapper) Name() proto.NameUtf8     { return u.prot.Username.B.NameUtf8 }
func (u *UserWrapper) TeamMemberKeys(rk core.RoleKey) (*proto.TeamMemberKeys, *proto.HEPK, error) {
	puks := u.puks[rk]
	if len(puks) == 0 {
		return nil, nil, core.KeyNotFoundError{Which: "puk at role"}
	}
	lst := core.Last(puks)
	hepk, ok := u.Hepks.Lookup(&lst.HepkFp)
	if !ok {
		return nil, nil, core.KeyNotFoundError{Which: "hepk"}
	}
	return &proto.TeamMemberKeys{
		VerifyKey: lst.VerifyKey,
		HepkFp:    lst.HepkFp,
		Gen:       lst.Gen,
	}, hepk.Obj(), nil
}

func (u *UserWrapper) CheckTeamIndexRange(targetTeam core.RationalRange, joinReqIndexRange *proto.RationalRange) error {
	return nil
}

func (u *UserWrapper) StalePUKs() *StaleKeys {
	return u.stalePUKs
}

func (u *UserWrapper) HasDeviceID(d proto.DeviceID) bool {
	if d == nil {
		return false
	}
	for _, k := range u.Prot().Devices {
		if k.Key.Member.Id.Entity.Eq(d.EntityID()) {
			return true
		}
	}
	return false
}

func (u *UserWrapper) AllDeviceIDs() ([]proto.DeviceID, error) {
	set := make(map[proto.FixedEntityID]bool)
	for _, k := range u.Prot().Devices {
		fqid, err := k.Key.Member.Id.Entity.Fixed()
		if err != nil {
			return nil, err
		}
		set[fqid] = true
	}
	ret := make([]proto.DeviceID, 0, len(set))
	for k := range set {
		did, err := k.Unfix().ToDeviceID()
		if err == nil {
			ret = append(ret, did)
		}
	}
	return ret, nil
}

func (u *UserWrapper) BookendSigningKey(e proto.FQEntity, epno proto.MerkleEpno) (*KeyBookends, error) {
	ef, err := e.Fixed()
	if err != nil {
		return nil, err
	}
	lst, ok := u.DevInfo[*ef]
	if !ok {
		return nil, core.KeyNotFoundError{}
	}
	for _, di := range lst {
		if epno < di.Provisioned.Chain.Root.Epno {
			continue
		}
		if di.Revoked == nil {
			return nil, nil
		}
		if di.Revoked.Chain.Root.Epno >= epno {
			return &KeyBookends{
				Provision: di.Provisioned,
				Revoke:    *di.Revoked,
			}, nil
		}
	}
	return nil, core.KeyNotFoundError{}
}

func (u *UserWrapper) deviceIdx(e proto.EntityID) (*proto.FQEntityFixed, error) {
	fqe, err := e.Fixed()
	if err != nil {
		return nil, err
	}
	idx := proto.FQEntityFixed{
		Entity: fqe,
		Host:   u.fqu.HostID,
	}
	return &idx, nil
}

func (u *UserWrapper) CountOwnerDevices() (int, error) {
	ret := 0
	for _, k := range u.keys {
		role := k.Ps.GetRole()
		typ, err := role.GetT()
		if err != nil {
			return ret, err
		}
		if typ == proto.RoleType_OWNER {
			ret++
		}
	}
	return ret, nil
}

func (u *UserWrapper) FindDevice(e proto.EntityID) (*proto.DeviceInfo, error) {

	if len(u.DevInfo) == 0 {
		return nil, nil
	}
	idx, err := u.deviceIdx(e)
	if err != nil {
		return nil, err
	}
	dev := u.DevInfo[*idx]
	if dev == nil {
		return nil, nil
	}
	lst := core.Last(dev)
	return &lst, nil
}

func (u *UserWrapper) ActiveDevices() []core.PublicSuiter {
	ret := make([]core.PublicSuiter, 0, len(u.keys))
	for _, k := range u.keys {
		ret = append(ret, k.Ps)
	}
	return ret
}

func (u *UserWrapper) LatestOwnerPUK() (*proto.SharedKeyAndHEPK, error) {
	var retSk *proto.SharedKey
	for _, sk := range u.prot.Puks {
		eq, err := sk.Role.Eq(proto.OwnerRole)
		if err != nil {
			return nil, err
		}
		if eq && (retSk == nil || sk.Gen > retSk.Gen) {
			retSk = &sk
		}
	}
	if retSk == nil {
		return nil, nil
	}
	hepk, ok := u.Hepks.Lookup(&retSk.HepkFp)
	if !ok {
		return nil, core.KeyNotFoundError{Which: "hepk"}
	}
	ret := proto.SharedKeyAndHEPK{
		Sk:   *retSk,
		Hepk: *hepk.Obj(),
	}
	return &ret, nil
}

func (u *UserWrapper) Prot() *lcl.UserSigchainState {
	return u.prot
}

func (u *UserWrapper) ProtoWithMetadata() *lcl.UserMetadataAndSigchainState {
	return &lcl.UserMetadataAndSigchainState{
		Fqu:      u.fqu,
		State:    *u.prot,
		Hostname: u.hostAddr.Hostname(),
	}
}

type LoadUserArg struct {
	Uid               proto.UID
	Username          proto.NameUtf8
	LoadMode          LoadMode
	Host              *LoadUserHost
	ActiveUser        *UserContext
	NoStore           bool
	TeamVOBearerToken *rem.TeamVOBearerToken // Provide if loading a user on behalf of a team
}

type LoadUserHost struct {
	HostID  proto.HostID
	Addr    proto.TCPAddr
	DefPort proto.Port
	CAs     *x509.CertPool
	Timeout time.Duration
	Tok     proto.PermissionToken
}

type UserPrivate struct {
	UserWrapper
}

func NewUserLoader(arg LoadUserArg) *UserLoader {
	ret := &UserLoader{
		arg:       arg,
		stalePUKs: NewStaleKeys(),
	}
	return ret
}

func LoadUser(m MetaContext, arg LoadUserArg) (*UserWrapper, error) {
	loader := NewUserLoader(arg)
	return loader.Run(m)
}

func LoadMe(m MetaContext, au *UserContext) (*UserWrapper, error) {
	if au == nil {
		au = m.G().ActiveUser()
	}
	if au == nil {
		return nil, core.NoActiveUserError{}
	}
	arg := LoadUserArg{
		Uid:        au.Info.Fqu.Uid,
		LoadMode:   LoadModeSelf,
		ActiveUser: au,
	}
	loader := NewUserLoader(arg)
	return loader.Run(m)
}

func LoadUserByFQUserParsed(m MetaContext, fqu proto.FQUserParsed) (*UserWrapper, error) {
	au := m.G().ActiveUser()
	if au == nil {
		return nil, core.NoActiveUserError{}
	}
	arg := LoadUserArg{
		LoadMode:   LoadModeOpenOthers,
		ActiveUser: au,
	}
	isS, err := fqu.User.GetS()
	if err != nil {
		return nil, err
	}
	if isS {
		nm := fqu.User.True()
		arg.Username = nm
	} else {
		uid := fqu.User.False()
		arg.Uid = uid
	}
	if fqu.Host != nil {
		isS, err := fqu.Host.GetS()
		if err != nil {
			return nil, err
		}
		if isS {
			arg.Host = &LoadUserHost{
				Addr: fqu.Host.True(),
			}
		} else {
			arg.Host = &LoadUserHost{
				HostID: fqu.Host.False(),
			}
		}
	}
	return LoadUser(m, arg)
}

func (u *UserLoader) SetRPCLoader(l UserChainRPCLoader) {
	// In test we set this as a mock so we can emulate an EVIL server
	if u.rpcLoader == nil {
		u.rpcLoader = l
	}
}

func (u *UserLoader) connectHostHome(m MetaContext) error {
	au := m.G().ActiveUser()
	if au == nil {
		return core.NoDefaultHostError{}
	}
	return u.connectActiveUser(m, au)
}

func (u *UserLoader) connectActiveUser(m MetaContext, au *UserContext) error {
	hs := au.HomeServer()

	hid := au.HostID()

	if hs == nil && hid.IsZero() {
		return core.NoDefaultHostError{}
	}

	if hs != nil {
		u.probe = hs
	} else {
		err := u.resolveHost(m, hid)
		if err != nil {
			return err
		}
		au.SetHomeServer(u.probe)
	}

	cli, err := au.UserClient(m)
	if err != nil {
		return err
	}
	u.SetRPCLoader(cli)
	return nil
}

func (u *UserLoader) resolveHost(m MetaContext, hid proto.HostID) error {
	res, err := m.ResolveHostID(hid, &chains.ResolveOpts{})
	if err != nil {
		return err
	}
	u.probe = res.Probe
	return nil
}

func (u *UserLoader) resolveAndConnect(m MetaContext) error {
	err := u.resolveHost(m, u.arg.Host.HostID)
	if err != nil {
		return err
	}
	rcli, err := u.probe.RegCli(m)
	if err != nil {
		return err
	}
	u.SetRPCLoader(rcli)
	return nil
}

func (u *UserLoader) connectHost(m MetaContext) error {

	if u.arg.ActiveUser != nil {
		return u.connectActiveUser(m, u.arg.ActiveUser)
	}

	if u.arg.Host == nil && u.arg.ActiveUser == nil {
		return u.connectHostHome(m)
	}
	host := u.arg.Host

	if !u.arg.Username.IsZero() {
		return core.PermissionError("cannot load user by username without active user")
	}

	if host != nil && !host.HostID.IsZero() && host.Addr.Hostname().IsZero() {
		return u.resolveAndConnect(m)
	}

	if host == nil {
		return core.NoDefaultHostError{}
	}

	pr, err := m.G().DiscoveryMgr().Probe(m, chains.ProbeArg{
		Addr:    host.Addr,
		DefPort: host.DefPort,
		Timeout: host.Timeout,
		RootCAs: host.CAs,
	})

	if err != nil {
		return err
	}
	u.probe = pr

	cli, err := u.probe.RegCli(m)
	if err != nil {
		return err
	}
	u.SetRPCLoader(cli)

	return nil
}

func (u *UserLoader) loadUserFromServer(m MetaContext) error {
	var tok *proto.PermissionToken

	if u.arg.Host != nil {
		tok = &u.arg.Host.Tok
	}

	ma, err := u.probe.MerkleAgent(m)
	if err != nil {
		return err
	}

	u.msess = merkle.NewSession(ma)
	err = u.msess.Init(m.Ctx())
	if err != nil {
		return err
	}

	arg := rem.LoadUserChainArg{
		Uid:   u.arg.Uid,
		Start: proto.ChainEldestSeqno,
	}

	var auth rem.LoadUserChainAuth
	switch {
	case u.arg.LoadMode == LoadModeOpenOthers:
		auth = rem.NewLoadUserChainAuthWithOpenvhost()
	case tok != nil && tok.IsZero():
		return core.InternalError("zero'ed permissions token passed through loader is a bug")
	case tok != nil && !u.arg.LoadMode.IsSelf():
		auth = rem.NewLoadUserChainAuthWithToken(*tok)
	case tok != nil && u.arg.LoadMode.IsSelf():
		auth = rem.NewLoadUserChainAuthWithSelftoken(*tok)
	case u.arg.TeamVOBearerToken != nil:
		auth = rem.NewLoadUserChainAuthWithAslocalteam(*u.arg.TeamVOBearerToken)
	default:
		auth = rem.NewLoadUserChainAuthWithAslocaluser()
	}

	arg.Auth = auth

	if u.existing != nil {
		arg.Start = u.existing.Tail.Base.Seqno + 1
		arg.Username = &rem.NameSeqnoPair{
			N: u.existing.Username.B.Name,
			S: u.existing.Username.S + 1,
		}
	}
	res, err := u.rpcLoader.LoadUserChain(m.Ctx(), arg)
	if err != nil {
		race := true
		if core.IsAuthError(err) {
			race = false
		}
		return core.ChainLoaderError{
			Err:  err,
			Race: race,
		}
	}
	u.raw = res
	return nil
}

func (u *UserLoader) dbType() DbType {
	if u.arg.LoadMode.IsSelf() {
		return DbTypeHard
	}
	return DbTypeSoft
}

func (u *UserLoader) fqu() proto.FQUser {
	return proto.FQUser{
		Uid:    u.arg.Uid,
		HostID: u.HostID(),
	}
}

func (u *UserLoader) loadExistingUser(m MetaContext) error {

	var ret lcl.UserSigchainState
	scoper := u.fqu()
	_, err := m.DbGet(&ret, u.dbType(), &scoper, lcl.DataType_UserSigchainState, core.EmptyKey{})
	if errors.Is(err, core.RowNotFoundError{}) {
		return nil
	}
	if err != nil {
		return err
	}
	u.existing = &ret

	err = u.readKeysFromState(m)
	if err != nil {
		return err
	}

	err = u.readPuksFromState(m)
	if err != nil {
		return err
	}
	err = u.readStaleKeys(m)
	if err != nil {
		return err
	}

	u.sctlsc = &ret.Sctlsc

	return nil
}

func (u *UserLoader) checkMerkleRoot(m MetaContext) error {
	err := u.msess.Run(m.Ctx(), &u.raw.Merkle.Root)
	if err != nil {
		return core.ChainLoaderError{Err: err}
	}
	return nil
}

func (u *UserLoader) chainerAtIndex(n int) *proto.HidingChainer {
	if n >= len(u.odcs) {
		return nil
	}
	return &u.odcs[n].Gc.Chainer
}

func (u *UserLoader) checkUIDChain(m MetaContext) error {
	var prev *proto.LinkHash
	seqno := proto.ChainEldestSeqno
	if u.existing != nil {
		prev = &u.existing.LastHash
		seqno = u.existing.Tail.Base.Seqno + 1
	}
	return u.BaseChainLoader.checkChain(m, prev, seqno, u.raw.Links, u.chainerAtIndex, "uid", u.testing)
}

func (u *UserLoader) checkMerkleUIDPaths(m MetaContext) error {

	// The first few are username links, the rest are UID
	// links.
	offset := int(u.raw.NumUsernameLinks)
	var ntlc *proto.TreeLocationCommitment
	seqno := proto.ChainEldestSeqno

	if u.existing != nil {
		ntlc = &u.existing.Tail.NextLocationCommitment
		seqno = u.existing.Tail.Base.Seqno + 1
	}

	err := u.BaseChainLoader.checkMerklePaths(
		m,
		u.arg.Uid.EntityID(),
		proto.ChainType_User,
		u.raw.Locations,
		u.raw.Links,
		u.chainerAtIndex,
		u.raw.Merkle,
		ntlc,
		seqno,
		nil,
		offset,
		"uid",
		u.testing,
	)
	if err != nil {
		return err
	}

	// Make a list of all merkle keys known, one for each chainlink
	var keys []proto.MerkleLeaf
	if u.existing != nil {
		keys = append(keys, u.existing.MerkleLeaves...)
	}
	keys = append(keys, u.BaseChainLoader.merkleLeaves...)
	u.allMerkleLeaves = keys

	return nil
}

func (u *UserLoader) openLinks(m MetaContext) error {
	fqu := u.fqu()
	for n, link := range u.raw.Links {
		odc, err := core.OpenDeviceChange(&link, u.hepks, &fqu.Uid, fqu.HostID)
		if err != nil {
			return core.ChainLoaderError{Err: core.CLOpenLinkError{Err: err, N: n}}
		}
		u.odcs = append(u.odcs, odc)
	}
	return nil
}

func (u *UserLoader) readStaleKeys(m MetaContext) error {
	if u.existing == nil {
		return nil
	}
	err := u.stalePUKs.Import(u.existing.StalePUKs)
	if err != nil {
		return err
	}
	return nil
}

func (u *UserLoader) readPuksFromState(m MetaContext) error {
	if u.existing == nil {
		return nil
	}
	for _, k := range u.existing.Puks {
		hepk, ok := u.hepks.Lookup(&k.HepkFp)
		if !ok {
			return core.KeyNotFoundError{Which: "hepk"}
		}
		puk, err := core.ImportSharedPublicSuite(&k, hepk.Obj())
		if err != nil {
			return err
		}
		err = u.addPuk(m, *puk)
		if err != nil {
			return err
		}
	}
	return nil

}

func (u *UserLoader) readKeysFromState(m MetaContext) error {
	if u.existing == nil {
		return nil
	}

	hepks, err := core.ImportHEPKSet(&u.existing.Hepks)
	if err != nil {
		return err
	}
	u.hepks = hepks

	hid := u.probe.Chain().HostID()

	for _, d := range u.existing.Devices {

		ps, err := core.ImportPublicSuite(&d.Key, hepks, hid)
		if err != nil {
			return err
		}
		err = u.addDeviceKey(ps, d)
		if err != nil {
			return err
		}
	}

	return nil
}

func (u *UserLoader) HostID() proto.HostID {
	return u.probe.Chain().HostID()
}

func (u *UserLoader) addDeviceKey(
	ps core.PublicSuiter,
	di proto.DeviceInfo,
) error {
	fid, err := ps.GetEntityID().Fixed()
	if err != nil {
		return err
	}
	mapKey := proto.FQEntityFixed{Entity: fid, Host: u.HostID()}

	// If the device is revoked, we need to the device info but keep the key
	// out of the "keys" dictionary, which means currently active keys
	// that are allowed to sign new links for the user.
	if di.Revoked == nil {
		u.keys[mapKey] = core.PublicSuiterWithSeqno{
			Ps:    ps,
			Seqno: di.Provisioned.Chain.Seqno,
		}
	}

	lst := u.devInfo[mapKey]
	if lst == nil {
		u.deviceOrder = append(u.deviceOrder, mapKey)
		lst = []proto.DeviceInfo{di}
	} else {
		lst = append(lst, di)
	}
	u.devInfo[mapKey] = lst
	return err
}

func (u *UserLoader) UsernameNormalized() (proto.Name, error) {
	return core.NormalizeName(u.raw.UsernameUtf8)
}

func (u *UserLoader) addPuk(m MetaContext, puk core.SharedPublicSuite) error {
	// hold onto the PUK too
	pukKey, err := core.ImportRoleKeyAndGen(&puk)
	if err != nil {
		return err
	}
	u.puks[*pukKey] = puk
	rk, err := core.ImportRole(puk.Role)
	if err != nil {
		return err
	}

	// Need to be careful in the case of loading state back from
	// stored existing state, that we don't rollback the puk gen
	// here.
	gen, found := u.pukGens[*rk]
	if !found || gen < puk.Gen {
		u.pukGens[*rk] = puk.Gen
	}

	plist := u.puksByRole[*rk]
	if len(plist) > 0 && core.Last(plist).Gen >= puk.Gen {
		return core.InternalError("puk gen not increasing")
	}
	u.puksByRole[*rk] = append(plist, puk)

	u.stalePUKs.Refresh(*rk)
	return nil
}

func (u *UserLoader) playDeviceName(
	m MetaContext,
	c *proto.Commitment,
) (
	*proto.DeviceLabelAndName,
	error,
) {
	if c == nil {
		// This error shouldn't happen and should already have been caught
		return nil, core.InternalError("no new device in eldest link")
	}
	if u.arg.LoadMode != LoadModeSelf {
		return nil, nil
	}
	idx := u.dnIdx
	if idx >= len(u.raw.DeviceNames) {
		return nil, core.ChainLoaderError{
			Err: core.CLBadCountError{
				Which:    "device-names",
				Expected: idx + 1,
				Actual:   len(u.raw.DeviceNames),
			},
		}
	}
	dnk := u.raw.DeviceNames[idx]
	err := core.OpenCommitment(&dnk.Dln.Label, &dnk.CommitmentKey, c)
	if err != nil {
		return nil, core.ChainLoaderError{
			Err: core.ULOpenCommitmentError{
				Which: "device-name",
				Err:   err,
				Idx:   idx,
			},
		}
	}
	u.dnIdx++
	return &dnk.Dln, nil
}

func (u *UserLoader) playLinkEldest(m MetaContext, link *proto.LinkOuter, odc *core.OpenDeviceChangeRes) error {
	oer, err := core.OpenEldestLinkWithODC(link, u.fqu().HostID, odc)
	if err != nil {
		return core.ChainLoaderError{Err: core.ULEldestError{Err: err}}
	}
	if !oer.Uid.Eq(u.arg.Uid) {
		// WE already checked this in OpenDeviceChange, so we can
		// probably never hit this condition. Still, keep this as a
		// guard against future changes and bugs.
		return core.InternalError("wrong uid in eldest link")
	}

	if oer.UsernameCommitment == nil {
		// Should already have been covered in OpenEldestLinkWithODC
		return core.InternalError("no username commitment in eldest link")
	}

	dn, err := u.playDeviceName(m, oer.DeviceNameCommitment)
	if err != nil {
		return err
	}

	if len(u.allMerkleLeaves) == 0 {
		return core.InternalError("no merkle keys")
	}

	err = u.addDeviceKey(
		oer.Device,
		proto.DeviceInfo{
			Status: proto.DeviceStatus_ACTIVE,
			Dn:     dn,
			Key:    *odc.RawNewDevice,
			Ctime:  odc.Gc.Chainer.Base.Time,
			Provisioned: proto.ProvisionInfo{
				Chain:  odc.Gc.Chainer.Base,
				Signer: odc.Gc.Signer.Key,
				Leaf:   u.allMerkleLeaves[0],
			},
		},
	)

	if err != nil {
		return err
	}

	u.uncs = append(u.uncs, *oer.UsernameCommitment)

	err = u.addPuk(m, oer.UserKey)
	if err != nil {
		return err
	}

	u.sctlsc = oer.SubchainTreeLocationCommitment
	return nil
}

func (u *UserLoader) markPotentiallyStale(r proto.Role) error {
	rk, err := core.ImportRole(r)
	if err != nil {
		return err
	}

	// Mark all roles rk2 <= rk as requiring a rotation, so therefore
	// potentially stale if we don't see a rotation.
	for _, k := range u.puks {
		role := k.Role
		rk2, err := core.ImportRole(role)
		if err != nil {
			return err
		}
		cmp := rk.Cmp(*rk2)
		if cmp >= 0 {
			u.stalePUKs.MarkStale(*rk2)
		}
	}
	return nil
}

func (u *UserLoader) playRevoke(m MetaContext, odc *core.OpenDeviceChangeRes) error {

	cdrr, err := core.CheckDeviceRevokeOrRotate(odc, u.HostID(), u.keys, u.pukGens)
	if err != nil {
		return core.ChainLoaderError{
			Err: core.ULRevokeError{
				Seqno: odc.Gc.Chainer.Base.Seqno,
				Err:   err,
			},
		}
	}

	fid, err := cdrr.ID.Fixed()
	if err != nil {
		return err
	}
	mk := proto.FQEntityFixed{Entity: fid, Host: u.HostID()}
	_, ok := u.keys[mk]
	if !ok {
		// Should have already been caught in CheckDeviceRevoke
		return core.InternalError("no key for device; revoke failed")
	}

	delete(u.keys, mk)

	lst, ok := u.devInfo[mk]
	if !ok {
		return core.LinkError("no device info for device; revoke failed")
	}
	l := len(lst)
	di := lst[l-1]
	di.Status = proto.DeviceStatus_REVOKED
	di.Revoked = &proto.RevokeInfo{
		Revoker: odc.Gc.Signer.Key,
		Chain:   odc.Gc.Chainer.Base,
	}
	lst[l-1] = di
	u.devInfo[mk] = lst

	err = u.markPotentiallyStale(di.Key.DstRole)
	if err != nil {
		return err
	}

	return nil
}

func (u *UserLoader) playProvision(m MetaContext, odc *core.OpenDeviceChangeRes) error {
	odpr, err := core.OpenDeviceProvision(odc, u.keys, u.pukGens, u.HostID())
	if err != nil {
		return core.ChainLoaderError{
			Err: core.CLProvisionError{
				Seqno: odc.Gc.Chainer.Base.Seqno,
				Err:   err,
			},
		}
	}

	if odc.RawNewDevice == nil {
		// Should have been picked up in earlier call to OpenDeviceProvision
		return core.InternalError("no new device in provision")
	}

	dn, err := u.playDeviceName(m, odpr.DeviceNameCommitment)
	if err != nil {
		return err
	}

	// reminder that chain-link seqnos are 1-indexed, and the
	// allMerkleLeaves array is 0-indexed, so we need to subtract 1
	seqno := odpr.Gc.Chainer.Base.Seqno
	if !seqno.IsValid() {
		return core.InternalError("invalid seqno; refusing to -1 on 0")
	}
	idx := int(seqno) - 1
	if idx < 0 {
		return core.InternalError("invalid seqno; wound up with < 0 index")
	}
	if idx >= len(u.allMerkleLeaves) {
		return core.InternalError("no merkle key for provision")
	}

	err = u.addDeviceKey(odpr.NewDevice, proto.DeviceInfo{
		Status: proto.DeviceStatus_ACTIVE,
		Dn:     dn,
		Key:    *odc.RawNewDevice,
		Ctime:  odc.Gc.Chainer.Base.Time,
		Provisioned: proto.ProvisionInfo{
			Chain:  odc.Gc.Chainer.Base,
			Signer: odc.Gc.Signer.Key,
			Leaf:   u.allMerkleLeaves[idx],
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func (u *UserLoader) playDeviceChange(m MetaContext, odc *core.OpenDeviceChangeRes) error {

	l := len(odc.Gc.Changes)
	if l == 0 {
		return nil
	}
	if l > 1 {
		// Is not an expected return from OpenDeviceChange
		return core.InternalError("unexpected number of changes")
	}

	chng := odc.Gc.Changes[0]
	rt, err := chng.DstRole.GetT()
	if err != nil {
		return err
	}

	if rt == proto.RoleType_NONE {
		err = u.playRevoke(m, odc)
	} else {
		err = u.playProvision(m, odc)
	}

	if err != nil {
		return err
	}

	return nil
}

func (u *UserLoader) playUsernameChange(m MetaContext, odc *core.OpenDeviceChangeRes) error {

	for _, md := range odc.Gc.Metadata {
		t, err := md.GetT()
		if err != nil {
			return err
		}
		if t == proto.ChangeType_Username {
			u.uncs = append(u.uncs, md.Username())
		}
	}

	return nil
}

func (u *UserLoader) checkSigner(m MetaContext, odc *core.OpenDeviceChangeRes) error {
	signer := odc.LastSigner
	fid, err := signer.GetEntityID().Fixed()
	if err != nil {
		return err
	}
	ind := proto.FQEntityFixed{
		Entity: fid,
		Host:   u.HostID(),
	}
	_, found := u.keys[ind]

	if !found {
		return core.ChainLoaderError{
			Err: core.CLInvalidSignerError{
				Seqno: odc.Gc.Chainer.Base.Seqno,
				Fqe: proto.FQEntity{
					Entity: signer.GetEntityID(),
					Host:   u.HostID(),
				},
			},
		}
	}
	return nil
}

func (u *UserLoader) playLinkNonEldest(m MetaContext, link *proto.LinkOuter, odc *core.OpenDeviceChangeRes) error {

	// Note that we also check signers inside of opening provision and revoke links, but it feels safer
	// to do it here, so that if we add another link type in the future, we don't forget to check.
	// As it is now, an attempt to sign with a key that's not currently in the key family will fail here
	// or later in the various lib/chain.go functions.
	err := u.checkSigner(m, odc)
	if err != nil {
		return err
	}

	err = u.playUsernameChange(m, odc)
	if err != nil {
		return err
	}

	err = u.playDeviceChange(m, odc)
	if err != nil {
		return err
	}

	// now consume all new puks
	for _, puk := range odc.SharedKeys {
		err = u.addPuk(m, puk)
		if err != nil {
			return err
		}
	}

	return nil
}

func (u *UserLoader) playLinks(m MetaContext) error {

	for i, odc := range u.odcs {

		link := u.raw.Links[i]

		var err error
		switch {
		case !odc.Gc.Chainer.Base.Seqno.IsValid():
			err = core.ChainLoaderError{
				Err: core.CLInvalidSeqnoError{},
			}
		case odc.Gc.Chainer.Base.Seqno.IsEldest():
			err = u.playLinkEldest(m, &link, odc)
		default:
			err = u.playLinkNonEldest(m, &link, odc)
		}
		if err != nil {
			return err
		}
	}

	return nil

}

func (u *UserLoader) checkRes(m MetaContext) error {
	err := u.checkMerkleRoot(m)
	if err != nil {
		return err
	}

	err = u.openLinks(m)
	if err != nil {
		return err
	}

	err = u.checkUIDChain(m)
	if err != nil {
		return err
	}

	err = u.checkMerkleUIDPaths(m)
	if err != nil {
		return err
	}

	return nil
}

func (u *UserLoader) checkUsername(m MetaContext) error {
	var existingName *proto.NameAndSeqnoBundle
	if u.existing != nil {
		existingName = &u.existing.Username
	}
	nseq, err := u.checkNameLoad(
		m,
		u.arg.Uid.ToPartyID(),
		u.HostID(),
		u.uncs,
		u.raw.Usernames,
		existingName,
		u.raw.UsernameUtf8,
		int(u.raw.NumUsernameLinks),
		u.raw.Merkle,
	)
	if err != nil {
		return err
	}

	if !u.arg.Username.IsZero() {
		un := u.arg.Username
		nun, err := core.NormalizeName(un)
		if err != nil {
			return err
		}

		var nameFromLoad proto.Name
		if len(u.raw.Usernames) > 0 {
			nameFromLoad = core.Last(u.raw.Usernames).Unc.Name
		} else if existingName != nil {
			nameFromLoad = existingName.B.Name
		} else {
			return core.InternalError("no existing name and no username links")
		}

		if !nun.Eq(nameFromLoad) {
			return core.NameError("username mismatch")
		}
	}

	u.unseq = nseq
	return nil
}

func (u *UserLoader) saveState(m MetaContext) error {
	l := len(u.raw.Links)
	if u.existing == nil && l == 0 {
		return core.InternalError("no links in sigchain")
	}

	unb, err := core.NewNameBundle(u.raw.UsernameUtf8)
	if err != nil {
		return err
	}

	if l == 0 {
		u.newState = u.existing
		// The user might have updated the UTf8 preimage of the normalized username,
		// so update that here. This is based on server-trust, for now.
		u.newState.Username.B = unb
		return nil
	}

	res := lcl.UserSigchainState{
		Tail:     u.odcs[l-1].Gc.Chainer,
		LastHash: *u.lastHash,
		Username: proto.NameAndSeqnoBundle{
			B: unb,
			S: u.unseq,
		},
		MerkleLeaves: u.allMerkleLeaves,
		Hepks:        u.hepks.Export(),
		StalePUKs:    u.stalePUKs.Export(),
	}
	if u.sctlsc != nil {
		res.Sctlsc = *u.sctlsc
	}

	for _, v := range u.puks {
		res.Puks = append(res.Puks, v.SharedKey)
	}

	// Puks just came out of a map, so they'll be in random order.
	// Sort by role first, and then by gen.
	var sortErr error
	slices.SortFunc(res.Puks, func(x, y proto.SharedKey) int {
		if sortErr != nil {
			return 0
		}
		roleCmp, err := x.Role.Cmp(y.Role)
		if err != nil {
			sortErr = err
			return 0
		}
		if roleCmp != 0 {
			return roleCmp
		}
		return int(x.Gen - y.Gen)
	})
	if sortErr != nil {
		return sortErr
	}

	for _, did := range u.deviceOrder {
		device, found := u.devInfo[did]
		if !found {
			return core.InternalError("device not found in saveState")
		}
		res.Devices = append(res.Devices, device...)
	}

	scoper := u.fqu()

	if u.arg.LoadMode != LoadModeDeadSelf {
		err = m.DbPut(u.dbType(), PutArg{
			Scope: &scoper,
			Typ:   lcl.DataType_UserSigchainState,
			Val:   &res,
			Key:   core.EmptyKey{},
		})
		if err != nil {
			return err
		}
	}
	u.newState = &res

	return nil
}

func (u *UserLoader) checkArgs(m MetaContext) error {
	return u.arg.check(m)
}

func (u LoadUserArg) check(m MetaContext) error {
	if u.LoadMode == LoadModeSelf && u.ActiveUser != nil && !u.ActiveUser.Info.Fqu.Uid.Eq(u.Uid) {
		return core.InternalError("self-load uid mismatch")
	}
	byUid := !u.Uid.IsZero()
	byName := !u.Username.IsZero()
	if byUid && byName {
		return core.InternalError("can't load by UID and Username")
	}
	if !byUid && !byName {
		return core.InternalError("can't load by both UID and username")
	}
	return nil
}

func (u *UserLoader) resetState() {
	u.resetLists()
	u.resetMaps()
}

func (u *UserLoader) resetLists() {
	u.existing = nil
	u.odcs = nil
	u.deviceOrder = nil
	u.keys = nil
}

func (u *UserLoader) resetMaps() {
	u.devInfo = make(map[proto.FQEntityFixed][]proto.DeviceInfo)
	u.puks = make(map[core.RoleKeyAndGen]core.SharedPublicSuite)
	u.keys = make(map[proto.FQEntityFixed]core.PublicSuiterWithSeqno)
	u.pukGens = make(map[core.RoleKey]proto.Generation)
	u.puksByRole = make(map[core.RoleKey][]core.SharedPublicSuite)
}

func (u *UserLoader) Run(m MetaContext) (*UserWrapper, error) {
	err := u.BaseChainLoader.runMany(m, u.runOnce, nil)
	if err != nil {
		return nil, err
	}
	return u.res, nil
}

func (u *UserLoader) resolveUID(m MetaContext) error {
	if !u.arg.Uid.IsZero() {
		return nil
	}
	nun, err := core.NormalizeName(u.arg.Username)
	if err != nil {
		return err
	}
	var auth rem.LoadUserChainAuth
	switch u.arg.LoadMode {
	case LoadModeOpenOthers:
		auth = rem.NewLoadUserChainAuthWithOpenvhost()
	default:
		auth = rem.NewLoadUserChainAuthWithAslocaluser()
	}
	uid, err := u.rpcLoader.ResolveUsername(
		m.Ctx(),
		rem.ResolveUsernameArg{
			N:    nun,
			Auth: auth,
		},
	)
	if err != nil {
		return err
	}
	u.arg.Uid = uid
	return nil
}

func (u *UserLoader) runOnce(m MetaContext) error {

	u.resetState()

	err := u.checkArgs(m)
	if err != nil {
		return err
	}

	err = u.connectHost(m)
	if err != nil {
		return err
	}

	err = u.resolveUID(m)
	if err != nil {
		return err
	}

	err = u.loadExistingUser(m)
	if err != nil {
		return err
	}

	err = u.loadUserFromServer(m)
	if err != nil {
		return err
	}

	err = u.updateHEPKs(m)
	if err != nil {
		return err
	}

	err = u.checkRes(m)
	if err != nil {
		return err
	}

	err = u.playLinks(m)
	if err != nil {
		return err
	}

	// must play links before we can check username
	err = u.checkUsername(m)
	if err != nil {
		return err
	}

	// In testing we might want to skip errors, but if we do, they
	// are remembered here, so there is no path through by accident
	// where the error is skipped
	if u.fatalError != nil {
		return u.fatalError
	}

	err = u.saveState(m)
	if err != nil {
		return err
	}

	u.res = &UserWrapper{
		prot:      u.newState,
		hostAddr:  u.probe.CanonicalAddr(),
		keys:      u.keys,
		DevInfo:   u.devInfo,
		pukGens:   u.pukGens,
		puks:      u.puksByRole,
		fqu:       u.fqu(),
		Hepks:     u.hepks,
		stalePUKs: u.stalePUKs,
	}

	return nil
}

func (u *UserLoader) updateHEPKs(m MetaContext) error {
	s2, err := core.ImportHEPKSet(&u.raw.Hepks)
	if err != nil {
		return err
	}
	u.hepks = u.hepks.Merge(s2)
	return nil
}

func (u *UserWrapper) AssertPUK(p core.SharedPrivateSuiter) error {

	eid, err := p.RollingEntityID()
	if err != nil {
		return err
	}

	for _, v := range u.prot.Puks {
		ok, err := v.Role.Eq(p.GetRole())
		if err != nil {
			return err
		}
		if ok && eid.Eq(v.VerifyKey) && v.Gen == p.Metadata().Gen {
			return nil
		}
	}
	return core.KeyNotFoundError{Which: "PUK"}
}

func (u *UserWrapper) LatestPUKGenForRole(r proto.Role) (proto.Generation, error) {
	rk, err := core.ImportRole(r)
	if err != nil {
		return 0, err
	}
	gen, found := u.pukGens[*rk]
	if !found {
		return 0, core.KeyNotFoundError{Which: "PUK"}
	}
	return gen, nil
}

func (a LoadUserArg) SetFQU(u proto.FQUser, tok proto.PermissionToken) LoadUserArg {
	a.Uid = u.Uid
	a.Host = &LoadUserHost{HostID: u.HostID, Tok: tok}
	return a
}

func (a LoadUserArg) SetLoadMode(m LoadMode) LoadUserArg {
	a.LoadMode = m
	return a
}
