// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libyubi"
	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/stretchr/testify/require"
)

var globalTestEnv *common.TestEnv
var G *shared.GlobalContext

func setup() {
	globalTestEnv = common.NewTestEnv()
	err := globalTestEnv.Setup(common.SetupOpts{})
	if err != nil {
		panic(err)
	}
	G = globalTestEnv.G
}

var shutdownHooks [](func() error)

func pushShutdownHook(fn func() error) {
	shutdownHooks = append(shutdownHooks, fn)
}

func shutdown() {
	// In general, don't panic on shutdown problems. Just ignore these
	// errors.
	_ = globalTestEnv.ShutdownFn()
	for _, fn := range shutdownHooks {
		_ = fn()
	}
}

func testMetaContext() shared.MetaContext {
	return globalTestEnv.MetaContext()
}

type HEPKExporter interface {
	ExportHEPK() (*proto.HEPK, error)
}

func collectHEPK(t *testing.T, s *proto.HEPKSet, e HEPKExporter) {
	hepk, err := e.ExportHEPK()
	require.NoError(t, err)
	s.Push(*hepk)
}

func collectHEPKToMap(t *testing.T, s *core.HEPKSet, e HEPKExporter) {
	hepk, err := e.ExportHEPK()
	require.NoError(t, err)
	err = s.Add(*hepk)
	require.NoError(t, err)
}

func connectSrv(m shared.MetaContext, srv shared.Server, clientCert *tls.Certificate, vhost *core.HostIDAndName) (net.Conn, error) {
	rootCAs := x509.NewCertPool()
	var hn proto.Hostname
	if vhost != nil {
		hn = vhost.Hostname
	}
	ca := m.G().CertMgr()
	set, err := ca.AllCerts(m, nil, []proto.CKSAssetType{proto.CKSAssetType_HostchainFrontendCA}, hn)
	if err != nil {
		return nil, err
	}
	for _, c := range set {
		rootCAs.AddCert(c)
	}

	tlsCfg := &tls.Config{
		RootCAs: rootCAs,
	}
	if !hn.IsZero() {
		tlsCfg.ServerName = hn.String()
	}
	if clientCert != nil {
		tlsCfg.Certificates = []tls.Certificate{*clientCert}
	}
	conn, err := tls.Dial("tcp", srv.ListenerAddr().String(), tlsCfg)
	if err != nil {
		return nil, err
	}
	err = conn.Handshake()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func RandomUsername(l int) (string, error) {
	return core.RandomUsername(l)
}

func newGenericClient(m shared.MetaContext, srv shared.Server, clientCert *tls.Certificate, vhost *core.HostIDAndName) (*rpc.Client, func(), error) {
	conn, err := connectSrv(m, srv, clientCert, vhost)
	if err != nil {
		return nil, nil, err
	}
	retFn := func() { conn.Close() }

	lf := rpc.NewSimpleLogFactory(rpc.NilLogOutput{}, nil)
	wef := rem.RegMakeGenericErrorWrapper(core.ErrorToStatus)
	xp := rpc.NewTransport(m.Ctx(), conn, lf, nil, wef, core.RpcMaxSz)
	gcli := rpc.NewClient(xp, nil, nil)
	return gcli, retFn, nil
}

func newRegClient(ctx context.Context) (*rem.RegClient, func(), error) {
	m := shared.NewMetaContext(ctx, G)
	return newRegClientFromEnv(m, globalTestEnv)
}

func newRegClientFromEnv(m shared.MetaContext, env *common.TestEnv) (*rem.RegClient, func(), error) {
	gcli, fn, err := newGenericClient(m, env.RegSrv(), nil, nil)
	if err != nil {
		return nil, fn, err
	}
	cli := core.NewRegClient(gcli, m.G())
	return &cli, fn, err
}

func newUserClient(ctx context.Context, clientCert *tls.Certificate) (*rem.UserClient, func(), error) {
	m := shared.NewMetaContext(ctx, G)
	return newUserClientFromEnv(m, clientCert, globalTestEnv, nil)
}

func newUserClientFromEnv(m shared.MetaContext, clientCert *tls.Certificate, env *common.TestEnv, vhost *core.HostIDAndName) (*rem.UserClient, func(), error) {
	gcli, fn, err := newGenericClient(m, env.UserSrv(), clientCert, vhost)
	if err != nil {
		return nil, fn, err
	}
	cli := core.NewUserClient(gcli, m)
	return &cli, fn, err
}

func newTeamAdminClientFromEnv(m shared.MetaContext, clientCert *tls.Certificate, env *common.TestEnv, vhost *core.HostIDAndName) (*rem.TeamAdminClient, func(), error) {
	gcli, fn, err := newGenericClient(m, env.UserSrv(), clientCert, vhost)
	if err != nil {
		return nil, fn, err
	}
	cli := rem.TeamAdminClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}
	return &cli, fn, err
}

func newTeamMemberClientFromEnv(m shared.MetaContext, clientCert *tls.Certificate, env *common.TestEnv, vhost *core.HostIDAndName) (*rem.TeamMemberClient, func(), error) {
	gcli, fn, err := newGenericClient(m, env.UserSrv(), clientCert, vhost)
	if err != nil {
		return nil, fn, err
	}
	cli := rem.TeamMemberClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}
	return &cli, fn, err
}

func newTeamGuestClientFromEnv(m shared.MetaContext, env *common.TestEnv, vhost *core.HostIDAndName) (*rem.TeamGuestClient, func(), error) {
	gcli, fn, err := newGenericClient(m, env.RegSrv(), nil, vhost)
	if err != nil {
		return nil, fn, err
	}
	cli := rem.TeamGuestClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}
	return &cli, fn, err
}

func newTeamLoaderClientFromUser(m shared.MetaContext, u *TestUser, crt *tls.Certificate, loggedIn bool) (*rem.TeamLoaderClient, func(), error) {
	env := u.env
	var srv shared.Server
	if loggedIn {
		srv = env.UserSrv()
	} else {
		srv = env.RegSrv()
	}
	gcli, fn, err := newGenericClient(m, srv, crt, u.vhost)
	if err != nil {
		return nil, fn, err
	}
	cli := rem.TeamLoaderClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}
	return &cli, fn, err
}

func (u *TestUser) newUserClient(ctx context.Context, clientCert *tls.Certificate) (*rem.UserClient, func(), error) {
	g := u.g
	if g == nil {
		g = G
	}
	te := u.env
	if te == nil {
		te = globalTestEnv
	}
	m := shared.NewMetaContext(ctx, g)
	return newUserClientFromEnv(m, clientCert, te, u.vhost)
}

func (u *TestUser) newUserCertAndClient(t *testing.T, ctx context.Context) (*rem.UserClient, func()) {
	crt := u.ClientCertRobust(ctx, t)
	ucli, closeFn, err := u.newUserClient(ctx, crt)
	require.NoError(t, err)
	return ucli, closeFn
}

func (u *TestUser) newTeamAdminClient(t *testing.T, ctx context.Context) (*rem.TeamAdminClient, func()) {
	crt := u.ClientCertRobust(ctx, t)
	m := shared.NewMetaContext(ctx, u.g)
	ucli, closeFn, err := newTeamAdminClientFromEnv(m, crt, u.env, u.vhost)
	require.NoError(t, err)
	return ucli, closeFn
}

func (u *TestUser) newTeamMemberClient(t *testing.T, ctx context.Context) (*rem.TeamMemberClient, func()) {
	crt := u.ClientCertRobust(ctx, t)
	m := shared.NewMetaContext(ctx, u.g)
	ucli, closeFn, err := newTeamMemberClientFromEnv(m, crt, u.env, u.vhost)
	require.NoError(t, err)
	return ucli, closeFn
}

func (u *TestUser) newTeamGuestClient(t *testing.T, ctx context.Context) (*rem.TeamGuestClient, func()) {
	m := shared.NewMetaContext(ctx, u.g)
	ucli, closeFn, err := newTeamGuestClientFromEnv(m, u.env, u.vhost)
	require.NoError(t, err)
	return ucli, closeFn
}

func (u *TestUser) newTeamLoaderClient(t *testing.T, ctx context.Context, loggedIn bool) (*rem.TeamLoaderClient, func()) {
	m := shared.NewMetaContext(ctx, u.g)
	var crt *tls.Certificate
	if loggedIn {
		crt = u.ClientCertRobust(ctx, t)
	}
	ucli, closeFn, err := newTeamLoaderClientFromUser(m, u, crt, loggedIn)
	require.NoError(t, err)
	return ucli, closeFn
}

func (u *TestUser) newRegClient(ctx context.Context) (*rem.RegClient, func(), error) {
	g := u.g
	if g == nil {
		g = G
	}
	te := u.env
	if te == nil {
		te = globalTestEnv
	}
	m := shared.NewMetaContext(ctx, g)
	return newRegClientFromEnv(m, te)
}

func (u *TestUser) GetSubkey(t *testing.T, ctx context.Context) core.EntityPrivate {
	rc, closeFn, err := u.newRegClient(ctx)
	require.NoError(t, err)
	defer closeFn()
	key := u.devices[0]
	pub, err := key.Publicize(&u.host)
	require.NoError(t, err)
	pubid := pub.GetEntityID()
	chal, err := rc.GetSubkeyBoxChallenge(ctx, pubid)
	require.NoError(t, err)
	require.Equal(t, chal.Payload.EntityID, pubid)
	tmp, err := key.Sign(&chal.Payload)
	require.NoError(t, err)
	arg := rem.LoadSubkeyBoxArg{
		Challenge: chal,
		Signature: *tmp,
		Parent:    pubid,
	}
	box, err := rc.LoadSubkeyBox(ctx, arg)
	require.NoError(t, err)
	var boxPayload proto.SubkeySeed
	err = core.SelfUnbox(key, &boxPayload, box)
	require.NoError(t, err)
	require.Equal(t, pubid, boxPayload.Parent)
	subkeySeed, err := core.DeviceSigningSecretKey(boxPayload.Seed)
	require.NoError(t, err)
	ret := core.NewEntityPrivateEd25519WithSeed(
		proto.EntityType_Subkey,
		*subkeySeed,
	)
	retPub, err := ret.EntityPublic()
	require.NoError(t, err)
	require.Equal(t, retPub.GetEntityID(), boxPayload.Subkey)
	return ret
}

func newTestProtClient(ctx context.Context, clientCert *tls.Certificate, vhost *core.HostIDAndName) (*infra.TestServicesClient, func(), error) {
	m := shared.NewMetaContext(ctx, G)
	gcli, fn, err := newGenericClient(m, globalTestEnv.UserSrv(), clientCert, vhost)
	if err != nil {
		return nil, fn, err
	}
	cli := infra.TestServicesClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}
	return &cli, fn, err
}

func TestReserve(t *testing.T) {
	ctx := context.Background()
	cli, closeFn, err := newRegClient(ctx)
	require.NoError(t, err)
	defer closeFn()

	un, err := RandomUsername(8)
	require.NoError(t, err)

	unn, err := core.NormalizeName(proto.NameUtf8(un))
	require.NoError(t, err)

	res, err := cli.ReserveUsername(ctx, unn)
	require.NoError(t, err)
	require.Equal(t, 17, len(res.Tok)) // Should be 16 bytes of entropy, just assert length for now
	require.Equal(t, byte(proto.ID16Type_ReservationToken), res.Tok[0])
	require.Equal(t, proto.NameSeqno(1), res.Seq)

	_, err = cli.ReserveUsername(ctx, unn)
	require.Error(t, err)
	require.IsType(t, core.NameInUseError{}, err)

	// Push the clock forward one Month, reservation should have expired
	globalTestEnv.RegSrv().SetTestTimeTravel(24 * 30 * time.Hour)
	res2, err := cli.ReserveUsername(ctx, unn)
	require.NoError(t, err)
	require.NotEqual(t, res, res2)

	// Reset it for next tests, etc
	globalTestEnv.RegSrv().SetTestTimeTravel(0)
}

type userSettingsChainTail struct {
	seqno proto.Seqno
	hash  proto.LinkHash
}

type testKeySequence map[proto.Generation]core.SharedPrivateSuiter

type testKeyMatrix map[core.RoleKey]testKeySequence

func newTestKeyMarix() testKeyMatrix {
	return make(testKeyMatrix)
}

func (m testKeyMatrix) add(t *testing.T, s core.SharedPrivateSuiter) {
	g := s.Metadata().Gen
	r := s.GetRole()
	rk, err := core.ImportRole(r)
	require.NoError(t, err)
	row := m[*rk]
	if row == nil {
		row = make(testKeySequence)
		m[*rk] = row
	}
	row[g] = s
}

func (m testKeyMatrix) Seq(t *testing.T, r proto.Role) libclient.SharedKeySequence {
	rk, err := core.ImportRole(r)
	require.NoError(t, err)
	row := m[*rk]
	require.NotNil(t, row)
	return row
}

func (s testKeySequence) At(g proto.Generation) core.SharedPrivateSuiter {
	ret := s[g]
	if ret == nil {
		return nil
	}
	return ret
}

func (s testKeySequence) Current() core.SharedPrivateSuiter {
	var ret core.SharedPrivateSuiter
	max := -1
	for g, k := range s {
		if int(g) > max {
			max = int(g)
			ret = k
		}
	}
	if max < 0 {
		return nil
	}
	return ret
}

func (s testKeySequence) NextGen() proto.Generation {
	max := -1
	for g := range s {
		if int(g) > max {
			max = int(g)
		}
	}
	if max < 0 {
		return 0
	}
	return proto.Generation(max + 1)
}

type TestUser struct {
	name             proto.NameUtf8
	host             proto.HostID
	uid              proto.UID
	puks             map[core.RoleKey]core.SharedPrivateSuite25519
	eldest           core.PrivateSuiter
	certChain        [][]byte
	prev             *proto.LinkHash
	devices          []core.PrivateSuiter
	deviceLabels     map[proto.DeviceLabel]bool
	rootEpno         proto.MerkleEpno
	userSeqno        proto.Seqno
	nextTreeLocation *proto.TreeLocation
	cleanupHooks     []func()
	g                *shared.GlobalContext
	env              *common.TestEnv
	uscl             *userSettingsChainTail
	vhost            *core.HostIDAndName // if the client is connected to a vhost, we have to set it on regclis
	tkm              testKeyMatrix
	teamMembSeqno    proto.Seqno
	teamMembPrev     *proto.LinkHash
}

func (u *TestUser) KeySeq(t *testing.T, r proto.Role) libclient.SharedKeySequence {
	return u.tkm.Seq(t, r)
}

func (u *TestUser) exportToUserContext(t *testing.T) *libclient.UserContext {
	ret := &libclient.UserContext{
		Info: proto.UserInfo{
			Fqu: u.FQUser(),
			Username: proto.NameBundle{
				Name:     u.UsernameNormalized(t),
				NameUtf8: u.name,
			},
		},
	}
	ret.PrivKeys.SetDevkey(u.devices[0])

	return ret
}

func (u *TestUser) AddCleanupHook(f func()) {
	u.cleanupHooks = append(u.cleanupHooks, f)
}

func (u *TestUser) Cleanup() {
	for _, h := range u.cleanupHooks {
		h()
	}
}

func (u *TestUser) FQE() proto.FQEntity {
	return proto.FQEntity{
		Entity: u.uid.EntityID(),
		Host:   u.host,
	}
}

func (u *TestUser) FQUser() proto.FQUser {
	return proto.FQUser{
		Uid:    u.uid,
		HostID: u.host,
	}
}

func (u *TestUser) NextRoot() proto.TreeRoot {
	ret := proto.TreeRoot{
		Epno: u.rootEpno,
		Hash: core.RandomMerkleRootHash(),
	}
	u.rootEpno++
	return ret
}

func NewTestUserWithUsername(un proto.NameUtf8) *TestUser {
	return &TestUser{
		name:         un,
		puks:         make(map[core.RoleKey]core.SharedPrivateSuite25519),
		deviceLabels: make(map[proto.DeviceLabel]bool),
		tkm:          newTestKeyMarix(),
	}
}

func NewTestUserWithPrefix(t *testing.T, prefix string) *TestUser {
	baselen := 9
	if len(prefix) > 0 {
		baselen = 7
	}
	un, err := RandomUsername(baselen)
	require.NoError(t, err)
	if len(prefix) > 0 {
		un = prefix + "_" + un
	}
	return NewTestUserWithUsername(proto.NameUtf8(un))
}

func NewTestUser(t *testing.T) *TestUser {
	return NewTestUserWithPrefix(t, "")
}

func deviceKeyConstructor(role proto.Role, host proto.HostID) (core.PrivateSuiter, error) {
	ss := core.RandomSecretSeed32()
	return core.NewPrivateSuite25519(proto.EntityType_Device, role, ss, host)
}

func (u *TestUser) Signup(t *testing.T, m shared.MetaContext, cli *rem.RegClient,
	opts *TestUserOpts) {
	u.SignupWithOpts(t, m, cli, opts)
}

func (u *TestUser) SignupWithInviteCode(ctx context.Context, t *testing.T, cli *rem.RegClient, inviteCode rem.InviteCode) {
	opts := &TestUserOpts{
		InviteCode: &inviteCode,
	}
	m := shared.NewMetaContext(ctx, G)
	u.SignupWithOpts(t, m, cli, opts)
}

func emailForUsername(u proto.Name) proto.Email {
	return proto.Email(u + "@example.com")
}

func (u *TestUser) G() *shared.GlobalContext {
	if u.g != nil {
		return u.g
	}
	return G
}

func (u *TestUser) UsernameNormalized(t *testing.T) proto.Name {
	unn, err := core.NormalizeName(u.name)
	require.NoError(t, err)
	return unn
}

type TestUserOpts struct {
	RealTreeRoot   bool
	KeyConstructor func(role proto.Role, host proto.HostID) (core.PrivateSuiter, error)
	InviteCode     *rem.InviteCode
	HostID         *core.HostIDAndName
	UsernamePrefix string
}

func (u *TestUser) SignupWithOpts(
	t *testing.T,
	m shared.MetaContext,
	cli *rem.RegClient,
	opts *TestUserOpts,
) {
	err := u.SignupWithOptsAndError(t, m, cli, opts)
	require.NoError(t, err)
}

func (u *TestUser) SignupWithOptsAndError(
	t *testing.T,
	m shared.MetaContext,
	cli *rem.RegClient,
	opts *TestUserOpts,
) error {
	ctx := m.Ctx()

	if opts == nil {
		opts = &TestUserOpts{}
	}
	if opts.KeyConstructor == nil {
		opts.KeyConstructor = deviceKeyConstructor
	}

	unn, err := core.NormalizeName(u.name)
	require.NoError(t, err)
	rur, err := cli.ReserveUsername(ctx, unn)
	if err != nil {
		return err
	}

	hostID, err := cli.GetHostID(ctx)
	require.NoError(t, err)

	ownerRole := proto.NewRoleDefault(proto.RoleType_OWNER)
	device, err := opts.KeyConstructor(ownerRole, hostID)
	require.NoError(t, err)
	did, err := device.EntityID()
	require.NoError(t, err)

	var hepks proto.HEPKSet

	collectHEPK(t, &hepks, device)

	var subkey core.EntityPrivate
	var subkeyBox *proto.Box
	var hint *proto.YubiSlotAndPQKeyID
	if did.Type() == proto.EntityType_Yubi {
		subkey, subkeyBox, err = core.MakeSubkey(device, hostID)
		require.NoError(t, err)
		yi, err := device.(*libyubi.KeySuiteHybrid).ExportToYubiKeyInfo(ctx)
		require.NoError(t, err)
		hint = &yi.PqKey
	}

	pukSs := core.RandomSecretSeed32()
	puk, err := core.NewSharedPrivateSuite25519(
		proto.EntityType_PUKVerify,
		ownerRole,
		pukSs,
		core.FirstPUKGeneration,
		u.host,
	)
	require.NoError(t, err)
	dn := "macbook"
	dl := proto.DeviceLabel{
		DeviceType: proto.DeviceType_Computer,
		Name:       proto.DeviceNameNormalized("macbook"),
		Serial:     proto.FirstDeviceSerial,
	}
	nu, err := core.NormalizeName(u.name)
	require.NoError(t, err)

	collectHEPK(t, &hepks, puk)

	var root proto.TreeRoot
	if !opts.RealTreeRoot {
		if u.rootEpno == 0 {
			u.rootEpno = 1000
		}
		root = proto.TreeRoot{
			Epno: u.rootEpno,
			Hash: core.RandomMerkleRootHash(),
		}
		u.rootEpno++
	} else {
		var idp *proto.HostID
		if opts.HostID != nil {
			idp = opts.HostID.IDp()
		}
		root = getCurrentSignedTreeRootWithHostID(t, m, idp)
	}

	mer, err := core.MakeEldestLink(
		hostID,
		rem.NameCommitment{
			Name: proto.Name(nu),
			Seq:  rur.Seq,
		},
		device,
		puk,
		dl,
		root,
		subkey,
	)
	require.NoError(t, err)
	require.NotNil(t, mer)

	pukid, err := puk.EntityID()
	require.NoError(t, err)
	uid, err := pukid.Persistent()
	require.NoError(t, err)

	devicePub, err := device.Publicize(&hostID)
	require.NoError(t, err)
	pukBox, err := core.BoxOne(u.host, puk, device, devicePub)
	require.NoError(t, err)

	inviteCode := opts.InviteCode
	if inviteCode == nil {
		tmp := u.G().TestMultiUseInviteCode()
		inviteCode = &tmp
	}

	dlnck := rem.DeviceLabelNameAndCommitmentKey{
		Dln: proto.DeviceLabelAndName{
			Name:  proto.DeviceName(dn),
			Label: dl,
		},
		CommitmentKey: *mer.DevNameCommitmentKey,
	}

	arg := rem.SignupArg{
		UsernameUtf8:             proto.NameUtf8(u.name),
		Rur:                      rur,
		Link:                     *mer.Link,
		Dlnck:                    dlnck,
		UsernameCommitmentKey:    *mer.UsernameCommitmentKey,
		PukBox:                   *pukBox,
		NextTreeLocation:         *mer.NextTreeLocation,
		InviteCode:               *inviteCode,
		Email:                    emailForUsername(unn),
		SubkeyBox:                subkeyBox,
		SubchainTreeLocationSeed: *mer.SubchainTreeLocationSeed,
		Hepks:                    hepks,
		YubiPQhint:               hint,
	}
	arg.SelfToken, err = core.NewPermissionToken()
	require.NoError(t, err)

	err = cli.Signup(ctx, arg)
	if err != nil {
		fmt.Printf("XXXXX signup error %T %v\n", err, err)
		return err
	}

	linkHash, err := core.LinkHash(mer.Link)
	require.NoError(t, err)

	uidFixed, err := uid.ToUID()
	require.NoError(t, err)

	u.puks[core.RoleKey{Typ: proto.RoleType_OWNER}] = *puk
	u.eldest = device
	u.uid = uidFixed
	u.host = hostID
	u.prev = linkHash
	u.devices = []core.PrivateSuiter{device}
	u.deviceLabels[dl] = true
	u.userSeqno = mer.Seqno + 1
	u.nextTreeLocation = mer.NextTreeLocation
	u.addPuksToMatrix(t)
	u.teamMembSeqno = proto.ChainEldestSeqno
	return nil
}

func (u *TestUser) addPuksToMatrix(t *testing.T) {
	for _, puk := range u.puks {
		u.tkm.add(t, &puk)
	}
}
func (u *TestUser) GetCertWithErr(ctx context.Context, cli *rem.RegClient) error {
	deviceID, err := u.eldest.EntityID()
	if err != nil {
		return err
	}
	certChain, err := cli.GetClientCertChain(ctx, rem.GetClientCertChainArg{
		Uid: proto.UID(u.uid),
		Key: deviceID,
	})
	if err != nil {
		return err
	}
	u.certChain = certChain
	return nil
}

func (u *TestUser) GetCert(ctx context.Context, t *testing.T, cli *rem.RegClient) {
	err := u.GetCertWithErr(ctx, cli)
	require.NoError(t, err)
}

func GenerateNewTestUser(t *testing.T) *TestUser {
	ctx := context.Background()
	cli, closeFn, err := newRegClient(ctx)
	require.NoError(t, err)
	defer closeFn()
	return GenerateNewTestUserWithRegCli(t, globalTestEnv, cli, nil)
}

func GenerateNewTestUserWithRegCli(t *testing.T, te *common.TestEnv, cli *rem.RegClient, opts *TestUserOpts) *TestUser {
	m := te.MetaContext()
	var prfx string
	if opts != nil && opts.UsernamePrefix != "" {
		prfx = opts.UsernamePrefix
	}
	testUser := NewTestUserWithPrefix(t, prfx)
	testUser.SignupWithRegCli(t, m, te, cli, opts)
	return testUser
}

func GenerateNewTestUserWithRegCliAndErr(
	t *testing.T,
	te *common.TestEnv,
	cli *rem.RegClient,
	opts *TestUserOpts,
) (*TestUser, error) {
	m := te.MetaContext()
	un, err := RandomUsername(9)
	if err != nil {
		return nil, err
	}
	testUser := NewTestUserWithUsername(proto.NameUtf8(un))
	err = testUser.SignupWithRegCliAndErr(t, m, te, cli, opts)
	if err != nil {
		return nil, err
	}
	return testUser, nil

}

func GenerateNewTestUserWithUsername(t *testing.T, tenv *common.TestEnv, un proto.NameUtf8) *TestUser {
	m := tenv.MetaContext()
	cli, closeFn, err := newRegClientFromEnv(m, tenv)
	require.NoError(t, err)
	defer closeFn()
	u := NewTestUserWithUsername(un)
	u.SignupWithRegCli(t, m, tenv, cli, nil)
	return u
}

func (u *TestUser) SignupWithRegCliAndErr(
	t *testing.T,
	m shared.MetaContext,
	te *common.TestEnv,
	cli *rem.RegClient,
	opts *TestUserOpts,
) error {
	u.g = te.G
	u.env = te
	ctx := m.Ctx()
	err := u.SignupWithOptsAndError(t, m, cli, opts)
	if err != nil {
		return err
	}
	err = u.GetCertWithErr(ctx, cli)
	if err != nil {
		return err
	}
	return nil
}
func (u *TestUser) SignupWithRegCli(t *testing.T, m shared.MetaContext, te *common.TestEnv, cli *rem.RegClient, opts *TestUserOpts) {
	u.g = te.G
	u.env = te
	ctx := m.Ctx()
	u.Signup(t, m, cli, opts)
	u.GetCert(ctx, t, cli)
}

func (u *TestUser) SignupYubiWithRegCli(t *testing.T, ctx context.Context, te *common.TestEnv, cli *rem.RegClient) {
	u.g = te.G
	u.env = te
	u.SignupYubi(ctx, t, cli, te.YubiDisp(t))
	u.GetCert(ctx, t, cli)
}

func (u *TestUser) ClientCert(t *testing.T) *tls.Certificate {
	key, err := u.eldest.PrivateKeyForCert()
	require.NoError(t, err)
	return &tls.Certificate{
		PrivateKey:  key,
		Certificate: u.certChain,
	}
}

// Get a client cert but don't do it necessarily for the eldest device, which
// could have been revoked by now. This setup isn't great and should be refactored
// at some point.
func (u *TestUser) ClientCertRobust(ctx context.Context, t *testing.T) *tls.Certificate {
	cli, closeFn, err := u.newRegClient(ctx)
	require.NoError(t, err)
	defer closeFn()

	deviceID, err := u.devices[0].EntityID()
	require.NoError(t, err)

	if deviceID.Type() == proto.EntityType_Yubi {
		return u.ClientSubkeyCertRobust(ctx, t)
	}

	if u.vhost != nil {
		err := cli.SelectVHost(ctx, u.vhost.Id)
		require.NoError(t, err)
	}

	certChain, err := cli.GetClientCertChain(ctx, rem.GetClientCertChainArg{
		Uid: proto.UID(u.uid),
		Key: deviceID,
	})
	require.NoError(t, err)
	require.NotNil(t, certChain)

	key, err := u.devices[0].PrivateKeyForCert()
	require.NoError(t, err)

	return &tls.Certificate{
		PrivateKey:  key,
		Certificate: certChain,
	}
}

func (u *TestUser) ClientSubkeyCertRobust(ctx context.Context, t *testing.T) *tls.Certificate {
	subkey := u.GetSubkey(t, ctx)

	cli, closeFn, err := u.newRegClient(ctx)
	require.NoError(t, err)
	defer closeFn()

	pubkey, err := subkey.EntityPublic()
	require.NoError(t, err)
	eid := pubkey.GetEntityID()

	certChain, err := cli.GetClientCertChain(ctx, rem.GetClientCertChainArg{
		Uid: u.uid,
		Key: eid,
	})
	require.NoError(t, err)
	require.NotNil(t, certChain)

	privKey, err := subkey.PrivateKeyForCert()
	require.NoError(t, err)

	return &tls.Certificate{
		PrivateKey:  privKey,
		Certificate: certChain,
	}
}

func TestSignup(t *testing.T) {
	ctx := context.Background()
	cli, closeFn, err := newRegClient(ctx)
	require.NoError(t, err)
	defer closeFn()

	un, err := RandomUsername(8)
	require.NoError(t, err)
	un = un + ".łaøß"
	un8 := proto.NameUtf8(un)
	testUser := NewTestUserWithUsername(un8)

	m := globalTestEnv.MetaContext()
	testUser.Signup(t, m, cli, nil)
	testUser.GetCert(ctx, t, cli)

	una, err := core.NormalizeName(un8)
	require.NoError(t, err)

	_, err = cli.ReserveUsername(ctx, proto.Name(una))
	require.Error(t, err)
	require.Equal(t, core.NameInUseError{}, err)

	err = cli.CheckNameExists(ctx, proto.Name(una))
	require.NoError(t, err)
}

func TestCheckUsernameExists(t *testing.T) {
	ctx := context.Background()
	cli, closeFn, err := newRegClient(ctx)
	require.NoError(t, err)
	defer closeFn()

	un, err := RandomUsername(8)
	require.NoError(t, err)
	un = un + ".łaøß"
	un8 := proto.NameUtf8(un)
	una, err := core.NormalizeName(un8)
	require.NoError(t, err)

	err = cli.CheckNameExists(ctx, proto.Name(una))
	require.Error(t, err)
	require.Equal(t, core.UserNotFoundError{}, err)
}

func TestAuth(t *testing.T) {
	u := GenerateNewTestUser(t)
	require.NotNil(t, u)
	ctx := context.Background()

	// Should get closed down right away if no cert
	ucli, userCloseFn, err := newUserClient(ctx, nil)
	defer userCloseFn()
	require.NoError(t, err)
	_, err = ucli.Ping(ctx)
	require.Error(t, err)

	// sometimes get a different error (from tls.permamentError)
	// so we don't check the type
	// require.Equal(t, io.EOF, err)

	key, err := u.eldest.PrivateKeyForCert()
	require.NoError(t, err)

	crt := tls.Certificate{
		PrivateKey:  key,
		Certificate: u.certChain,
	}

	ucli, userCloseFn, err = newUserClient(ctx, &crt)
	defer userCloseFn()
	require.NoError(t, err)
	uid, err := ucli.Ping(ctx)
	require.NoError(t, err)
	require.Equal(t, u.uid, uid)

	// If no certificate, it shouldn't work.
	crt = tls.Certificate{
		PrivateKey:  key,
		Certificate: nil,
	}
	ucli, userCloseFn, err = newUserClient(ctx, &crt)
	defer userCloseFn()
	require.NoError(t, err)
	_, err = ucli.Ping(ctx)
	require.Error(t, err)

	// The Error here is usually io.EOF but sometimes we get tls.permanentError,
	// so stop this check for fear of flakes.
	//require.Equal(t, io.EOF, err)
}

func TestLookupByDevice(t *testing.T) {
	ctx := context.Background()
	cli, closeFn, err := newRegClient(ctx)
	require.NoError(t, err)
	defer closeFn()

	un, err := RandomUsername(8)
	require.NoError(t, err)
	testUser := NewTestUserWithUsername(proto.NameUtf8(un))

	m := globalTestEnv.MetaContext()
	testUser.Signup(t, m, cli, nil)

	devId, err := testUser.eldest.EntityID()
	require.NoError(t, err)
	chal, err := cli.GetUIDLookupChallege(ctx, devId)
	require.NoError(t, err)

	sig, err := testUser.eldest.Sign(&chal.Payload)
	require.NoError(t, err)

	// Test happy path
	res, err := cli.LookupUIDByDevice(ctx, rem.LookupUIDByDeviceArg{
		EntityID:  devId,
		Signature: *sig,
		Challenge: chal,
	})
	require.NoError(t, err)
	require.Equal(t, testUser.uid, res.Fqu.Uid)
	require.Equal(t, proto.Name(un).Normalize(), res.Username)
	require.Equal(t, proto.NameUtf8(un), res.UsernameUtf8)

	// Test replay error handled properly
	_, err = cli.LookupUIDByDevice(ctx, rem.LookupUIDByDeviceArg{
		EntityID:  devId,
		Signature: *sig,
		Challenge: chal,
	})
	require.Error(t, err)
	require.Equal(t, core.ReplayError{}, err)

	// Test bad signature payload
	chal, err = cli.GetUIDLookupChallege(ctx, devId)
	require.NoError(t, err)
	chal.Payload.Rand[2] ^= 0x04
	sig, err = testUser.eldest.Sign(&chal.Payload)
	require.NoError(t, err)
	_, err = cli.LookupUIDByDevice(ctx, rem.LookupUIDByDeviceArg{
		EntityID:  devId,
		Signature: *sig,
		Challenge: chal,
	})
	require.Error(t, err)
	require.Equal(t, core.ValidationError("hmac failed"), err)

	// Test bad signature payload
	chal, err = cli.GetUIDLookupChallege(ctx, devId)
	require.NoError(t, err)
	sig, err = testUser.eldest.Sign(&chal.Payload)
	require.NoError(t, err)
	sig.F_0__[2] ^= 0x04
	_, err = cli.LookupUIDByDevice(ctx, rem.LookupUIDByDeviceArg{
		EntityID:  devId,
		Signature: *sig,
		Challenge: chal,
	})
	require.Error(t, err)
	require.Equal(t, core.VerifyError("lookupUID signature"), err)
}

// Test the getNextTreeLocation RPC works
func TestGetNextTreeLocation(t *testing.T) {
	u := GenerateNewTestUser(t)
	ctx := context.Background()
	crt := u.ClientCertRobust(ctx, t)
	ucli, userCloseFn, err := u.newUserClient(ctx, crt)
	require.NoError(t, err)
	defer userCloseFn()
	loc, err := ucli.GetTreeLocation(ctx, proto.Seqno(2))
	require.NoError(t, err)
	require.Equal(t, loc, *u.nextTreeLocation)
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	shutdown()
	os.Exit(code)
}
