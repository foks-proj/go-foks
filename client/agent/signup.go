// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package agent

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libyubi"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	"github.com/foks-proj/go-foks/lib/sso"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type SignupSession struct {
	SessionBase
	id                  proto.UISessionID
	ctime               time.Time
	typ                 proto.UISessionType
	email               proto.Email
	ic                  rem.InviteCode
	createYubi          *proto.YubiSlot
	createYubiPQ        *proto.YubiSlot
	reuseYubi           *libyubi.KeySuite
	reuseYubiPQ         *libyubi.KeySuitePQ
	finalYubi           *libyubi.KeySuiteHybrid
	finalYubiInfo       *proto.YubiKeyInfoHybrid
	usernameUtf8        proto.NameUtf8
	username            proto.Name
	usernameReservation rem.ReserveNameRes
	deviceName          proto.DeviceName
	privKey             core.PrivateSuiter
	role                proto.Role
	fqu                 proto.FQUser
	puk                 *core.SharedPrivateSuite25519
	root                *proto.TreeRoot
	pukBox              *proto.SharedKeyBoxSet
	kex                 *libclient.KexProvisionee
	kexEng              *kexProvisioneeEngine
	deviceType          proto.DeviceType
	activeUser          *libclient.UserContext
	passphrase          proto.Passphrase
	passphraseArg       *rem.SetPassphraseArg
	keyPrimed           bool
	oauth2              *proto.OAuth2Session
}

func (s *SignupSession) UserContext() (*libclient.UserContext, error) {
	var yi *proto.YubiKeyInfoHybrid
	kg := proto.KeyGenus_Device
	if s.finalYubi != nil {
		yi = s.finalYubiInfo
		kg = proto.KeyGenus_Yubi
	}

	keyID, err := s.privKey.EntityID()
	if err != nil {
		return nil, err
	}

	ret := &libclient.UserContext{
		Info: proto.UserInfo{
			Fqu: s.fqu,
			Username: proto.NameBundle{
				Name:     s.username,
				NameUtf8: s.usernameUtf8,
			},
			HostAddr: s.homeServer.CanonicalAddr(),
			Role:     s.role,
			YubiInfo: yi,
			KeyGenus: kg,
			Key:      keyID,
		},
		Devname: s.deviceName,
	}
	ret.PrivKeys.SetDevkey(s.privKey)
	if s.puk != nil {
		ret.PrivKeys.SetPUKs(
			libclient.NewPUKSet(
				[]core.SharedPrivateSuiter{s.puk},
				s.fqu.HostID,
			),
		)
	}

	if !s.selfTok.IsZero() {
		ret.Info.ViewToken = &proto.ViewToken{
			Token:  s.selfTok,
			IsSelf: true,
		}
	}

	// CAREFUL. Be sure not to set a nil libyubi.KeySuite here, since that will make
	// for a non-nil interface, which will fail type checks later.
	if s.finalYubi != nil {
		ret.Yubi = s.finalYubi
	}
	ret.SetHomeServer(s.SessionBase.homeServer)
	ret.SetSkmm(s.skm)
	return ret, nil
}

func (s *SignupSession) Init(id proto.UISessionID) {
	s.SessionBase.Init()
	s.typ = id.Type
	s.id = id
	s.ctime = time.Now()
	s.deviceType = proto.DeviceType_Computer

	// For now, all signups use the owner role
	s.role = proto.NewRoleDefault(proto.RoleType_OWNER)
}

func (c *AgentConn) MetaContext(ctx context.Context) libclient.MetaContext {
	return libclient.NewMetaContext(ctx, c.g)
}

func (c *AgentConn) LoginAs(ctx context.Context, arg lcl.LoginAsArg) error {
	m := c.MetaContext(ctx)
	return libclient.SwitchActiveUserFallbackToLoad(m, arg.User)
}

func (c *AgentConn) GetActiveUserForProvision(
	ctx context.Context,
	id proto.UISessionID,
) (
	proto.UserContext,
	error,
) {
	var zed proto.UserContext
	sess, err := c.agent.sessions.Signup(id)
	if err != nil {
		return zed, err
	}
	m := c.MetaContext(ctx)
	au, err := m.ActiveConnectedUser(nil)
	if err != nil {
		return zed, err
	}
	exp, err := au.Export()
	if err != nil {
		return zed, err
	}
	sess.activeUser = au
	return *exp, nil
}

func (c *AgentConn) PutUsername(ctx context.Context, arg lcl.PutUsernameArg) error {
	sess, err := c.agent.sessions.Signup(arg.SessionId)
	if err != nil {
		return err
	}
	m := c.MetaContext(ctx)
	return c.putUsername(m, arg.Username, sess)
}

func stopReprovision(
	m libclient.MetaContext,
	hostid proto.HostID,
	username proto.Name,
) error {
	uid, err := libclient.LookupUIDFromDB(m, hostid, username)
	if err != nil && errors.Is(err, core.RowNotFoundError{}) {
		return nil
	}
	if err != nil {
		return err
	}
	if uid == nil {
		return nil
	}
	ss := m.G().SecretStore()

	row, err := ss.Get(libclient.SecretStoreGetArgs{
		Fqu: proto.FQUser{
			Uid:    *uid,
			HostID: hostid,
		},
		Role: proto.OwnerRole,
		Opts: libclient.SecretStoreGetOpts{NoProvisional: true},
	})
	if err != nil {
		return err
	}
	if row != nil {
		return core.DeviceAlreadyProvisionedError{}
	}
	return nil
}

func (c *AgentConn) putUsername(m libclient.MetaContext, arg proto.NameUtf8, sess *SignupSession) error {

	usernameAscii, err := core.NormalizeName(arg)
	if err != nil {
		return nil
	}

	regCli, err := sess.RegCli(m)
	if err != nil {
		return err
	}

	switch sess.typ {
	case proto.UISessionType_Signup:

		var rures rem.ReserveNameRes
		var err error

		hostId := sess.homeServer.Chain().HostID()
		_, err = m.DbGet(&rures, libclient.DbTypeHard, &hostId, lcl.DataType_UsernameReservation, usernameAscii)

		// If we did get a hit, but the reservation is expired, then
		// we treat it as a miss.
		if err == nil && rures.Etime.Import().Before(m.G().Now()) {
			err = core.RowNotFoundError{}
		}

		if err == nil {
			m.Infow("Reusing username", "username", arg, "res", rures)
			sess.usernameUtf8 = arg
			sess.username = usernameAscii
			sess.usernameReservation = rures
			return nil
		}

		if !errors.Is(err, core.RowNotFoundError{}) {
			return err
		}

		rures, err = regCli.ReserveUsername(m.Ctx(),
			usernameAscii,
		)
		if err != nil {
			return err
		}
		sess.usernameUtf8 = arg
		sess.username = usernameAscii
		sess.usernameReservation = rures
		m.Infow("Picked username", "reservation", hex.EncodeToString(rures.Tok.Bytes()))

		err = m.DbPut(libclient.DbTypeHard, libclient.PutArg{
			Scope: &hostId,
			Typ:   lcl.DataType_UsernameReservation,
			Key:   usernameAscii,
			Val:   &rures,
		})
		if err != nil {
			return err
		}

	case proto.UISessionType_Provision, proto.UISessionType_NewKeyWizard:
		// We might be able to stop a reprovisioning based on the hostID and the username,
		// but only if we have a username -> UID mapping in the local DB, since we don't have
		// a way to look it up on the server. In case we miss here, and the reprovisioning is
		// a duplicate, we'll still die, but later on in the flow.
		err := stopReprovision(m, sess.homeServer.Chain().HostID(), usernameAscii)
		if err != nil {
			return err
		}

		err = regCli.CheckNameExists(m.Ctx(), usernameAscii)
		if err != nil {
			return err
		}
		sess.usernameUtf8 = arg
		sess.username = usernameAscii

	default:
		return core.InternalError("unknown signup session type")

	}
	m.Infow("Picked username", "username", arg)

	return nil
}

func (c *AgentConn) PutDeviceName(ctx context.Context, arg lcl.PutDeviceNameArg) error {
	sess, err := c.agent.sessions.Signup(arg.SessionId)
	if err != nil {
		return err
	}
	_, err = core.NormalizeDeviceName(arg.DeviceName)
	if err != nil {
		return err
	}
	sess.deviceName = arg.DeviceName
	return nil
}

func (c *AgentConn) PutEmail(ctx context.Context, arg lcl.PutEmailArg) error {
	m := c.MetaContext(ctx)
	sess, err := c.agent.sessions.Signup(arg.SessionId)
	if err != nil {
		return err
	}
	return c.putEmail(m, arg.Email, sess)
}

func (c *AgentConn) putEmail(m libclient.MetaContext, arg proto.Email, sess *SignupSession) error {
	if core.ValidateEmail(arg) != nil {
		return core.InvalidEmailError(arg)
	}
	sess.email = arg
	m.Infow("picked email", "email", arg)
	return nil
}

func (c *AgentConn) makeYubiPrimary(
	m libclient.MetaContext,
	sess *SignupSession,
) (
	*libyubi.KeySuite,
	error,
) {
	if sess.activeYubiDevice == nil {
		return nil, core.InternalError("no active yubi")
	}

	var yk *libyubi.KeySuite

	switch {
	case sess.createYubi != nil:
		var err error
		yk, err = m.G().YubiDispatch().GenerateKey(
			m.Ctx(),
			sess.activeYubiDevice.Id,
			*sess.createYubi,
			sess.role,
			sess.fqu.HostID,
			&libyubi.GenerateKeyOpts{
				LockWithPIN: sess.SessionBase.doPinProtect,
			},
		)
		if err != nil {
			return nil, err
		}
	case sess.reuseYubi != nil:
		yk = sess.reuseYubi
	default:
		return nil, core.InternalError("no yubi to use")
	}
	return yk, nil
}

func (c *AgentConn) makeYubiPQ(
	m libclient.MetaContext,
	sess *SignupSession,
) (
	*libyubi.KeySuitePQ,
	error,
) {
	if sess.activeYubiDevice == nil {
		return nil, core.InternalError("no active yubi")
	}

	var ret *libyubi.KeySuitePQ
	switch {
	case sess.createYubiPQ != nil:
		var err error
		ret, err = m.G().YubiDispatch().GenerateKeyPQ(
			m.Ctx(),
			sess.activeYubiDevice.Id,
			*sess.createYubiPQ,
			&libyubi.GenerateKeyOpts{
				LockWithPIN: sess.SessionBase.doPinProtect,
			},
		)
		if err != nil {
			return nil, err
		}
		id, err := ret.PQKeyID()
		if err != nil {
			return nil, err
		}
		if sess.finalYubiInfo == nil {
			return nil, core.InternalError("unexpected nil finalYubiInfo")
		}
		sess.finalYubiInfo.PqKey.Id = *id
	case sess.reuseYubiPQ != nil:
		ret = sess.reuseYubiPQ
	default:
		return nil, core.InternalError("no yubi PQ to use")
	}
	return ret, nil
}

func (c *AgentConn) makeYubiHybid(
	m libclient.MetaContext,
	sess *SignupSession,
) error {
	if sess.activeYubiDevice == nil {
		return core.InternalError("no active yubi")
	}
	pri, err := c.makeYubiPrimary(m, sess)
	if err != nil {
		return err
	}
	pq, err := c.makeYubiPQ(m, sess)
	if err != nil {
		return err
	}
	ret := pri.Fuse(pq)
	sess.privKey = ret
	sess.finalYubi = ret
	sess.finalYubiInfo.Key.Id = pri.ID()
	return nil
}

func (c *AgentConn) primeKey(m libclient.MetaContext, sess *SignupSession) error {
	return sess.primeKey(m)
}

func (s *SignupSession) primeKey(m libclient.MetaContext) error {
	if s.homeServer == nil || s.homeServer.Chain() == nil {
		return core.InternalError("no home server")
	}

	if s.keyPrimed {
		return nil
	}

	hostId := s.homeServer.Chain().HostID()

	pukSs := core.RandomSecretSeed32()

	puk, err := core.NewSharedPrivateSuite25519(
		proto.EntityType_PUKVerify,
		s.role,
		pukSs,
		proto.Generation(core.FirstPUKGeneration),
		hostId,
	)

	if err != nil {
		return err
	}

	err = s.hepks.AddHEPKExporter(puk)
	if err != nil {
		return err
	}

	pukEntity, err := puk.EntityID()
	if err != nil {
		return err
	}
	uidEntity, err := pukEntity.Persistent()
	if err != nil {
		return err
	}

	uid, err := uidEntity.ToUID()
	if err != nil {
		return err
	}
	s.puk = puk
	s.fqu = proto.FQUser{
		Uid:    uid,
		HostID: hostId,
	}

	ma, err := s.homeServer.MerkleAgent(m)
	if err != nil {
		return err
	}
	// We don't need this for now, can shut it down, the server connection has some background threads that we
	// should clean out.
	defer ma.Shutdown()

	root, err := ma.GetLatestRootAndValidate(m.Ctx())
	if err != nil {
		return err
	}
	var rootHash proto.MerkleRootHash
	err = merkle.HashRoot(root, &rootHash)
	if err != nil {
		return err
	}

	v, err := root.GetV()
	if err != nil {
		return err
	}
	if v != proto.MerkleRootVersion_V1 {
		return core.VersionNotSupportedError("can only support merkle V1")
	}

	s.root = &proto.TreeRoot{
		Hash: rootHash,
		Epno: root.V1().Epno,
	}

	tok, err := core.NewPermissionToken()
	if err != nil {
		return err
	}
	s.selfTok = tok
	s.keyPrimed = true
	return nil
}

// signup Passphrase Mgr Server Interface. This is a slight hack to get at the SetPassphrase
// method, but it's fine for now, and easier than a refactor.
type signupPMI struct {
	rcli rem.RegClient
	res  *rem.SetPassphraseArg
	opts libclient.StretchOpts
	raw  proto.Passphrase
	puk  core.SharedPrivateSuiter
}

func newSignupPMI(
	m libclient.MetaContext,
	rcli rem.RegClient,
	raw proto.Passphrase,
	puk core.SharedPrivateSuiter,
) *signupPMI {
	return &signupPMI{
		rcli: rcli,
		opts: libclient.StretchOpts{
			IsTest: m.G().Cfg().TestingMode(),
		},
		raw: raw,
		puk: puk,
	}
}

func (s *signupPMI) RawPassphrase() proto.Passphrase        { return s.raw }
func (s *signupPMI) PME() libclient.PassphraseManagerEngine { return s }
func (s *signupPMI) PUK() core.SharedPrivateSuiter          { return s.puk }

func (s *signupPMI) MakeUserSettingsLink(
	ctx context.Context,
	info proto.PassphraseInfo,
) (
	*rem.PostGenericLinkArg,
	error,
) {
	return nil, nil
}

func (s *signupPMI) GetUserSettings(
	ctx context.Context,
) (
	*proto.PassphraseInfo,
	error,
) {
	return nil, nil
}

var _ libclient.PassphraseManagerEngine = (*signupPMI)(nil)
var _ libclient.PassphraseManagerInterface = (*signupPMI)(nil)
var _ libclient.UserServerInterface = (*signupPMI)(nil)

func (s *signupPMI) RegServer() libclient.RegServerInterface                { return s.rcli }
func (s *signupPMI) UserServer(uid proto.UID) libclient.UserServerInterface { return s }
func (s *signupPMI) StretchOpts() libclient.StretchOpts                     { return s.opts }

func (s *signupPMI) SetPassphrase(ctx context.Context, arg rem.SetPassphraseArg) error {
	s.res = &arg
	return nil
}

func (s *signupPMI) GetPpeParcel(
	ctx context.Context,
) (
	proto.PpeParcel,
	error,
) {
	return proto.PpeParcel{}, core.NotImplementedError{}
}

func (s *signupPMI) ChangePassphrase(ctx context.Context, arg rem.ChangePassphraseArg) error {
	return core.NotImplementedError{}
}
func (s *signupPMI) GetSalt(ctx context.Context) (proto.PassphraseSalt, error) {
	return proto.PassphraseSalt{}, core.NotImplementedError{}
}
func (s *signupPMI) NextPassphraseGeneration(ctx context.Context) (proto.PassphraseGeneration, error) {
	return 0, core.NotImplementedError{}
}
func (s *signupPMI) StretchVersion(ctx context.Context) (proto.StretchVersion, error) {
	return s.rcli.StretchVersion(ctx)
}

func (s *signupPMI) Arg() *rem.SetPassphraseArg {
	return s.res
}

func (c *AgentConn) makeKeyDevice(m libclient.MetaContext, sess *SignupSession) error {

	ss := core.RandomSecretSeed32()
	devKey, err := core.NewPrivateSuite25519(proto.EntityType_Device, sess.role, ss, sess.fqu.HostID)
	if err != nil {
		return err
	}
	var pmi libclient.PassphraseManagerInterface
	if !sess.passphrase.IsZero() {
		regCli, err := sess.RegCli(m)
		if err != nil {
			return err
		}
		pmi = newSignupPMI(m, *regCli, sess.passphrase, sess.puk)
	}

	did, err := devKey.DeviceID()
	if err != nil {
		return err
	}

	row := lcl.LabeledSecretKeyBundle{
		Fqur: proto.FQUserAndRole{
			Fqu:  sess.fqu,
			Role: sess.role,
		},
		KeyID:   did,
		SelfTok: sess.selfTok,
	}

	skm, err := libclient.StoreSecretWithDefaults(m, row, ss, pmi, nil)
	if err != nil {
		return err
	}

	if pmi != nil {
		sess.passphraseArg = pmi.Arg()
	}

	sess.privKey = devKey
	sess.skm = skm
	return nil
}

func (c *AgentConn) makeKey(m libclient.MetaContext, sess *SignupSession) error {
	var err error
	switch {
	case sess.reuseYubi != nil || sess.createYubi != nil:
		err = c.makeYubiHybid(m, sess)
	default:
		// For non-yubi, we also make the PQKEM key here.
		err = c.makeKeyDevice(m, sess)
	}
	if err != nil {
		return err
	}
	err = sess.hepks.AddHEPKExporter(sess.privKey)
	if err != nil {
		return err
	}
	return err
}

func (c *AgentConn) signSSOArgsWithSignupSession(
	m libclient.MetaContext,
	sess *SignupSession,
) (rem.RegSSOArgs, error) {

	return c.signSSOArgs(
		m,
		sess.oauth2,
		sess.privKey,
		sess.fqu.HostID,
	)
}

func (c *AgentConn) signSSOArgs(
	m libclient.MetaContext,
	oauth2 *proto.OAuth2Session,
	privKey core.PrivateSuiter,
	hostid proto.HostID,
) (rem.RegSSOArgs, error) {

	def := rem.NewRegSSOArgsWithNone()
	if oauth2 == nil {
		return def, nil
	}
	if privKey == nil {
		return def, core.InternalError("no private key")
	}
	devicePub, err := privKey.Publicize(&hostid)
	if err != nil {
		return def, err
	}
	if oauth2.Idtok == nil {
		return def, core.InternalError("no idtok set; we should have one")
	}
	payload := proto.OAuth2IDTokenBindingPayload{
		IdToken: oauth2.Idtok.Raw,
		Binding: oauth2.Binding,
	}
	sig, o, err := core.Sign2(privKey, &payload)
	if err != nil {
		return def, err
	}
	ret := rem.NewRegSSOArgsWithOauth2(
		rem.RegSSOArgsOAuth2{
			Id: oauth2.Id,
			Sig: proto.OAuth2IDTokenBinding{
				Key:   devicePub.GetEntityID(),
				Sig:   *sig,
				Inner: *o,
			},
		},
	)
	return ret, nil
}

func (c *AgentConn) runReg(m libclient.MetaContext, sess *SignupSession) error {

	devicePub, err := sess.privKey.Publicize(&sess.fqu.HostID)
	if err != nil {
		return err
	}

	pukBox, err := core.BoxOne(sess.fqu.HostID, sess.puk, sess.privKey, devicePub)
	if err != nil {
		return err
	}
	sess.pukBox = pukBox

	dln, err := sess.deviceLabelAndName()
	if err != nil {
		return err
	}

	var subkey core.EntityPrivate
	var subkeyBox *proto.Box
	var pqHint *proto.YubiSlotAndPQKeyID
	if sess.finalYubi != nil {
		subkey, subkeyBox, err = core.MakeSubkey(sess.finalYubi, sess.fqu.HostID)
		if err != nil {
			return err
		}
		pqHint = &sess.finalYubiInfo.PqKey
	}

	mer, err := core.MakeEldestLink(
		sess.fqu.HostID,
		rem.NameCommitment{
			Name: sess.username,
			Seq:  sess.usernameReservation.Seq,
		},
		sess.privKey,
		sess.puk,
		dln.Label,
		*sess.root,
		subkey,
	)
	if err != nil {
		return err
	}
	sso, err := c.signSSOArgsWithSignupSession(m, sess)
	if err != nil {
		return err
	}

	dlnck := rem.DeviceLabelNameAndCommitmentKey{
		Dln:           *dln,
		CommitmentKey: *mer.DevNameCommitmentKey,
	}

	arg := rem.SignupArg{
		UsernameUtf8:             sess.usernameUtf8,
		Rur:                      sess.usernameReservation,
		Link:                     *mer.Link,
		Dlnck:                    dlnck,
		UsernameCommitmentKey:    *mer.UsernameCommitmentKey,
		PukBox:                   *pukBox,
		NextTreeLocation:         *mer.NextTreeLocation,
		InviteCode:               sess.ic,
		Email:                    sess.email,
		SubkeyBox:                subkeyBox,
		Passphrase:               sess.passphraseArg,
		SubchainTreeLocationSeed: *mer.SubchainTreeLocationSeed,
		SelfToken:                sess.selfTok,
		Hepks:                    sess.hepks.Export(),
		YubiPQhint:               pqHint,
		Sso:                      sso,
	}

	regCli, err := sess.RegCli(m)
	if err != nil {
		return err
	}
	err = regCli.Signup(m.Ctx(), arg)
	if err != nil {
		return err
	}

	return nil
}

func (c *AgentConn) writeLocalDB(
	m libclient.MetaContext,
	sess *SignupSession,
	uc *libclient.UserContext,
) error {

	if sess.homeServer == nil || sess.homeServer.PublicZone() == nil || sess.homeServer.Chain() == nil {
		return core.InternalError("no public zone")
	}

	uinf := uc.Info

	var ltx libclient.LocalDbTx
	err := ltx.PutUser(uinf, false)
	if err != nil {
		return err
	}

	var nb int
	if sess.pukBox != nil {
		nb = len(sess.pukBox.Boxes)
	}

	if nb > 0 && nb != 1 {
		return core.InternalError("expected one PUK box")
	}

	if nb == 1 {
		// Seedchain is nil since it's our first PUK. Also, we are certain there
		// should be only one PUK since we are creating the account (see above assertion)
		pukParcel := proto.SharedKeyParcel{
			Box:             sess.pukBox.Boxes[0],
			TempDHKeySigned: sess.pukBox.TempDHKeySigned,
		}

		err := ltx.PutPukParcel(uinf.Fqu, pukParcel)
		if err != nil {
			return err
		}
	}

	err = m.DbPutTx(libclient.DbTypeHard, ltx.Arg())
	if err != nil {
		return err
	}

	return nil
}

func (c *AgentConn) commonFinish(
	m libclient.MetaContext,
	sess *SignupSession,
) (
	*libclient.UserContext,
	error,
) {
	uc, err := sess.UserContext()
	if err != nil {
		return nil, err
	}
	err = c.writeLocalDB(m, sess, uc)
	if err != nil {
		return nil, err
	}
	err = libclient.SetActiveUser(m, uc)
	if err != nil {
		return nil, err
	}
	return uc, nil
}

func (c *AgentConn) finishSession(
	ctx context.Context,
	id proto.UISessionID,
	fn func(m libclient.MetaContext, sess *SignupSession) error,
) error {
	defer func() {
		c.agent.sessions.completeSession(id)
	}()
	m := c.MetaContext(ctx)
	sess, err := c.agent.sessions.Signup(id)
	if err != nil || sess == nil {
		return err
	}
	err = fn(m, sess)
	if err != nil {
		return err
	}
	return nil
}

func (c *AgentConn) Finish(ctx context.Context, id proto.UISessionID) (lcl.FinishRes, error) {
	var ret lcl.FinishRes
	err := c.finishSession(ctx, id,
		func(m libclient.MetaContext, sess *SignupSession) error {
			err := c.primeKey(m, sess)
			if err != nil {
				return err
			}

			err = c.makeKey(m, sess)
			if err != nil {
				return err
			}

			err = c.runReg(m, sess)
			if err != nil {
				return err
			}

			_, err = c.commonFinish(m, sess)
			if err != nil {
				return err
			}
			ret.RegServerType = sess.regServerType
			ret.HostType = sess.hostType
			return nil
		},
	)
	if err != nil {
		return ret, err
	}
	return ret, nil
}

func (c *AgentConn) FinishYubiProvision(ctx context.Context, id proto.UISessionID) error {
	return c.finishSession(ctx, id,
		func(m libclient.MetaContext, sess *SignupSession) error {
			uc, err := c.commonFinish(m, sess)
			if err != nil {
				return err
			}
			err = uc.PopulateWithDevkey(m)
			if err != nil {
				return err
			}
			return nil
		},
	)
}

func (c *AgentConn) ErrorWrapper() func(error) proto.Status {
	return core.ErrorToStatus
}

func (c *AgentConn) PutInviteCode(ctx context.Context, arg lcl.PutInviteCodeArg) error {
	sess, err := c.agent.sessions.Signup(arg.SessionId)
	m := c.MetaContext(ctx)
	if err != nil {
		return err
	}

	ic, err := core.ImportInviteCode(string(arg.InviteCode), sess.icr)
	if err != nil {
		m.Infow("import invite code", "err", err)
		return core.BadInviteCodeError{}
	}

	regCli, err := sess.RegCli(m)
	if err != nil {
		return err
	}
	m.Infow("putInviteCode", "ic", ic)
	err = regCli.CheckInviteCode(m.Ctx(), ic)
	if err != nil {
		m.Warnw("putInviteCode", "err", err)
		return err
	}
	sess.ic = ic

	return nil
}

func (c *AgentConn) JoinWaitList(ctx context.Context, sessId proto.UISessionID) (proto.WaitListID, error) {
	var zed proto.WaitListID
	sess, err := c.agent.sessions.Signup(sessId)
	if err != nil {
		return zed, err
	}
	m := c.MetaContext(ctx)
	regCli, err := sess.RegCli(m)
	if err != nil {
		return zed, err
	}
	if sess.email == "" {
		return zed, core.InternalError("no email set")
	}
	wlid, err := regCli.JoinWaitList(m.Ctx(), sess.email)
	if err != nil {
		return proto.WaitListID{}, err
	}
	return wlid, nil
}

func (c *AgentConn) ListYubiSlots(ctx context.Context, sessId proto.UISessionID) (lcl.ListYubiSlotsRes, error) {
	sess, err := c.agent.sessions.Signup(sessId)
	m := c.MetaContext(ctx)
	var ret lcl.ListYubiSlotsRes
	if err != nil {
		return ret, err
	}
	if sess.activeYubiDevice == nil {
		m.Infow("ListYubiSlots", "early out", "no active yubi", "session", sessId)
		return ret, nil
	}
	ret.Device = sess.activeYubiDevice
	return ret, nil
}

func (a *AgentConn) lookupDeviceOnServer(
	m libclient.MetaContext,
	sess *SessionBase,
	dev core.PrivateSuiter,
) (
	*proto.LookupUserRes,
	error,
) {
	regCli, err := sess.RegCli(m)
	if err != nil {
		return nil, err
	}
	return lookupDeviceOnServer(m, dev, *regCli, sess.homeServer.Chain().HostID())
}

func lookupDeviceChallenge(
	m libclient.MetaContext,
	dev core.PrivateSuiter,
	regCli rem.RegClient,
	hostID proto.HostID,
) (
	*rem.LookupUIDByDeviceArg,
	error,
) {
	eid, err := dev.EntityID()
	if err != nil {
		return nil, err
	}
	chal, err := regCli.GetUIDLookupChallege(m.Ctx(), eid)
	if err != nil {
		return nil, err
	}

	if !chal.Payload.EntityID.Eq(eid) ||
		!chal.Payload.HostID.Eq(hostID) ||
		!chal.Payload.Time.IsNowish() {
		return nil, core.BadServerDataError("server sent back wrong challenge")
	}

	sig, err := dev.Sign(&chal.Payload)
	if err != nil {
		return nil, err
	}
	ret := rem.LookupUIDByDeviceArg{
		EntityID:  eid,
		Challenge: chal,
		Signature: *sig,
	}
	return &ret, nil
}

func lookupDeviceOnServer(
	m libclient.MetaContext,
	dev core.PrivateSuiter,
	regCli rem.RegClient,
	hostID proto.HostID,
) (
	*proto.LookupUserRes,
	error,
) {
	arg, err := lookupDeviceChallenge(m, dev, regCli, hostID)
	if err != nil {
		return nil, err
	}
	var res proto.LookupUserRes
	res, err = regCli.LookupUIDByDevice(m.Ctx(), *arg)
	if err != nil {
		return nil, err
	}

	// We had a bug here (see Issue #97) where the server was setting this incorrectly.
	// However, can ignore what the server says as to HostID since it must correspond
	// to our desired hostID above. Issue #97 was fixed here and on the server.
	res.Fqu.HostID = hostID

	return &res, nil
}

func (c *AgentConn) clearYubi(sess *SignupSession) {
	sess.createYubi = nil
	sess.reuseYubi = nil
	sess.createYubiPQ = nil
	sess.reuseYubiPQ = nil
	sess.finalYubi = nil
	sess.finalYubiInfo = nil
	sess.deviceType = proto.DeviceType_Computer
}

func (c *AgentConn) PutYubiSlot(ctx context.Context, arg lcl.PutYubiSlotArg) (lcl.PutYubiSlotRes, error) {
	m := c.MetaContext(ctx)
	var zed lcl.PutYubiSlotRes
	sess, err := c.agent.sessions.Signup(arg.SessionId)
	if err != nil {
		return zed, err
	}
	if sess.activeYubiDevice == nil {
		return zed, core.InternalError("no active yubi device")
	}
	if sess.homeServer == nil {
		return zed, core.InternalError("need a host set before picking yubi slot")
	}

	var un *proto.Name
	idxTyp, err := arg.Index.GetT()
	if err != nil {
		return zed, err
	}

	// If the user chose no yubikey to use, early-out
	if idxTyp == proto.YubiIndexType_None {
		c.clearYubi(sess)
		return lcl.PutYubiSlotRes{IdxType: idxTyp}, nil
	}

	switch arg.Typ {
	case proto.CryptosystemType_Classical:
		un, err = c.putYubiSlotClassical(m, arg, sess)
	case proto.CryptosystemType_PQKEM:
		err = c.putYubiSlotPQ(m, arg, sess)
	default:
		return zed, core.InternalError("unknown cryptosystem type")
	}
	if err != nil {
		return zed, err
	}
	if sess.activeYubiDevice == nil {
		return zed, core.InternalError("unexepected nil yubi device")
	}
	slot, err := sess.activeYubiDevice.SelectSlot(arg.Index)
	if err != nil {
		return zed, err
	}
	ret := lcl.PutYubiSlotRes{
		Username:   un,
		Device:     *sess.activeYubiDevice,
		ChosenSlot: slot,
		IdxType:    idxTyp,
	}
	return ret, nil
}

func (c *AgentConn) putYubiSlotPQ(
	m libclient.MetaContext,
	arg lcl.PutYubiSlotArg,
	sess *SignupSession,
) error {
	typ, err := arg.Index.GetT()
	if err != nil {
		return err
	}
	if sess.finalYubiInfo == nil {
		return core.InternalError("no final yubi info set")
	}
	switch typ {
	case proto.YubiIndexType_None:
		return core.InternalError("no slot index on PutYubiSlot PQ")

	case proto.YubiIndexType_Empty:
		i := arg.Index.Empty()
		if int(i) > len(sess.activeYubiDevice.EmptySlots) {
			return core.InternalError("slot index out of range")
		}
		slot := sess.activeYubiDevice.EmptySlots[i]
		sess.createYubiPQ = &slot
		sess.finalYubiInfo.PqKey.Slot = slot

	case proto.YubiIndexType_Reuse:
		if sess.createYubi != nil || sess.reuseYubi == nil {
			return core.InternalError("can't create primary and reuse PQ")
		}
		i := arg.Index.Reuse()
		key, err := sess.activeYubiDevice.KeyAt(int(i))
		if err != nil {
			return err
		}
		reuse, err := m.G().YubiDispatch().AccessPQKey(m.Ctx(), *key)
		if err != nil {
			return err
		}
		sess.reuseYubiPQ = reuse
		id, err := reuse.PQKeyID()
		if err != nil {
			return err
		}
		sess.finalYubiInfo.PqKey = proto.YubiSlotAndPQKeyID{
			Slot: key.Key.Slot,
			Id:   *id,
		}
	default:
		return core.InternalError("unknown yubi index type")
	}
	return nil
}

func (c *AgentConn) putYubiSlotClassical(
	m libclient.MetaContext,
	arg lcl.PutYubiSlotArg,
	sess *SignupSession,
) (
	*proto.Name,
	error,
) {
	var ret *proto.Name
	typ, err := arg.Index.GetT()
	if err != nil {
		return nil, err
	}

	switch typ {
	case proto.YubiIndexType_None:
		sess.createYubi = nil
		sess.reuseYubi = nil

	case proto.YubiIndexType_Empty:
		i := arg.Index.Empty()
		if int(i) > len(sess.activeYubiDevice.EmptySlots) {
			return nil, core.InternalError("slot index out of range")
		}
		slot := sess.activeYubiDevice.EmptySlots[i]
		sess.createYubi = &slot
		sess.reuseYubi = nil
		sess.finalYubiInfo = &proto.YubiKeyInfoHybrid{
			Card: sess.activeYubiDevice.Id,
			Key: proto.YubiSlotAndKeyID{
				Slot: slot,
			},
		}
		sess.deviceType = proto.DeviceType_YubiKey

	case proto.YubiIndexType_Reuse:
		ret, err = c.putYubiSlotClassicalReuse(m, arg, sess)
		if err != nil {
			return nil, err
		}
	default:
		return nil, core.InternalError("unknown yubi index type")
	}
	return ret, nil
}

func (c *AgentConn) putYubiSlotClassicalReuse(
	m libclient.MetaContext,
	arg lcl.PutYubiSlotArg,
	sess *SignupSession,
) (
	*proto.Name,
	error,
) {
	var ret *proto.Name
	i := arg.Index.Reuse()
	key, err := sess.activeYubiDevice.KeyAt(int(i))
	if err != nil {
		return nil, err
	}

	reuse, err := m.G().YubiDispatch().Load(m.Ctx(), *key, sess.role, sess.homeServer.Chain().HostID())
	if err != nil {
		return nil, err
	}

	sess.finalYubiInfo = &proto.YubiKeyInfoHybrid{
		Card: key.Card,
		Key:  key.Key,
	}

	sess.reuseYubi = reuse
	sess.createYubi = nil
	sess.deviceType = proto.DeviceType_YubiKey

	lres, err := c.lookupDeviceOnServer(m, &sess.SessionBase, reuse)

	switch sess.typ {
	case proto.UISessionType_Signup, proto.UISessionType_YubiNew, proto.UISessionType_NewKeyWizard:
		if err == nil {
			return nil, core.KeyInUseError{}
		}
		if errors.Is(err, core.KeyNotFoundError{}) {
			err = nil
		}
		if err != nil {
			return nil, err
		}

	case proto.UISessionType_YubiProvision:
		if err != nil {
			return nil, err
		}
		sess.fqu.Uid = lres.Fqu.Uid
		sess.fqu.HostID = sess.homeServer.Chain().HostID()
		sess.username = lres.Username
		sess.usernameUtf8 = lres.UsernameUtf8

		pqkey, err := sess.activeYubiDevice.KeyAtSlot(lres.YubiPQHint.Slot)
		if err != nil {
			return nil, err
		}

		reuse, err := m.G().YubiDispatch().AccessPQKey(m.Ctx(), *pqkey)
		if err != nil {
			return nil, err
		}
		sess.reuseYubiPQ = reuse
		pqKeyId, err := reuse.PQKeyID()
		if err != nil {
			return nil, err
		}

		sess.finalYubiInfo = &proto.YubiKeyInfoHybrid{
			Card: sess.activeYubiDevice.Id,
			Key: proto.YubiSlotAndKeyID{
				Slot: key.Key.Slot,
				Id:   key.Key.Id,
			},
			PqKey: proto.YubiSlotAndPQKeyID{
				Id:   lres.YubiPQHint.Id,
				Slot: lres.YubiPQHint.Slot,
			},
		}

		if !pqKeyId.Eq(&lres.YubiPQHint.Id) {
			return nil, core.KeyNotFoundError{Which: "PQ key"}
		}
		err = c.makeYubiHybid(m, sess)
		if err != nil {
			return nil, err
		}
		sess.role = lres.Role

		ret = &lres.Username
	default:
		return nil, core.InternalError("unknown signup type in PutYubiSlot")
	}

	return ret, nil
}

// When we have SSO-powered logins, the server will assign username based on the
// email address.
func (c *AgentConn) IsUsernameServerAssigned(ctx context.Context, sessId proto.UISessionID) (bool, error) {
	return false, nil
}

func (c *AgentConn) GetDeviceType(ctx context.Context, id proto.UISessionID) (proto.DeviceType, error) {
	var ret proto.DeviceType
	err := c.withSession(id, func(sess *SignupSession) error {
		ret = sess.deviceType
		return nil
	})
	return ret, err
}

func (c *AgentConn) withSession(sid proto.UISessionID, fn func(sess *SignupSession) error) error {
	sess, err := c.agent.sessions.Signup(sid)
	if err != nil {
		return err
	}
	return fn(sess)
}

func (c *AgentConn) PutPassphrase(ctx context.Context, arg lcl.PutPassphraseArg) error {
	return c.withSession(arg.SessionID, func(sess *SignupSession) error {
		sess.passphrase = arg.Passphrase
		return nil
	})
}

func (c *AgentConn) PromptForPassphrase(ctx context.Context, id proto.UISessionID) (bool, error) {
	var ret bool
	m := c.MetaContext(ctx)
	err := c.withSession(id, func(sess *SignupSession) error {
		if sess.activeYubiDevice != nil {
			return nil
		}
		keyEncTyp, err := m.G().Cfg().DefaultLocalKeyEncryption()
		if err != nil {
			return err
		}
		if keyEncTyp != nil && *keyEncTyp == proto.SecretKeyStorageType_ENC_PASSPHRASE {
			ret = true
		}
		return nil
	})
	return ret, err

}

func (c *AgentConn) LoadStateFromActiveUser(ctx context.Context, id proto.UISessionID) (proto.UserInfo, error) {
	m := c.MetaContext(ctx)
	var zed proto.UserInfo
	var ret proto.UserInfo
	err := c.withSession(id, func(sess *SignupSession) error {
		au, err := m.ActiveConnectedUser(nil)
		if err != nil {
			return err
		}
		sess.homeServer = au.HomeServer()
		ret = au.UserInfo()
		return nil
	})
	if err != nil {
		return zed, err
	}
	return ret, nil
}

func (s *SignupSession) deviceLabelAndName() (*proto.DeviceLabelAndName, error) {
	if s.deviceName == "" {
		return nil, core.InternalError("no device name")
	}
	dnNorm, err := core.NormalizeDeviceName(s.deviceName)
	if err != nil {
		return nil, err
	}
	return &proto.DeviceLabelAndName{
		Label: proto.DeviceLabel{
			DeviceType: s.deviceType,
			Name:       dnNorm,
			Serial:     proto.FirstDeviceSerial,
		},
		Name: s.deviceName,
	}, nil
}

func (c *AgentConn) FinishYubiNew(ctx context.Context, id proto.UISessionID) error {
	m := c.MetaContext(ctx)
	return c.withSession(id, func(sess *SignupSession) error {
		err := c.makeYubiHybid(m, sess)
		if err != nil {
			return err
		}
		role := proto.OwnerRole
		dln, err := sess.deviceLabelAndName()
		if err != nil {
			return err
		}

		// In the NewKeyWizard, we might be creating a yubikey with
		// another yubi. In that case, we need to be unlocked. We might
		// want to revisit this since it might take user interaction to unlock
		// the device.
		if sess.typ == proto.UISessionType_NewKeyWizard {
			err = c.yubiUnlock(m)
			if err != nil {
				return err
			}
		}
		return c.yubiNew(m, role, *dln,
			func(r *prepareNewDeviceRes) (*libyubi.KeySuiteHybrid, error) {
				return sess.finalYubi, nil
			},
		)
	})
}

func (c *AgentConn) SignupStartSsoLoginFlow(
	ctx context.Context,
	id proto.UISessionID,
) (
	lcl.SsoLoginFlow,
	error,
) {
	m := c.MetaContext(ctx)
	var ret lcl.SsoLoginFlow
	err := c.withSession(id, func(sess *SignupSession) error {
		err := sess.primeKey(c.MetaContext(ctx))
		if err != nil {
			return err
		}
		if sess.ssoCfg == nil {
			return core.InternalError("no SSO config")
		}
		if sess.root == nil {
			return core.InternalError("no root set")
		}

		flow, err := sso.PrepOAuth2Session(sess.fqu, *sess.root)
		if err != nil {
			return err
		}
		sess.oauth2 = flow

		reg, err := sess.RegCli(m)
		if err != nil {
			return err
		}
		authURI, err := reg.InitOAuth2Session(m.Ctx(),
			rem.InitOAuth2SessionArg{
				Id:           flow.Id,
				PkceVerifier: flow.Verifier,
				Nonce:        flow.Nonce,
			})
		if err != nil {
			return err
		}

		ret.Url = authURI
		return nil
	})
	if err != nil {
		return ret, err
	}
	return ret, nil
}

func (c *AgentConn) SignupWaitForSsoLogin(ctx context.Context, id proto.UISessionID) (proto.SSOLoginRes, error) {
	var ret proto.SSOLoginRes
	m := c.MetaContext(ctx)
	err := c.withSession(id, func(sess *SignupSession) error {
		if sess.oauth2 == nil {
			return core.InternalError("no oauth2 session")
		}
		regCli, err := sess.RegCli(m)
		if err != nil {
			return err
		}
		res, err := regCli.PollOAuth2SessionCompletion(m.Ctx(), rem.PollOAuth2SessionCompletionArg{
			Id:   sess.oauth2.Id,
			Wait: proto.ExportDurationMilli(time.Minute * time.Duration(10)),
		})
		if err != nil {
			return err
		}
		if sess.ssoCfg == nil {
			return core.InternalError("no SSO config")
		}
		if sess.ssoCfg.Oauth2 == nil {
			return core.InternalError("no oauth2 config")
		}
		url := sess.ssoCfg.Oauth2.ConfigURI
		g, err := m.G().OAuth2GlobalContext()
		if err != nil {
			return err
		}
		o2cfg, err := m.G().OAuth2IdPConfigSet().Get(m.Ctx(), g, url)
		if err != nil {
			return err
		}
		idtok, err := sso.OAuth2CheckTokens(m.Ctx(), g, o2cfg, res.Toks, sess.ssoCfg.Oauth2.ClientID, sess.oauth2.Nonce)
		if err != nil {
			return err
		}
		sess.oauth2.Idtok = idtok
		if idtok.Email != "" {
			err = c.putEmail(m, idtok.Email, sess)
			if err != nil {
				return err
			}
		}

		// If the Username came back non-nil, we should also get a username reservation back from the
		// server.
		if idtok.Username != "" {
			unn, err := core.NormalizeName(idtok.Username)
			if err != nil {
				return err
			}
			sess.usernameUtf8 = idtok.Username
			sess.username = unn
			sess.usernameReservation = res.Res
		}
		ret.Email = idtok.Email
		ret.Username = idtok.Username
		ret.Issuer = idtok.Issuer
		return nil

	})
	if err != nil {
		return ret, err
	}
	return ret, nil
}

func (c *AgentConn) GetUsernameSSO(
	ctx context.Context,
	sid proto.UISessionID,
) (
	proto.NameUtf8,
	error,
) {
	var ret proto.NameUtf8
	err := c.withSession(sid, func(sess *SignupSession) error {
		if sess.oauth2 != nil && sess.oauth2.Idtok != nil {
			ret = sess.oauth2.Idtok.Username
		}
		return nil
	})
	return ret, err
}

func (c *AgentConn) GetEmailSSO(
	ctx context.Context,
	sid proto.UISessionID,
) (
	proto.Email,
	error,
) {
	var ret proto.Email
	err := c.withSession(sid, func(sess *SignupSession) error {
		if sess.oauth2 != nil && sess.oauth2.Idtok != nil {
			ret = sess.oauth2.Idtok.Email
		}
		return nil
	})
	return ret, err
}

func (c *AgentConn) GetInviteCodeRegime(
	ctx context.Context,
	sid proto.UISessionID,
) (
	proto.InviteCodeRegime,
	error,
) {
	var ret proto.InviteCodeRegime
	err := c.withSession(sid, func(sess *SignupSession) error {
		if sess.oauth2 != nil && sess.oauth2.Idtok != nil {
			ret = proto.InviteCodeRegime_SkipViaSSO
		} else {
			ret = sess.icr
		}
		return nil
	})
	return ret, err
}

func (c *AgentConn) FinishNKWNewDeviceKey(ctx context.Context, id proto.UISessionID) error {
	return c.withSession(id, func(sess *SignupSession) error {
		dn := sess.deviceName
		if dn == "" {
			return core.InternalError("no device name")
		}
		dnn, err := core.NormalizeDeviceName(dn)
		if err != nil {
			return err
		}
		dln := proto.DeviceLabelAndName{
			Label: proto.DeviceLabel{
				Name:       dnn,
				DeviceType: proto.DeviceType_Computer,
				Serial:     proto.FirstDeviceSerial,
			},
			Name: dn,
		}

		m := c.MetaContext(ctx)

		// Note that if we need a pin or password, we need to insert that into
		// the wizard flow. For now, leave as is. It's safe to call this on a backup
		// key.
		err = c.yubiUnlock(m)
		if err != nil {
			return err
		}

		role := proto.OwnerRole
		arg := lcl.SelfProvisionArg{
			Role: role,
			Dln:  dln,
		}
		err = c.SelfProvision(ctx, arg)
		if err != nil {
			return err
		}
		return nil
	})
}

func (c *AgentConn) FinishNKWNewBackupKey(
	ctx context.Context,
	id proto.UISessionID,
) (
	lcl.BackupHESP,
	error,
) {
	return c.BackupNew(ctx, proto.OwnerRole)
}

var _ lcl.SignupInterface = (*AgentConn)(nil)
