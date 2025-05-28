// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package engine

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RegServer struct {
	shared.BaseRPCServer
	testTimeTravel time.Duration
}

func (s *RegServer) SetTestTimeTravel(t time.Duration) {
	s.Lock()
	defer s.Unlock()
	s.testTimeTravel = t
}

func (s *RegServer) TestTimeTravel() time.Duration {
	s.RLock()
	defer s.RUnlock()
	return s.testTimeTravel
}

var _ shared.RPCServer = (*RegServer)(nil)

func (s *RegServer) ToRPCServer() shared.RPCServer        { return s }
func (s *RegServer) ConfigureCLIOptions(fs *flag.FlagSet) {}
func (s *RegServer) NewClientConn(xp rpc.Transporter, uhc shared.UserHostContext) shared.ClientConn {
	return &RegClientConn{
		srv:            s,
		xp:             xp,
		BaseClientConn: shared.NewBaseClientConn(s.G(), uhc),
	}
}

func (s *RegServer) Setup(m shared.MetaContext) error {
	_, err := m.G().Config().RegServerConfig(m.Ctx())
	return err
}

func (s *RegServer) ServerType() proto.ServerType {
	return proto.ServerType_Reg
}

func (s *RegServer) RequireAuth() shared.AuthType { return shared.AuthTypeNone }

func (s *RegServer) CheckDeviceKey(m shared.MetaContext, uhc shared.UserHostContext, key proto.EntityID) (*proto.Role, error) {
	return shared.CheckKeyValidGuest(m, uhc, key)
}

type RegClientConn struct {
	shared.BaseClientConn
	srv *RegServer
	xp  rpc.Transporter
}

var _ shared.ClientConn = (*RegClientConn)(nil)

func (c *RegClientConn) RegisterProtocols(m shared.MetaContext, srv *rpc.Server) error {

	prots := []rpc.ProtocolV2{
		rem.RegProtocol(c),
		rem.KexProtocol(c),
		rem.ProbeProtocol(c),
		rem.TeamGuestProtocol(c),
		rem.TeamLoaderProtocol(c),
	}
	for _, p := range prots {
		if err := srv.RegisterV2(p); err != nil {
			return err
		}
	}

	return nil
}

func (c *RegClientConn) ReserveUsername(ctx context.Context, nm proto.Name) (rem.ReserveNameRes, error) {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.ReserveName(m, nm, rem.NameType_User, c.srv.TestTimeTravel())
}

func (c *RegClientConn) Signup(ctx context.Context, arg rem.SignupArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()

	return shared.RetryTx(m, db, "signup", func(m shared.MetaContext, tx pgx.Tx) error {
		return c.signupTryTx(m, tx, arg)
	})
}

func (c *RegClientConn) signupInviteCode(
	m shared.MetaContext,
	tx pgx.Tx,
	code rem.InviteCode,
	uid proto.UID,
	sso rem.RegSSOArgs,
) error {
	ssoTyp, err := sso.GetT()
	if err != nil {
		return err
	}
	if ssoTyp != proto.SSOProtocolType_None {
		m.Infow("signup", "stage", "invite code", "short-circuit", true)
		return nil
	}
	typ, err := code.GetT()
	if err != nil {
		return err
	}
	var tags pgconn.CommandTag
	switch typ {
	case rem.InviteCodeType_MultiUse:
		tags, err = tx.Exec(m.Ctx(),
			`UPDATE multiuse_invite_codes 
			 SET num_uses=num_uses+1, last_use=NOW()
			 WHERE short_host_id=$1 AND code=$2 AND valid=TRUE`,
			m.ShortHostID().ExportToDB(),
			code.Multiuse(),
		)
		if err != nil || tags.RowsAffected() != 1 {
			return core.BadInviteCodeError{}
		}
		tags, err = tx.Exec(
			m.Ctx(),
			`INSERT INTO multiuse_invite_code_users(short_host_id, uid, code, ctime)
			 VALUES ($1, $2, $3, NOW())`,
			m.ShortHostID().ExportToDB(),
			uid.ExportToDB(),
			code.Multiuse(),
		)

	case rem.InviteCodeType_Standard:
		tags, err = tx.Exec(m.Ctx(),
			`UPDATE invite_codes 
  			SET used_by=$1, used_on=NOW() 
			WHERE short_host_id=$2 AND code=$3 AND used_by IS NULL`,
			uid.ExportToDB(),
			m.ShortHostID().ExportToDB(),
			code.Standard(),
		)
	}
	if err != nil || tags.RowsAffected() != 1 {
		return core.BadInviteCodeError{}
	}
	return nil
}

func (c *RegClientConn) signupHandleUsernameReservation(
	m shared.MetaContext,
	tx pgx.Tx,
	arg rem.SignupArg,
) (proto.Name, error) {

	expectedUsername, err := core.NormalizeName(arg.UsernameUtf8)
	if err != nil {
		return "", err
	}
	err = shared.ClaimReservation(m, tx, m.HostID(), expectedUsername, arg.Rur, rem.NameType_User)
	if err != nil {
		return "", err
	}
	return expectedUsername, nil
}

func (c *RegClientConn) signupInsertShortParty(m shared.MetaContext, tx pgx.Tx, uid proto.UID) error {
	return shared.ShortPartyIns(m, tx, uid.ToPartyID())
}

func (c *RegClientConn) signupInsertIntoUsers(m shared.MetaContext, tx pgx.Tx, uid proto.UID, un proto.Name) error {

	tag, err := tx.Exec(
		m.Ctx(),
		`INSERT INTO users(short_host_id,uid,name_ascii,ctime)
		VALUES($1, $2, $3, NOW())`,
		m.ShortHostID().ExportToDB(),
		uid.ExportToDB(),
		string(un),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("users")
	}
	return err
}

func (c *RegClientConn) signupInsertLink(
	m shared.MetaContext,
	tx pgx.Tx,
	uid proto.UID,
	link *proto.LinkOuter,
	signer proto.EntityID,
) error {

	return shared.InsertLink(
		m,
		tx,
		proto.ChainType_User,
		uid.ToPartyID(),
		core.SignerPair{Eid: signer},
		nil,
		proto.BaseChainer{Seqno: proto.ChainEldestSeqno},
		*link,
		proto.NewUpdateTriggerWithProvision(proto.UpdateTriggerProvision{Eid: signer}),
		nil,
	)
}

func (c *RegClientConn) signupInsertDevice(
	m shared.MetaContext,
	tx pgx.Tx,
	signer proto.EntityID,
	openRes *core.OpenEldestRes,
	arg rem.SignupArg,
) error {

	hepks, err := core.ImportHEPKSet(&arg.Hepks)
	if err != nil {
		return err
	}

	return shared.InsertDevice(
		m,
		tx,
		hepks,
		m.ShortHostID(),
		openRes.Uid,
		proto.OwnerRole,
		signer,
		openRes.Device,
		openRes.DeviceNameCommitment,
		arg.Dlnck,
		arg.SelfToken,
		openRes.Seqno,
		arg.YubiPQhint,
	)
}

func (c *RegClientConn) signupInsertPUKs(
	m shared.MetaContext,
	tx pgx.Tx,
	signer proto.EntityID,
	openRes *core.OpenEldestRes,
	arg rem.SignupArg,
) error {
	uot := openRes.Uid.EntityID()
	return shared.InsertProvisionSharedKeys(
		m, tx, uot, uot, openRes.Device, nil, nil,
		arg.PukBox, &openRes.UserKey,
		openRes.Device,
		arg.Hepks,
	)
}

func (c *RegClientConn) signupTreeLocation(
	m shared.MetaContext,
	tx pgx.Tx,
	uid proto.UID,
	openRes *core.OpenEldestRes,
	nextTreeLocation proto.TreeLocation,
) error {

	err := shared.InsertTreeLocationMachinery(m, tx,
		proto.ChainType_User,
		uid.EntityID(),
		openRes.Seqno,
		openRes.LocationVRFID,
		nextTreeLocation,
		openRes.NextLocationCommitment,
	)
	if err != nil {
		m.Infow("signup", "stage", "InsertTreeLocationMachinery", "err", err)
		return err
	}
	return nil
}

func (c *RegClientConn) signupInsertSubchainTreeLocationSeed(
	m shared.MetaContext,
	tx pgx.Tx,
	uid proto.UID,
	openRes *core.OpenEldestRes,
	subchainTreeLocationSeed proto.TreeLocation,
) error {
	return shared.InsertSubchainTreeLocationSeed(m, tx, uid.ToPartyID(), subchainTreeLocationSeed,
		*openRes.SubchainTreeLocationCommitment)
}

func (c *RegClientConn) signupEmail(m shared.MetaContext, tx pgx.Tx, uid proto.UID, em proto.Email) error {
	if err := core.ValidateEmail(em); err != nil {
		m.Warnw("signup", "stage", "signupEmail", "err", err)
		return core.ValidationError("invalid email")
	}
	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO emails(short_host_id, email, uid, verified)
		 VALUES($1, $2, $3, 0)`,
		m.ShortHostID().ExportToDB(),
		string(em), uid.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("failed to insert email")
	}
	return nil

}

func (c *RegClientConn) signupInsertPassphrase(
	m shared.MetaContext,
	tx pgx.Tx,
	uid proto.UID,
	pp *rem.SetPassphraseArg,
) error {
	if pp == nil {
		return nil
	}

	err := shared.UpdatePassphrase(
		m,
		tx,
		uid,
		m.ShortHostID(),
		pp.Key,
		pp.SkwkBox,
		pp.PassphraseBox,
		pp.PukBox,
		pp.StretchVersion,
		&pp.Salt,
		proto.FirstPassphraseGeneration,
		nil,
	)
	if err != nil {
		return err
	}
	return nil
}

func (c *RegClientConn) signupTryTx(m shared.MetaContext, tx pgx.Tx, arg rem.SignupArg) error {

	hostId := m.HostID().Id

	err := shared.CheckSeatLimits(m, tx)
	if err != nil {
		return err
	}

	username, err := c.signupHandleUsernameReservation(m, tx, arg)
	if err != nil {
		return err
	}
	hepks, err := core.ImportHEPKSet(&arg.Hepks)
	if err != nil {
		return err
	}
	openRes, err := core.OpenEldestLink(&arg.Link, hepks, hostId)
	if err != nil {
		return err
	}
	uid := openRes.Uid

	signer := openRes.Device.GetEntityID()

	err = shared.InsertName(
		m, tx, uid.EntityID(), signer, m.HostID(),
		username, arg.UsernameUtf8,
		&arg.UsernameCommitmentKey, openRes.UsernameCommitment,
		arg.Rur.Seq,
		rem.NameType_User,
	)
	if err != nil {
		return err
	}

	err = c.signupInsertIntoUsers(m, tx, uid, username)
	if err != nil {
		return err
	}

	// Must happen after signupInsertIntoUsers due to foreign key constraints.
	err = shared.SignupHandleSSO(m, tx, uid, signer, arg.Sso, arg.UsernameUtf8, arg.Email)
	if err != nil {
		return err
	}

	err = c.signupInsertShortParty(m, tx, uid)
	if err != nil {
		return err
	}

	err = c.signupInviteCode(m, tx, arg.InviteCode, uid, arg.Sso)
	if err != nil {
		return err
	}

	err = c.signupEmail(m, tx, uid, arg.Email)
	if err != nil {
		return err
	}

	err = c.signupInsertLink(m, tx, uid, &arg.Link, signer)
	if err != nil {
		return err
	}

	err = c.signupInsertDevice(m, tx, signer, openRes, arg)
	if err != nil {
		return err
	}

	err = shared.InsertSubkeyCheckSanity(m, tx, signer, openRes.Subkey, arg.SubkeyBox)
	if err != nil {
		return err
	}

	err = c.signupInsertPUKs(m, tx, signer, openRes, arg)
	if err != nil {
		return err
	}

	err = c.signupTreeLocation(m, tx, uid, openRes, arg.NextTreeLocation)
	if err != nil {
		return err
	}

	err = c.signupInsertPassphrase(m, tx, uid, arg.Passphrase)
	if err != nil {
		return err
	}

	err = c.signupInsertSubchainTreeLocationSeed(m, tx, uid, openRes, arg.SubchainTreeLocationSeed)
	if err != nil {
		return err
	}

	return nil
}

func (c *RegClientConn) GetHostID(ctx context.Context) (proto.HostID, error) {
	m := shared.NewMetaContextConn(ctx, c)
	return m.HostID().Id, nil
}

func (c *RegClientConn) GetClientCertChain(ctx context.Context, arg rem.GetClientCertChainArg) ([][]byte, error) {
	m := shared.NewMetaContextConn(ctx, c)
	tmp := m.HostID()
	uhc := shared.UserHostContext{
		Uid:    arg.Uid,
		HostID: &tmp,
	}
	certChain, err := shared.IssueCertChain(m, uhc, arg.Key)
	if err != nil {
		return nil, err
	}
	return certChain, nil
}

func (r *RegClientConn) GetLoginChallenge(ctx context.Context, uid proto.UID) (rem.Challenge, error) {
	return r.getChallenge(ctx, uid.EntityID(), shared.HmacKeyTypeLogin)
}

func (r *RegClientConn) GetUIDLookupChallege(ctx context.Context, eid proto.EntityID) (rem.Challenge, error) {
	return r.getChallenge(ctx, eid, shared.HmacKeyTypeLookup)
}

func (r *RegClientConn) GetSubkeyBoxChallenge(ctx context.Context, parent proto.EntityID) (rem.Challenge, error) {
	return r.getChallenge(ctx, parent, shared.HmacKeyTypeSubkeyBox)
}

func (c *RegClientConn) getChallenge(ctx context.Context, eid proto.EntityID, which shared.HmacKeyType) (rem.Challenge, error) {

	m := shared.NewMetaContextConn(ctx, c)
	var ret rem.Challenge
	id, key, err := shared.LookupLatestChallengeKey(m, which)
	if err != nil {
		return ret, err
	}
	ret.Payload.HmacKeyID = *id
	err = core.RandomFill(ret.Payload.Rand[:])
	if err != nil {
		return ret, err
	}
	ret.Payload.Time = proto.Now()
	ret.Payload.EntityID = eid
	ret.Payload.HostID = m.HostID().Id

	mac, err := core.Hmac(&ret.Payload, key)
	if err != nil {
		return ret, err
	}
	ret.Mac = *mac
	return ret, nil
}

func validateUIDChallenge(m shared.MetaContext, db *pgxpool.Conn, challenge rem.Challenge, uid proto.UID) error {
	return validateChallenge(m, db, challenge, uid.EntityID(), shared.HmacKeyTypeLogin)
}

func validateLookupChallenge(m shared.MetaContext, db *pgxpool.Conn, challenge rem.Challenge, eid proto.EntityID) error {
	return validateChallenge(m, db, challenge, eid, shared.HmacKeyTypeLookup)
}

func validateSubkeyBoxChallenge(m shared.MetaContext, db *pgxpool.Conn, challenge rem.Challenge, parent proto.EntityID) error {
	return validateChallenge(m, db, challenge, parent, shared.HmacKeyTypeSubkeyBox)
}

func validateChallenge(
	m shared.MetaContext,
	db *pgxpool.Conn,
	challenge rem.Challenge,
	eid proto.EntityID,
	which shared.HmacKeyType,
) error {
	key, err := shared.LookupHMACKeyByID(m, db, challenge.Payload.HmacKeyID, which)
	if err != nil {
		return err
	}
	computed, err := core.Hmac(&challenge.Payload, key)
	if err != nil {
		return err
	}
	if !computed.Eq(challenge.Mac) {
		return core.ValidationError("hmac failed")
	}
	if challenge.Payload.Time.IsStale(m.Now()) {
		return core.TimeoutError{}
	}
	if !eid.Eq(challenge.Payload.EntityID) {
		return core.WrongUserError{}
	}
	return nil
}

func recordBadLogin(m shared.MetaContext, db *pgxpool.Conn, uid proto.UID) {
	tag, err := db.Exec(m.Ctx(),
		`INSERT INTO bad_login_attempts(short_host_id, uid, ctime) VALUES($1, $2, NOW())`,
		m.ShortHostID().ExportToDB(),
		uid.ExportToDB(),
	)
	if err != nil {
		m.Errorw("recordBadLogin", "err", err)
		return
	}
	if tag.RowsAffected() != 1 {
		m.Errorw("recordBadogin", "err", "could not write to DB")
		return
	}
}

func checkBadLoginRateLimit(m shared.MetaContext, db *pgxpool.Conn, uid proto.UID, rl shared.RateLimit) error {
	var n int
	window := time.Duration(rl.WindowSecs) * time.Second
	if window < time.Second {
		window = time.Minute
	}
	limit := rl.Num
	if limit < 1 {
		limit = 6
	}
	err := db.QueryRow(m.Ctx(),
		`SELECT COUNT(*) FROM bad_login_attempts WHERE short_host_id=$1 AND uid=$2 AND ctime + $3 > NOW()`,
		m.ShortHostID().ExportToDB(),
		uid.ExportToDB(), window,
	).Scan(&n)
	if err != nil {
		return err
	}
	if n > int(limit) {
		return core.RateLimitError{}
	}
	return nil
}

func markChallengeUsed(m shared.MetaContext, db shared.DbExecer, rand proto.Random16) error {
	return shared.MarkChallengeUsed(m, db, rand.ExportToDB())
}

func (c *RegClientConn) LoadSubkeyBox(ctx context.Context, arg rem.LoadSubkeyBoxArg) (proto.Box, error) {
	var empty proto.Box
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return empty, err
	}
	defer db.Release()

	err = validateSubkeyBoxChallenge(m, db, arg.Challenge, arg.Parent)
	if err != nil {
		m.Warnw("LoadSubkeyBox", "err", err, "stage", "validateSubkeyBoxChallenge")
		return empty, err
	}
	ep, err := core.ImportEntityPublic(arg.Parent)
	if err != nil {
		return empty, err
	}
	err = ep.Verify(arg.Signature, &arg.Challenge.Payload)
	if err != nil {
		m.Warnw("LoadSubkeyBox",
			"stage", "verify sig",
			"err", err,
		)
		return empty, core.VerifyError("LoadSubkeyBox signature")
	}

	// We need to burn the random challenge before we check the device_keys tables.
	// To do so in the opposite order would allow replay attacks in the case of
	// keys not found.
	err = markChallengeUsed(m, db, arg.Challenge.Payload.Rand)
	if err != nil {
		m.Warnw("LoadSubkeyBox",
			"stage", "replay detection",
			"err", err)
		return empty, err
	}

	var boxRaw []byte

	err = db.QueryRow(m.Ctx(),
		`SELECT S.box 
		 FROM subkeys AS S
		 INNER JOIN device_keys AS D
		 ON (S.short_host_id=D.short_host_id AND S.parent=D.verify_key)
		 WHERE D.short_host_id=$1 AND D.verify_key=$2
		 AND S.key_state='valid' AND D.key_state='valid'
		 ORDER BY S.ctime DESC
		 LIMIT 1`,
		m.ShortHostID().ExportToDB(),
		arg.Parent.ExportToDB(),
	).Scan(&boxRaw)

	if err == pgx.ErrNoRows {
		return empty, core.KeyNotFoundError{}
	}
	if err != nil {
		return empty, err
	}

	var ret proto.Box
	err = core.DecodeFromBytes(&ret, boxRaw)
	if err != nil {
		return empty, err
	}
	return ret, nil
}

func (c *RegClientConn) LookupUIDByDevice(ctx context.Context, arg rem.LookupUIDByDeviceArg) (proto.LookupUserRes, error) {
	var ret proto.LookupUserRes
	err := c.lookupByDevice(
		ctx,
		arg,
		func(_ shared.MetaContext,
			_ *pgxpool.Conn,
			res proto.LookupUserRes,
		) error {
			ret = res
			return nil
		})
	return ret, err
}

func (c *RegClientConn) lookupByDevice(
	ctx context.Context,
	arg rem.LookupUIDByDeviceArg,
	f func(m shared.MetaContext, db *pgxpool.Conn, res proto.LookupUserRes) error,
) error {
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()

	err = validateLookupChallenge(m, db, arg.Challenge, arg.EntityID)
	if err != nil {
		m.Infow("lookupUIDByDevice", "err", err, "stage", "validateLookupChallenge")
		return err
	}

	ep, err := core.ImportEntityPublic(arg.EntityID)
	if err != nil {
		return err
	}
	err = ep.Verify(arg.Signature, &arg.Challenge.Payload)
	if err != nil {
		m.Warnw("lookupUIDByDevice",
			"stage", "verify sig",
			"err", err,
		)
		return core.VerifyError("lookupUID signature")
	}

	// We need to burn the random challenge before we check the device_keys tables.
	// To do so in the opposite order would allow replay attacks in the case of
	// keys not found.
	err = markChallengeUsed(m, db, arg.Challenge.Payload.Rand)
	if err != nil {
		m.Warnw("lookupUIDByDevice",
			"stage", "replay detection",
			"err", err)
		return err
	}

	m.Infow("lookupUIDByDevice", "stage", "pre-select")

	var uidRaw []byte
	var rtRaw, vlRaw int
	err = db.QueryRow(ctx,
		`SELECT uid, role_type, viz_level
		 FROM device_keys 
		 WHERE short_host_id=$1 
		   AND verify_key=$2 
		   AND key_state='valid'`,
		m.ShortHostID().ExportToDB(),
		arg.EntityID.ExportToDB(),
	).Scan(&uidRaw, &rtRaw, &vlRaw)

	if err == pgx.ErrNoRows {
		m.Infow("lookupUIDByDevice", "err", err, "stage", "select.A")
		return core.KeyNotFoundError{}
	}
	if err != nil {
		m.Infow("lookupUIDByDevice", "err", err, "stage", "select.B")
		return fmt.Errorf("%T %v", err, err)
	}

	rk, err := core.ImportRoleKeyFromDB(rtRaw, vlRaw)
	if err != nil {
		return err
	}
	role := rk.Export()

	tmp, err := proto.ImportUIDFromBytes(uidRaw)
	if err != nil {
		return err
	}
	fqu := proto.FQUser{
		Uid:    *tmp,
		HostID: m.HostID().Id,
	}
	var unr, un8 string
	err = db.QueryRow(ctx,
		`SELECT name_ascii, name_utf8
		 FROM users
		 JOIN names USING(short_host_id, name_ascii)
		 WHERE short_host_id=$1
		 AND uid=$2`,
		m.ShortHostID().ExportToDB(),
		tmp.ExportToDB(),
	).Scan(&unr, &un8)
	if err != nil {
		m.Infow("lookupUIDByDevice", "err", err, "stage", "select username")
		return err
	}

	var slot int
	var pqkeyid []byte
	var hint *proto.YubiSlotAndPQKeyID

	err = db.QueryRow(ctx,
		`SELECT slot, pqkeyid FROM yubi_pq_hints
		 WHERE short_host_id=$1 AND uid=$2 AND parent=$3`,
		m.ShortHostID().ExportToDB(),
		uidRaw,
		arg.EntityID.ExportToDB(),
	).Scan(&slot, &pqkeyid)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	} else if err == nil {
		hint = &proto.YubiSlotAndPQKeyID{
			Slot: proto.YubiSlot(slot),
		}
		err = hint.Id.ImportFromDB(pqkeyid)
		if err != nil {
			return err
		}
	}

	ret := proto.LookupUserRes{
		Username:     proto.Name(unr),
		UsernameUtf8: proto.NameUtf8(un8),
		Fqu:          fqu,
		Role:         role,
		YubiPQHint:   hint,
	}
	err = f(m, db, ret)
	if err != nil {
		return err
	}
	return nil
}

func (c *RegClientConn) Login(ctx context.Context, arg rem.LoginArg) (rem.LoginRes, error) {
	var empty rem.LoginRes
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return empty, err
	}
	defer db.Release()
	cfg, err := m.G().Config().UserServerConfig(ctx)
	if err != nil {
		return empty, err
	}
	rl := cfg.BadLoginRateLimit()

	err = checkBadLoginRateLimit(m, db, arg.Uid, rl)
	if err != nil {
		return empty, err
	}

	err = validateUIDChallenge(m, db, arg.Challenge, arg.Uid)
	if err != nil {
		return empty, err
	}

	var rawKey, skwkBox, passphraseBox []byte
	var ppgen int
	err = db.QueryRow(ctx,
		`SELECT ppgen, verify_key, skwk_box, passphrase_box
		FROM passphrase_boxes 
		WHERE short_host_id=$1 AND uid=$2
		ORDER BY ppgen DESC LIMIT 1`,
		m.ShortHostID().ExportToDB(),
		arg.Uid.ExportToDB(),
	).Scan(&ppgen, &rawKey, &skwkBox, &passphraseBox)
	if err != nil {
		return empty, err
	}
	eid, err := proto.ImportEntityIDFromBytes(rawKey)
	if err != nil {
		return empty, err
	}
	if len(eid) == 0 {
		return empty, core.BadServerDataError("empty entity ID for passphrase verify key")
	}
	if eid.Type() != proto.EntityType_PassphraseKey {
		return empty, core.BadServerDataError("wrong entity type for passphrase verify key")
	}
	ep, err := core.ImportEntityPublic(eid)
	if err != nil {
		return empty, err
	}
	err = ep.Verify(arg.Signature, &arg.Challenge.Payload)
	if err != nil {
		m.Warnw("login",
			"stage", "verify sig",
			"err", err,
		)
		recordBadLogin(m, db, arg.Uid)
		return empty, core.BadPassphraseError{}
	}

	err = markChallengeUsed(m, db, arg.Challenge.Payload.Rand)
	if err != nil {
		m.Warnw("login",
			"stage", "replay detection",
			"err", err)
		return empty, err
	}

	var ret rem.LoginRes
	ret.PpGen = proto.PassphraseGeneration(ppgen)
	err = core.DecodeFromBytes(&ret.SkwkBox, skwkBox)
	if err != nil {
		return empty, err
	}
	err = core.DecodeFromBytes(&ret.PassphraseBox.Box, passphraseBox)
	if err != nil {
		return empty, err
	}

	return ret, nil
}

func (c *RegClientConn) Send(ctx context.Context, arg rem.SendArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	msg := arg.Msg

	key, err := core.ImportEntityPublic(msg.Sender)
	if err != nil {
		return err
	}

	// Require that the device key can sign the message; otherwise the device
	// can fake inserts. This wouldn't be a huge deal, since these messages are
	// scoped to the Kex Sesssion ID. Still, it doesn't feel right to allow
	// an attacker to forge the device ID, maybe it would come back to bite us
	// if not checked.
	err = key.Verify(arg.Sig, &msg)
	if err != nil {
		return err
	}

	sbox, err := core.EncodeToBytes(&msg.Payload)
	if err != nil {
		return err
	}

	tag, err := db.Exec(ctx,
		`INSERT INTO kex_msgs (short_host_id, session_id, seqno, sender_device_id, msg, ctime)
		VALUES($1, $2, $3, $4, $5, NOW())`,
		m.ShortHostID().ExportToDB(),
		msg.SessionID.ExportToDB(),
		msg.Seq,
		msg.Sender.ExportToDB(),
		sbox,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("kex message")
	}

	q := m.G().QueueServer(ctx)
	err = shared.KexPoke(ctx, q, msg.SessionID, msg.Sender, msg.Seq, arg.Actor)
	if err != nil {
		return err
	}

	return nil
}

var errRetry = errors.New("please retry")

func (c *RegClientConn) Receive(ctx context.Context, arg rem.ReceiveArg) (rem.KexWrapperMsg, error) {
	var ret rem.KexWrapperMsg
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return ret, err
	}
	defer db.Release()

	start := time.Now()
	dur := arg.PollWait.Duration()
	end := start.Add(dur)
	err = errRetry

	// A special case is duration=0, which implies that the receiver doesn't
	// want to wait at all, and just to fail if there isn't a message waiting.
	// This is what we want on the first message receipt, since if there isn't
	// a Kex message waiting for us, we have a bogus channel, and there was likely
	// a mistake in user input.
	for err == errRetry && (time.Now().Before(end) || dur == 0) {
		err = c.pollOnce(m, db, arg, &ret)
	}
	return ret, err
}

func (c *RegClientConn) pollOnce(m shared.MetaContext, db *pgxpool.Conn, arg rem.ReceiveArg, ret *rem.KexWrapperMsg) error {

	var deviceIdRaw, msgRaw []byte
	err := db.QueryRow(m.Ctx(),
		`SELECT sender_device_id, msg 
		 FROM kex_msgs 
		 WHERE short_host_id=$1
		 AND session_id=$2
		 AND seqno=$3
		 AND sender_device_id != $4`,
		m.ShortHostID().ExportToDB(),
		arg.SessionID.ExportToDB(),
		arg.Seq,
		arg.Receiver.ExportToDB(),
	).Scan(
		&deviceIdRaw,
		&msgRaw,
	)

	if err == nil {
		ret.Seq = arg.Seq
		ret.SessionID = arg.SessionID
		sender, err := proto.ImportEntityIDFromBytes(deviceIdRaw)
		if err != nil {
			return err
		}

		// Can handle either a yubikey or a device key
		if sender.Type() != proto.EntityType_Device && sender.Type() != proto.EntityType_Yubi {
			return core.InternalError("wrong entity type for sender device")
		}

		ret.Sender = sender
		err = core.DecodeFromBytes(&ret.Payload, msgRaw)
		if err != nil {
			return err
		}
		return nil
	}

	// See above, on the first receive we should quit fast, since a message should
	// always be waiting for us on valid channel.
	if err == pgx.ErrNoRows && arg.PollWait == 0 {
		return core.KexBadSecretError{}
	}

	if err != pgx.ErrNoRows {
		return err
	}
	q := m.G().QueueServer(m.Ctx())
	_, _, err = shared.KexWait(m.Ctx(), q, arg.SessionID, arg.Seq, 5*time.Second, arg.Actor.Other())

	// Keep polling in the case we timed out waiting for the message to arrive
	if errors.Is(err, core.TimeoutError{}) {
		err = nil
	}

	if err != nil {
		return err
	}

	return errRetry
}

func (c *RegClientConn) CheckInviteCode(ctx context.Context, ic rem.InviteCode) error {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.CheckInviteCode(m, ic)
}

func (c *RegClientConn) Probe(ctx context.Context, arg rem.ProbeArg) (rem.ProbeRes, error) {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.LoadProbe(m, arg)
}

func (c *RegClientConn) JoinWaitList(ctx context.Context, em proto.Email) (proto.WaitListID, error) {
	m := shared.NewMetaContextConn(ctx, c)
	var ret proto.WaitListID
	db, err := m.G().Db(ctx, shared.DbTypeUsers)
	if err != nil {
		return ret, err
	}
	defer db.Release()
	wl, err := proto.GenerateWaitListID()
	if err != nil {
		return ret, err
	}
	ret = *wl
	tag, err := db.Exec(m.Ctx(),
		`INSERT INTO waitlist(short_host_id, wlid, email, ctime, status)
		VALUES($1, $2, $3, NOW(), 'waiting')`,
		m.ShortHostID().ExportToDB(),
		ret.ExportToDB(), string(em),
	)
	if err != nil {
		return ret, err
	}
	if tag.RowsAffected() != 1 {
		return ret, core.InsertError("waitlist")
	}
	return ret, nil
}

func (c *RegClientConn) CheckNameExists(ctx context.Context, arg proto.Name) error {
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.G().Db(ctx, shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()

	err = db.QueryRow(m.Ctx(),
		`SELECT 1 FROM names
		 WHERE short_host_id=$1
		 AND name_ascii=$2
		 AND state='in_use'`,
		m.ShortHostID().ExportToDB(),
		string(arg),
	).Scan()
	if err == pgx.ErrNoRows {
		return core.UserNotFoundError{}
	}
	return nil
}

func (c *RegClientConn) LoadUserChain(ctx context.Context, arg rem.LoadUserChainArg) (rem.UserChain, error) {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.LoadUserChain(m, nil, nil, arg)
}

func (c *RegClientConn) ErrorWrapper() func(error) proto.Status {
	return core.ErrorToStatus
}

func (c *RegClientConn) StretchVersion(ctx context.Context) (proto.StretchVersion, error) {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.StretchVersion(m)
}

func (c *RegClientConn) SelectVHost(ctx context.Context, hid proto.HostID) error {
	return shared.SelectVHost(ctx, c, hid)
}

func (c *RegClientConn) MakeResHeader() proto.Header {
	// For test, we can override the standard response header
	if tmrh := c.G().TestMakeResHeader; tmrh != nil {
		return tmrh()
	}
	return c.BaseClientConn.MakeResHeader()
}

func (c *RegClientConn) CheckArgHeader(ctx context.Context, arg proto.Header) error {
	// For test, override the standard check
	if tcah := c.G().TestCheckArgHeader; tcah != nil {
		return tcah(ctx, arg)
	}
	return c.BaseClientConn.CheckArgHeader(ctx, arg)
}

func (c *RegClientConn) ResolveUsername(
	ctx context.Context,
	arg rem.ResolveUsernameArg,
) (
	proto.UID,
	error,
) {
	var zed proto.UID
	return zed, core.PermissionError("resolve doesn't worked logged out")
}

func (c *RegClientConn) GetServerConfig(ctx context.Context) (proto.RegServerConfig, error) {
	m := shared.NewMetaContextConn(ctx, c)
	ret, err := shared.GetServerConfig(m)
	var zed proto.RegServerConfig
	if err != nil {
		return zed, err
	}
	return *ret, nil
}

func (c *RegClientConn) InitOAuth2Session(ctx context.Context, arg rem.InitOAuth2SessionArg) (proto.URLString, error) {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.InitOAuth2Session(m, arg)
}

func (c *RegClientConn) PollOAuth2SessionCompletion(
	ctx context.Context,
	arg rem.PollOAuth2SessionCompletionArg,
) (rem.OAuth2PollRes, error) {
	m := shared.NewMetaContextConn(ctx, c)
	tmp, err := shared.PollOAuth2SessionCompletion(m, arg.Id, arg.Wait.Import())
	var ret rem.OAuth2PollRes
	if err != nil {
		return ret, err
	}
	ret.Toks = *tmp

	// For login (and if no username returned), then skip the username reservation, and we're done.
	if tmp.Username.IsZero() || arg.ForLogin {
		return ret, nil
	}
	// Also try to reserve the username that corresponds to the name that we're logged in as.
	unn, err := core.NormalizeName(tmp.Username)
	if err != nil {
		return ret, err
	}
	rt, err := shared.ReserveName(m, unn, rem.NameType_User, c.srv.TestTimeTravel())
	if err != nil {
		return ret, err
	}
	ret.Res = rt
	return ret, nil
}

func (c *RegClientConn) SsoLogin(ctx context.Context, arg rem.SsoLoginArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.LoginSSO(m, arg.Uid, arg.Args)
}

func (c *RegClientConn) ProbeKeyExists(
	ctx context.Context,
	arg rem.ProbeKeyExistsArg,
) error {
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	var n int
	err = db.QueryRow(m.Ctx(),
		`SELECT 1 FROM self_view_tokens
		 WHERE short_host_id=$1 AND uid=$2 AND view_token=$3 AND verify_key=$4`,
		m.ShortHostID().ExportToDB(),
		arg.Uid.ExportToDB(),
		arg.SelfTok.ExportToDB(),
		arg.DevID.ExportToDB(),
	).Scan(&n)

	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return core.KeyNotFoundError{Which: "probed key"}
	}
	return err
}

func (c *RegClientConn) GetVHostMgmtHost(ctx context.Context) (proto.TCPAddr, error) {
	m := shared.NewMetaContextConn(ctx, c)
	cfg, err := m.G().Config().RegServerConfig(ctx)
	if err != nil {
		return "", err
	}
	return cfg.VHostMgmtAddr(), nil
}

func (c *RegClientConn) GetClientVersionInfo(
	ctx context.Context,
	arg proto.ClientVersionExt,
) (
	proto.ServerClientVersionInfo,
	error,
) {
	m := shared.NewMetaContextConn(ctx, c)
	var ret proto.ServerClientVersionInfo
	tmp, err := shared.ClientVersionInfo(m, arg)
	if err != nil {
		return ret, err
	}
	if tmp != nil {
		ret = *tmp
	}
	return ret, nil
}

var _ rem.RegInterface = (*RegClientConn)(nil)
var _ rem.KexInterface = (*RegClientConn)(nil)
var _ rem.ProbeInterface = (*RegClientConn)(nil)
