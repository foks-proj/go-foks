// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package engine

import (
	"context"
	"errors"
	"flag"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/jackc/pgx/v5"
)

type UserServer struct {
	shared.BaseRPCServer

	testTimeTravel             time.Duration
	TestStopPostMembershipLink core.TestStopper
	TestStopPostGenericLink    core.TestStopper
}

func (u *UserServer) SetTestTimeTravel(d time.Duration) {
	u.Lock()
	defer u.Unlock()
	u.testTimeTravel = d
}

func (u *UserServer) TestTimeTravel() time.Duration {
	u.RLock()
	defer u.RUnlock()
	return u.testTimeTravel
}

var _ shared.RPCServer = (*UserServer)(nil)

func (s *UserServer) ToRPCServer() shared.RPCServer        { return s }
func (s *UserServer) ConfigureCLIOptions(fs *flag.FlagSet) {}
func (s *UserServer) NewClientConn(xp rpc.Transporter, uhc shared.UserHostContext) shared.ClientConn {
	return &UserClientConn{
		srv:            s,
		xp:             xp,
		BaseClientConn: shared.NewBaseClientConn(s.G(), uhc),
	}
}

func (s *UserServer) Setup(m shared.MetaContext) error {
	_, err := m.G().Config().UserServerConfig(m.Ctx())
	return err
}

func (s *UserServer) ServerType() proto.ServerType {
	return proto.ServerType_User
}

func (s *UserServer) RequireAuth() shared.AuthType { return shared.AuthTypeExternal }

func (s *UserServer) CheckDeviceKey(m shared.MetaContext, uhc shared.UserHostContext, key proto.EntityID) (*proto.Role, error) {
	return shared.CheckKeyValid(m, uhc, key)
}

type UserClientConn struct {
	shared.BaseClientConn
	srv *UserServer
	xp  rpc.Transporter
}

var _ shared.ClientConn = (*UserClientConn)(nil)

func (c *UserClientConn) RegisterProtocols(m shared.MetaContext, srv *rpc.Server) error {
	prots := []rpc.ProtocolV2{
		rem.UserProtocol(c),
		infra.TestServicesProtocol(c),
		rem.TeamAdminProtocol(c),
		rem.TeamLoaderProtocol(c),
		rem.TeamMemberProtocol(c),
	}
	for _, p := range prots {
		err := srv.RegisterV2(p)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *UserClientConn) ErrorWrapper() func(error) proto.Status {
	return core.ErrorToStatus
}

func (c *UserClientConn) Ping(ctx context.Context) (proto.UID, error) {
	m := shared.NewMetaContextConn(ctx, c)
	return m.UID(), nil
}

func (c *UserClientConn) ChangePassphrase(ctx context.Context, arg rem.ChangePassphraseArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	return c.updatePassphrase(
		m,
		arg.Key,
		arg.SkwkBox,
		arg.PassphraseBox,
		arg.PukBox,
		arg.StretchVersion,
		nil,
		arg.PpGen,
		arg.UserSettingsLink,
	)
}

func (c *UserClientConn) SetPassphrase(ctx context.Context, arg rem.SetPassphraseArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	return c.updatePassphrase(
		m,
		arg.Key,
		arg.SkwkBox,
		arg.PassphraseBox,
		arg.PukBox,
		arg.StretchVersion,
		&arg.Salt,
		proto.FirstPassphraseGeneration,
		arg.UserSettingsLink,
	)
}

func (c *UserClientConn) updatePassphrase(
	m shared.MetaContext,
	key proto.EntityID,
	skwkBox proto.SecretBox,
	passphraseBox proto.PpePassphraseBox,
	pukBox *proto.PpePUKBox,
	stretchVersion proto.StretchVersion,
	salt *proto.PassphraseSalt,
	ppgen proto.PassphraseGeneration,
	userSettingsLink *rem.PostGenericLinkArg,
) error {

	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()

	return shared.RetryTx(m, db, "updatePassphrase", func(_ shared.MetaContext, tx pgx.Tx) error {
		return shared.UpdatePassphrase(
			m,
			tx,
			m.UID(),
			m.HostID().Short,
			key,
			skwkBox,
			passphraseBox,
			pukBox,
			stretchVersion,
			salt,
			ppgen,
			userSettingsLink,
		)
	})
}

func (c *UserClientConn) GetSalt(ctx context.Context) (proto.PassphraseSalt, error) {
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	var ret proto.PassphraseSalt
	if err != nil {
		return ret, err
	}
	defer db.Release()
	var salt []byte
	err = db.QueryRow(
		ctx,
		`SELECT salt FROM users_salts WHERE short_host_id=$1 AND uid=$2`,
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
	).Scan(&salt)
	if err != nil {
		return ret, err
	}
	copy(ret[:], salt[:])
	return ret, nil
}

func (c *UserClientConn) NextPassphraseGeneration(ctx context.Context) (proto.PassphraseGeneration, error) {
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	var ret proto.PassphraseGeneration
	if err != nil {
		return ret, err
	}
	defer db.Release()
	var count int
	err = db.QueryRow(ctx,
		`SELECT MAX(ppgen)+1 FROM passphrase_boxes WHERE short_host_id=$1 AND uid=$2`,
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
	).Scan(&count)

	// No rows is OK, that means next generation is going to be 0
	if err != nil && err == pgx.ErrNoRows {
		err = nil
		count = 0
	}
	if err != nil {
		return ret, err
	}
	return ret, nil
}

func (c *UserClientConn) StretchVersion(ctx context.Context) (proto.StretchVersion, error) {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.StretchVersion(m)
}

func readChainTailForUser(m shared.MetaContext, tx pgx.Tx, uid proto.UID) (*proto.HidingChainer, error) {
	base, err := shared.ReadChainTail(m, tx, proto.ChainType_User, uid.EntityID())
	if err != nil {
		return nil, err
	}
	return &proto.HidingChainer{Base: *base}, nil
}

func readPUKGenerationsForUser(
	m shared.MetaContext,
	tx pgx.Tx,
	uid proto.UID,
) (
	map[core.RoleKey]proto.Generation,
	error,
) {
	rows, err := tx.Query(m.Ctx(),
		`SELECT role_type, viz_level, gen FROM shared_key_generations WHERE short_host_id=$1 AND entity_id=$2`,
		m.ShortHostID().ExportToDB(),
		uid.ExportToDB(),
	)
	if err != nil {
		return nil, err
	}
	var roleType, vizLevel, gen int
	ret := make(map[core.RoleKey]proto.Generation)
	_, err = pgx.ForEachRow(rows, []any{&roleType, &vizLevel, &gen}, func() error {
		rk, err := core.ImportRoleKeyFromDB(roleType, vizLevel)
		if err != nil {
			return err
		}
		ret[*rk] = proto.Generation(gen)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (c *UserClientConn) insertDevice(
	m shared.MetaContext,
	tx pgx.Tx,
	hepks *core.HEPKSet,
	newDevice core.PublicSuiter,
	deviceNameCommitment *proto.Commitment,
	dlnck rem.DeviceLabelNameAndCommitmentKey,
	tok proto.PermissionToken,
	seqno proto.Seqno,
	hint *proto.YubiSlotAndPQKeyID,
) error {
	return shared.InsertDevice(
		m,
		tx,
		hepks,
		m.HostID().Short,
		m.UID(),
		newDevice.GetRole(),
		newDevice.GetEntityID(),
		newDevice,
		deviceNameCommitment,
		dlnck,
		tok,
		seqno,
		hint,
	)
}

func (c *UserClientConn) insertLink(
	m shared.MetaContext,
	tx pgx.Tx,
	prev *proto.HidingChainer,
	curr proto.HidingChainer,
	link proto.LinkOuter,
	signer core.SignerPair,
	trigger proto.UpdateTrigger,
	revokeID *core.SignerPair,
) error {

	var bprev *proto.BaseChainer
	bcurr := curr.Base
	if prev != nil {
		bprev = &prev.Base
	}
	var revokeIDs []core.SignerPair
	if revokeID != nil {
		revokeIDs = append(revokeIDs, *revokeID)
	}
	return shared.InsertLink(m, tx, proto.ChainType_User,
		m.UID().ToPartyID(), signer, bprev,
		bcurr, link, trigger, revokeIDs,
	)
}

type prepareDeviceRes struct {
	odc            *core.OpenDeviceChangeRes
	prev           *proto.HidingChainer
	currentDevices map[proto.FQEntityFixed]core.PublicSuiterWithSeqno
	pukGens        map[core.RoleKey]proto.Generation
	signer         core.PublicSuiterWithSeqno
}

func (c *UserClientConn) prepareDeviceChange(
	m shared.MetaContext,
	tx pgx.Tx,
	hepks *core.HEPKSet,
	link *proto.LinkOuter,
	which string,
) (
	*prepareDeviceRes,
	error,
) {
	odc, err := core.OpenDeviceChange(link, hepks, m.UIDp(), m.HostID().Id)
	if err != nil {
		m.Warnw(which, "stage", "OpenDeviceChange", "err", err)
		return nil, err
	}

	// If two threads are trying this at the same time, one will do the insert
	// and the other will block until the first either commits or aborts.
	// If commit, the second will fail the primary key constraint. If abovrt,
	// the second can go forward.
	err = shared.LockEntity(m, tx, m.UID().EntityID(), proto.ChainType_User, odc.Gc.Chainer.Base.Seqno)
	if err != nil {
		m.Warnw(which, "stage", "LockEntity", "err", err)
		return nil, err
	}

	prev, err := readChainTailForUser(m, tx, m.UID())
	if err != nil {
		m.Warnw(which, "stage", "readChainTail", "err", err)
		return nil, err
	}
	currentDevices, err := readDevicesForUser(m, tx, m.UID(), m.HostID())
	if err != nil {
		m.Warnw(which, "stage", "readDevices", "err", err)
		return nil, err
	}
	pukGens, err := readPUKGenerationsForUser(m, tx, m.UID())
	if err != nil {
		m.Warnw(which, "stage", "readPUKGenerations", "err", err)
		return nil, err
	}

	signerFixed, err := odc.Gc.Signer.Key.Fixed()
	if err != nil {
		return nil, err
	}
	idx := proto.FQEntityFixed{
		Entity: signerFixed,
		Host:   m.HostID().Id,
	}

	signer, found := currentDevices[idx]
	if !found {
		return nil, core.ValidationError("signing key wasn't a current device")
	}

	return &prepareDeviceRes{
		odc:            odc,
		prev:           prev,
		currentDevices: currentDevices,
		pukGens:        pukGens,
		signer:         signer,
	}, nil

}

func (c *UserClientConn) removeDevice(m shared.MetaContext, tx pgx.Tx, id proto.EntityID, epno proto.MerkleEpno) error {
	return shared.RemoveDevice(m, tx, id, epno)
}

func currentDevicesExtraRoles(
	m map[proto.FQEntityFixed]core.PublicSuiterWithSeqno,
) (
	map[proto.FQEntityFixed]core.RoleKey,
	error,
) {
	ret := make(map[proto.FQEntityFixed]core.RoleKey)
	for k, v := range m {
		rk, err := core.ImportRole(v.Ps.GetRole())
		if err != nil {
			return nil, err
		}
		ret[k] = *rk
	}
	return ret, nil
}

func (c *UserClientConn) checkDeviceInTree(m shared.MetaContext, tx pgx.Tx, id proto.EntityID) error {
	var i int
	if id == nil {
		return nil
	}
	err := tx.QueryRow(m.Ctx(),
		`SELECT COALESCE(provision_epno, -1) FROM device_keys
  	     WHERE short_host_id=$1 AND verify_key=$2 AND uid=$3`,
		m.ShortHostID().ExportToDB(),
		id.ExportToDB(),
		m.UID().ExportToDB(),
	).Scan(&i)
	if err != nil {
		return err
	}
	if i < 0 {
		return core.SigningKeyNotFullyProvisionedError{}
	}
	return nil
}

func (c *UserClientConn) revokeDeviceTryTx(m shared.MetaContext, tx pgx.Tx, arg rem.RevokeDeviceArg) error {

	hepks, err := core.ImportHEPKSet(&arg.Hepks)
	if err != nil {
		return err
	}

	pdcr, err := c.prepareDeviceChange(m, tx, hepks, &arg.Link, "revoke")
	if err != nil {
		return err
	}
	hid := m.HostID().Id
	currentDevices := pdcr.currentDevices

	target, err := core.CheckDeviceRevokeOrRotate(pdcr.odc, hid, pdcr.currentDevices, pdcr.pukGens)
	if err != nil {
		return err
	}

	// Noop if rotate without revoke
	if target.ID != nil {
		err = c.checkDeviceInTree(m, tx, target.ID)
		if err != nil {
			return err
		}
	}
	signer := pdcr.odc.Gc.Signer.Key

	// we already check this in prepareDeviceChange
	if pdcr.odc.Gc.Chainer.Base.Root.Epno == 0 {
		return core.ValidationError("need non-nil Chainer for revocation with valid Merkle Tree root")
	}
	var sp *core.SignerPair
	if target.Pswsqno != nil {
		tmp := target.Pswsqno.ToSignerPair()
		sp = &tmp
	}

	trig := proto.NewUpdateTriggerDefault(proto.UpdateTriggerType_None)
	if target.ID != nil {
		trig = proto.NewUpdateTriggerWithRevoke(proto.UpdateTriggerRevoke{
			Epno:        target.Epno,
			PartyID:     m.UID().ToPartyID(),
			VerifyKeyID: target.ID,
		})
	}

	err = c.insertLink(
		m,
		tx,
		pdcr.prev,
		pdcr.odc.Gc.Chainer,
		arg.Link,
		pdcr.signer.ToSignerPair(),
		trig,
		sp,
	)
	if err != nil {
		m.Warnw("revoke", "stage", "insertLink", "err", err)
		return err
	}

	// Noop if we're doing a rotation (without a revoke)
	if target.ID != nil {
		err = c.removeDevice(m, tx, target.ID, pdcr.odc.Gc.Chainer.Base.Root.Epno)
		if err != nil {
			m.Warnw("revoke", "stage", "removeDevice", "err", err)
			return err
		}
		fid, err := target.ID.Fixed()
		if err != nil {
			return err
		}
		delete(currentDevices, proto.FQEntityFixed{Entity: fid, Host: hid})
	}

	currDevRoles, err := currentDevicesExtraRoles(currentDevices)
	if err != nil {
		return err
	}

	err = shared.InsertRotateSharedKeys(m, tx, target.Role, signer, pdcr.pukGens,
		currDevRoles, arg.PukBoxes, pdcr.odc.SharedKeys, arg.SeedChain,
		arg.Hepks,
	)

	if err != nil {
		m.Warnw("revoke", "stage", "insertSharedKeys", "err", err)
		return err
	}

	gc := pdcr.odc.Gc
	err = shared.InsertTreeLocationMachinery(m, tx, proto.ChainType_User,
		m.UID().EntityID(), gc.Chainer.Base.Seqno, gc.LocationVRFID,
		arg.NextTreeLocation, gc.Chainer.NextLocationCommitment)
	if err != nil {
		m.Warnw("revoke", "stage", "insertTreeLocationMachiner", "err", err)
		return err
	}

	if arg.Ppa != nil {
		err = shared.UpdatePassphrase(
			m,
			tx,
			m.UID(),
			m.HostID().Short,
			arg.Ppa.Arg.Key,
			arg.Ppa.Arg.SkwkBox,
			arg.Ppa.Arg.PassphraseBox,
			arg.Ppa.Arg.PukBox,
			arg.Ppa.Arg.StretchVersion,
			nil,
			arg.Ppa.Arg.PpGen,
			&arg.Ppa.Link,
		)
		if err != nil {
			m.Warnw("revoke", "stage", "UpdatePassphrase", "err", err)
			return err
		}
	}

	return nil
}

func (c *UserClientConn) insertSubkey(
	m shared.MetaContext,
	tx pgx.Tx,
	newDev proto.EntityID,
	subkey core.EntityPublic,
	box *proto.Box,
) error {
	return shared.InsertSubkeyCheckSanity(m, tx, newDev, subkey, box)
}

func (c *UserClientConn) provisionDeviceTryTx(m shared.MetaContext, tx pgx.Tx, arg rem.ProvisionDeviceArg) error {

	hepks, err := core.ImportHEPKSet(&arg.Hepks)
	if err != nil {
		return err
	}

	pdcr, err := c.prepareDeviceChange(m, tx, hepks, &arg.Link, "provision")
	if err != nil {
		return err
	}

	odp, err := core.OpenDeviceProvision(pdcr.odc, pdcr.currentDevices, pdcr.pukGens, m.HostID().Id)
	if err != nil {
		m.Warnw("provision", "stage", "OpenDeviceProvision", "err", err)
		return err
	}

	err = c.insertLink(
		m,
		tx,
		pdcr.prev,
		odp.Gc.Chainer,
		arg.Link,
		pdcr.signer.ToSignerPair(),
		proto.NewUpdateTriggerWithProvision(
			proto.UpdateTriggerProvision{
				Eid: odp.NewDevice.GetEntityID(),
			},
		), nil,
	)
	if err != nil {
		m.Warnw("provision", "stage", "insertLink", "err", err)
		return err
	}

	err = c.insertDevice(m,
		tx,
		hepks,
		odp.NewDevice,
		odp.DeviceNameCommitment,
		arg.Dlnc,
		arg.SelfToken,
		pdcr.odc.Gc.Chainer.Base.Seqno,
		arg.YubiPQhint,
	)
	if err != nil {
		m.Warnw("provision", "stage", "insertDevice", "err", err)
		return err
	}

	err = c.provisionInsertSharedKeys(
		m, tx, odp.NewDevice, pdcr.pukGens, pdcr.currentDevices,
		arg.PukBoxes, odp.SharedKey, odp.ExistingDevice, arg.Hepks,
	)
	if err != nil {
		m.Warnw("provision", "stage", "insertSharedKey", "err", err)
		return err
	}

	err = c.insertSubkey(m, tx, odp.NewDevice.GetEntityID(), odp.Subkey, arg.SubkeyBox)
	if err != nil {
		m.Warnw("provision", "stage", "insertSubkey", "err", err)
		return err
	}

	err = shared.InsertTreeLocationMachinery(m, tx, proto.ChainType_User,
		m.UID().EntityID(), odp.Gc.Chainer.Base.Seqno, odp.Gc.LocationVRFID,
		arg.NextTreeLocation, odp.Gc.Chainer.NextLocationCommitment)
	if err != nil {
		m.Warnw("provision", "stage", "insertTreeLocationMachiner", "err", err)
		return err
	}

	return nil
}

func (c *UserClientConn) provisionInsertSharedKeys(
	m shared.MetaContext,
	tx pgx.Tx,
	newDevice core.PublicSuiter,
	pukGens map[core.RoleKey]proto.Generation,
	currentDevices map[proto.FQEntityFixed]core.PublicSuiterWithSeqno,
	sbs proto.SharedKeyBoxSet,
	sharedKey *core.SharedPublicSuite,
	signer core.EntityPublic,
	hepks proto.HEPKSet,
) error {

	currDevRoles, err := currentDevicesExtraRoles(currentDevices)
	if err != nil {
		return err
	}
	e := m.UID().EntityID()
	return shared.InsertProvisionSharedKeys(
		m, tx, e, e, newDevice, pukGens, currDevRoles,
		sbs, sharedKey, signer,
		hepks,
	)
}

func readDevicesForUser(
	m shared.MetaContext,
	tx pgx.Tx,
	uid proto.UID,
	hostId core.HostID,
) (
	map[proto.FQEntityFixed]core.PublicSuiterWithSeqno,
	error,
) {
	return shared.ReadDevicesForUser(m, tx, uid, hostId)
}

func (c *UserClientConn) ProvisionDevice(ctx context.Context, arg rem.ProvisionDeviceArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()

	return shared.RetryTx(m, db, "provision", func(m shared.MetaContext, tx pgx.Tx) error {
		return c.provisionDeviceTryTx(m, tx, arg)
	})
}

func (c *UserClientConn) RevokeDevice(ctx context.Context, arg rem.RevokeDeviceArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()

	return shared.RetryTx(m, db, "revoke", func(m shared.MetaContext, tx pgx.Tx) error {
		return c.revokeDeviceTryTx(m, tx, arg)
	})
}

func (c *UserClientConn) Probe(ctx context.Context, arg rem.ProbeArg) (rem.ProbeRes, error) {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.LoadProbe(m, arg)
}

func (c *UserClientConn) TestQueueService(ctx context.Context, arg infra.TestQueueServiceArg) ([]byte, error) {
	m := shared.NewMetaContextConn(ctx, c)
	q := m.G().QueueServer(ctx)
	qarg := infra.EnqueueArg(arg)
	err := q.Enqueue(ctx, qarg)
	if err != nil {
		return nil, err
	}
	msg, err := q.Dequeue(ctx, infra.DequeueArg{QueueId: arg.QueueId, LaneId: arg.LaneId, Wait: proto.DurationMilli(1000 * 10)})
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func (c *UserClientConn) LoadUserChain(ctx context.Context, arg rem.LoadUserChainArg) (rem.UserChain, error) {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.LoadUserChain(m, m.UIDp(), arg)
}

func (c *UserClientConn) ResolveUsername(ctx context.Context, arg rem.ResolveUsernameArg) (proto.UID, error) {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.ResolveUsername(m, m.UIDp(), arg)
}

func (c *UserClientConn) GrantLocalViewPermissionForUser(
	ctx context.Context,
	arg rem.GrantLocalViewPermissionPayload,
) (
	proto.PermissionToken,
	error,
) {
	return shared.GrantLocalViewPermission(ctx, c, arg, nil, proto.PartyType_User)
}

func (c *UserClientConn) GrantRemoteViewPermissionForUser(
	ctx context.Context,
	arg rem.GrantRemoteViewPermissionPayload,
) (
	proto.PermissionToken,
	error,
) {
	return shared.GrantRemoteViewPermission(ctx, c, arg, nil, proto.PartyType_User)
}

type usernameTriple struct {
	ascii proto.Name
	utf8  proto.NameUtf8
	id    int
}

func (c *UserClientConn) selectExistingUsername(m shared.MetaContext, tx pgx.Tx) (*usernameTriple, error) {
	var un, un8 string
	var reuseID int64
	err := tx.QueryRow(m.Ctx(),
		`SELECT name_ascii, name_utf8, reuse_id
		 FROM users 
		 JOIN names USING(short_host_id, name_ascii)
		 WHERE short_host_id=$1 AND uid=$2`,
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
	).Scan(&un, &un8, &reuseID)
	if err == pgx.ErrNoRows {
		return nil, core.UserNotFoundError{}
	}
	if err != nil {
		return nil, err
	}
	return &usernameTriple{proto.Name(un), proto.NameUtf8(un8), int(reuseID)}, nil
}

func (c *UserClientConn) updateUsernameInPlace(
	m shared.MetaContext,
	tx pgx.Tx,
	arg rem.ChangeUsernameArg,
	existing *usernameTriple,
) error {
	if arg.Full != nil {
		return core.BadArgsError("don't need commitment key or link if username normalized stays the same")
	}

	tag, err := tx.Exec(m.Ctx(),
		`UPDATE names
		     SET name_utf8=$1
		     WHERE short_host_id=$2
		     AND name_ascii=$3
			 AND name_utf8=$4
		     AND reuse_id=$5`,
		string(arg.UsernameUtf8),
		m.ShortHostID().ExportToDB(),
		string(existing.ascii),
		string(existing.utf8),
		existing.id,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("no updates made on new UTF8 username")
	}
	m.Infow(
		"changeUsername",
		"outcome", "utf8update",
		"existing", string(existing.utf8),
		"new", arg.UsernameUtf8,
		"uid", m.UID(),
	)
	return nil
}

func (c *UserClientConn) finishRename(
	m shared.MetaContext,
	tx pgx.Tx,
	newUsername proto.Name,
	trip *usernameTriple,
) error {

	tag, err := tx.Exec(
		m.Ctx(),
		"UPDATE users SET name_ascii=$1 WHERE short_host_id=$2 AND uid=$3",
		string(newUsername),
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("no updates made on user")
	}
	tag, err = tx.Exec(
		m.Ctx(),
		`UPDATE names 
		SET state='dead',mtime=NOW()
		WHERE short_host_id=$1 AND name_ascii=$2 AND reuse_id=$3`,
		m.ShortHostID().ExportToDB(),
		string(trip.ascii),
		trip.id,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("no updates made on old username")
	}
	return nil
}

func (c *UserClientConn) changeUsernameTryTx(m shared.MetaContext, tx pgx.Tx, arg rem.ChangeUsernameArg) error {

	trip, err := c.selectExistingUsername(m, tx)
	if err != nil {
		return err
	}

	if trip.utf8 == arg.UsernameUtf8 {
		return core.NoChangeError("username given matches current username")
	}

	nnun, err := core.NormalizeName(arg.UsernameUtf8)
	if err != nil {
		return err
	}

	if trip.ascii == nnun {
		return c.updateUsernameInPlace(m, tx, arg, trip)
	}

	if arg.Full == nil {
		return core.BadArgsError("need commitment key and link if username normalized changes")
	}

	err = shared.ClaimReservation(m, tx, m.HostID(), nnun, arg.Full.Rur, rem.NameType_User)
	if err != nil {
		return err
	}

	pdr, err := c.prepareDeviceChange(m, tx, nil, &arg.Full.Link, "changeUsername")
	if err != nil {
		return err
	}

	newUsernameCommit, err := core.CheckChangeUsername(pdr.odc, m.HostID().Id, pdr.currentDevices)
	if err != nil {
		return err
	}

	signer := pdr.odc.Gc.Signer.Key

	err = shared.InsertName(
		m, tx, m.UID().EntityID(), signer, m.HostID(), nnun, arg.UsernameUtf8,
		&arg.Full.UsernameCommitmentKey,
		newUsernameCommit,
		arg.Full.Rur.Seq,
		rem.NameType_User,
	)
	if err != nil {
		return err
	}

	err = c.insertLink(
		m,
		tx,
		pdr.prev,
		pdr.odc.Gc.Chainer,
		arg.Full.Link,
		pdr.signer.ToSignerPair(),
		proto.NewUpdateTriggerDefault(proto.UpdateTriggerType_None),
		nil,
	)
	if err != nil {
		m.Warnw("changeUsername", "stage", "insertLink", "err", err)
		return err
	}
	gc := pdr.odc.Gc
	err = shared.InsertTreeLocationMachinery(m, tx,
		proto.ChainType_User,
		m.UID().EntityID(),
		gc.Chainer.Base.Seqno,
		gc.LocationVRFID,
		arg.Full.NextTreeLocation,
		gc.Chainer.NextLocationCommitment)
	if err != nil {
		m.Warnw("changeUsername", "stage", "insertTreeLocationMachiner", "err", err)
		return err
	}

	err = c.finishRename(m, tx, nnun, trip)
	if err != nil {
		return err
	}
	return nil
}

func (c *UserClientConn) ChangeUsername(ctx context.Context, arg rem.ChangeUsernameArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	return shared.RetryTx(m, db, "changeUsername", func(m shared.MetaContext, tx pgx.Tx) error {
		return c.changeUsernameTryTx(m, tx, arg)
	})
}

func (c *UserClientConn) ReserveUsernameForChange(ctx context.Context, u proto.Name) (rem.ReserveNameRes, error) {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.ReserveName(m, u, rem.NameType_User, time.Duration(0))
}

func (c *UserClientConn) GetTreeLocation(ctx context.Context, seqno proto.Seqno) (proto.TreeLocation, error) {
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	var ret proto.TreeLocation
	if err != nil {
		return ret, err
	}
	defer db.Release()

	var raw []byte

	err = db.QueryRow(
		ctx,
		`SELECT loc
		 FROM tree_locations
		 WHERE short_host_id=$1 AND entity_id=$2 AND seqno=$3`,
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
		int(seqno),
	).Scan(&raw)

	if err == pgx.ErrNoRows {
		return ret, core.NotFoundError("no tree location found")
	}
	if err != nil {
		return ret, err
	}
	err = ret.ImportFromBytes(raw)
	if err != nil {
		return ret, err
	}
	return ret, nil
}

func (c *UserClientConn) GetPUKForRole(ctx context.Context, arg rem.GetPUKForRoleArg) (proto.SharedKeyParcel, error) {
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	var ret proto.SharedKeyParcel
	if err != nil {
		return ret, err
	}
	defer db.Release()
	rt, vl, err := arg.Role.ExportToDB()
	if err != nil {
		return ret, err
	}
	var gen int
	var box, dh, thid, sid, boxSetId []byte
	err = db.QueryRow(
		ctx,
		`SELECT gen, box, ephemeral_dh_key, target_host_id, signer_id, box_set_id
		 FROM shared_key_boxes
		 JOIN shared_key_box_metadata USING(short_host_id, box_set_id)
		 WHERE short_host_id=$1 AND entity_id=$2 AND role_type=$3 and viz_level=$4 AND target_entity_id=$5 AND target_host_id=$6
		 ORDER BY gen DESC LIMIT 1`,
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
		rt,
		vl,
		arg.TargetPublicKeyId.ExportToDB(),
		shared.ExportLocalHost(),
	).Scan(&gen, &box, &dh, &thid, &sid, &boxSetId)
	if err == pgx.ErrNoRows {
		return ret, core.KeyNotFoundError{}
	}
	if err != nil {
		return ret, err
	}
	ret.Box.Gen = proto.Generation(gen)
	ret.Box.Role = arg.Role
	var tmp proto.Box
	err = core.DecodeFromBytes(&tmp, box)
	if err != nil {
		return ret, err
	}
	ret.Box.Box = tmp
	ret.Box.Targ.Eid = arg.TargetPublicKeyId
	if dh != nil {
		var tmp proto.TempDHKeySigned
		err = core.DecodeFromBytes(&tmp, dh)
		if err != nil {
			return ret, err
		}
		ret.TempDHKeySigned = &tmp
	}
	ret.Sender, err = proto.ImportEntityIDFromBytes(sid)
	if err != nil {
		return ret, err
	}
	err = ret.BoxId.ImportFromBytes(boxSetId)
	if err != nil {
		return ret, err
	}
	hostIdp, err := shared.ImportHostInScope(thid)
	if err != nil {
		return ret, err
	}
	ret.Box.Targ.Host = hostIdp

	rows, err := db.Query(
		ctx,
		`SELECT gen, secret_box FROM shared_key_seed_chain
		 WHERE short_host_id=$1 AND entity_id=$2 AND role_type=$3 AND viz_level=$4
		 ORDER BY gen ASC`,
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
		rt,
		vl,
	)
	if err != nil {
		return ret, err
	}
	defer rows.Close()
	for rows.Next() {
		var gen int
		var box []byte
		err = rows.Scan(&gen, &box)
		if err != nil {
			return ret, err
		}
		tmp := proto.SeedChainBox{
			Gen:  proto.Generation(gen),
			Role: arg.Role,
		}
		err = core.DecodeFromBytes(&tmp.Box, box)
		if err != nil {
			return ret, err
		}
		ret.SeedChain = append(ret.SeedChain, tmp)
	}

	return ret, nil
}

func (c *UserClientConn) GetPpeParcel(
	ctx context.Context,
) (
	proto.PpeParcel,
	error,
) {
	var empty proto.PpeParcel
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return empty, err
	}
	defer db.Release()
	var rawKey, skwkBox, passphraseBox, pukBox, salt []byte
	var ppgen, pukGen, sv int
	err = db.QueryRow(ctx,
		`SELECT ppgen, verify_key, skwk_box, passphrase_box, puk_box, puk_gen, salt, stretch_version
		 FROM passphrase_boxes 
		 JOIN user_salts USING(short_host_id, uid)
		 WHERE short_host_id=$1 AND uid=$2
		 ORDER BY ppgen DESC LIMIT 1`,
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
	).Scan(&ppgen, &rawKey, &skwkBox, &passphraseBox, &pukBox, &pukGen, &salt, &sv)

	if errors.Is(err, pgx.ErrNoRows) {
		return empty, core.PassphraseNotFoundError{}
	}
	if err != nil {
		return empty, err
	}

	vk, err := proto.ImportEntityIDFromBytes(rawKey)
	if err != nil {
		return empty, err
	}
	if vk.Type() != proto.EntityType_PassphraseKey {
		return empty, core.BadServerDataError("bad entity type on verify key; wanted passphrase key type")
	}

	ret := proto.PpeParcel{
		PpGen:     proto.PassphraseGeneration(ppgen),
		Sv:        proto.StretchVersion(sv),
		VerifyKey: vk,
	}
	if len(salt) != len(ret.Salt) {
		return empty, core.BadServerDataError("bad salt length")
	}
	copy(ret.Salt[:], salt)
	err = core.DecodeFromBytes(&ret.SkwkBox, skwkBox)
	if err != nil {
		return empty, nil
	}
	err = core.DecodeFromBytes(&ret.PassphraseBox.Box, passphraseBox)
	if err != nil {
		return empty, nil
	}
	if len(pukBox) > 0 {
		var tmp proto.PpePUKBox
		err = core.DecodeFromBytes(&tmp.Box, pukBox)
		if err != nil {
			return empty, nil
		}
		tmp.PukGen = proto.Generation(pukGen)
		tmp.PukRole = proto.OwnerRole
		ret.PukBox = &tmp
	}
	return ret, nil
}

func (c *UserClientConn) LoadGenericChain(
	ctx context.Context,
	arg rem.LoadGenericChainArg,
) (
	rem.GenericChain,
	error,
) {
	m := shared.NewMetaContextConn(ctx, c)
	var ret rem.GenericChain

	// Eventually we will support team chains too, but right now,
	// can only load your own personal generic chains.
	uid, err := arg.Eid.ToUID()
	if err != nil {
		return ret, err
	}
	if !uid.Eq(m.UID()) {
		return ret, core.PermissionError("can only load own generic chain")
	}
	tmp, err := shared.LoadGenericChain(m, arg.Typ, m.UID().EntityID(), arg.Start)
	if err != nil {
		return ret, err
	}
	return *tmp, nil
}

func (c *UserClientConn) PostGenericLink(
	ctx context.Context,
	arg rem.PostGenericLinkArg,
) error {
	m := shared.NewMetaContextConn(ctx, c)

	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()

	return shared.RetryTx(m, db, "postGenericLink", func(_ shared.MetaContext, tx pgx.Tx) error {
		return shared.PostGenericLinkTryTx(m, tx, arg, m.UID().ToPartyID(),
			&c.srv.TestStopPostGenericLink)
	})
}

func (c *UserClientConn) AssertPQKeyNotInUse(
	ctx context.Context,
	arg proto.YubiPQKeyID,
) error {
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	err = db.QueryRow(
		ctx,
		`SELECT COUNT(*) FROM yubi_pq_keys
		 WHERE short_host_id=$1 AND uid=$2 AND pq_key_id=$3`,
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
		arg.ExportToDB(),
	).Scan()
	if err != nil {
		return err
	}
	return core.NotImplementedError{}
}

func (c *UserClientConn) GetTeamListServerTrust(
	ctx context.Context,
) (
	rem.LocalTeamList,
	error,
) {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.GetTeamListForUser(m)
}

func (c *UserClientConn) NewWebAdminPanelURL(
	ctx context.Context,
) (
	proto.URLString,
	error,
) {
	var zed proto.URLString
	m := shared.NewMetaContextConn(ctx, c)
	ret, err := shared.NewWebAdminPanelURL(m)
	if err != nil {
		return zed, err
	}
	return *ret, nil
}

func (c *UserClientConn) CheckURL(
	ctx context.Context,
	arg proto.URLString,
) error {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.CheckURL(m, arg)
}

func (c *UserClientConn) GetHostConfig(
	ctx context.Context,
) (
	proto.HostConfig,
	error,
) {
	var zed proto.HostConfig
	m := shared.NewMetaContextConn(ctx, c)
	cfg, err := m.HostConfig()
	if err != nil {
		return zed, err
	}
	return *cfg, nil
}

func (c *UserClientConn) GetDeviceNag(
	ctx context.Context,
) (
	proto.DeviceNagInfo,
	error,
) {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.GetDeviceNagData(m)
}

func (c *UserClientConn) ClearDeviceNag(
	ctx context.Context,
	val bool,
) error {
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	_, err = db.Exec(
		ctx,
		`UPDATE data_loss_nag
		SET cleared=$1
		WHERE short_host_id=$2 AND uid=$3`,
		val,
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
	)
	return err
}

func (c *UserClientConn) PutYubiManagementKey(
	ctx context.Context,
	yemk rem.YubiEncryptedManagementKey,
) error {
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()

	rawBox, err := core.EncodeToBytes(&yemk.Box)
	if err != nil {
		return err
	}
	rt, rl, err := yemk.Role.ExportToDB()
	if err != nil {
		return err
	}

	tag, err := db.Exec(
		ctx,
		`INSERT INTO yubi_mgmt_keys
		 (short_host_id, uid, key_id, ctime, mtime, box, puk_gen, puk_role_type, puk_viz_level)
		 VALUES ($1, $2, $3, NOW(), NOW(), $4, $5, $6, $7)
		 ON CONFLICT (short_host_id, uid, key_id) 
		 DO UPDATE SET 
			 box=EXCLUDED.box,
			 puk_gen=EXCLUDED.puk_gen, 
			 mtime=NOW(),
			 puk_role_type=EXCLUDED.puk_role_type, 
			 puk_viz_level=EXCLUDED.puk_viz_level
		 WHERE yubi_mgmt_keys.puk_gen <= EXCLUDED.puk_gen`,
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
		yemk.Yk.EntityID().ExportToDB(),
		rawBox,
		int(yemk.Gen),
		rt,
		rl,
	)
	if err != nil {
		return err
	}
	switch tag.RowsAffected() {
	case 1:
		return nil
	case 0:
		return core.BadArgsError("can only replace with a newer generation")
	default:
		return core.InsertError("yubi_mgmt_keys")
	}
}

func (c *UserClientConn) GetYubiManagementKey(
	ctx context.Context,
	yid proto.YubiID,
) (
	rem.YubiEncryptedManagementKey,
	error,
) {
	var zed rem.YubiEncryptedManagementKey
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return zed, err
	}
	defer db.Release()

	var rawBox []byte
	var gen, rt, rl int
	err = db.QueryRow(
		ctx,
		`SELECT box, puk_gen, puk_role_type, puk_viz_level
		 FROM yubi_mgmt_keys
		 WHERE short_host_id=$1 AND uid=$2 AND key_id=$3`,
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
		yid.EntityID().ExportToDB(),
	).Scan(&rawBox, &gen, &rt, &rl)
	if err == pgx.ErrNoRows {
		return zed, core.KeyNotFoundError{Which: "yubi_mgmt_key"}
	}
	if err != nil {
		return zed, err
	}
	ret := rem.YubiEncryptedManagementKey{
		Yk:  yid,
		Gen: proto.Generation(gen),
	}
	err = core.DecodeFromBytes(&ret.Box, rawBox)
	if err != nil {
		return zed, err
	}
	tmp, err := proto.ImportRoleFromDB(rt, rl)
	if err != nil {
		return zed, err
	}
	ret.Role = *tmp
	return ret, nil
}

func (c *UserClientConn) GetAllYubiManagementKeys(
	ctx context.Context,
) (
	[]rem.YubiEncryptedManagementKey,
	error,
) {
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()

	rows, err := db.Query(
		ctx,
		`SELECT key_id, box, puk_gen, puk_role_type, puk_viz_level
		FROM yubi_mgmt_keys
		WHERE short_host_id=$1 AND uid=$2`,
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ret []rem.YubiEncryptedManagementKey
	for rows.Next() {
		var rawId, rawBox []byte
		var gen, rt, vl int

		err := rows.Scan(&rawId, &rawBox, &gen, &rt, &vl)
		if err != nil {
			return nil, err
		}
		row := rem.YubiEncryptedManagementKey{
			Gen: proto.Generation(gen),
		}
		err = core.DecodeFromBytes(&row.Box, rawBox)
		if err != nil {
			return nil, err
		}
		eid, err := proto.ImportEntityIDFromBytes(rawId)
		if err != nil {
			return nil, err
		}
		row.Yk, err = eid.ToYubiID()
		if err != nil {
			return nil, err
		}
		tmp, err := proto.ImportRoleFromDB(rt, vl)
		if err != nil {
			return nil, err
		}
		row.Role = *tmp
		ret = append(ret, row)
	}
	return ret, nil
}

var _ rem.UserInterface = (*UserClientConn)(nil)
var _ infra.TestServicesInterface = (*UserClientConn)(nil)
var _ rem.ProbeInterface = (*UserClientConn)(nil)
