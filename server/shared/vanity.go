// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"errors"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5"
)

// Vanity domains are of the form `foks.nike.com` or `foks.chase.com`  -- they're CNAMEs
// owned by the customer that point to a hosted Foks instance. To rig up the plumbing,
// we'll need to handle DNS resolutions and also getting probe certificates from LetsEncrypt.
// To test it, we mock out several key interfaces: DNS resolution, DNS setting, and autocert.
type DNSResolver interface {
	CheckCNAMEResolvesTo(MetaContext, proto.Hostname, proto.Hostname) error
}

type DNSSetter interface {
	SetCNAME(MetaContext, proto.Hostname, proto.Hostname) error
	ClearCNAME(MetaContext, proto.Hostname) error
}

type Autocerter interface {
	Autocert(MetaContext, AutocertPackage) error
}

// VanityHelper is a struct that combines the three interfaces above, to assist in setting
// up vanity domains.
type VanityHelper interface {
	DNSResolver
	DNSSetter
	Autocerter
}

type RealVanityHelper struct {
	setter DNSSetter
}

func NewRealVanityHelper(setter DNSSetter) *RealVanityHelper {
	return &RealVanityHelper{setter: setter}
}

type NoopDNSSetter struct{}

func (n *NoopDNSSetter) SetCNAME(m MetaContext, from proto.Hostname, to proto.Hostname) error {
	return nil
}
func (n *NoopDNSSetter) ClearCNAME(m MetaContext, from proto.Hostname) error {
	return nil
}

func ConfigNewRealVanityHelper(m MetaContext) (*RealVanityHelper, error) {
	cfg, err := m.G().Config().VHostsConfig(m.Ctx())
	if err != nil {
		return nil, err
	}
	var setter DNSSetter
	switch cfg.DNSSetStrategy() {
	case DNSSetStrategyAWS:
		hd, err := cfg.HostingDomain()
		if err != nil {
			return nil, err
		}

		domains := append([]DNSZoner{hd}, cfg.CannedDomains()...)
		aws := NewAWSRoute53DNSSetter(domains, cfg.AWSCredentials())
		err = aws.Init(m)

		if err != nil {
			return nil, err
		}
		setter = aws
	default:
		return nil, core.ConfigError("unknown DNS set strategy (can only support AWS currently)")
	}
	return NewRealVanityHelper(setter), nil
}

func (h *RealVanityHelper) CheckCNAMEResolvesTo(m MetaContext, from proto.Hostname, to proto.Hostname) error {
	cfg, err := m.G().Config().VHostsConfig(m.Ctx())
	if err != nil {
		return err
	}
	srvs := cfg.DNSResolvers()
	if len(srvs) == 0 {
		return core.ConfigError("no DNS resolvers configured")
	}
	timeout := cfg.DNSResolveTimeout()
	return CheckCNAME(m, from, to, srvs, timeout, nil)
}

func (h *RealVanityHelper) Autocert(
	m MetaContext,
	pkg AutocertPackage,
) error {
	return DoAutocertViaClient(m, 20*time.Second, pkg)
}

func (h *RealVanityHelper) SetCNAME(m MetaContext, from proto.Hostname, to proto.Hostname) error {
	return h.setter.SetCNAME(m, from, to)
}

func (h *RealVanityHelper) ClearCNAME(m MetaContext, from proto.Hostname) error {
	return h.setter.ClearCNAME(m, from)
}

var _ VanityHelper = (*RealVanityHelper)(nil)

type VanityMinder struct {
	// Args passed in from caller (Stage1); loaded from DB (Stage2)
	Vstem proto.Hostname // E.g., foks.nike.com
	// Args passed in from caller (Stage2)
	HostedStem proto.Hostname // E.g., d-a1j492jzege.ne43.net
	// In test, we might need to pass the Beacon service through
	Beacon *GlobalService
	// If we want a multiuse invite code for the domain, set it here
	InviteCode rem.MultiUseInviteCode
	// How to meter the new domain
	Metering proto.Metering
	// Either generated or passed in in round2
	VHostID *proto.VHostID
	// On if this is a canned host
	IsCanned bool

	// used by friend classes, like CannedMinder
	dbInsStage1TxHook func(MetaContext, pgx.Tx) error
	autosetDNSHook    func(m MetaContext) error

	// Internal State
	cfg    VHostsConfigger
	hlp    VanityHelper
	hostId *core.HostID
	hc     *HostChain
	ufsMap map[proto.ServerType]proto.Hostname
	stage  proto.HostBuildStage // Last completed checkpoint
}

func (v *VanityMinder) HostID() *core.HostID {
	return v.hostId
}

func (v *VanityMinder) HostIDAndName() (*core.HostIDAndName, error) {
	if v.hostId == nil {
		return nil, core.InternalError("no host ID")
	}
	return &core.HostIDAndName{
		HostID:   *v.hostId,
		Hostname: v.Vstem,
	}, nil
}

func (v *VanityMinder) GetHostedStem() proto.Hostname {
	return v.HostedStem
}

func (v *VanityMinder) init(m MetaContext) error {
	m.Infow("VanityMinder", "op", "init")
	cfg, err := m.G().Config().VHostsConfig(m.Ctx())
	if err != nil {
		return err
	}
	v.Vstem = v.Vstem.Normalize()
	v.cfg = cfg
	hlp := m.G().VanityHelper()
	if hlp == nil {
		return core.InternalError("no vanity helper")
	}
	if m.UID().IsZero() {
		return core.InternalError("no UID for admin")
	}
	v.hlp = hlp
	return nil
}

func (v *VanityMinder) makeVHostID(m MetaContext) error {
	m.Infow("VanityMinder", "op", "makeVHostID")
	id, err := proto.RandomID16er[proto.VHostID]()
	if err != nil {
		return err
	}
	v.VHostID = id
	return nil
}

func (v *VanityMinder) makeHostedStem(m MetaContext) error {
	m.Infow("VanityMinder", "op", "makeHostedStem")
	var buf [12]byte
	err := core.RandomFill(buf[:])
	if err != nil {
		return err
	}
	s := core.Base36Encoding.EncodeToString(buf[:])
	base, err := v.cfg.HostingDomain()
	if err != nil {
		return err
	}

	ret := "d-" + s + "." + base.Domain().String()
	v.HostedStem = proto.Hostname(ret)
	return nil
}

func (v *VanityMinder) dbInsStage1(m MetaContext) error {
	m.Infow("VanityMinder", "op", "dbInsStage1")
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	return RetryTx(m, db, "VanityMinder.dbInsStage1", func(m MetaContext, tx pgx.Tx) error {
		err := v.dbInsStage1Tx(m, tx)
		if err != nil {
			return err
		}
		if v.dbInsStage1TxHook == nil {
			return nil
		}
		err = v.dbInsStage1TxHook(m, tx)
		if err != nil {
			return err
		}
		return nil
	})
}

func (v *VanityMinder) dbInsStage1Tx(m MetaContext, tx pgx.Tx) error {
	tag, err := tx.Exec(
		m.Ctx(),
		`INSERT INTO vanity_host_build (
			vhost_id, short_host_id, uid, stem, vanity_host, vanity_host_cancel_id, 
			stage, ctime, is_canned)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8)`,
		v.VHostID.ExportToDB(),
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
		v.HostedStem.String(),
		v.Vstem.String(),
		proto.NilCancelID(),
		proto.HostBuildStage_Stage1.String(),
		v.IsCanned,
	)
	if IsDuplicateKeyError(err, "vanity_host_build_vanity_host_idx") {
		return core.HostInUseError{Host: v.Vstem}
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("vanity_host_build")
	}
	return nil
}

// Stage1 we make a new stem domain, insert into the DB, and
// return the challenge to the user.
func (v *VanityMinder) Stage1(m MetaContext) error {
	m.Infow("VanityMinder", "stage", "1")

	err := v.init(m)
	if err != nil {
		return err
	}
	err = v.checkLimits(m)
	if err != nil {
		return err
	}
	err = v.makeHostedStem(m)
	if err != nil {
		return err
	}
	err = v.makeVHostID(m)
	if err != nil {
		return err
	}
	err = v.dbInsStage1(m)
	if err != nil {
		return err
	}
	return nil
}

func (v *VanityMinder) dbLoadStage2(m MetaContext) error {
	m.Infow("VanityMinder", "op", "dbLoadStage2")

	if v.VHostID == nil {
		return core.InternalError("no VHostID")
	}

	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	var vanityHostname, stem, stageRaw string
	var isCanned bool
	err = db.QueryRow(
		m.Ctx(),
		`SELECT vanity_host, stage, stem, is_canned
		FROM vanity_host_build
		WHERE vhost_id=$1 AND short_host_id=$2 AND uid=$3`,
		v.VHostID.ExportToDB(),
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
	).Scan(&vanityHostname, &stageRaw, &stem, &isCanned)

	if errors.Is(err, pgx.ErrNoRows) {
		return core.NotFoundError("vanity_host_build")
	}
	if err != nil {
		return err
	}
	var stage proto.HostBuildStage
	err = stage.ImportFromString(stageRaw)
	if err != nil {
		return err
	}
	if !stage.IsBuilding() {
		return core.BadArgsError("stage1 or stage2 expected")
	}
	v.stage = stage
	v.Vstem = proto.Hostname(vanityHostname)
	v.HostedStem = proto.Hostname(stem)
	v.IsCanned = isCanned
	return nil
}

func (v *VanityMinder) checkStemDNS(m MetaContext) error {
	m.Infow("VanityMinder", "op", "checkStemDNS")
	return v.hlp.CheckCNAMEResolvesTo(m, v.Vstem, v.HostedStem)
}

func (v *VanityMinder) insertDNSHosts(m MetaContext) error {
	m.Infow("VanityMinder", "op", "insertDNSHosts")

	put := func(from, to proto.Hostname) error {
		doput := (v.stage == proto.HostBuildStage_Stage1)
		if !doput {
			return nil
		}
		err := v.hlp.SetCNAME(m, from, to)
		m.Infow("VanityMinder.insertDNSHosts", "from", from, "to", to)
		if err != nil {
			return err
		}
		return nil
	}

	v.ufsMap = make(map[proto.ServerType]proto.Hostname)
	hosts := proto.FrontFacingServers

	// Set the probe server
	_, ext, _, err := m.G().Config().ListenParams(m.Ctx(), proto.ServerType_Probe, 0)
	if err != nil {
		return err
	}

	probeBase := ext.Hostname()
	err = put(v.HostedStem, probeBase)
	if err != nil {
		return err
	}
	vanity := v.Vstem.Normalize()
	v.ufsMap[proto.ServerType_Probe] = vanity

	for _, h := range hosts {
		if h == proto.ServerType_Probe {
			continue
		}
		_, ext, _, err := m.G().Config().ListenParams(m.Ctx(), h, 0)
		if err != nil {
			return err
		}
		host := ext.Hostname()

		// The simplest case is that the reg (or whatever) server
		// and the probe server are the same, so just keep remapping
		// our vanity domain to the same base domain.
		if host.NormEq(probeBase) {
			v.ufsMap[h] = vanity
			continue
		}

		// Slightly more complicated case, we're going to need to set up
		// a CNAME record for the reg server.
		from, err := h.Hostname(v.HostedStem)
		if err != nil {
			return err
		}
		err = put(from, host)
		if err != nil {
			return err
		}
		v.ufsMap[h] = from
	}
	return nil
}

func (v *VanityMinder) loadHostchain(m MetaContext) error {
	m.Infow("VanityMinder", "op", "loadHostchain")
	chid, err := m.G().HostIDMap().LookupByVHostID(m, *v.VHostID)
	if err != nil {
		return err
	}
	m = m.WithHostID(chid)
	hc, err := LoadHostChain(m, []proto.EntityType{
		proto.EntityType_Host,
	})
	if err != nil {
		return err
	}
	v.hc = hc
	v.hostId = chid
	return nil
}

func (v *VanityMinder) vHostLoadOrMake(m MetaContext) error {
	m.Infow("VanityMinder", "op", "vHostLoadOrMake")
	err := v.loadHostchain(m)
	if err == nil {
		return nil
	}
	if !errors.Is(err, core.HostIDNotFoundError{}) {
		return err
	}
	return v.vHostInit(m)
}

func (v *VanityMinder) vHostInit(m MetaContext) error {
	m.Infow("VanityMinder", "op", "vHostInit")

	i := &vHostInit{
		vhostId:    v.VHostID,
		hn:         v.Vstem,
		skipBeacon: true, // we need to skip the beacon registration until after let's encrypt
		merklePoke: func() error { return PokeMerklePipeline(m) },
		ufsMap:     v.ufsMap,
		config: proto.HostConfig{
			Metering: v.Metering,
			Typ:      proto.HostType_VHost,
		},
	}
	err := i.run(m)
	if err != nil {
		return err
	}
	id := i.hc.HostIDp()
	v.hostId = id
	v.hc = i.hc
	return nil
}

func (v *VanityMinder) bumpStage(
	m MetaContext,
	tx pgx.Tx,
	from, to proto.HostBuildStage,
) error {
	m.Infow("VanityMinder", "op", "bumpStage", "from", from, "to", to)
	tag, err := tx.Exec(
		m.Ctx(),
		`UPDATE vanity_host_build
		SET stage=$1
		WHERE vhost_id=$2 AND stage=$3`,
		to.String(),
		v.VHostID.ExportToDB(),
		from.String(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("vanity_host_build")
	}
	return nil
}

func (v *VanityMinder) doInviteCode(m MetaContext) error {
	if len(v.InviteCode) == 0 {
		return nil
	}
	m.Infow("VanityMinder", "op", "doInviteCode")
	m = m.WithHostID(v.hostId)
	err := InsertMultiuseInviteCodeAllowRepeat(m, v.InviteCode)
	if err != nil {
		return err
	}
	return nil
}

func (v *VanityMinder) dbUpdateStage2Complete(m MetaContext) error {
	m.Infow("VanityMinder", "op", "dbUpdateStage2Complete")
	return RetryTxUserDB(m, "VanityMinder.dbUpdateStage2Complete", func(m MetaContext, tx pgx.Tx) error {
		return v.bumpStage(m, tx,
			proto.HostBuildStage_Stage2b, proto.HostBuildStage_Complete)
	})
}
func (v *VanityMinder) dbUpdateStage2b(m MetaContext) error {
	m.Infow("VanityMinder", "op", "dbUpdateStage2b")
	err := RetryTxUserDB(m, "VanityMinder.dbUpdateStage2b", func(m MetaContext, tx pgx.Tx) error {
		return v.bumpStage(m, tx,
			proto.HostBuildStage_Stage2a, proto.HostBuildStage_Stage2b)
	},
	)
	if err != nil {
		return err
	}
	v.stage = proto.HostBuildStage_Stage2b
	return nil
}

func vhostAdminInsert(
	m MetaContext,
	tx pgx.Tx,
	vhostID proto.VHostID,
) error {
	tag, err := tx.Exec(
		m.Ctx(),
		`INSERT INTO vhost_admins(short_host_id, uid, vhost_id, ctime)
			VALUES ($1, $2, $3, NOW())`,
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
		vhostID.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("vhost_admins")
	}
	tag, err = tx.Exec(
		m.Ctx(),
		`INSERT INTO vhost_quota_masters(short_host_id, uid, vhost_id, 
			    ctime, mtime)
			VALUES ($1, $2, $3, NOW(), NOW())`,
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
		vhostID.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("vhost_quota_masters")
	}
	return nil
}

func (v *VanityMinder) dbUpdateStage2a(m MetaContext) error {

	// No need to try again if we've already hit this checkpoint,
	if v.stage.Gt(proto.HostBuildStage_Stage1) {
		return nil
	}

	m.Infow("VanityMinder", "op", "dbUpdateStage2a")

	err := RetryTxUserDB(m, "VanityMinder.dbUpdateStage2a", func(m MetaContext, tx pgx.Tx) error {
		err := v.bumpStage(m, tx,
			proto.HostBuildStage_Stage1, proto.HostBuildStage_Stage2a)
		if err != nil {
			return err
		}
		err = vhostAdminInsert(m, tx, *v.VHostID)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	v.stage = proto.HostBuildStage_Stage2a
	return nil
}

func autocertPackageForVanity(
	m MetaContext,
	cfg VHostsConfigger,
	pkg *AutocertPackage,
) error {
	return nil
}

func vhostBuilderDoAutocert(
	m MetaContext,
	ac Autocerter,
	cfg VHostsConfigger,
	hn proto.Hostname,
	hid proto.HostID,
	isVanity bool,
) error {

	pkg, err := m.G().Config().AutocertPackage(m.Ctx(), proto.ServerType_Probe, 0)
	if err != nil {
		return err
	}
	pkg.Hostname = hn.Normalize()

	err = autocertPackageForVanity(m, cfg, pkg)
	if err != nil {
		return err
	}

	pkg.HostID = hid
	pkg.IsVanity = isVanity
	pkg.ServerType = proto.ServerType_Probe

	m.Infow("vhostBuilderDoAutocert", "pkg", pkg, "func", "enter")
	err = ac.Autocert(m, *pkg)
	m.Infow("vhostBuilderDoAutocert", "pkg", pkg, "func", "exit", "err", err)

	return err
}

func (v *VanityMinder) doAutocert(m MetaContext) error {
	m.Infow("VanityMinder", "op", "doAutocert")
	return vhostBuilderDoAutocert(m, v.hlp, v.cfg, v.Vstem, v.hostId.Id, true)
}

func (v *VanityMinder) doBeacon(m MetaContext) error {
	m.Infow("VanityMinder", "op", "doBeacon", "func", "enter")
	m = m.WithHostID(v.hostId)
	err := BeaconRegisterCli(m, v.Vstem, v.Beacon)
	m.Infow("VanityMinder", "op", "doBeacon", "func", "exit", "err", err)
	if err != nil {
		return err
	}
	return err
}

func (v *VanityMinder) checkLimits(m MetaContext) error {
	m.Infow("VanityMinder", "op", "checkLimits")
	return CheckVHostLimits(m)
}

func CheckVHostLimits(m MetaContext) error {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	err = CheckVHostLimitsWithDB(m, db, m.UID())
	if err != nil {
		return err
	}
	return nil
}

func (v *VanityMinder) stage2a(m MetaContext) error {
	m.Infow("VanityMinder", "stage", "2a")

	// Is idempotent; works after a session is recoeverd.
	err := v.insertDNSHosts(m)
	if err != nil {
		return err
	}

	// Is idempotent; if we've previously done this, we'll wind up loading
	// the vhost.
	err = v.vHostLoadOrMake(m)
	if err != nil {
		return err
	}

	// Puts a checkpoint at stage 2a.
	err = v.dbUpdateStage2a(m)
	if err != nil {
		return err
	}

	return nil
}

func (v *VanityMinder) stage2b(m MetaContext) error {
	if v.stage != proto.HostBuildStage_Stage2a {
		return nil
	}
	m.Infow("VanityMinder", "stage", "2b")

	// Is idempotent; we'll overwrite our old cerificates in the autocert manager.
	err := v.doAutocert(m)
	if err != nil {
		return err
	}

	err = v.dbUpdateStage2b(m)
	if err != nil {
		return err
	}

	return nil
}

func (v *VanityMinder) stage2c(m MetaContext) error {
	if v.stage != proto.HostBuildStage_Stage2b {
		return nil
	}
	m.Infow("VanityMinder", "stage", "2c")
	// Is idempotent; it's ok to reregister the same server twice.
	err := v.doBeacon(m)
	if err != nil {
		return err
	}

	// Is idempotent, since we overwrite the old code with the same one if necessary.
	err = v.doInviteCode(m)
	if err != nil {
		return err
	}

	err = v.dbUpdateStage2Complete(m)
	if err != nil {
		return err
	}

	return nil
}

// autosetDNS only fires for friend classes like CannedCreator.
func (v *VanityMinder) autosetDNS(m MetaContext) error {
	if v.stage.Gt(proto.HostBuildStage_Stage1) {
		return nil
	}
	m.Infow("VanityMinder", "op", "autosetDNS")
	if v.autosetDNSHook == nil {
		return nil
	}
	err := v.autosetDNSHook(m)
	if err != nil {
		return err
	}
	return nil
}

// Stage2 we load the session from the database, and check for the
// DNS resolution. If there, we can complete the task which means:
// 1. Inserting further CNAME records
// 2. Making keys and certs
// 3. Asking LetsEncrypt for a cert
// 4. Finalizing the DB record
func (v *VanityMinder) Stage2(m MetaContext) error {
	m.Infow("VanityMinder", "stage", "2")

	err := v.init(m)
	if err != nil {
		return err
	}
	err = v.dbLoadStage2(m)
	if err != nil {
		return err
	}

	err = v.autosetDNS(m)
	if err != nil {
		return err
	}

	// Is idempotent; works after a session is recovered.
	err = v.checkStemDNS(m)
	if err != nil {
		return err
	}

	err = v.stage2a(m)
	if err != nil {
		return err
	}

	err = v.stage2b(m)
	if err != nil {
		return err
	}

	err = v.stage2c(m)
	if err != nil {
		return err
	}

	return nil
}

func AbortVanityBuild(
	m MetaContext,
	uid proto.UID,
	vhid proto.VHostID,
) error {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	return RetryTxUserDB(m, "AbortVanityBuild", func(m MetaContext, tx pgx.Tx) error {
		return abortVanityBuildTx(m, tx, uid, vhid)
	})
}

func abortVanityBuildTx(
	m MetaContext,
	tx pgx.Tx,
	uid proto.UID,
	vhid proto.VHostID,
) error {
	canc, err := proto.NewCancelID()
	if err != nil {
		return err
	}
	tag, err := tx.Exec(
		m.Ctx(),
		`UPDATE vanity_host_build
		 SET stage=$1, vanity_host_cancel_id=$2
		 WHERE short_host_id=$3 AND uid=$4 AND vhost_id=$5`,
		proto.HostBuildStage_Aborted.String(),
		canc.ExportToDB(),
		m.ShortHostID().ExportToDB(),
		uid.ExportToDB(),
		vhid.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("vanity_host_build")
	}
	return nil
}
