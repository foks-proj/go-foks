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
	"github.com/jackc/pgx/v5/pgxpool"
)

// Base VHosts are Vhosts that the admin of the site configures (rather than a user on the service).
// As such they are similar to Vanity Vhosts and Canned Vhosts, but there is no DNS redirection
// needed, and therefore some other mechanism is absent. Note, this isn't ideal since it's
// quite duplicative of VanitytMinder. We might consider a future refactor, but it will be
// tricky.

type BaseVHostMinder struct {
	// Passed in from the caller
	Hostname proto.Hostname
	// In test, might be needed
	Beacon *GlobalService
	// Optional
	InviteCode rem.MultiUseInviteCode
	Type       proto.HostType

	// internal state
	vHostID *proto.VHostID
	ac      Autocerter
	hostId  *core.HostID
	hc      *HostChain
	stage   proto.HostBuildStage
	db      *pgxpool.Conn
	cfg     VHostsConfigger
	ufsMap  map[proto.ServerType]proto.Hostname
}

func (b *BaseVHostMinder) HostID() *core.HostID {
	return b.hostId
}

func (b *BaseVHostMinder) initUfsMap(m MetaContext) error {
	b.ufsMap = make(map[proto.ServerType]proto.Hostname)
	for _, st := range proto.FrontFacingServers {
		b.ufsMap[st] = b.Hostname.Normalize()
	}
	return nil
}

func (b *BaseVHostMinder) Autocert(m MetaContext, pkg AutocertPackage) error {
	return DoAutocertViaClient(m, time.Minute, pkg)
}

func (b *BaseVHostMinder) init(m MetaContext) error {
	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return err
	}
	b.db = db
	cfg, err := m.G().Config().VHostsConfig(m.Ctx())
	if err != nil {
		return err
	}
	b.cfg = cfg

	err = b.initUfsMap(m)
	if err != nil {
		return err
	}
	if b.ac == nil {
		b.ac = b
	}
	return nil
}

func (b *BaseVHostMinder) lookupPrevSession(m MetaContext) error {

	var vhidRaw []byte
	var stageRaw string

	err := b.db.QueryRow(m.Ctx(),
		`SELECT vhost_id, stage 
		 FROM base_vhost_build
		 WHERE hostname = $1
		 AND cancel_id = $2`,
		b.Hostname.Normalize().String(),
		proto.NilCancelID(),
	).Scan(&vhidRaw, &stageRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	err = b.stage.ImportFromString(stageRaw)
	if err != nil {
		return err
	}
	var vhid proto.VHostID
	err = vhid.ImportFromDB(vhidRaw)
	if err != nil {
		return err
	}
	b.vHostID = &vhid
	return nil
}

func (b *BaseVHostMinder) makeVHostID(m MetaContext) error {
	if b.vHostID != nil {
		return nil
	}
	id, err := proto.RandomID16er[proto.VHostID]()
	if err != nil {
		return err
	}
	b.vHostID = id

	tag, err := b.db.Exec(m.Ctx(),
		`INSERT INTO base_vhost_build
		 (vhost_id, hostname, cancel_id, stage, mtime)
		 VALUES($1, $2, $3, $4, NOW())`,
		b.vHostID.ExportToDB(),
		b.Hostname.Normalize().String(),
		proto.NilCancelID(),
		b.stage.String(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("base_vhost_build")
	}
	return nil
}

func (v *BaseVHostMinder) loadHostchain(m MetaContext) error {
	chid, err := m.G().HostIDMap().LookupByVHostID(m, *v.vHostID)
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

func (v *BaseVHostMinder) vHostLoadOrMake(m MetaContext) error {
	err := v.loadHostchain(m)
	if err == nil {
		return nil
	}
	if !errors.Is(err, core.HostIDNotFoundError{}) {
		return err
	}
	return v.vHostInit(m)
}

func (v *BaseVHostMinder) vHostInit(m MetaContext) error {

	i := &vHostInit{
		vhostId:    v.vHostID,
		hn:         v.Hostname,
		skipBeacon: true, // we need to skip the beacon registration until after let's encrypt
		merklePoke: func() error { return PokeMerklePipeline(m) },
		ufsMap:     v.ufsMap,
		config: proto.HostConfig{
			Typ: v.Type,
		},
	}
	switch v.Type {
	case proto.HostType_VHostManagement:
		i.config.Metering.VHosts = true
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

func (b *BaseVHostMinder) bumpStage(
	m MetaContext,
	e DbExecer,
	from, to proto.HostBuildStage,
) error {
	if from == to {
		return nil
	}
	if e == nil {
		e = b.db
	}
	tag, err := e.Exec(
		m.Ctx(),
		`UPDATE base_vhost_build
		SET stage=$1
		WHERE vhost_id=$2 AND stage=$3`,
		to.String(),
		b.vHostID.ExportToDB(),
		from.String(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("base_vhost_build")
	}
	b.stage = to
	return nil
}

func (b *BaseVHostMinder) stage2a(m MetaContext) error {

	if b.stage.Gte(proto.HostBuildStage_Stage2a) {
		return nil
	}

	err := b.bumpStage(m, nil, b.stage, proto.HostBuildStage_Stage2a)
	if err != nil {
		return err
	}
	return nil
}

func (b *BaseVHostMinder) stage2b(m MetaContext) error {

	if b.stage.Gte(proto.HostBuildStage_Stage2b) {
		return nil
	}

	// Is idempotent; can afford to do this if already done
	err := vhostBuilderDoAutocert(m, b.ac, b.cfg, b.Hostname, b.hostId.Id, true)
	if err != nil {
		return err
	}

	err = b.bumpStage(m, nil, b.stage, proto.HostBuildStage_Stage2b)
	if err != nil {
		return err
	}
	return nil
}

func (b *BaseVHostMinder) stage2c(m MetaContext) error {
	if b.stage.Gt(proto.HostBuildStage_Stage2b) {
		return nil
	}
	m = m.WithHostID(b.hostId)
	err := BeaconRegisterCli(m, b.Hostname, b.Beacon)
	if err != nil {
		return err
	}
	if len(b.InviteCode) > 0 {
		err = InsertMultiuseInviteCodeAllowRepeat(m, b.InviteCode)
		if err != nil {
			return err
		}
	}
	err = b.bumpStage(m, nil, b.stage, proto.HostBuildStage_Complete)
	if err != nil {
		return err
	}
	return nil
}

func (b *BaseVHostMinder) Run(m MetaContext) error {

	err := b.init(m)
	if err != nil {
		return err
	}
	defer b.db.Release()

	err = b.lookupPrevSession(m)
	if err != nil {
		return err
	}

	err = b.makeVHostID(m)
	if err != nil {
		return err
	}

	err = b.vHostLoadOrMake(m)
	if err != nil {
		return err
	}

	err = b.stage2a(m)
	if err != nil {
		return err
	}

	err = b.stage2b(m)
	if err != nil {
		return err
	}

	err = b.stage2c(m)
	if err != nil {
		return err
	}
	return nil
}
