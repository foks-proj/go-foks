// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"errors"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type VHostAdmin struct {
	Host core.ShortHostID
	Uid  proto.UID
}

type VHost struct {
	ShortID core.ShortHostID // might be 0 if not yet complete
	Name    proto.Hostname
	Id      proto.VHostID
	Stage   proto.HostBuildStage
}

type VHostAdminWithManagedVHosts struct {
	VHostAdmin
	Vhosts map[proto.VHostID]VHost
}

func (v *VHostAdminWithManagedVHosts) NumHosts() int {
	return len(v.Vhosts)
}

func (v *VHostAdminWithManagedVHosts) loadAllHosts(m MetaContext, q Querier) error {
	v.Vhosts = make(map[proto.VHostID]VHost)
	err := v.loadBuilds(m, q)
	if err != nil {
		return err
	}
	err = v.loadVHosts(m, q)
	if err != nil {
		return err
	}
	return nil
}

func (v *VHostAdminWithManagedVHosts) loadBuilds(m MetaContext, q Querier) error {

	rows, err := q.Query(
		m.Ctx(),
		`SELECT vanity_host, vhost_id, stage
		 FROM vanity_host_build
		 WHERE short_host_id = $1 AND uid = $2
		 AND stage::TEXT=ANY($3::TEXT[])`,
		v.Host.ExportToDB(),
		v.Uid.ExportToDB(),
		core.Map(proto.HostBuildStagesInProgress, func(s proto.HostBuildStage) string { return s.String() }),
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, stage string
		var vhid []byte
		err = rows.Scan(&name, &vhid, &stage)
		if err != nil {
			return err
		}
		var vhost VHost
		err = vhost.Stage.ImportFromString(stage)
		if err != nil {
			return err
		}
		err = vhost.Id.ImportFromDB(vhid)
		if err != nil {
			return err
		}
		vhost.Name = proto.Hostname(name)
		v.Vhosts[vhost.Id] = vhost
	}
	return nil
}

func (v *VHostAdminWithManagedVHosts) loadVHosts(m MetaContext, q Querier) error {
	rows, err := q.Query(
		m.Ctx(),
		`SELECT vhost_id 
		 FROM vhost_quota_masters 
		 WHERE short_host_id = $1 AND uid = $2`,
		v.Host.ExportToDB(),
		v.Uid.ExportToDB(),
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	hidm := m.G().HostIDMap()
	for rows.Next() {
		var vhidRaw []byte
		err = rows.Scan(&vhidRaw)
		if err != nil {
			return nil
		}
		var vhost VHost
		err = vhost.Id.ImportFromDB(vhidRaw)
		if err != nil {
			return nil
		}
		hid, err := hidm.LookupByVHostID(m, vhost.Id)
		if err != nil {
			return err
		}
		vhost.ShortID = hid.Short
		hn, err := hidm.Hostname(m, hid.Short)
		if err != nil {
			return err
		}
		vhost.Name = hn
		vhost.Stage = proto.HostBuildStage_Complete
		v.Vhosts[vhost.Id] = vhost
	}

	return nil
}

func (v *VHostAdminWithManagedVHosts) ShortHostIDsInt() []int {
	var ret []int
	for _, vhost := range v.Vhosts {
		if vhost.ShortID != 0 {
			ret = append(ret, int(vhost.ShortID))
		}
	}
	return ret
}

func (v *VHostAdminWithManagedVHosts) ShortHostIDs() []core.ShortHostID {
	var ret []core.ShortHostID
	for _, vhost := range v.Vhosts {
		if vhost.ShortID != 0 {
			ret = append(ret, vhost.ShortID)
		}
	}
	return ret
}

func (v *VHostAdminWithManagedVHosts) TotalDiskUsage(m MetaContext) (proto.Size, error) {
	var sumAll int64

	shids := v.ShortHostIDsInt()

	doShard := func(db *pgxpool.Conn) error {
		var sum int64
		err := db.QueryRow(
			m.Ctx(),
			`SELECT COALESCE(SUM(sum_small+sum_large), 0)
 		     FROM usage_vhost WHERE short_host_id=ANY($1)`,
			shids,
		).Scan(&sum)
		if err == pgx.ErrNoRows {
			return core.BadServerDataError("no usage sum row")
		}
		if err != nil {
			return err
		}
		sumAll += sum
		return nil
	}
	err := m.ForAllShards(doShard)
	if err != nil {
		return 0, err
	}
	usage := proto.Size(sumAll)
	return usage, nil
}

func vHostQuotaMasterForCurrentVHost(
	m MetaContext,
	q Querier,
) (*VHostAdminWithManagedVHosts, error) {

	var uidRaw []byte
	var shid int

	err := q.QueryRow(
		m.Ctx(),
		`SELECT short_host_id, uid FROM vhost_quota_masters WHERE vhost_id = $1`,
		m.HostID().VId.ExportToDB(),
	).Scan(&shid, &uidRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ret := VHostAdminWithManagedVHosts{
		VHostAdmin: VHostAdmin{
			Host: core.ShortHostID(shid),
		},
	}
	err = ret.Uid.ImportFromDB(uidRaw)
	if err != nil {
		return nil, err
	}
	err = ret.loadAllHosts(m, q)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func allManagedVhosts(
	m MetaContext,
	q Querier,
) ([]int, error) {

	vhid := m.HostID().VId
	if vhid.IsZero() {
		return nil, core.InternalError("nil vhostID not expected")
	}

	rows, err := q.Query(
		m.Ctx(),
		`SELECT B.vhost_id 
		 FROM vhost_quota_masters AS A 
		 JOIN vhost_quota_masters AS B
		 ON (A.uid = B.uid AND A.short_host_id = B.short_host_id)
		 WHERE A.vhost_host_id = $1`,
		vhid.ExportToDB(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ret []int
	hidm := m.G().HostIDMap()
	for rows.Next() {
		var vhidRaw []byte
		err = rows.Scan(&vhidRaw)
		if err != nil {
			return nil, err
		}
		var vhid proto.VHostID
		err = vhid.ImportFromDB(vhidRaw)
		if err != nil {
			return nil, err
		}
		chid, err := hidm.LookupByVHostID(m, vhid)
		if err != nil {
			return nil, err
		}
		ret = append(ret, chid.Short.ExportToDB())
	}
	return ret, nil
}

func CountGroupedUserSeats(
	m MetaContext,
	q Querier,
) (int, error) {

	hosts, err := allManagedVhosts(m, q)
	if err != nil {
		return 0, err
	}
	if len(hosts) == 0 {
		return 0, core.NoActivePlanError{}
	}

	var ret int
	err = q.QueryRow(
		m.Ctx(),
		`SELECT COUNT(*) FROM users WHERE short_host_id = ANY($1)`,
		hosts,
	).Scan(&ret)
	if err != nil {
		return 0, err
	}

	return ret, nil
}

func (a *VHostAdminWithManagedVHosts) countOccupiedSeats(m MetaContext, q Querier) (int, error) {
	var ret int
	shids := a.ShortHostIDsInt()
	err := q.QueryRow(
		m.Ctx(),
		`SELECT COUNT(*) FROM users WHERE short_host_id = ANY($1)`,
		shids,
	).Scan(&ret)
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func SelectHostConfig(m MetaContext, shid core.ShortHostID) (proto.HostConfig, error) {
	var ret proto.HostConfig
	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return ret, err
	}
	var typ, uv string
	defer db.Release()
	err = db.QueryRow(
		m.Ctx(),
		`SELECT user_metering, vhost_metering, per_vhost_disk_metering, host_type, user_viewing
		 FROM host_config WHERE short_host_id = $1`,
		shid.ExportToDB(),
	).Scan(&ret.Metering.Users, &ret.Metering.VHosts, &ret.Metering.PerVHostDisk, &typ, &uv)
	if errors.Is(err, pgx.ErrNoRows) {
		return ret, nil
	}
	if err != nil {
		return ret, err
	}
	err = ret.Typ.ImportFromString(typ)
	if err != nil {
		return ret, err
	}
	err = ret.Viewership.User.ImportFromDB(uv)
	if err != nil {
		return ret, err
	}
	ret.Viewership.Team = proto.ViewershipMode_Closed
	return ret, nil
}

func CheckSeatLimits(
	m MetaContext,
	userDb Querier,
) error {
	cfg, err := SelectHostConfig(m, m.ShortHostID())
	if err != nil {
		return err
	}
	if !cfg.Metering.Users {
		return nil
	}

	quotaMaster, err := vHostQuotaMasterForCurrentVHost(m, userDb)
	if err != nil {
		return err
	}
	if quotaMaster == nil {
		return core.NoActivePlanError{}
	}
	occupied, err := quotaMaster.countOccupiedSeats(m, userDb)
	if err != nil {
		return err
	}
	plan, err := LoadPlanForUser(m, userDb, quotaMaster.Host, quotaMaster.Uid)
	switch {
	case err != nil:
		return err
	case plan.Plan.Scope != infra.QuotaScope_VHost:
		return core.NoActivePlanError{}
	case occupied >= int(plan.Plan.MaxSeats):
		return core.OverQuotaError{}
	default:
		return nil
	}
}

func CheckVHostLimitsWithDB(
	m MetaContext,
	userDb Querier,
	uid proto.UID,
) error {
	// when we create vhost B on top of vhost A, we check if A is metered
	// to apply any quota limitations.
	cfg, err := SelectHostConfig(m, m.ShortHostID())
	if err != nil {
		return err
	}
	if !cfg.Metering.VHosts {
		return nil
	}
	qm := VHostAdminWithManagedVHosts{
		VHostAdmin: VHostAdmin{
			Host: m.ShortHostID(),
			Uid:  uid,
		},
	}
	err = qm.loadAllHosts(m, userDb)
	if err != nil {
		return err
	}
	plan, err := LoadPlanForUser(m, userDb, qm.Host, qm.Uid)
	switch {
	case err != nil:
		return err
	case plan.Plan.Scope != infra.QuotaScope_VHost:
		return core.NoActivePlanError{}
	case qm.NumHosts() >= int(plan.Plan.MaxVhosts):
		return core.OverQuotaError{}
	default:
		return nil
	}
}
