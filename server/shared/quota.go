// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"errors"
	"fmt"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type QuotaUser struct {
	ShortHostID core.ShortHostID
	Uid         proto.UID
	Teams       []proto.TeamID
	UserPlan    *infra.UserPlan
	QCfg        infra.QuotaConfig
}

func (q *QuotaUser) Parties() []proto.PartyID {
	var ret []proto.PartyID
	for _, tid := range q.Teams {
		pid := tid.ToPartyID()
		ret = append(ret, pid)
	}
	ret = append(ret, q.Uid.ToPartyID())
	return ret
}

func LoadQuotaUserByKVParty(
	m MetaContext,
	shid core.ShortHostID,
	pid proto.PartyID,
) (
	*QuotaUser,
	error,
) {
	uidp, tid, err := pid.Select()
	if err != nil {
		return nil, err
	}
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()

	if tid != nil {
		var uidRaw []byte
		err := db.QueryRow(
			m.Ctx(),
			`SELECT uid FROM team_quota_masters WHERE short_host_id=$1 AND team_id=$2`,
			shid.ExportToDB(),
			tid.ExportToDB(),
		).Scan(&uidRaw)
		if err == pgx.ErrNoRows {
			return nil, core.UserNotFoundError{}
		}
		if err != nil {
			return nil, err
		}
		var uid proto.UID
		err = uid.ImportFromDB(uidRaw)
		if err != nil {
			return nil, err
		}
		uidp = &uid
	}

	if uidp == nil {
		return nil, core.InternalError("uidp is nil")
	}

	uid := *uidp

	rows, err := db.Query(
		m.Ctx(),
		`SELECT team_id FROM team_quota_masters WHERE short_host_id=$1 AND uid=$2`,
		shid.ExportToDB(),
		uid.ExportToDB(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var teams []proto.TeamID

	for rows.Next() {
		var tidRaw []byte
		err = rows.Scan(&tidRaw)
		if err != nil {
			return nil, err
		}
		var tid proto.TeamID
		err = tid.ImportFromDB(tidRaw)
		if err != nil {
			return nil, err
		}
		teams = append(teams, tid)
	}
	cfg, err := m.G().Config().QuotaServerConfig(m.Ctx())
	if err != nil {
		return nil, err
	}
	qcfg, err := ExportQuotaConfig(cfg)
	if err != nil {
		return nil, err
	}
	ret := QuotaUser{
		ShortHostID: shid,
		Uid:         uid,
		Teams:       teams,
		QCfg:        *qcfg,
	}
	plan, err := LoadPlanForUser(m, db, shid, uid)
	switch err.(type) {
	case nil:
		ret.UserPlan = plan
	case core.NoActivePlanError:
	default:
		return nil, err
	}
	return &ret, nil
}

func ComputePlanStatus(
	m MetaContext,
	paidThrough time.Time,
) (
	infra.PlanStatus,
	error,
) {
	qcfg, err := m.G().Config().QuotaServerConfig(m.Ctx())
	if err != nil {
		return 0, err
	}
	slacks, err := qcfg.GetSlacks()
	if err != nil {
		return 0, err
	}
	timeLeft := paidThrough.Sub(m.Now())
	switch {
	case timeLeft >= time.Duration(0):
		return infra.PlanStatus_Active, nil
	case -timeLeft <= slacks.PaidThrough.Duration():
		return infra.PlanStatus_Overtime, nil
	default:
		return infra.PlanStatus_Expired, nil
	}
}

func LoadPlanForUser(
	m MetaContext,
	qry Querier,
	shid core.ShortHostID,
	uid proto.UID,
) (
	*infra.UserPlan,
	error,
) {
	var quota int64
	var maxTeams uint64
	var maxVhosts uint64
	var planId, priceId []byte
	var name, displayName string
	var detailsRaw []byte
	var stripeProdId string
	var paidThrough time.Time
	var timeLeft time.Duration
	var promoted bool
	var pendingCancel bool
	var subId string
	var quotaScope string
	var ssoSupport bool

	err := qry.QueryRow(
		m.Ctx(),
		`SELECT plan_id, name, display_name, quota_scope, max_seats, max_vhosts,
		   quota, details, stripe_prod_id, promoted, paid_through, 
		   pending_cancel, price_id, stripe_sub_id, sso_support
		FROM quota_plans
		JOIN user_plans USING(plan_id)
		WHERE short_host_id=$1 AND uid=$2 AND cancel_id=$3`,
		shid.ExportToDB(),
		uid.ExportToDB(),
		proto.NilCancelID(),
	).Scan(&planId, &name, &displayName, &quotaScope, &maxTeams, &maxVhosts, &quota,
		&detailsRaw, &stripeProdId, &promoted, &paidThrough, &pendingCancel, &priceId,
		&subId, &ssoSupport,
	)

	if err == pgx.ErrNoRows {
		return nil, core.NoActivePlanError{}
	}
	if err != nil {
		return nil, err
	}

	planStatus, err := ComputePlanStatus(m, paidThrough)
	if err != nil {
		return nil, err
	}

	planp, err := readQuotaPlanFromDB(planId, name, displayName, quotaScope, maxTeams, maxVhosts,
		quota, detailsRaw, stripeProdId, promoted, ssoSupport)
	if err != nil {
		return nil, err
	}

	tmp := make(map[proto.PlanID]*infra.Plan)
	tmp[planp.Id] = planp
	err = loadPricesIntoPlans(m, qry, tmp)
	if err != nil {
		return nil, err
	}

	ret := infra.UserPlan{
		Plan:           *planp,
		Status:         planStatus,
		TimeLeft:       proto.ExportDurationSecs(timeLeft),
		PendingCancel:  pendingCancel,
		PaidThrough:    proto.ExportTime(paidThrough),
		SubscriptionId: infra.StripeSubscriptionID(subId),
	}

	err = ret.Price.ImportFromDB(priceId)
	if err != nil {
		return nil, err
	}

	return &ret, nil
}

func SetPlanForUser(
	m MetaContext,
	tx pgx.Tx,
	shid core.ShortHostID,
	uid proto.UID,
	planId proto.PlanID,
	priceId proto.PriceID,
	paidThrough time.Time,
	subID infra.StripeSubscriptionID,
) error {
	_, err := tx.Exec(
		m.Ctx(),
		`INSERT INTO user_plans (short_host_id, uid, cancel_id, plan_id, price_id, stripe_sub_id, 
		   paid_through, ctime, pending_cancel, mtime)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, false, NOW())`,
		shid.ExportToDB(),
		uid.ExportToDB(),
		proto.NilCancelID(),
		planId.ExportToDB(),
		priceId.ExportToDB(),
		subID.String(),
		paidThrough,
		m.Now().UTC(),
	)
	if err != nil && IsDuplicateKeyError(err, "pkey") {
		return core.PlanExistsError{}
	}
	return err
}

func UpdatePlanForUser(
	m MetaContext,
	tx pgx.Tx,
	shid core.ShortHostID,
	uid proto.UID,
	planId *proto.PlanID,
	priceId *proto.PriceID,
	paidThrough *time.Time,
	subID infra.StripeSubscriptionID,
) error {

	// NOOP, nothing to do.
	if planId == nil && priceId == nil && paidThrough == nil {
		return nil
	}

	q := `UPDATE user_plans SET mtime=NOW() `
	var args []any
	i := 1
	idx := func() string {
		ret := fmt.Sprintf("$%d", i)
		i++
		return ret
	}
	if planId != nil {
		q += ", plan_id=" + idx()
		args = append(args, planId.ExportToDB())
	}
	if priceId != nil {
		q += ", price_id=" + idx()
		args = append(args, priceId.ExportToDB())
	}
	if paidThrough != nil {
		q += ", paid_through=" + idx()
		args = append(args, *paidThrough)
	}
	q += " WHERE short_host_id=" + idx() + " AND uid=" + idx() + " AND cancel_id=" + idx() + " AND stripe_sub_id=" + idx()
	args = append(args, shid.ExportToDB(), uid.ExportToDB(), proto.NilCancelID(), subID.String())

	tag, err := tx.Exec(m.Ctx(), q, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("updatePlanForUser")
	}
	return nil
}

func CancelPlanForUserWithSub(
	m MetaContext,
	db *pgxpool.Conn,
	uid proto.UID,
	subID infra.StripeSubscriptionID,
) error {
	cid, err := proto.NewCancelID()
	if err != nil {
		return err
	}
	op := func(m MetaContext, tx pgx.Tx) error {
		tag, err := tx.Exec(
			m.Ctx(),
			`UPDATE user_plans
			 SET cancel_id=$1, cancel_time=$2
			 WHERE uid=$3 AND stripe_sub_id=$4`,
			cid.ExportToDB(),
			m.Now().UTC(),
			uid.ExportToDB(),
			subID.String(),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.UpdateError("CancelPlanForUserWithSub")
		}
		return nil
	}
	return RetryTx(m, db, "cancelPlanForUserWithSub", op)
}

func CancelPlanForUser(
	m MetaContext,
	tx pgx.Tx,
	shid core.ShortHostID,
	uid proto.UID,
	planId proto.PlanID,
) (
	*proto.CancelID,
	error,
) {
	var cancelId proto.CancelID
	err := core.RandomFill(cancelId[:])
	if err != nil {
		return nil, err
	}
	args := []any{
		cancelId.ExportToDB(),
		m.Now().UTC(),
		shid.ExportToDB(),
		uid.ExportToDB(),
	}
	q := `UPDATE user_plans
		SET cancel_id=$1, cancel_time=$2
		WHERE short_host_id=$3 AND uid=$4`

	if !planId.IsZero() {
		args = append(args, planId.ExportToDB())
		q += " AND plan_id=$5"
	}
	tag, err := tx.Exec(
		m.Ctx(),
		q, args...,
	)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, core.NotFoundError("existing plan")
	}
	return &cancelId, nil

}

func checkMaxTeamsQuota(
	m MetaContext,
	tx pgx.Tx,
	uid proto.UID,
	noPlanMaxTeams int,
) error {

	var maxSeats int
	plan, err := LoadPlanForUser(m, tx, m.ShortHostID(), uid)

	switch {
	case errors.Is(err, core.NoActivePlanError{}):
		maxSeats = noPlanMaxTeams
	case err != nil:
		return err
	case plan.Plan.Scope == infra.QuotaScope_VHost:
		return nil
	case plan.Plan.Scope != infra.QuotaScope_Teams:
		return core.BadServerDataError("unexpected quota scope")
	default:
		maxSeats = int(plan.Plan.MaxSeats)
	}

	var nTeams int
	err = tx.QueryRow(
		m.Ctx(),
		`SELECT COUNT(*) FROM team_quota_masters
		 WHERE short_host_id=$1 AND uid=$2`,
		m.ShortHostID(),
		uid.ExportToDB(),
	).Scan(&nTeams)

	if errors.Is(err, pgx.ErrNoRows) {
		return core.BadServerDataError("no count of teams for team master")
	}
	if err != nil {
		return err
	}

	if nTeams > maxSeats {
		return core.OverQuotaError{}
	}

	return nil
}

func AssignQuotaMaster(
	m MetaContext,
	tx pgx.Tx,
	uid proto.UID,
	teamId proto.TeamID,
	noPlanMaxTeams int,
) error {
	tags, err := tx.Exec(
		m.Ctx(),
		`INSERT INTO team_quota_masters (short_host_id, uid, team_id, ctime, mtime)
 	     VALUES ($1, $2, $3, $4, $4)
		 ON CONFLICT (short_host_id, team_id) 
		 DO UPDATE SET mtime=$4, uid=$2`,
		m.ShortHostID().ExportToDB(),
		uid.ExportToDB(),
		teamId.ExportToDB(),
		m.Now().UTC(),
	)
	if err != nil {
		return err
	}
	if tags.RowsAffected() != 1 {
		return core.UpdateError("team_quota_masters")
	}
	err = InsQuotaPoke(m, tx,
		[]proto.PartyID{
			uid.ToPartyID(),
		},
	)
	if err != nil {
		return err
	}

	err = checkMaxTeamsQuota(m, tx, uid, noPlanMaxTeams)
	if err != nil {
		return err
	}
	return nil
}

func ChangeQuotaMasterRetry(
	m MetaContext,
	doAdd bool,
	uid proto.UID,
	teamId proto.TeamID,
) error {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	cfg, err := m.G().Config().QuotaServerConfig(m.Ctx())
	if err != nil {
		return err
	}
	mt := cfg.GetNoPlanMaxTeams()
	return RetryTx(m, db, "assignQuotaMaster",
		func(m MetaContext, tx pgx.Tx) error {
			if doAdd {
				return AssignQuotaMaster(m, tx, uid, teamId, mt)
			}
			return UnassignQuotaMaster(m, tx, uid, teamId)
		},
	)
}

func UnassignQuotaMaster(
	m MetaContext,
	tx pgx.Tx,
	uid proto.UID,
	teamId proto.TeamID,
) error {
	tags, err := tx.Exec(
		m.Ctx(),
		`DELETE FROM team_quota_masters 
		 WHERE short_host_id=$1 AND uid=$2 AND team_id=$3`,
		m.ShortHostID().ExportToDB(),
		uid.ExportToDB(),
		teamId.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tags.RowsAffected() != 1 {
		return core.UpdateError("team_quota_masters")
	}
	err = InsQuotaPoke(m, tx,
		[]proto.PartyID{
			uid.ToPartyID(),
			teamId.ToPartyID(),
		},
	)
	if err != nil {
		return err
	}
	return nil
}

func (u *UsageManager) updateUsageVHost(
	m MetaContext,
	shids []core.ShortHostID,
	inQuota bool,
	why string,
	hasPlan bool,
) error {
	shidsDb := core.Map(shids, func(s core.ShortHostID) int { return s.ExportToDB() })

	doShard := func(db *pgxpool.Conn) error {
		_, err := db.Exec(
			m.Ctx(),
			`UPDATE quota_check_vhost
		     SET num_new_writes = 0, check_time = $1, in_quota = $2
			 WHERE short_host_id = ANY($3)`,
			m.Now().UTC(),
			inQuota,
			shidsDb,
		)
		if err != nil {
			return err
		}
		return nil
	}

	err := m.ForAllShards(doShard)
	if err != nil {
		return err
	}

	if !inQuota {
		m.Infow("killAccess", "shortHostIDs", shidsDb, "why", why, "hasPlan", hasPlan)
	}
	return nil
}

func (u *UsageManager) updateUsage(
	m MetaContext,
	pids []proto.PartyID,
	inQuota bool,
	why string,
	hasPlan bool,
) error {

	doShard := func(db *pgxpool.Conn, pids []proto.PartyID) error {
		pidsDb := core.Map(pids, func(p proto.PartyID) []byte { return p.ExportToDB() })
		_, err := db.Exec(
			m.Ctx(),
			`UPDATE quota_check
		     SET num_new_writes = 0,
		 		check_time = $1,
		 		in_quota = $2 
		 	 WHERE short_host_id = $3 
		 	 AND party_id = ANY($4)`,
			m.Now().UTC(),
			inQuota,
			m.ShortHostID().ExportToDB(),
			pidsDb,
		)
		if err != nil {
			return err
		}
		return nil
	}

	err := m.ForSomeShards(pids, doShard)
	if err != nil {
		return err
	}

	if !inQuota {
		pidsMsg := core.Map(pids, func(p proto.PartyID) string {
			s, _ := p.EntityID().StringErr()
			return s
		})
		m.Infow("killAccess", "shortHostID", m.ShortHostID(), "partyIDs", pidsMsg, "why", why, "hasPlan", hasPlan)
	}
	return nil
}

func queryUsageSum(
	m MetaContext,
	pids []proto.PartyID,
) (
	proto.Size,
	error,
) {
	var sumAll int64
	doShard := func(db *pgxpool.Conn, pids []proto.PartyID) error {
		pidsDB := core.Map(pids, func(p proto.PartyID) []byte { return p.ExportToDB() })

		var sum int64
		err := db.QueryRow(
			m.Ctx(),
			`SELECT COALESCE(SUM(sum_small+sum_large), 0)
 		    FROM usage WHERE short_host_id = $1 AND party_id = ANY($2)`,
			m.ShortHostID().ExportToDB(),
			pidsDB,
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

	err := m.ForSomeShards(pids, doShard)
	if err != nil {
		return 0, err
	}

	usage := proto.Size(sumAll)
	return usage, nil
}

func (u *UsageManager) processFloatingTeam(
	m MetaContext,
	pid proto.PartyID,
	slack proto.Size,
) error {
	if !pid.IsTeam() {
		return core.InternalError("expected team but got user in processFloatingTeam")
	}
	usage, err := queryUsageSum(m, []proto.PartyID{pid})
	if err != nil {
		return err
	}
	inQuota := (usage <= slack)
	return u.updateUsage(m, []proto.PartyID{pid}, inQuota, "floating team usage", false)
}

func (u *UsageManager) ProcessVHostAdmin(
	m MetaContext,
	admin *VHostAdminWithManagedVHosts,
) error {
	usage, err := admin.TotalDiskUsage(m)
	if err != nil {
		return err
	}
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	plan, err := LoadPlanForUser(m, db, admin.Host, admin.Uid)
	if err != nil {
		return err
	}

	fuid, err := admin.Uid.EntityID().Fixed()
	if err != nil {
		return err
	}

	lock := u.locks.Acquire(fuid)
	defer lock.Release()

	var quota proto.Size
	var hasPlan bool
	var slack proto.Size

	if plan != nil && plan.IsLive() {
		quota = plan.Plan.Quota
		hasPlan = true
		slack = u.slacks.PlanUser
	} else {
		slack = u.slacks.NoPlanUser
	}
	overQuota := usage > quota+slack
	err = u.updateUsageVHost(m, admin.ShortHostIDs(), !overQuota, "over-quota", hasPlan)
	if err != nil {
		return err
	}
	return nil
}

func (u *UsageManager) Process(
	m MetaContext,
	pid proto.PartyID,
) error {

	slacks := u.slacks
	qu, err := LoadQuotaUserByKVParty(m, m.ShortHostID(), pid)

	if _, ok := err.(core.UserNotFoundError); ok {
		return u.processFloatingTeam(m, pid, slacks.FloatingTeam)
	}

	if err != nil {
		m.Errorw("processParty", "shortHostID", m.ShortHostID(), "partyID", pid, "err", err)
		return err
	}
	fuid, err := qu.Uid.EntityID().Fixed()
	if err != nil {
		return err
	}

	lock := u.locks.Acquire(fuid)
	defer lock.Release()

	var quota proto.Size
	var hasPlan bool
	var slack proto.Size

	if qu.UserPlan != nil && qu.UserPlan.IsLive() {
		quota = qu.UserPlan.Plan.Quota
		hasPlan = true
		slack = slacks.PlanUser
	} else {
		slack = slacks.NoPlanUser
	}

	usage, err := queryUsageSum(m, qu.Parties())
	if err != nil {
		return err
	}

	teams := core.Map(qu.Teams, func(t proto.TeamID) string {
		s, _ := t.StringErr()
		return s
	})

	if usage > quota+slack {
		m.Infow("processParty",
			"shortHostID", m.ShortHostID(),
			"uid", qu.Uid,
			"teams", teams,
			"usage", usage,
			"slack", slack,
			"quota", quota,
			"hasPlan", hasPlan,
		)
		err = u.updateUsage(m, qu.Parties(), false, "over-quota", hasPlan)
		if err != nil {
			return err
		}
		return nil
	}
	err = u.updateUsage(m, qu.Parties(), true, "", hasPlan)
	if err != nil {
		return err
	}
	return nil
}

type UsageManager struct {
	locks  core.Locktab[proto.FixedEntityID]
	slacks infra.Slacks
}

func NewUsageManager(s infra.Slacks) *UsageManager {
	return &UsageManager{
		slacks: s,
	}
}

func LoadUsageForParties(
	m MetaContext,
	parties []proto.PartyID,
) (
	map[proto.FixedPartyID]proto.Size,
	error,
) {
	ret := make(map[proto.FixedPartyID]proto.Size)

	perShard := func(db *pgxpool.Conn, parties []proto.PartyID) error {

		lst := core.Map(parties, func(p proto.PartyID) []byte { return p.ExportToDB() })
		rows, err := db.Query(
			m.Ctx(),
			`SELECT sum_small+sum_large, party_id 
			FROM usage 
			WHERE short_host_id=$1 AND party_id=ANY($2)`,
			m.ShortHostID(),
			lst,
		)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var sum int64
			var id []byte

			err = rows.Scan(&sum, &id)
			if err != nil {
				return err
			}
			var tmp proto.PartyID
			err = tmp.ImportFromDB(id)
			if err != nil {
				return err
			}
			fpid, err := tmp.Fixed()
			if err != nil {
				return err
			}
			ret[fpid] = proto.Size(sum)
		}
		return nil
	}

	err := m.ForSomeShards(parties, perShard)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func LoadQuotaMastersForTeams(
	m MetaContext,
	teams []proto.TeamID,
) (
	map[proto.FixedEntityID]proto.UID,
	error,
) {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return nil, err
	}
	ids := core.Map(teams, func(t proto.TeamID) []byte { return t.ExportToDB() })
	defer db.Release()
	rows, err := db.Query(
		m.Ctx(),
		`SELECT uid, team_id 
		 FROM team_quota_masters
		 WHERE short_host_id=$1 AND team_id=ANY($2)`,
		m.ShortHostID(),
		ids,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ret := make(map[proto.FixedEntityID]proto.UID)
	for rows.Next() {
		var uidRaw []byte
		var tidRaw []byte
		err = rows.Scan(&uidRaw, &tidRaw)
		if err != nil {
			return nil, err
		}

	}
	return ret, nil
}

func LoadOverQuota(
	m MetaContext,
) error {
	db, err := m.KVShard(m.UID().ToPartyID())
	if err != nil {
		return err
	}
	defer db.Release()
	var inQuota bool
	err = db.QueryRow(
		m.Ctx(),
		`SELECT in_quota FROM quota_check WHERE short_host_id=$1 AND party_id=$2`,
		m.ShortHostID(),
		m.UID().ExportToDB(),
	).Scan(&inQuota)

	if errors.Is(err, pgx.ErrNoRows) {
		return core.UserNotFoundError{}
	}
	if err != nil {
		return err
	}
	if !inQuota {
		return core.OverQuotaError{}
	}
	return nil
}

type PokeID [16]byte

func RandomPokeID() (*PokeID, error) {
	var ret PokeID
	err := core.RandomFill(ret[:])
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (p *PokeID) ExportToDB() []byte {
	return (*p)[:]
}

func InsQuotaPoke(
	m MetaContext,
	tx pgx.Tx,
	pids []proto.PartyID,
) error {
	insOne := func(pid proto.PartyID) error {
		id, err := RandomPokeID()
		if err != nil {
			return err
		}
		tag, err := tx.Exec(
			m.Ctx(),
			`INSERT INTO quota_poke(short_host_id, party_id, poke_id)
		 VALUES($1, $2, $3)
		 ON CONFLICT(short_host_id, party_id)
		 DO UPDATE SET poke_id=$3`,
			m.ShortHostID(),
			pid.ExportToDB(),
			id.ExportToDB(),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.UpdateError("insQuotaPoke")
		}
		return nil
	}
	for _, pid := range pids {
		err := insOne(pid)
		if err != nil {
			return err
		}
	}
	return nil
}

func DelQuotaPoke(
	m MetaContext,
	db *pgxpool.Conn,
	partyID proto.PartyID,
	pokeID PokeID,
) error {
	_, err := db.Exec(
		m.Ctx(),
		`DELETE FROM quota_poke
		 WHERE short_host_id=$1 
		   AND party_id=$2 
		   AND poke_id=$3`,
		m.ShortHostID().ExportToDB(),
		partyID.ExportToDB(),
		pokeID.ExportToDB(),
	)
	if err != nil {
		return err
	}
	return nil
}

func (p *PokeID) ImportFromDB(b []byte) error {
	if len(*p) != len(b) {
		return core.BadServerDataError("pokeID is wrong size")
	}
	copy((*p)[:], b)
	return nil
}

func TestBumpUsage(
	m MetaContext,
	hid *core.HostID,
	partyID proto.PartyID,
	amt proto.Size,
) error {
	m = m.WithHostID(hid)

	db, err := m.KVShard(partyID)
	if err != nil {
		return err
	}
	defer db.Release()

	tags, err := db.Exec(
		m.Ctx(),
		`UPDATE usage
		 SET sum_large = sum_large + $1
	     WHERE short_host_id = $2
		 AND party_id = $3`,
		amt,
		m.ShortHostID().ExportToDB(),
		partyID.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tags.RowsAffected() != 1 {
		return core.UpdateError("bumpUsage")
	}
	return nil
}

func SegmentVHosts(
	m MetaContext,
	vhosts []core.ShortHostID,
) (
	[]VHostAdminWithManagedVHosts,
	error,
) {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()

	var vhidsDb [][]byte
	hmap := m.G().HostIDMap()
	vhidMap := make(map[proto.VHostID]core.ShortHostID)
	for _, shid := range vhosts {
		chid, err := hmap.LookupByShortID(m, shid)
		if err != nil {
			return nil, err
		}
		vhidMap[chid.VId] = shid
		vhidsDb = append(vhidsDb, chid.VId.ExportToDB())
	}

	retMap := make(map[VHostAdmin]map[proto.VHostID]struct{})
	rows, err := db.Query(
		m.Ctx(),
		`SELECT B.vhost_id, B.short_host_id, B.uid
		 FROM vhost_quota_masters AS A
		 JOIN vhost_quota_masters AS B
		 ON (A.uid = B.uid AND A.short_host_id = B.short_host_id)
		 WHERE A.vhost_id=ANY($1)`,
		vhidsDb,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var adminShid int
		var uidRaw, vhidRaw []byte
		err = rows.Scan(&vhidRaw, &adminShid, &uidRaw)
		if err != nil {
			return nil, err
		}
		var uid proto.UID
		err = uid.ImportFromDB(uidRaw)
		if err != nil {
			return nil, err
		}
		var vhid proto.VHostID
		err = vhid.ImportFromDB(vhidRaw)
		if err != nil {
			return nil, err
		}
		admin := VHostAdmin{
			Host: core.ShortHostID(adminShid),
			Uid:  uid,
		}
		if retMap[admin] == nil {
			retMap[admin] = make(map[proto.VHostID]struct{})
		}
		retMap[admin][vhid] = struct{}{}
	}

	ret := make([]VHostAdminWithManagedVHosts, 0, len(retMap))
	for admin, vhosts := range retMap {
		tmp := VHostAdminWithManagedVHosts{
			VHostAdmin: admin,
		}
		tmp.Vhosts = make(map[proto.VHostID]VHost)
		for vhid := range vhosts {
			tmp.Vhosts[vhid] = VHost{
				Id:      vhid,
				ShortID: vhidMap[vhid],
			}
		}
		ret = append(ret, tmp)
	}
	return ret, nil
}
