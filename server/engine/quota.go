// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package engine

import (
	"context"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type QuotaServer struct {
	shared.BaseRPCServer
	lock     *shared.Lock
	cfg      shared.QuotaServerConfigger
	pokeCh   chan chan<- error
	usageMgr *shared.UsageManager

	tstMu sync.RWMutex
	tst   *infra.QuotaConfig
}

type QuotaClientConn struct {
	shared.BaseClientConn
	srv *QuotaServer
	xp  rpc.Transporter
}

func (s *QuotaServer) ToRPCServer() shared.RPCServer { return s }

func (q *QuotaServer) SetTestParams(tst *infra.QuotaConfig) error {
	q.tstMu.Lock()
	defer q.tstMu.Unlock()
	q.tst = tst
	var slacks infra.Slacks
	if tst != nil {
		slacks = tst.Slacks
	} else {
		tmp, err := q.cfg.GetSlacks()
		if err != nil {
			return err
		}
		slacks = *tmp
	}
	q.usageMgr = shared.NewUsageManager(slacks)
	return nil
}

func (q *QuotaServer) NewClientConn(xp rpc.Transporter, uhc shared.UserHostContext) shared.ClientConn {
	return &QuotaClientConn{
		srv:            q,
		xp:             xp,
		BaseClientConn: shared.NewBaseClientConn(q.G(), uhc),
	}
}

func (q *QuotaServer) ServerType() proto.ServerType {
	return proto.ServerType_Quota
}

func (q *QuotaServer) RequireAuth() shared.AuthType { return shared.AuthTypeInternal }
func (q *QuotaServer) CheckDeviceKey(m shared.MetaContext, uhc shared.UserHostContext, key proto.EntityID) (*proto.Role, error) {
	return nil, shared.CheckKeyValidInternal(m, uhc, key)
}

func (q *QuotaServer) Setup(m shared.MetaContext) error {
	var err error
	q.lock, err = shared.NewLock(q.GetHostID().Short, q.ServerType())
	if err != nil {
		return err
	}
	q.cfg, err = m.G().Config().QuotaServerConfig(m.Ctx())
	if err != nil {
		return err
	}
	slacks, err := q.cfg.GetSlacks()
	if err != nil {
		return err
	}
	q.usageMgr = shared.NewUsageManager(*slacks)
	q.pokeCh = make(chan chan<- error)
	return nil
}

func (q *QuotaServer) IsInternal() bool { return true }

func (c *QuotaClientConn) RegisterProtocols(m shared.MetaContext, srv *rpc.Server) error {
	return srv.RegisterV2(infra.QuotaProtocol(c))
}

func (s *QuotaServer) RunBackgroundLoops(m shared.MetaContext, shutdownCh chan<- error) error {
	return s.RunBackgroundLoopsWithLooper(m, shutdownCh, s)
}

func (s *QuotaServer) GetNoPlanMaxTeams() int {
	s.tstMu.RLock()
	defer s.tstMu.RUnlock()
	ret := s.tst.NoPlanMaxTeams
	if ret >= 0 {
		return int(ret)
	}
	return s.cfg.GetNoPlanMaxTeams()
}

func (s *QuotaServer) DoResurrection() bool {
	s.tstMu.RLock()
	defer s.tstMu.RUnlock()
	if s.tst == nil {
		return true
	}
	return !s.tst.NoResurrection
}

func (c *QuotaClientConn) ErrorWrapper() func(error) proto.Status {
	return core.ErrorToStatus
}

func (s *QuotaServer) Poke() error {
	retCh := make(chan error)
	s.pokeCh <- retCh
	return <-retCh
}

func (c *QuotaClientConn) Poke(ctx context.Context) error {
	return c.srv.Poke()
}

var _ shared.Looper = (*QuotaServer)(nil)

func (c *QuotaServer) GetName() string                         { return "QuotaCheckServer" }
func (c *QuotaServer) GetLock() *shared.Lock                   { return c.lock }
func (c *QuotaServer) GetConfig() shared.ServerLooperConfigger { return c.cfg }
func (c *QuotaServer) GetPokeCh() chan chan<- error            { return c.pokeCh }
func (c *QuotaServer) InitLoop(m shared.MetaContext) error     { return nil }

func (c *QuotaServer) GetDelay() time.Duration {
	c.tstMu.RLock()
	defer c.tstMu.RUnlock()
	if c.tst != nil {
		return c.tst.Delay.Duration()
	}
	return c.cfg.GetDelay()
}

func (c *QuotaServer) PollReadyHosts(m shared.MetaContext) ([]core.ShortHostID, error) {
	set := make(map[core.ShortHostID]bool)
	err := c.pollReadyHostsKVDB(m, set)
	if err != nil {
		return nil, err
	}
	err = c.pollReadyHostsUserDB(m, set)
	if err != nil {
		return nil, err
	}
	out := make([]core.ShortHostID, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out, nil
}

func (c *QuotaServer) pollReadyHostsUserDB(
	m shared.MetaContext,
	out map[core.ShortHostID]bool,
) error {
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	rows, err := db.Query(
		m.Ctx(),
		`SELECT DISTINCT(short_host_id)
		FROM quota_poke`,
	)
	if err != nil {
		return err
	}
	collect := func(rows pgx.Rows) error {
		defer rows.Close()
		for rows.Next() {
			var shidRaw int
			err = rows.Scan(&shidRaw)
			if err != nil {
				return err
			}
			out[core.ShortHostID(shidRaw)] = true
		}
		return nil
	}
	err = collect(rows)
	if err != nil {
		return err
	}
	cfg, err := m.G().Config().QuotaServerConfig(m.Ctx())
	if err != nil {
		return err
	}
	slacks, err := cfg.GetSlacks()
	if err != nil {
		return err
	}
	slack := slacks.PaidThrough.Duration()

	rows, err = db.Query(
		m.Ctx(),
		`SELECT DISTINCT(short_host_id)
		FROM user_plans
		WHERE paid_through < $1`,
		m.Now().Add(-slack).UTC(),
	)
	if err != nil {
		return err
	}
	err = collect(rows)
	if err != nil {
		return err
	}

	return nil
}

func (c *QuotaServer) pollReadyHostsKVDB(
	m shared.MetaContext,
	out map[core.ShortHostID]bool,
) error {

	tmp := make(map[core.ShortHostID]bool)
	doShard := func(db *pgxpool.Conn) error {

		rows, err := db.Query(
			m.Ctx(),
			`(
				SELECT DISTINCT(short_host_id)
		 		FROM quota_check
		 		WHERE num_new_writes > 0
		 		AND check_time < $1
			) UNION (
			 	SELECT DISTINCT(short_host_id)
				FROM quota_check_vhost
				WHERE num_new_writes > 0
				AND check_time < $1	
		   )`,
			m.Now().Add(-c.GetDelay()).UTC(),
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		ret, err := scanShortHostIDs(rows)
		if err != nil {
			return err
		}
		for _, i := range ret {
			tmp[i] = true
		}
		return nil
	}
	err := m.ForAllShards(doShard)
	if err != nil {
		return err
	}
	var ret []core.ShortHostID
	for k := range tmp {
		ret = append(ret, k)
		out[k] = true
	}
	m.Infow("pollReadyHostsKVDB", "ready", ret)
	return nil
}

func (c *QuotaServer) loadBatchVhosts(
	m shared.MetaContext,
) ([]core.ShortHostID, error) {

	vhostMap := make(map[core.ShortHostID]bool)

	doShard := func(db *pgxpool.Conn) error {
		rows, err := db.Query(
			m.Ctx(),
			`SELECT short_host_id
			 FROM quota_check_vhost
			 WHERE num_new_writes > 0
			 AND check_time < $1
			 ORDER BY check_time ASC
			 LIMIT $2`,
			m.Now().Add(-c.GetDelay()).UTC(),
			c.cfg.BatchSize(),
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var shidRaw int
			err = rows.Scan(&shidRaw)
			if err != nil {
				return err
			}
			vhostMap[core.ShortHostID(shidRaw)] = true
		}
		return nil
	}
	err := m.ForAllShards(doShard)
	if err != nil {
		return nil, err
	}
	ret := core.Keys(vhostMap)
	return ret, nil
}

func (c *QuotaServer) loadBatch(
	m shared.MetaContext,
) ([]proto.PartyID, error) {

	var ret []proto.PartyID
	doShard := func(db *pgxpool.Conn) error {

		rows, err := db.Query(
			m.Ctx(),
			`SELECT party_id 
		 	 FROM quota_check 
		 	 WHERE num_new_writes > 0
		 	 AND short_host_id = $1
		 	 AND check_time < $2
		 	 ORDER BY check_time ASC
		 	 LIMIT $3`,
			m.ShortHostID().ExportToDB(),
			m.Now().Add(-c.GetDelay()).UTC(),
			c.cfg.BatchSize(),
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var pidRaw []byte
			err = rows.Scan(&pidRaw)
			if err != nil {
				return err
			}
			var pid proto.PartyID
			err = pid.ImportFromDB(pidRaw)
			if err != nil {
				return err
			}
			ret = append(ret, pid)
		}
		return nil
	}
	err := m.ForAllShards(doShard)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

type pokePair struct {
	partyID proto.PartyID
	pokeID  shared.PokeID
}

func (c *QuotaServer) loadPokeBatch(
	m shared.MetaContext,
	db *pgxpool.Conn,
) (
	[]pokePair,
	error,
) {
	rows, err := db.Query(
		m.Ctx(),
		`SELECT party_id, poke_id FROM quota_poke
		 WHERE short_host_id=$1 LIMIT 50`,
		m.ShortHostID().ExportToDB(),
	)
	if err != nil {
		return nil, err
	}
	var ret []pokePair
	defer rows.Close()
	for rows.Next() {
		var party, poke []byte
		err = rows.Scan(&party, &poke)
		if err != nil {
			return nil, err
		}
		var pair pokePair
		err = pair.partyID.ImportFromDB(party)
		if err != nil {
			return nil, err
		}
		err = pair.pokeID.ImportFromDB(poke)
		if err != nil {
			return nil, err
		}
		ret = append(ret, pair)
	}
	return ret, nil
}

type userSubPair struct {
	uid proto.UID
	sub infra.StripeSubscriptionID
}

func (c *QuotaServer) loadExpiringUsers(
	m shared.MetaContext,
	db *pgxpool.Conn,
) (
	[]userSubPair,
	error,
) {
	slacks, err := c.cfg.GetSlacks()
	if err != nil {
		return nil, err
	}
	slack := slacks.PaidThrough.Duration()
	rows, err := db.Query(
		m.Ctx(),
		`SELECT uid, stripe_sub_id FROM user_plans
		 WHERE short_host_id=$1 AND paid_through < $2 AND cancel_id=$3
		 LIMIT $4`,
		m.ShortHostID().ExportToDB(),
		m.Now().Add(-slack).UTC(),
		proto.NilCancelID(),
		c.cfg.BatchSize(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ret []userSubPair
	for rows.Next() {
		var uid []byte
		var sub string
		err = rows.Scan(&uid, &sub)
		if err != nil {
			return nil, err
		}
		var pair userSubPair
		err = pair.uid.ImportFromDB(uid)
		if err != nil {
			return nil, err
		}
		pair.sub = infra.StripeSubscriptionID(sub)
		ret = append(ret, pair)
	}
	return ret, nil
}

func (c *QuotaServer) doOnePollForHostQuotaCheck(m shared.MetaContext) error {
	parties, err := c.loadBatch(m)
	if err != nil {
		return err
	}
	for _, pid := range parties {
		err = c.usageMgr.Process(m, pid)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *QuotaServer) doOnePollForHostQuotaCheckVHost(m shared.MetaContext) error {
	vhosts, err := c.loadBatchVhosts(m)
	if err != nil {
		return err
	}
	admins, err := shared.SegmentVHosts(m, vhosts)
	if err != nil {
		return err
	}
	for _, admin := range admins {
		err = c.usageMgr.ProcessVHostAdmin(m, &admin)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *QuotaServer) doOnePollForHostPokes(m shared.MetaContext) error {
	udb, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer udb.Release()
	pps, err := c.loadPokeBatch(m, udb)
	if err != nil {
		return err
	}
	for _, pp := range pps {
		err = c.usageMgr.Process(m, pp.partyID)
		if err != nil {
			return err
		}
		err = shared.DelQuotaPoke(m, udb, pp.partyID, pp.pokeID)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *QuotaServer) doOnePollForHostExpiringUsers(m shared.MetaContext) error {
	udb, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer udb.Release()

	sups, err := c.loadExpiringUsers(m, udb)
	if err != nil {
		return err
	}
	for _, sup := range sups {

		var resurrected bool

		if c.DoResurrection() {
			// It could be that we missed a webhook, so just check that the subscription
			// is indeed dead as far as Stripe is concerned.
			var err error
			resurrected, err = shared.ResurrectPlan(m, udb, sup.uid, sup.sub)
			if err != nil {
				return err
			}
		}

		err = c.usageMgr.Process(m, sup.uid.ToPartyID())
		if err != nil {
			return err
		}

		if !resurrected {
			err = shared.CancelPlanForUserWithSub(m, udb, sup.uid, sup.sub)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *QuotaServer) DoOnePollForHost(m shared.MetaContext) error {

	err := c.doOnePollForHostQuotaCheck(m)
	if err != nil {
		return err
	}
	err = c.doOnePollForHostQuotaCheckVHost(m)
	if err != nil {
		return err
	}
	err = c.doOnePollForHostPokes(m)
	if err != nil {
		return err
	}
	err = c.doOnePollForHostExpiringUsers(m)
	if err != nil {
		return err
	}
	return nil
}

func (c *QuotaClientConn) asTesting(
	ctx context.Context,
	f func(m shared.MetaContext) error,
) error {
	m := shared.NewMetaContextConn(ctx, c)
	set, err := m.G().Config().Settings(ctx)
	if err != nil {
		return err
	}
	if !set.Testing {
		return core.TestingOnlyError{}
	}
	return f(m)
}

func (c *QuotaClientConn) TestSetConfig(ctx context.Context, cfg infra.QuotaConfig) error {
	return c.asTesting(ctx, func(m shared.MetaContext) error {
		return c.srv.SetTestParams(&cfg)
	})
}

func (c *QuotaClientConn) TestUnsetConfig(ctx context.Context) error {
	return c.asTesting(ctx, func(m shared.MetaContext) error {
		return c.srv.SetTestParams(nil)
	})
}

func withDBs(
	m shared.MetaContext,
	dbs []shared.DbType,
	f func(m shared.MetaContext, dbs []*pgxpool.Conn) error,
) error {
	arg := make([]*pgxpool.Conn, len(dbs))
	for i, dbType := range dbs {
		db, err := m.Db(dbType)
		if err != nil {
			return err
		}
		arg[i] = db
	}
	defer func() {
		for _, db := range arg {
			db.Release()
		}
	}()
	return f(m, arg)
}

func withDB(
	m shared.MetaContext,
	db shared.DbType,
	f func(m shared.MetaContext, db *pgxpool.Conn) error,
) error {
	return withDBs(m, []shared.DbType{db}, func(m shared.MetaContext, dbs []*pgxpool.Conn) error {
		return f(m, dbs[0])
	})
}

func (c *QuotaClientConn) TestBumpUsage(ctx context.Context, arg infra.TestBumpUsageArg) error {
	return c.asTesting(ctx, func(m shared.MetaContext) error {
		hid, err := m.G().HostIDMap().LookupByHostID(m, arg.Hid)
		if err != nil {
			return err
		}
		return shared.TestBumpUsage(m, hid, arg.Pid, arg.Amt)
	})
}

func (c *QuotaClientConn) MakePlan(
	ctx context.Context,
	arg infra.MakePlanArg,
) (
	infra.Plan,
	error,
) {
	m := shared.NewMetaContextConn(ctx, c)
	pm := shared.NewPlanMaker(&arg.Plan, arg.Opts)
	var zed infra.Plan
	err := pm.Run(m)
	if err != nil {
		return zed, err
	}
	ret := pm.Obj()
	return *ret, nil
}

func (c *QuotaClientConn) SetPlan(
	ctx context.Context,
	arg infra.SetPlanArg,
) (
	proto.CancelID,
	error,
) {
	m := shared.NewMetaContextConn(ctx, c)
	var ret proto.CancelID
	hid, err := m.G().HostIDMap().LookupByHostID(m, arg.Fqu.HostID)
	if err != nil {
		return ret, err
	}
	err = withDB(m, shared.DbTypeUsers, func(m shared.MetaContext, db *pgxpool.Conn) error {
		return shared.RetryTx(m, db, "setPlan", func(m shared.MetaContext, tx pgx.Tx) error {
			plan, err := shared.LoadPlanForUser(m, tx, hid.Short, arg.Fqu.Uid)
			switch err.(type) {
			case nil:
				if !arg.Replace {
					return core.PlanExistsError{}
				}
				cid, err := shared.CancelPlanForUser(m, tx, hid.Short, arg.Fqu.Uid, plan.Plan.Id)
				if err != nil {
					return err
				}
				ret = *cid
			case core.NoActivePlanError:
			default:
				return err
			}
			err = shared.SetPlanForUser(m, tx, hid.Short, arg.Fqu.Uid, arg.Plan, arg.Price,
				m.Now().Add(arg.ValidFor.Duration()),
				arg.StripeSubId,
			)
			if err != nil {
				return err
			}
			return nil
		})
	})
	if err != nil {
		return ret, err
	}

	// Now reprocess all quota computations, to maybe mark the user or their teams
	// within quota.
	m = m.WithHostID(hid)
	err = c.srv.usageMgr.Process(m, arg.Fqu.Uid.ToPartyID())
	if err != nil {
		return ret, err
	}
	return ret, err
}

func (c *QuotaClientConn) CancelPlan(
	ctx context.Context,
	fqu proto.FQUser,
) (
	proto.CancelID,
	error,
) {
	m := shared.NewMetaContextConn(ctx, c)
	var ret proto.CancelID
	err := withDB(m, shared.DbTypeUsers, func(m shared.MetaContext, db *pgxpool.Conn) error {
		hid, err := m.G().HostIDMap().LookupByHostID(m, fqu.HostID)
		if err != nil {
			return err
		}
		return shared.RetryTx(m, db, "cancelPlan", func(m shared.MetaContext, tx pgx.Tx) error {
			cid, err := shared.CancelPlanForUser(m, tx, hid.Short, fqu.Uid, proto.PlanID{})
			if err != nil {
				return err
			}
			ret = *cid
			return nil
		})
	})
	if err != nil {
		return ret, err
	}
	return ret, nil
}

func (c *QuotaClientConn) AssignQuotaMaster(ctx context.Context, arg infra.AssignQuotaMasterArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	return withDB(m, shared.DbTypeUsers, func(m shared.MetaContext, db *pgxpool.Conn) error {
		hid, err := m.G().HostIDMap().LookupByHostID(m, arg.Fqu.HostID)
		if err != nil {
			return err
		}
		return shared.RetryTx(m, db, "assignQuotaMaster", func(m shared.MetaContext, tx pgx.Tx) error {
			m = m.WithHostID(hid)
			err := shared.AssignQuotaMaster(m, tx, arg.Fqu.Uid, arg.Team, c.srv.GetNoPlanMaxTeams())
			if err != nil {
				return err
			}
			return nil
		})
	})
}

func (c *QuotaClientConn) UnassignQuotaMaster(ctx context.Context, arg infra.UnassignQuotaMasterArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	return withDB(m, shared.DbTypeUsers, func(m shared.MetaContext, db *pgxpool.Conn) error {
		hid, err := m.G().HostIDMap().LookupByHostID(m, arg.Fqu.HostID)
		if err != nil {
			return err
		}
		return shared.RetryTx(m, db, "assignQuotaMaster", func(m shared.MetaContext, tx pgx.Tx) error {
			m = m.WithHostID(hid)
			err := shared.UnassignQuotaMaster(m, tx, arg.Fqu.Uid, arg.Team)
			if err != nil {
				return err
			}
			return nil
		})
	})
}

var _ shared.ClientConn = (*QuotaClientConn)(nil)
var _ shared.RPCServer = (*QuotaServer)(nil)
var _ infra.QuotaInterface = (*QuotaClientConn)(nil)
