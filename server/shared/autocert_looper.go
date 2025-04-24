// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"errors"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AutocertHostError struct {
	Hostname proto.Hostname
	Err      error
}

type AutocertLooper struct {
	sync.Mutex
	swtch   *AutocertSwitchboard
	port    proto.Port
	acdoer  AutocertDoer
	accfg   AutocertServiceConfigger
	vhc     VHostsConfigger
	pkgCh   chan infra.AutocertPackage
	shidCh  chan core.ShortHostID
	eofCh   chan struct{}
	batchSz int

	// In test, can get notified on a host failure
	testFailCh chan *AutocertHostError
	testSuccCh chan proto.Hostname
}

func NewAutocertLooper(
	accfg AutocertServiceConfigger,
	vhc VHostsConfigger,
	acdoer AutocertDoer,
) *AutocertLooper {
	return &AutocertLooper{
		accfg:  accfg,
		vhc:    vhc,
		swtch:  NewAutocertSwitchboard(),
		acdoer: acdoer,
		pkgCh:  make(chan infra.AutocertPackage),
		shidCh: make(chan core.ShortHostID),
	}
}

func (a *AutocertLooper) SetTestFailCh(ch chan *AutocertHostError) {
	a.Lock()
	defer a.Unlock()
	a.testFailCh = ch
}

func (a *AutocertLooper) SetTestSuccessCh(ch chan proto.Hostname) {
	a.Lock()
	defer a.Unlock()
	a.testSuccCh = ch
}

func (a *AutocertLooper) Start(m MetaContext) error {
	a.Lock()
	defer a.Unlock()
	port, err := a.acdoer.GetBindAddr().GetPort()
	if err != nil {
		return err
	}
	a.port = port

	err = a.acdoer.Start(m)
	if err != nil {
		return err
	}
	a.batchSz = a.accfg.GetLooperConfigger().BatchSize()
	if a.eofCh != nil {
		return nil
	}
	a.eofCh = make(chan struct{})
	go a.run(m.Background())
	return nil
}

func (a *AutocertLooper) Stop() {
	a.Lock()
	defer a.Unlock()
	a.acdoer.Stop()
	if a.eofCh == nil {
		return
	}
	ch := a.eofCh
	a.eofCh = nil
	close(ch)
}

func (a *AutocertLooper) getStateForHostnameType(
	m MetaContext,
	db *pgxpool.Conn,
	hn proto.Hostname,
	styp proto.ServerType,
	chid core.HostID,
) (
	proto.AutocertState,
	error,
) {
	var stateRaw string
	var shid int
	err := db.QueryRow(
		m.Ctx(),
		`SELECT state, short_host_id 
		 FROM autocert_run_queue 
		 WHERE hostname=$1 AND cancel_id=$2 AND server_type=$3`,
		hn.Normalize(),
		proto.NilCancelID(),
		int(styp),
	).Scan(&stateRaw, &shid)
	var zed proto.AutocertState
	if errors.Is(err, pgx.ErrNoRows) {
		return proto.AutocertState_None, nil
	}
	if err != nil {
		return zed, err
	}
	var ret proto.AutocertState
	err = ret.ImportFromDB(stateRaw)
	if err != nil {
		return zed, err
	}
	if chid.Short != core.ShortHostID(shid) {
		return zed, core.HostMismatchError{}
	}
	return ret, nil
}

func (a *AutocertLooper) newHost(
	m MetaContext,
	db *pgxpool.Conn,
	chid core.HostID,
	pkg infra.AutocertPackage,
) error {
	acid, err := proto.RandomID16er[proto.AutocertID]()
	if err != nil {
		return err
	}
	now := m.Now()
	tag, err := db.Exec(
		m.Ctx(),
		`INSERT INTO autocert_run_queue
		  (short_host_id, autocert_id, hostname, cancel_id, scheduled_next, priority,
		   num_succ, num_failures, ctime, state, server_type, is_vanity)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`,
		chid.Short.ExportToDB(),
		acid.ExportToDB(),
		pkg.Hostname.Normalize(),
		proto.NilCancelID(),
		now.Add(-24*time.Hour),
		1,
		0,
		0,
		now,
		proto.AutocertState_None.String(),
		int(pkg.Styp),
		pkg.IsVanity,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("autocert_run_queue")
	}
	return nil
}

var errAutocertNeedWait = errors.New("autocert need wait")

func (a *AutocertLooper) loadOrCreate(
	m MetaContext,
	chid core.HostID,
	pkg infra.AutocertPackage,
) error {
	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return err
	}
	defer db.Release()

	state, err := a.getStateForHostnameType(m, db, pkg.Hostname, pkg.Styp, chid)
	if err != nil {
		return err
	}
	switch state {
	case proto.AutocertState_Failed:
		return core.AutocertFailedError{}
	case proto.AutocertState_Failing:
		return errAutocertNeedWait
	case proto.AutocertState_OK:
		return nil
	}
	err = a.newHost(m, db, chid, pkg)
	if err != nil {
		return err
	}
	return errAutocertNeedWait
}

func (a *AutocertLooper) doHost(
	m MetaContext,
	pkg infra.AutocertPackage,
) error {
	chid, err := m.G().HostIDMap().LookupByHostID(m, pkg.Hostid)
	doBroadcast := func(err error) error {
		return a.swtch.Broadcast(m.Ctx(),
			AutocertHost{
				Hostname: pkg.Hostname,
				Stype:    pkg.Styp,
			},
			err,
		)
	}
	if err != nil {
		return doBroadcast(err)
	}
	err = a.loadOrCreate(m, *chid, pkg)
	if !errors.Is(err, errAutocertNeedWait) {
		return doBroadcast(err)
	}
	err = a.doSome(m, chid.Short)
	if err != nil {
		return err
	}
	return nil
}

type autocertRow struct {
	acid    proto.AutocertID
	hn      proto.Hostname
	shid    core.ShortHostID
	stype   proto.ServerType
	expires time.Time
	isVan   bool
	pri     int
	numFail int
	numSucc int
}

func (a autocertRow) asKey() AutocertHost {
	return AutocertHost{
		Hostname: a.hn,
		Stype:    a.stype,
	}
}

func (a *AutocertLooper) fetchBatch(
	m MetaContext,
	db *pgxpool.Conn,
) (
	[]autocertRow,
	error,
) {
	now := m.Now()
	rows, err := db.Query(
		m.Ctx(),
		`SELECT autocert_id, hostname, short_host_id, server_type, is_vanity,
		   priority, num_failures, num_succ, expires
		FROM autocert_run_queue 
		WHERE short_host_id=$1
		AND scheduled_next <= $2
		AND cancel_id=$3
		AND state!=$4
		ORDER by priority ASC
		LIMIT $5`,
		m.ShortHostID().ExportToDB(),
		now,
		proto.NilCancelID(),
		proto.AutocertState_Failed.String(),
		a.batchSz,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ret []autocertRow
	for rows.Next() {
		var idRaw []byte
		var hnRaw string
		var shidRaw int
		var stypeRaw int
		var isVan bool
		var pri, numFail, numSucc int
		var expires *time.Time
		err := rows.Scan(&idRaw, &hnRaw, &shidRaw, &stypeRaw, &isVan, &pri, &numFail, &numSucc, &expires)
		if err != nil {
			return nil, err
		}
		item := autocertRow{
			hn:      proto.Hostname(hnRaw),
			shid:    core.ShortHostID(shidRaw),
			isVan:   isVan,
			stype:   proto.ServerType(stypeRaw),
			pri:     pri,
			numFail: numFail,
			numSucc: numSucc,
		}
		err = item.acid.ImportFromDB(idRaw)
		if err != nil {
			return nil, err
		}
		if expires != nil {
			item.expires = *expires
		}
		ret = append(ret, item)
	}
	return ret, nil
}

func (a *AutocertLooper) makePackage(
	m MetaContext,
	item autocertRow,
) (
	*AutocertPackage,
	error,
) {
	pkg, err := m.G().Config().AutocertPackage(m.Ctx(), item.stype, a.port)
	if err != nil {
		return nil, err
	}
	chid, err := m.G().HostIDMap().LookupByShortID(m, item.shid)
	if err != nil {
		return nil, err
	}
	pkg.HostID = chid.Id
	pkg.Hostname = item.hn.Normalize()
	pkg.IsVanity = item.isVan
	pkg.ServerType = item.stype
	if !item.isVan {
		return pkg, nil
	}
	ato := a.accfg.AcmeTimeout()
	pkg.Timeout = ato

	err = autocertPackageForVanity(m, a.vhc, pkg)
	if err != nil {
		return nil, err
	}
	return pkg, nil
}

func (a *AutocertLooper) markSuccess(
	m MetaContext,
	db *pgxpool.Conn,
	item autocertRow,
) error {
	now := m.Now()
	expire := now.Add(a.accfg.ExpireIn())
	refresh := now.Add(a.accfg.RefreshIn())
	tag, err := db.Exec(
		m.Ctx(),
		`UPDATE autocert_run_queue
		   SET num_succ=num_succ+1,
		     num_failures=0,
		     issued=$1,
		     expires=$2,
		     last_succ=$1,
		     scheduled_next=$3,
		     priority=50,
		     state=$4
		 WHERE short_host_id=$5
		   AND autocert_id=$6
		   AND server_type=$7`,
		now,
		expire,
		refresh,
		proto.AutocertState_OK.String(),
		item.shid.ExportToDB(),
		item.acid.ExportToDB(),
		int(item.stype),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("autocert_run_queue")
	}
	err = a.swtch.Broadcast(m.Ctx(), item.asKey(), nil)
	if err != nil {
		return err
	}
	if a.testSuccCh != nil {
		a.testSuccCh <- item.hn
	}
	return nil
}

func (a *AutocertLooper) WaitFor(
	m MetaContext,
	hn proto.Hostname,
	typ proto.ServerType,
	d time.Duration,
) error {
	return a.swtch.Wait(m.Ctx(), AutocertHost{Hostname: hn, Stype: typ}, d)
}

func (a *AutocertLooper) markFailure(
	m MetaContext,
	db *pgxpool.Conn,
	item autocertRow,
) error {
	now := m.Now()
	var wait time.Duration
	state := proto.AutocertState_Failing
	pri := item.pri

	ibck := a.accfg.InitialBackoffs()
	pri++

	if item.numSucc == 0 {
		if item.numFail >= len(ibck) {
			state = proto.AutocertState_Failed
			m.Infow("markFailure", "numFail", item.numFail, "newState", state.String())
		} else {
			wait = ibck[item.numFail]
			m.Infow("markFailure", "numFail", item.numFail, "len(ibck)", len(ibck), "wait", wait)
		}
	} else {
		wait = a.accfg.RefreshBackoff()
		if !item.expires.IsZero() && now.Sub(item.expires) > wait {
			state = proto.AutocertState_Failed
		}
	}

	tag, err := db.Exec(
		m.Ctx(),
		`UPDATE autocert_run_queue
		   SET state=$1,
			 num_failures=num_failures+1,
			 scheduled_next=$2,
			 priority=$3
		   WHERE short_host_id=$4
		     AND autocert_id=$5`,
		state.String(),
		now.Add(wait),
		pri,
		item.shid.ExportToDB(),
		item.acid.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("autocert_run_queue")
	}

	if a.testFailCh != nil {
		a.testFailCh <- &AutocertHostError{
			Hostname: item.hn,
			Err:      core.AutocertFailedError{},
		}
	}

	if state == proto.AutocertState_Failed {
		err = a.swtch.Broadcast(m.Ctx(), item.asKey(), core.AutocertFailedError{})
		if err != nil {
			return err
		}
	}
	return nil

}

func (a *AutocertLooper) logAction(
	m MetaContext,
	db *pgxpool.Conn,
	item autocertRow,
	err error,
) error {
	now := m.Now()
	var errstr string
	if err != nil {
		errstr = err.Error()
	}
	tag, err := db.Exec(
		m.Ctx(),
		`INSERT INTO autocert_log
		  (short_host_id, autocert_id, ctime, succ, error, num_failures, num_succ)
		VALUES($1, $2, $3, $4, $5, $6, $7)`,
		item.shid.ExportToDB(),
		item.acid.ExportToDB(),
		now,
		err == nil,
		errstr,
		item.numFail,
		item.numSucc,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("autocert_log")
	}
	return nil
}

func (a *AutocertLooper) doOne(
	m MetaContext,
	db *pgxpool.Conn,
	item autocertRow,
) error {

	pkg, err := a.makePackage(m, item)
	if err != nil {
		return err
	}

	m.Infow("AutocertLooper.doOne", "hn", pkg.Hostname, "stage", "enter")
	err = a.acdoer.DoOne(m, *pkg)
	m.Infow("AutocertLooper.doOne", "hn", pkg.Hostname, "stage", "exit", "err", err)

	logErr := a.logAction(m, db, item, err)

	var markError error

	if err == nil {
		markError = a.markSuccess(m, db, item)
	} else {
		markError = a.markFailure(m, db, item)
	}

	if err != nil {
		return err
	}
	if markError != nil {
		return markError
	}
	if logErr != nil {
		return logErr
	}

	return nil
}

func (a *AutocertLooper) doSome(
	m MetaContext,
	shid core.ShortHostID,
) error {
	chid, err := m.G().HostIDMap().LookupByShortID(m, shid)
	if err != nil {
		return err
	}
	m = m.WithHostID(chid)

	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return err
	}
	defer db.Release()
	btch, err := a.fetchBatch(m, db)
	if err != nil {
		m.Warnw("AutocertLooper.doSome", "stage", "fetchBatch", "err", err)
		return err
	}
	for _, item := range btch {
		err := a.doOne(m, db, item)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *AutocertLooper) run(m MetaContext) {
	keepGoing := true
	for keepGoing {
		select {
		case pkg := <-a.pkgCh:
			err := a.doHost(m, pkg)
			if err != nil {
				m.Warnw("AutocertLooper.run", "stage", "doHost", "err", err)
			}
		case shid := <-a.shidCh:
			err := a.doSome(m, shid)
			if err != nil {
				m.Warnw("AutocertLooper.run", "stage", "doSome", "err", err)
			}
		case <-a.eofCh:
			keepGoing = false
		}
	}
}

func (a *AutocertLooper) PollReadyHosts(m MetaContext) ([]core.ShortHostID, error) {
	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return nil, err
	}
	defer db.Release()
	now := m.Now()
	rows, err := db.Query(
		m.Ctx(),
		`SELECT DISTINCT(short_host_id)
		 FROM autocert_run_queue
		 WHERE scheduled_next <= $1
		 AND cancel_id=$2
		 AND state!=$3`,
		now,
		proto.NilCancelID(),
		proto.AutocertState_Failed.String(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ret []core.ShortHostID
	for rows.Next() {
		var shid int
		err := rows.Scan(&shid)
		if err != nil {
			return nil, err
		}
		ret = append(ret, core.ShortHostID(shid))
	}
	m.Infow("PollReadyHosts", "ret", ret)
	return ret, nil
}

func (a *AutocertLooper) DoHost(m MetaContext, arg infra.DoAutocertArg) error {
	m.Infow("AutocertLooper.DoHost", "hn", arg.Pkg.Hostname, "styp", arg.Pkg.Styp.String())
	a.pkgCh <- arg.Pkg
	err := a.swtch.Wait(
		m.Ctx(),
		AutocertHost{
			Hostname: arg.Pkg.Hostname,
			Stype:    arg.Pkg.Styp,
		},
		arg.WaitFor.Duration(),
	)
	return err
}

func (a *AutocertLooper) DoSome(m MetaContext) error {
	a.shidCh <- m.ShortHostID()
	return nil
}

func OneshotAutocert(
	m MetaContext,
	arg infra.DoAutocertArg,
	port proto.Port,
) error {
	m.Infow(
		"OneshotAutocert",
		"hostname", arg.Pkg.Hostname,
		"styp", arg.Pkg.Styp.String(),
	)
	if arg.Pkg.Styp == proto.ServerType_None {
		return core.InternalError("ServerType_None passed to OneshotAutocert")
	}
	cfg, err := m.G().Config().AutocertServiceConfig(m.Ctx())
	if err != nil {
		return err
	}
	vhc, err := m.G().Config().VHostsConfig(m.Ctx())
	if err != nil {
		return err
	}

	doer, err := m.G().AutocertDoerAtAddr(m.Ctx(), port)
	if err != nil {
		return err
	}
	looper := NewAutocertLooper(cfg, vhc, doer)
	err = looper.Start(m)
	if err != nil {
		return err
	}
	defer looper.Stop()

	err = looper.DoHost(m, arg)
	if err != nil {
		return err
	}
	return nil
}
