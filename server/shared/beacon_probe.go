// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5"
)

// BeaconProbe is like the probe client found in libclient, except it's simplified
// since it's meant to run in the beacon. It doesn't check merkle trees, and it
// only stores one row per host, for now. This storage is in SQL not SQLite. So it's
// slightly different.
type BeaconProbe struct {
	host    proto.Hostname
	port    proto.Port
	addr    proto.TCPAddr
	hostID  proto.HostID
	timeout time.Duration
	res     *rem.ProbeRes
	prev    *core.Hostchain
	ch      *core.Hostchain
	pz      *proto.PublicZone
}

func NewBeaconProbe(h proto.Hostname, p proto.Port, i proto.HostID, t time.Duration) *BeaconProbe {
	return &BeaconProbe{
		host:    h,
		port:    p,
		hostID:  i,
		timeout: t,
		prev:    nil,
		addr:    proto.NewTCPAddr(h, p),
	}
}

func (b *BeaconProbe) loadPrev(m MetaContext, tx pgx.Tx) error {

	var tailRaw []byte
	var seqRaw int

	err := tx.QueryRow(m.Ctx(),
		`SELECT tail, seqno FROM hosts WHERE host_id=$1`,
		b.hostID.ExportToDB(),
	).Scan(&tailRaw, &seqRaw)

	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	lh, err := proto.ImportLinkHashFromDB(tailRaw)
	if err != nil {
		return err
	}
	b.prev = core.NewHostchainSkeleton(b.hostID, *lh, proto.Seqno(seqRaw))

	return nil
}

func (b *BeaconProbe) probe(m MetaContext) error {
	if b.timeout > 0 {
		var canc func()
		m, canc = m.WithContextTimeout(b.timeout)
		defer canc()
	}
	rootCAs, _, err := m.G().Config().ProbeRootCAs(m.Ctx())
	if err != nil {
		return err
	}
	rm := RpcClientMetaContext{MetaContext: m}
	cli := core.NewRpcClient(
		rm,
		b.addr,
		rootCAs,
		nil,
		nil,
	)
	defer cli.Shutdown()
	pcli := core.NewProbeClient(cli, m)
	arg := rem.ProbeArg{
		HostchainLastSeqno: 0,
		Hostname:           b.addr.Hostname().Normalize(),
	}
	pr, err := pcli.Probe(m.Ctx(), arg)
	if err != nil {
		return err
	}
	b.res = &pr
	return nil
}

func (b *BeaconProbe) playChain(m MetaContext) error {
	ch, err := core.PlayChain(b.addr, b.res.Hostchain, &b.hostID)
	if err != nil {
		return err
	}
	b.ch = ch
	return nil
}

func (b *BeaconProbe) storeChain(m MetaContext, tx pgx.Tx) error {

	var prev *proto.HostchainTail
	if b.prev != nil {
		tmp := b.prev.Tail()
		prev = &tmp
	}

	if prev != nil && prev.Seqno == b.ch.Tail().Seqno {
		// No change, no need to store anything
		return nil
	}

	args := []any{
		b.hostID.ExportToDB(),
		b.ch.Tail().Hash.ExportToDB(),
		b.ch.Tail().Seqno,
		string(b.host.Normalize()),
		int(b.port),
	}

	if prev == nil {
		tag, err := tx.Exec(m.Ctx(),
			`INSERT INTO hosts(host_id, tail, seqno, hostname, port, ctime, mtime)
	         VALUES($1,$2,$3,$4,$5,NOW(),NOW())`,
			args...,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.InsertError("storeChain failed on initial insert; race?")
		}
		return nil
	}

	args = append(args, prev.Hash.ExportToDB(), prev.Seqno)
	tag, err := tx.Exec(m.Ctx(),
		`UPDATE hosts SET tail=$2, seqno=$3, hostname=$4, port=$5, mtime=NOW()
         WHERE host_id=$1 AND tail=$6 AND seqno=$7`,
		args...,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("failed to update in storeChain; race?")
	}

	return nil
}

func (b *BeaconProbe) runTryTx(m MetaContext, tx pgx.Tx) error {
	var err error

	err = b.loadPrev(m, tx)
	if err != nil {
		return err
	}

	err = b.probe(m)
	if err != nil {
		return err
	}

	err = b.playChain(m)
	if err != nil {
		return err
	}

	err = core.CheckChainAgainstPriorChains(*b.ch, b.prev)
	if err != nil {
		return err
	}

	b.pz, err = core.CheckZoneSig(*b.ch, *b.res)
	if err != nil {
		return err
	}

	err = b.checkHostname(m)
	if err != nil {
		return err
	}

	err = b.storeChain(m, tx)
	if err != nil {
		return err
	}

	return nil
}

func (b *BeaconProbe) checkHostname(m MetaContext) error {
	hn := b.pz.Services.Probe.Hostname()
	if !hn.NormEq(b.host) {
		return core.HostMismatchError{Which: "hostname"}
	}
	return nil
}

func (b *BeaconProbe) Run(m MetaContext) error {
	db, err := m.Db(DbTypeBeacon)
	if err != nil {
		return nil
	}
	defer db.Release()
	return RetryTx(m, db, "beacon", func(m MetaContext, tx pgx.Tx) error {
		return b.runTryTx(m, tx)
	})
}

func BeaconRegisterSrv(m MetaContext, host proto.Hostname, port proto.Port, hid proto.HostID, timeout time.Duration) error {
	return NewBeaconProbe(host, port, hid, timeout).Run(m)
}

func BeaconLookup(m MetaContext, hid proto.HostID) (proto.TCPAddr, error) {

	var zed proto.TCPAddr
	db, err := m.Db(DbTypeBeacon)
	if err != nil {
		return zed, err
	}
	defer db.Release()

	var hostRaw string
	var portRaw int

	err = db.QueryRow(m.Ctx(),
		`SELECT hostname, port FROM hosts WHERE host_id=$1`,
		hid.ExportToDB(),
	).Scan(&hostRaw, &portRaw)

	if err == pgx.ErrNoRows {
		return zed, core.NotFoundError("host")
	}
	if err != nil {
		return zed, err
	}
	return proto.NewTCPAddr(proto.Hostname(hostRaw), proto.Port(portRaw)), nil
}
