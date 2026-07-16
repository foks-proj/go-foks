// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type Looper interface {
	GetName() string
	InitLoop(m MetaContext) error
	DoOnePollForHost(m MetaContext) error
	PollReadyHosts(m MetaContext) ([]core.ShortHostID, error)
	GetLock() *Lock
	GetConfig() ServerLooperConfigger
	ServerType() proto.ServerType
	GetPokeCh() chan chan<- error
}

func (b *BaseServer) RunBackgroundLoopsWithLooper(
	m MetaContext,
	shutdownCh chan<- error,
	looper Looper,
) error {
	m.Infow("BaseServer.RunBackgroundLoops",
		"serverType", looper.ServerType().ToString(),
		"hostID", b.GetHostID().Short,
	)
	err := looper.GetLock().Acquire(m, looper.GetConfig().PollWait())
	if err != nil {
		return err
	}
	err = looper.InitLoop(m)
	if err != nil {
		return err
	}
	go b.runPoolLoopWithLooper(m, shutdownCh, looper)
	return nil

}

func (b *BaseServer) DoOnePoll(m MetaContext, looper Looper) error {
	hosts, err := looper.PollReadyHosts(m)
	if err != nil {
		return err
	}
	hosts, err = m.G().HostIDMap().Filter(m, hosts)
	if err != nil {
		return err
	}
	for _, host := range hosts {
		m, err = m.WithShortHostID(host)
		if err != nil {
			return err
		}
		err = looper.DoOnePollForHost(m)
		if err != nil {
			return err
		}
	}
	return nil
}

// looperDbTimeout bounds every database operation a background poll loop makes
// (the lock heartbeat and each poll). It is a hang detector, not a
// normal-operation bound: heartbeats and incremental polls complete in well
// under a second, so this only ever fires when a pooled connection has gone
// stale (the pool sets no MaxConnLifetime / statement_timeout, so a query on a
// dead connection would otherwise block forever and silently wedge the loop —
// stalling the merkle pipeline until a full server restart). On timeout pgx
// aborts the query and discards the bad connection, so the next iteration gets
// a fresh one and the loop self-recovers.
const looperDbTimeout = 60 * time.Second

func (b *BaseServer) heartbeatWithTimeout(m MetaContext, looper Looper) error {
	m, cancel := m.WithContextTimeout(looperDbTimeout)
	defer cancel()
	return looper.GetLock().Heartbeat(m)
}

func (b *BaseServer) pollWithTimeout(m MetaContext, looper Looper) error {
	m, cancel := m.WithContextTimeout(looperDbTimeout)
	defer cancel()
	return b.DoOnePoll(m, looper)
}

func (b *BaseServer) runPoolLoopWithLooper(
	m MetaContext,
	shutdownCh chan<- error,
	looper Looper,
) {
	keepGoing := true
	for keepGoing {

		// Renew the lock lease. A heartbeat error is only fatal when the lock
		// was genuinely taken over by another instance (LostLock) — then we
		// stand down. A transient DB/connection error (a stale pooled conn, a
		// brief postgres outage on `compose up`, a network blip) leaves the
		// lock ours, so we log and retry on the next tick rather than exiting
		// permanently, which used to kill the merkle pipeline until a full
		// server restart.
		hbErr := b.heartbeatWithTimeout(m, looper)
		if hbErr != nil && looper.GetLock().LostLock() {
			m.Warnw("runPollLoop", "stage", "lock-lost", "err", hbErr)
			shutdownCh <- hbErr
			keepGoing = false
			continue
		}
		if hbErr != nil {
			m.Warnw("runPollLoop", "stage", "heartbeat-transient", "err", hbErr)
		}

		select {
		case <-time.After(looper.GetConfig().PollWait()):
			if hbErr != nil {
				// The DB was unreachable this round; skip the poll and retry
				// the heartbeat after the poll-wait backoff.
				continue
			}
			if err := b.pollWithTimeout(m, looper); err != nil {
				m.Warnw("runPollLoop", "stage", "doOnePoll", "err", err)
			}
		case retCh := <-looper.GetPokeCh():
			retCh <- b.pollWithTimeout(m, looper)
		case <-m.Ctx().Done():
			keepGoing = false
		}
	}
	m.Infow("runPollLoop", "stage", "exit")
}
