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

func (b *BaseServer) runPoolLoopWithLooper(
	m MetaContext,
	shutdownCh chan<- error,
	looper Looper,
) {
	keepGoing := true
	for keepGoing {

		// If we fail the lock heartbeat, it's because someone else is acting as the merkle Batcher,
		// and we should get out of the way.
		err := looper.GetLock().Heartbeat(m)
		if err != nil {
			m.Warnw("heartbeat", "err", err)
			shutdownCh <- err
			keepGoing = false
		} else {

			select {
			case <-time.After(looper.GetConfig().PollWait()):
				err := b.DoOnePoll(m, looper)
				if err != nil {
					m.Warnw("runPollLoop", "stage", "doOnePoll", "err", err)
				}
			case retCh := <-looper.GetPokeCh():
				err := b.DoOnePoll(m, looper)
				retCh <- err
			case <-m.Ctx().Done():
				keepGoing = false
			}
		}
	}
	m.Infow("runPollLoop", "stage", "exit")
}
