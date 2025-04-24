// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/keybase/clockwork"
)

type AutocertHost struct {
	Hostname proto.Hostname
	Stype    proto.ServerType
}

func (k AutocertHost) Normalize() AutocertHost {
	return AutocertHost{
		Hostname: k.Hostname.Normalize(),
		Stype:    k.Stype,
	}
}

type autocertWaiters struct {
	sync.Mutex
	succ    bool
	failure error
	nxt     int
	chs     map[int](chan<- error)
}

type autocertWaiter struct {
	parent *autocertWaiters
	id     int
	ch     <-chan error
}

func (a *autocertWaiter) cancel() {
	a.parent.cancel(a.id)
}

func (a *autocertWaiter) waitCh() <-chan error {
	return a.ch
}

func newAutocertWaiters() *autocertWaiters {
	return &autocertWaiters{
		chs: make(map[int](chan<- error)),
		nxt: 0,
	}
}

type AutocertSwitchboard struct {
	sync.Mutex
	lanes map[AutocertHost]*autocertWaiters
	clock clockwork.Clock
}

func NewAutocertSwitchboard() *AutocertSwitchboard {
	return &AutocertSwitchboard{
		lanes: make(map[AutocertHost]*autocertWaiters),
		clock: clockwork.NewRealClock(),
	}
}

func (a *AutocertSwitchboard) WithClock(cl clockwork.Clock) *AutocertSwitchboard {
	a.clock = cl
	return a
}

func (a *autocertWaiters) newWaiter() (*autocertWaiter, error) {
	a.Lock()
	defer a.Unlock()
	if a.succ {
		return nil, nil
	}
	if a.failure != nil {
		return nil, a.failure
	}
	a.nxt++
	id := a.nxt
	ch := make(chan error, 1)
	a.chs[id] = ch
	return &autocertWaiter{
		parent: a,
		id:     id,
		ch:     ch,
	}, nil
}

func (a *autocertWaiters) cancel(id int) {
	a.Lock()
	defer a.Unlock()
	delete(a.chs, id)
}

func (a *autocertWaiters) broadcast(e error) {
	a.Lock()
	defer a.Unlock()
	a.failure = e
	if e == nil {
		a.succ = true
	}
	for _, ch := range a.chs {
		ch <- e
	}
	// Clear out the map to stop any races when 3 braodcasts happen in rapid sucessiong
	// before the watiers can a chance to call cancel. The 3nd broadcast would deadlock
	// the program since no one will be listening on the channel. I think 2 broacasts
	// would be fine for what it's worth.
	a.chs = make(map[int]chan<- error)
}

func (s *AutocertSwitchboard) getWaiters(key AutocertHost) *autocertWaiters {
	s.Lock()
	defer s.Unlock()
	key = key.Normalize()
	w := s.lanes[key]
	if w == nil {
		w = newAutocertWaiters()
		s.lanes[key] = w
	}
	return w
}

func (s *AutocertSwitchboard) Wait(
	ctx context.Context,
	key AutocertHost,
	tm time.Duration,
) error {
	waiters := s.getWaiters(key)
	waiter, err := waiters.newWaiter()
	if err != nil {
		return err
	}
	if waiter == nil {
		return nil
	}
	defer waiter.cancel()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.clock.After(tm):
		return core.TimeoutError{}
	case err := <-waiter.waitCh():
		return err
	}
}

func (s *AutocertSwitchboard) Broadcast(
	ctx context.Context,
	key AutocertHost,
	err error,
) error {
	waiters := s.getWaiters(key)
	waiters.broadcast(err)
	return nil
}
