// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	"github.com/keybase/clockwork"
)

type LaneID struct {
	q infra.QueueID
	l infra.QueueLaneID
}

type Waiter struct {
	sync.Mutex
	ch chan<- []byte
}

type WaitGroup struct {
	msg     []byte
	waiters [](*Waiter)
}

type cleanupQueueItem struct {
	timeIn time.Time
	id     LaneID
}

type Switchboard struct {
	sync.RWMutex
	lanes        map[LaneID]*WaitGroup
	cleanupQueue []cleanupQueueItem
	clock        clockwork.Clock
	timeout      time.Duration
	pollInterval time.Duration
	canc         func()
}

func (w *WaitGroup) notify() {
	for _, e := range w.waiters {
		e.notify(w.msg)
	}
}

func (w *Waiter) notify(m []byte) {
	w.Lock()
	defer w.Unlock()
	if w.ch != nil {
		w.ch <- m
	}
}

func (s *Switchboard) now() time.Time {
	return s.clock.Now()
}

func (s *Switchboard) queueCleanup(id LaneID) {
	now := s.now()
	s.cleanupQueue = append(s.cleanupQueue, cleanupQueueItem{timeIn: now, id: id})
}

func (s *Switchboard) cleanupThread(ctx context.Context) {
	s.Lock()
	d := s.pollInterval
	s.Unlock()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.clock.After(d):
			s.doCleanup()
		}
	}
}

func (s *Switchboard) doCleanup() {
	s.Lock()
	defer s.Unlock()
	now := s.clock.Now()
	cutoff := now.Add(-s.timeout)
	for len(s.cleanupQueue) > 0 && !s.cleanupQueue[0].timeIn.After(cutoff) {
		delete(s.lanes, s.cleanupQueue[0].id)
		s.cleanupQueue = s.cleanupQueue[1:]
	}
}

func (s *Switchboard) Enqueue(q infra.QueueID, l infra.QueueLaneID, msg []byte) {
	s.Lock()
	defer s.Unlock()
	id := LaneID{q: q, l: l}
	wg := s.lanes[id]
	if wg == nil {
		wg = &WaitGroup{msg: msg}
		s.lanes[id] = wg
		s.queueCleanup(id)
	} else {
		wg.msg = msg
	}
	wg.notify()
}

func (w *WaitGroup) push(ch chan<- []byte) *Waiter {
	ret := &Waiter{ch: ch}
	w.waiters = append(w.waiters, ret)
	return ret
}

func (s *Switchboard) waitForIt(q infra.QueueID, l infra.QueueLaneID, ch chan<- []byte) ([]byte, *Waiter) {
	s.Lock()
	defer s.Unlock()

	id := LaneID{q: q, l: l}
	wg := s.lanes[id]
	if wg != nil && len(wg.msg) > 0 {
		return wg.msg, nil
	}

	var ret *Waiter
	if wg == nil {
		wg = &WaitGroup{}
		s.lanes[id] = wg
		s.queueCleanup(id)
	}
	ret = wg.push(ch)

	return nil, ret
}

func (w *Waiter) cancelWait() {
	w.Lock()
	defer w.Unlock()
	w.ch = nil
}

func (s *Switchboard) Dequeue(ctx context.Context, q infra.QueueID, l infra.QueueLaneID) ([]byte, error) {
	ch := make(chan []byte)

	msg, w := s.waitForIt(q, l, ch)
	if len(msg) > 0 {
		return msg, nil
	}
	defer w.cancelWait()

	select {
	case <-ctx.Done():
		return nil, core.TimeoutError{}
	case msg := <-ch:
		return msg, nil
	}
}

func newSwitchboardForTest(timeout time.Duration, pollInterval time.Duration) (*Switchboard, clockwork.FakeClock) {
	cl := clockwork.NewFakeClock()
	ret := newSwitchboard(cl, timeout, pollInterval)
	return ret, cl
}

func NewSwitchboard() *Switchboard {
	return newSwitchboard(clockwork.NewRealClock(), time.Minute, 5*time.Second)
}

func newSwitchboard(clock clockwork.Clock, timeout time.Duration, pollInterval time.Duration) *Switchboard {
	ret := &Switchboard{
		lanes:        make(map[LaneID](*WaitGroup)),
		clock:        clock,
		timeout:      timeout,
		pollInterval: pollInterval,
	}
	ctx, canc := context.WithCancel(context.Background())
	ret.canc = canc
	go ret.cleanupThread(ctx)
	return ret
}

func (s *Switchboard) Shutdown() {
	s.canc()
}
