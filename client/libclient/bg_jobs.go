// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"container/heap"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/keybase/clockwork"
)

// An Item is something we manage in a priority queue.
type bgItem struct {
	item  BgJobber
	dueAt time.Time
	index int // The index of the item in the heap.
}

func (b *bgItem) priority() BgPriority {
	return b.item.Priority()
}

// A PriorityQueue implements heap.Interface and holds Items.
type BgPriorityQueue struct {
	items      []*bgItem
	byPriority bool
}

func (pq *BgPriorityQueue) Len() int { return len(pq.items) }

func (pq *BgPriorityQueue) Less(i, j int) bool {
	if pq.byPriority {
		// We want Pop to give us the highest, not lowest, priority so we use greater than here.
		return pq.items[i].priority() > pq.items[j].priority()
	}
	return pq.items[i].dueAt.After(pq.items[j].dueAt)
}

func (pq BgPriorityQueue) Swap(i, j int) {
	pq.items[i], pq.items[j] = pq.items[j], pq.items[i]
	pq.items[i].index = i
	pq.items[j].index = j
}

func (pq *BgPriorityQueue) Push(x any) {
	n := pq.Len()
	item := x.(*bgItem)
	item.index = n
	pq.items = append(pq.items, item)
}

func (pq *BgPriorityQueue) Pop() any {
	old := *pq
	n := pq.Len()
	item := old.items[n-1]
	old.items[n-1] = nil // avoid memory leak
	item.index = -1      // for safety
	pq.items = old.items[0 : n-1]
	return item
}

func NewBgPriorityQueue(byP bool) *BgPriorityQueue {
	ret := &BgPriorityQueue{
		items:      make([]*bgItem, 0),
		byPriority: byP,
	}
	heap.Init(ret)
	return ret
}

func (pq *BgPriorityQueue) MyPeek() *bgItem {
	if pq.Len() == 0 {
		return nil
	}
	return core.Last(pq.items)
}
func (pq *BgPriorityQueue) MyPush(x *bgItem) { heap.Push(pq, x) }
func (pq *BgPriorityQueue) MyPop() *bgItem   { return heap.Pop(pq).(*bgItem) }

type BgPriority int

type BgJobType int

const (
	BgJobTypeUserRefresh BgJobType = iota
	BgJobTypeCLKR
)

type BgJobber interface {
	Priority() BgPriority
	Reschedule() time.Duration
	Perform(m MetaContext) error
	Type() BgJobType
	Name() string
}

// Background Jobs (BBjobs) are poling to maintain important security properties. We envision there might
// be a lot of them in the future, so keep track of them here.
type BgJobMgr struct {
	sync.Mutex
	cfg     BgConfig
	pending *BgPriorityQueue
	due     *BgPriorityQueue
	stopper func()
	pokeCh  chan time.Duration
	clock   clockwork.Clock
	types   map[BgJobType]BgJobber
}

func NewBgJobMgr(cfg BgConfig) *BgJobMgr {
	ret := &BgJobMgr{
		cfg:     cfg,
		pending: NewBgPriorityQueue(false),
		due:     NewBgPriorityQueue(true),
		clock:   clockwork.NewRealClock(),
		pokeCh:  make(chan time.Duration),
		types:   make(map[BgJobType]BgJobber),
	}
	ret.Add(NewBgUserRefresh(cfg.User))
	ret.Add(NewBgCLKR(cfg.Clkr))
	return ret
}

func (b *BgJobMgr) Bump(m MetaContext, typ BgJobType) error {
	b.Lock()
	defer b.Unlock()
	j, ok := b.types[typ]
	if !ok {
		return core.NotFoundError("bg job type")
	}
	err := b.perform(m, j)
	if err != nil {
		return err
	}
	return nil
}

func (b *BgJobMgr) Add(j BgJobber) {
	b.Lock()
	defer b.Unlock()
	b.pending.MyPush(&bgItem{
		item:  j,
		dueAt: time.Now().Add(j.Reschedule()),
	})
	b.types[j.Type()] = j
}

func (b *BgJobMgr) stageDueJobs(t time.Time) {
	for {
		peek := b.pending.MyPeek()
		if peek == nil || peek.dueAt.After(t) {
			break
		}
		b.due.MyPush(b.pending.MyPop())
	}
}

func (b *BgJobMgr) popOneJob() *bgItem {
	if b.due.Len() == 0 {
		return nil
	}
	return b.due.MyPop()
}

func (b *BgJobMgr) perform(m MetaContext, j BgJobber) error {
	m = m.WithLogTag("bg")
	nm := j.Name()
	m.Infow("bgJobMgr", "name", nm, "stage", "start")
	err := j.Perform(m)
	if err != nil {
		m.Warnw("bgJobMgr", "name", nm, "stage", "exit", "err", err)
	} else {
		m.Infow("bgJobMgr", "name", nm, "stage", "exit")
	}
	return err
}

func (b *BgJobMgr) tick(m MetaContext, tm time.Time) {
	b.Lock()
	defer b.Unlock()

	b.stageDueJobs(tm)

	job := b.popOneJob()
	if job == nil {
		return
	}

	err := b.perform(m, job.item)
	if err != nil {
		m.Warnw("bgJobMgr", "name", job.item.Name(), "stage", "perform", "err", err)
	}

	if nxt := job.item.Reschedule(); nxt > 0 {
		b.pending.MyPush(&bgItem{
			item:  job.item,
			dueAt: tm.Add(nxt),
		})
	}

}

func (b *BgJobMgr) runBg(m MetaContext) {
	ctx := m.Ctx()
	for {
		select {
		case <-b.clock.After(b.cfg.Tick):
			now := b.clock.Now()
			b.tick(m, now)
		case <-ctx.Done():
			return
		case nxt := <-b.pokeCh:
			if fcl, ok := b.clock.(clockwork.FakeClock); ok && nxt > 0 {
				fcl.Advance(nxt)
			}
			now := b.clock.Now()
			b.tick(m, now)
		}
	}
}

func (b *BgJobMgr) Run(m MetaContext) {
	m, cnc := m.Background().WithContextCancel()
	go b.runBg(m)
	b.stopper = cnc
}

func (b *BgJobMgr) Poke(t time.Duration) {
	b.pokeCh <- t
}

func (b *BgJobMgr) Stop() {
	b.stopper()
}
