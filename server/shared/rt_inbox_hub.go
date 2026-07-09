// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"sync"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

// RTInboxHubKey identifies one user's per-app inbox version stream.
type RTInboxHubKey struct {
	HostID core.ShortHostID
	Uid    proto.UID
	App    proto.RTAppID
}

// RTInboxHub wakes parked inbox long-pollers (rtPollInbox) when a write bumps
// a user's inbox version. Wakes carry no data -- a woken poller re-reads the
// version from the DB -- so spurious wakes are harmless; what matters is that
// wakes are never missed. Two rules keep that true:
//
//   - Pollers must Subscribe BEFORE reading the version they compare against,
//     so a bump landing between the read and the park still wakes them.
//   - Writers must Wake only AFTER their transaction commits (i.e., after
//     RetryTx returns success). A pre-commit wake sends the poller to a read
//     that can't yet see the bump, and no second wake follows.
//
// In-process only: a poller parked on one realtime server won't get an
// instant wake for a bump handled by another; it catches up at its poll
// timeout. The waiter registry is the durable part of this design -- Stage 2c
// replaces the wake *source* with Redis pub/sub (and thus cross-process
// wakes) without changing pollers or writers.
type RTInboxHub struct {
	sync.Mutex
	waiters map[RTInboxHubKey]map[chan struct{}]bool
}

func NewRTInboxHub() *RTInboxHub {
	return &RTInboxHub{
		waiters: make(map[RTInboxHubKey]map[chan struct{}]bool),
	}
}

// Subscribe registers a waiter and returns its one-shot wake channel, which
// is closed by the next Wake for this key. Always pair with Unsubscribe (a
// no-op if a Wake already retired the channel).
func (h *RTInboxHub) Subscribe(k RTInboxHubKey) chan struct{} {
	h.Lock()
	defer h.Unlock()
	ch := make(chan struct{})
	set := h.waiters[k]
	if set == nil {
		set = make(map[chan struct{}]bool)
		h.waiters[k] = set
	}
	set[ch] = true
	return ch
}

func (h *RTInboxHub) Unsubscribe(k RTInboxHubKey, ch chan struct{}) {
	h.Lock()
	defer h.Unlock()
	set := h.waiters[k]
	if set == nil {
		return
	}
	delete(set, ch)
	if len(set) == 0 {
		delete(h.waiters, k)
	}
}

// Wake retires and closes all current waiters for the key. Call only after
// the bump's transaction has committed; see the type doc.
func (h *RTInboxHub) Wake(k RTInboxHubKey) {
	h.Lock()
	defer h.Unlock()
	for ch := range h.waiters[k] {
		close(ch)
	}
	delete(h.waiters, k)
}

// NumWaiters reports how many pollers are currently subscribed on k. For
// metrics and tests (e.g., deterministically waiting for a poller to park
// before triggering the bump that should wake it).
func (h *RTInboxHub) NumWaiters(k RTInboxHubKey) int {
	h.Lock()
	defer h.Unlock()
	return len(h.waiters[k])
}
