// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/proto/infra"
	"github.com/stretchr/testify/require"
)

func newSwitchboardObj(key byte, val byte) (LaneID, []byte) {
	ret := LaneID{
		q: infra.QueueID_Kex,
	}
	ret.l[0] = key
	return ret, []byte{val}
}

func TestSwitchboardSimple(t *testing.T) {
	sw, cl := newSwitchboardForTest(time.Minute, time.Second)
	lid, msg := newSwitchboardObj(1, 1)
	ch := make(chan struct{})
	ctx := context.Background()
	go func() {
		gotMsg, err := sw.Dequeue(ctx, lid.q, lid.l)
		require.NoError(t, err)
		require.Equal(t, msg, gotMsg)
		ch <- struct{}{}
	}()
	sw.Enqueue(lid.q, lid.l, msg)
	<-ch
	cl.Advance(time.Minute + time.Second)
	lid, msg = newSwitchboardObj(2, 2)
	sw.Enqueue(lid.q, lid.l, msg)
	gotMsg, err := sw.Dequeue(ctx, lid.q, lid.l)
	require.NoError(t, err)
	require.Equal(t, msg, gotMsg)
	cl.Advance(time.Minute + time.Second)
}

func TestSwitchboardMultiple(t *testing.T) {
	sw, cl := newSwitchboardForTest(time.Minute, time.Second)

	testOne := func(i int) {
		b := byte(i)
		lid, msg := newSwitchboardObj(b, b)
		ch := make(chan struct{})
		ctx := context.Background()
		go func() {
			gotMsg, err := sw.Dequeue(ctx, lid.q, lid.l)
			require.NoError(t, err)
			require.Equal(t, msg, gotMsg)
			ch <- struct{}{}
		}()
		sw.Enqueue(lid.q, lid.l, msg)
		<-ch
		cl.Advance(time.Minute + time.Second)
	}

	for i := 1; i < 100; i++ {
		testOne(i)
	}

	// Most evevrything should be cleaned out, but it's not really
	// deterministic
	sw.Lock()
	require.Greater(t, 100, len(sw.lanes))
	sw.Unlock()

}

func TestSwitchboardRandomizeOrder(t *testing.T) {
	sw, cl := newSwitchboardForTest(time.Minute, time.Second)

	n := 100
	ch := make([](chan struct{}), n)

	for i := 0; i < n; i++ {
		ch[i] = make(chan struct{})
	}

	go func() {
		for i := 0; i < 100; i++ {
			b := byte(i)
			lid, msg := newSwitchboardObj(b, b)
			ctx := context.Background()
			gotMsg, err := sw.Dequeue(ctx, lid.q, lid.l)
			time.Sleep(time.Microsecond)
			require.NoError(t, err)
			require.Equal(t, msg, gotMsg)
			ch[i] <- struct{}{}
		}
	}()

	go func() {
		for i := 0; i < 100; i++ {
			b := byte(i)
			lid, msg := newSwitchboardObj(b, b)
			sw.Enqueue(lid.q, lid.l, msg)
			cl.Advance(time.Millisecond)
			time.Sleep(time.Microsecond)
		}
	}()

	for _, e := range ch {
		<-e
	}

}
