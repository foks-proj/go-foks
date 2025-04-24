// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libgit

import (
	"context"
	"sync"

	"github.com/foks-proj/go-foks/lib/core"
	remhelp "github.com/foks-proj/go-git-remhelp"
)

type rpcOutput struct {
	lines []string
	err   error
}

type RpcLineOutputter struct {
	ch chan<- rpcOutput
}

func (r *RpcLineOutputter) Output(lines []string, err error) error {
	r.ch <- rpcOutput{lines: lines, err: err}
	return nil
}

var _ remhelp.LineOutputter = (*RpcLineOutputter)(nil)

type nextArg struct {
	line string
	out  remhelp.LineOutputter
	err  error
}

type RpcBatchedLineIO struct {
	nextCh  chan nextArg
	closeCh chan struct{}

	doneMu sync.RWMutex
	done   bool
}

func (r *RpcBatchedLineIO) setDone() {
	r.doneMu.Lock()
	r.done = true
	r.doneMu.Unlock()

	// drain the remaining writers, if there are anymore
	for {
		select {
		case arg := <-r.nextCh:
			_ = arg.out.Output(nil, core.InternalError("RPC batched line IO shut down"))
		default:
			close(r.nextCh)
			return
		}
	}
}

func (r *RpcBatchedLineIO) isDone() bool {
	r.doneMu.RLock()
	defer r.doneMu.RUnlock()
	return r.done
}

func (r *RpcBatchedLineIO) Next(ctx context.Context) (string, remhelp.LineOutputter, error) {
	if r.isDone() {
		return "", nil, core.InternalError("RpcBatchedLineIO.Next called after done")
	}
	select {
	case <-r.closeCh:
		r.setDone()
		return "", nil, core.InternalError("RPC batched line IO shutdown before Next was called")
	case <-ctx.Done():
		return "", nil, ctx.Err()
	case arg := <-r.nextCh:
		return arg.line, arg.out, arg.err
	}
}

func (r *RpcBatchedLineIO) PumpInRPC(
	ctx context.Context,
	line string,
) (
	[]string,
	error,
) {
	if r.isDone() {
		return nil, core.InternalError("RpcBatchedLineIO.PumpInRPC called after done")
	}

	retch := make(chan rpcOutput)
	outputter := &RpcLineOutputter{ch: retch}
	r.nextCh <- nextArg{line: line, out: outputter}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-retch:
		return res.lines, res.err
	}
}

var _ remhelp.BatchedLineIOer = (*RpcBatchedLineIO)(nil)

func NewRpcBatchedLineIO(ch chan struct{}) *RpcBatchedLineIO {
	return &RpcBatchedLineIO{
		nextCh:  make(chan nextArg),
		closeCh: ch,
	}
}
