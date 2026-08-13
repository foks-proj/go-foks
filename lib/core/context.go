// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"context"
	"time"

	"github.com/foks-proj/go-ctxlog"
	"go.uber.org/zap"
)

type LogHook func() *zap.Logger

type MetaContext struct {
	ctx context.Context
	log LogHook
}

func NewMetaContextBackground(h LogHook) MetaContext {
	return MetaContext{ctx: context.Background(), log: h}
}
func NewMetaContext(ctx context.Context, h LogHook) MetaContext {
	return MetaContext{ctx: ctx, log: h}
}

func NewMetaContextTODO(h LogHook) MetaContext {
	return MetaContext{ctx: context.TODO(), log: h}
}

func (m MetaContext) WithContext(ctx context.Context) MetaContext {
	m.ctx = ctx
	return m
}

func (m MetaContext) Ctx() context.Context {
	return m.ctx
}

// WithRpcStats scopes RPC accounting to the returned MetaContext: every
// outbound RPC issued under it is counted, until the scope is abandoned. See
// RpcStats for what the numbers mean.
func (m MetaContext) WithRpcStats() (MetaContext, *RpcStats) {
	var st *RpcStats
	m.ctx, st = WithRpcStats(m.ctx)
	return m, st
}

func (m MetaContext) WithLogTag(k string) MetaContext {
	m.ctx = ctxlog.WithLogTag(m.ctx, k)
	return m
}

func (m MetaContext) WithContextCancel() (MetaContext, func()) {
	var f func()
	m.ctx, f = context.WithCancel(m.ctx)
	return m, f
}

func (m MetaContext) WithContextTimeout(d time.Duration) (MetaContext, func()) {
	var f func()
	m.ctx, f = context.WithTimeout(m.ctx, d)
	return m, f
}

func (m MetaContext) BackgroundWithCancel() (MetaContext, func()) {
	var f func()
	m.ctx, f = context.WithCancel(context.Background())
	return m, f
}

func (m MetaContext) Background() MetaContext {
	m.ctx = context.Background()
	return m
}

func (m MetaContext) logWithSkip() *zap.SugaredLogger {
	return LogWithSkip(m.log())
}

func (m MetaContext) Error(s string) {
	m.logWithSkip().Error(s)
}

func (m MetaContext) Infof(format string, args ...interface{}) {
	m.logWithSkip().Infof(format, args...)
}

func (m MetaContext) Errorf(format string, args ...interface{}) {
	m.logWithSkip().Errorf(format, args...)
}

func (m MetaContext) Warnw(msg string, keysAndValues ...interface{}) {
	m.logWithSkip().Warnw(msg, AddCtxLog(m.ctx, keysAndValues...)...)
}
func (m MetaContext) Debugw(msg string, keysAndValues ...interface{}) {
	m.logWithSkip().Debugw(msg, AddCtxLog(m.ctx, keysAndValues...)...)
}
func (m MetaContext) Infow(msg string, keysAndValues ...interface{}) {
	m.logWithSkip().Infow(msg, AddCtxLog(m.ctx, keysAndValues...)...)
}
func (m MetaContext) Errorw(msg string, keysAndValues ...interface{}) {
	m.logWithSkip().Errorw(msg, AddCtxLog(m.ctx, keysAndValues...)...)
}
func (m MetaContext) Debugf(msg string, args ...interface{}) {
	m.logWithSkip().Debugf(msg, args...)
}
func (m MetaContext) WarnwWithContext(ctx context.Context, msg string, keysAndValues ...interface{}) {
	m.logWithSkip().Warnw(msg, AddCtxLog(ctx, keysAndValues...)...)
}
