// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"context"

	"github.com/foks-proj/go-ctxlog"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"go.uber.org/zap"
)

type ZapLogWrapper struct {
	log *zap.Logger
}

func NewZapLogWrapper(l *zap.Logger) ZapLogWrapper {
	return ZapLogWrapper{log: l}
}

var _ rpc.LogOutput = ZapLogWrapper{}

func convert(f []rpc.LogField) []zap.Field {
	ret := make([]zap.Field, len(f))
	for i, x := range f {
		ret[i] = zap.Any(x.Key, x.Value)
	}
	return ret
}

func (z ZapLogWrapper) Errorf(s string, args ...interface{}) {
	z.log.Sugar().Errorf(s, args...)
}
func (z ZapLogWrapper) Errorw(s string, args ...rpc.LogField) {
	z.log.Error(s, convert(args)...)
}
func (z ZapLogWrapper) Warnf(s string, args ...interface{}) {
	z.log.Sugar().Warnf(s, args...)
}
func (z ZapLogWrapper) Warnw(s string, args ...rpc.LogField) {
	z.log.Warn(s, convert(args)...)
}
func (z ZapLogWrapper) Infof(s string, args ...interface{}) {
	z.log.Sugar().Infof(s, args...)
}
func (z ZapLogWrapper) Infow(s string, args ...rpc.LogField) {
	z.log.Warn(s, convert(args)...)
}
func (z ZapLogWrapper) Debugf(s string, args ...interface{}) {
	z.log.Sugar().Debugf(s, args...)
}
func (z ZapLogWrapper) Debugw(s string, args ...rpc.LogField) {
	z.log.Debug(s, convert(args)...)
}
func (z ZapLogWrapper) Profilef(s string, args ...interface{}) {
	z.log.Sugar().Infof(s, args...)
}
func (z ZapLogWrapper) Profilew(s string, args ...rpc.LogField) {
	z.log.Info(s, convert(args)...)
}

type ThinLogger interface {
	Errorw(msg string, keysAndValues ...interface{})
	Warnw(msg string, keysAndValues ...interface{})
	Infow(msg string, keysAndValues ...interface{})
}

func AddCtxLog(ctx context.Context, keysAndValues ...interface{}) []interface{} {
	tags, _ := ctxlog.TagsFromContext(ctx)
	for k, v := range tags {
		keysAndValues = append(keysAndValues, k, v)
	}
	return keysAndValues
}

func WarnwWithContext(
	ctx context.Context,
	l *zap.Logger,
	msg string,
	keysAndValues ...interface{},
) {
	LogWithSkip(l).Warnw(msg, AddCtxLog(ctx, keysAndValues...)...)
}

func LogWithSkip(l *zap.Logger) *zap.SugaredLogger {
	return l.Sugar().WithOptions(zap.AddCallerSkip(1))
}

type ThinLog struct {
	l   *zap.Logger
	ctx context.Context
}

func NewThinLog(ctx context.Context, l *zap.Logger) ThinLog {
	return ThinLog{ctx: ctx, l: l}
}

func (t ThinLog) Errorw(msg string, keysAndValues ...interface{}) {
	LogWithSkip(t.l).Errorw(msg, AddCtxLog(t.ctx, keysAndValues...)...)
}
func (t ThinLog) Warnw(msg string, keysAndValues ...interface{}) {
	LogWithSkip(t.l).Warnw(msg, AddCtxLog(t.ctx, keysAndValues...)...)
}
func (t ThinLog) Infow(msg string, keysAndValues ...interface{}) {
	LogWithSkip(t.l).Infow(msg, AddCtxLog(t.ctx, keysAndValues...)...)
}

var _ ThinLogger = ThinLog{}
