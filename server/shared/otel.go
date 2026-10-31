// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"go.opentelemetry.io/contrib/bridges/otelzap"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// OpenTelemetry support for FOKS server daemons.
//
// Telemetry is opt-in and configured entirely via the standard OTEL_* environment
// variables; nothing is exported unless an OTLP endpoint is set:
//
//	OTEL_EXPORTER_OTLP_ENDPOINT          base endpoint for traces + metrics + logs (e.g. http://otel-collector:4318)
//	OTEL_EXPORTER_OTLP_TRACES_ENDPOINT   enable/override traces only
//	OTEL_EXPORTER_OTLP_METRICS_ENDPOINT  enable/override metrics only
//	OTEL_EXPORTER_OTLP_LOGS_ENDPOINT     enable/override logs only
//	OTEL_{TRACES,METRICS,LOGS}_EXPORTER=none  turn off one signal
//	OTEL_SERVICE_NAME                    defaults to foks-<server type>, e.g. foks-user
//	OTEL_RESOURCE_ATTRIBUTES             extra resource attributes
//	OTEL_SDK_DISABLED=true               force-disable
//
// plus the rest of the exporter/SDK env vars (headers, timeouts, sampler,
// OTEL_METRIC_EXPORT_INTERVAL, ...). Exporters speak OTLP over HTTP.
//
// When disabled, the global no-op providers stay in place, so the RPC wrapper
// below costs roughly a time.Now() and a couple of no-op calls per request.

const otelScope = "github.com/foks-proj/go-foks/server"

// InitOTel installs global trace, meter and logger providers for this process,
// if enabled by environment. When logs are enabled, the server's zap logger is
// teed into OTel, at the same level and sampling as the local log output. The returned shutdown func flushes pending telemetry
// and is always non-nil.
func InitOTel(m MetaContext, typ proto.ServerType) (func(context.Context) error, error) {
	noop := func(context.Context) error { return nil }

	if strings.EqualFold(os.Getenv("OTEL_SDK_DISABLED"), "true") {
		return noop, nil
	}
	doTraces := otelSignalEnabled("TRACES")
	doMetrics := otelSignalEnabled("METRICS")
	doLogs := otelSignalEnabled("LOGS")
	if !doTraces && !doMetrics && !doLogs {
		return noop, nil
	}

	ctx := m.Ctx()
	res, err := resource.New(ctx,
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithProcessPID(),
		resource.WithAttributes(
			attribute.String("service.name", "foks-"+strings.ToLower(typ.String())),
			attribute.String("service.namespace", "foks"),
			attribute.String("foks.server.type", typ.String()),
		),
		// Last, so OTEL_SERVICE_NAME / OTEL_RESOURCE_ATTRIBUTES win.
		resource.WithFromEnv(),
	)
	if err != nil {
		return noop, err
	}

	// Report export errors to the local log only; sending them through the
	// OTel log pipeline would feed failures back into the thing that's failing.
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		m.G().LocalLog().Warnw("otel", "err", err)
	}))

	var shutdowns []func(context.Context) error
	shutdown := func(ctx context.Context) error {
		var errs []error
		for _, f := range shutdowns {
			errs = append(errs, f(ctx))
		}
		return errors.Join(errs...)
	}

	if doTraces {
		exp, err := otlptracehttp.New(ctx)
		if err != nil {
			return noop, err
		}
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exp),
			sdktrace.WithResource(res),
		)
		otel.SetTracerProvider(tp)
		shutdowns = append(shutdowns, tp.Shutdown)
	}

	if doMetrics {
		exp, err := otlpmetrichttp.New(ctx)
		if err != nil {
			_ = shutdown(ctx)
			return noop, err
		}
		mp := sdkmetric.NewMeterProvider(
			sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp)),
			sdkmetric.WithResource(res),
		)
		otel.SetMeterProvider(mp)
		shutdowns = append(shutdowns, mp.Shutdown)
	}

	if doLogs {
		exp, err := otlploghttp.New(ctx)
		if err != nil {
			_ = shutdown(ctx)
			return noop, err
		}
		lp := sdklog.NewLoggerProvider(
			sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)),
			sdklog.WithResource(res),
		)
		global.SetLoggerProvider(lp)
		// Untee before flushing, so nothing is logged into a closed provider.
		shutdowns = append(shutdowns, func(ctx context.Context) error {
			_ = m.G().TeeLogCore(nil)
			return lp.Shutdown(ctx)
		})
		err = m.G().TeeLogCore(otelzap.NewCore(otelScope, otelzap.WithLoggerProvider(lp)))
		if err != nil {
			_ = shutdown(ctx)
			return noop, err
		}
	}

	m.Infow("otel", "stage", "enabled", "traces", doTraces, "metrics", doMetrics, "logs", doLogs)
	return shutdown, nil
}

// otelSignalEnabled reports whether a signal (TRACES, METRICS, LOGS) has an
// OTLP endpoint and hasn't been turned off with OTEL_<SIGNAL>_EXPORTER=none.
func otelSignalEnabled(signal string) bool {
	if strings.EqualFold(os.Getenv("OTEL_"+signal+"_EXPORTER"), "none") {
		return false
	}
	return os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" ||
		os.Getenv("OTEL_EXPORTER_OTLP_"+signal+"_ENDPOINT") != ""
}

// traceLogField is a zap field value that is both a context.Context and a
// zap ObjectMarshaler. Local log output renders it as {trace_id, span_id};
// the otelzap bridge sees a context.Context, uses it to stamp the record's
// trace and span IDs, and leaves it out of the attributes.
type traceLogField struct {
	context.Context
	sc trace.SpanContext
}

func (t traceLogField) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("trace_id", t.sc.TraceID().String())
	enc.AddString("span_id", t.sc.SpanID().String())
	return nil
}

// appendTraceLogField adds a "trace" field if ctx carries a valid span.
func appendTraceLogField(ctx context.Context, kvs []interface{}) []interface{} {
	if ctx == nil {
		return kvs
	}
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return kvs
	}
	return append(kvs, zap.Object("trace", traceLogField{Context: ctx, sc: sc}))
}

// RPCRegistrar is what ClientConn.RegisterProtocols registers protocols with.
// It is satisfied by *rpc.Server; in production it's an instrumenting wrapper
// that times every server-side RPC.
type RPCRegistrar interface {
	RegisterV2(p rpc.ProtocolV2) error
}

var _ RPCRegistrar = (*rpc.Server)(nil)

type rpcHandler = func(ctx context.Context, arg interface{}) (interface{}, error)

type rpcInstruments struct {
	tracer   trace.Tracer
	duration metric.Float64Histogram
}

// Instruments are created once against the global providers. The otel global
// providers delegate, so instruments created before InitOTel still pick up
// the real SDK once it's installed.
var getRPCInstruments = sync.OnceValue(func() *rpcInstruments {
	meter := otel.Meter(otelScope)
	h, err := meter.Float64Histogram(
		"rpc.server.call.duration",
		metric.WithDescription("Time spent serving an RPC on the server, from dispatch to handler return."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(
			0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1,
			0.25, 0.5, 1, 2.5, 5, 10, 30, 60,
		),
	)
	if err != nil {
		otel.Handle(err)
	}
	return &rpcInstruments{
		tracer:   otel.Tracer(otelScope),
		duration: h,
	}
})

type instrumentedRegistrar struct {
	srv  *rpc.Server
	inst *rpcInstruments
	typ  proto.ServerType
}

func newInstrumentedRegistrar(srv *rpc.Server, typ proto.ServerType) instrumentedRegistrar {
	return instrumentedRegistrar{srv: srv, inst: getRPCInstruments(), typ: typ}
}

func (r instrumentedRegistrar) RegisterV2(p rpc.ProtocolV2) error {
	methods := make(map[rpc.Position]rpc.ServeHandlerDescriptionV2, len(p.Methods))
	for pos, d := range p.Methods {
		d.Handler = r.inst.wrap(r.typ, p.Name, d.Name, d.Handler)
		methods[pos] = d
	}
	p.Methods = methods
	return r.srv.RegisterV2(p)
}

func (ri *rpcInstruments) wrap(typ proto.ServerType, svc, method string, h rpcHandler) rpcHandler {
	base := []attribute.KeyValue{
		attribute.String("rpc.system", "snowpack"),
		attribute.String("rpc.service", svc),
		attribute.String("rpc.method", method),
		attribute.String("foks.server.type", typ.String()),
	}
	okSet := attribute.NewSet(base...)
	spanName := svc + "/" + method

	return func(ctx context.Context, arg interface{}) (interface{}, error) {
		start := time.Now()
		ctx, span := ri.tracer.Start(ctx, spanName,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithTimestamp(start),
			trace.WithAttributes(base...),
		)

		res, err := h(ctx, arg)
		dur := time.Since(start)

		set := okSet
		if err != nil {
			errType := statusCodeName(err)
			span.RecordError(err)
			span.SetStatus(codes.Error, errType)
			span.SetAttributes(attribute.String("error.type", errType))
			set = attribute.NewSet(append(base, attribute.String("error.type", errType))...)
		}
		span.End(trace.WithTimestamp(start.Add(dur)))
		if ri.duration != nil {
			ri.duration.Record(ctx, dur.Seconds(), metric.WithAttributeSet(set))
		}
		return res, err
	}
}

// statusCodeName maps an error to its FOKS StatusCode name, a bounded set
// that's safe to use as a metric label.
func statusCodeName(err error) string {
	sc, e := core.ErrorToStatus(err).GetSc()
	if e != nil {
		return "unknown"
	}
	if s, ok := proto.StatusCodeRevMap[sc]; ok {
		return s
	}
	return fmt.Sprintf("status_%d", int(sc))
}
