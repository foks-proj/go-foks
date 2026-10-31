// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/contrib/bridges/otelzap"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/log/global"
	lognoop "go.opentelemetry.io/otel/log/noop"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

func TestRPCInstrumentsWrap(t *testing.T) {
	ctx := context.Background()

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	spans := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))

	h, err := mp.Meter("test").Float64Histogram("rpc.server.call.duration")
	require.NoError(t, err)
	ri := &rpcInstruments{tracer: tp.Tracer("test"), duration: h}

	var sawSpan bool
	ok := ri.wrap(proto.ServerType_User, "User", "loadMe",
		func(ctx context.Context, arg interface{}) (interface{}, error) {
			sawSpan = trace.SpanFromContext(ctx).SpanContext().IsValid()
			time.Sleep(5 * time.Millisecond)
			return arg, nil
		})
	bad := ri.wrap(proto.ServerType_User, "User", "loadMe",
		func(context.Context, interface{}) (interface{}, error) {
			return nil, core.AuthError{}
		})

	res, err := ok(ctx, 42)
	require.NoError(t, err)
	require.Equal(t, 42, res)
	require.True(t, sawSpan, "handler ctx should carry the server span")

	_, err = bad(ctx, nil)
	require.ErrorIs(t, err, core.AuthError{})

	// Traces
	ended := spans.Ended()
	require.Len(t, ended, 2)
	require.Equal(t, "User/loadMe", ended[0].Name())
	require.Equal(t, trace.SpanKindServer, ended[0].SpanKind())
	require.GreaterOrEqual(t, ended[0].EndTime().Sub(ended[0].StartTime()), 5*time.Millisecond)
	require.Equal(t, codes.Error, ended[1].Status().Code)

	// Metrics
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(ctx, &rm))
	require.Len(t, rm.ScopeMetrics, 1)
	hist := rm.ScopeMetrics[0].Metrics[0].Data.(metricdata.Histogram[float64])
	require.Len(t, hist.DataPoints, 2, "ok and error calls get separate series")

	var okPts, errPts int
	for _, dp := range hist.DataPoints {
		require.Equal(t, uint64(1), dp.Count)
		v, found := dp.Attributes.Value("rpc.method")
		require.True(t, found)
		require.Equal(t, "loadMe", v.AsString())
		if et, found := dp.Attributes.Value(attribute.Key("error.type")); found {
			errPts++
			require.Equal(t, statusCodeName(core.AuthError{}), et.AsString())
			require.NotEqual(t, "unknown", et.AsString())
		} else {
			okPts++
			require.GreaterOrEqual(t, dp.Sum, 0.005)
		}
	}
	require.Equal(t, 1, okPts)
	require.Equal(t, 1, errPts)
}

type memLogExporter struct {
	mu   sync.Mutex
	recs []sdklog.Record
}

func (e *memLogExporter) Export(_ context.Context, recs []sdklog.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range recs {
		e.recs = append(e.recs, r.Clone())
	}
	return nil
}
func (e *memLogExporter) Shutdown(context.Context) error   { return nil }
func (e *memLogExporter) ForceFlush(context.Context) error { return nil }

func (e *memLogExporter) bodies() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var ret []string
	for _, r := range e.recs {
		ret = append(ret, r.Body().AsString())
	}
	return ret
}

func TestLogTeeToOTel(t *testing.T) {
	g := NewGlobalContext(nil)
	g.logCfg.OutputPaths = []string{filepath.Join(t.TempDir(), "log")}
	require.NoError(t, g.configureLogLevel("info"))

	exp := &memLogExporter{}
	lp := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(exp)))
	require.NoError(t, g.TeeLogCore(otelzap.NewCore("test", otelzap.WithLoggerProvider(lp))))

	tp := sdktrace.NewTracerProvider()
	ctx, span := tp.Tracer("test").Start(context.Background(), "op")
	m := NewMetaContext(ctx, g)

	m.Debugw("hidden")         // below the configured level
	m.Infow("hello", "k", "v") // exported, correlated with span
	g.LocalLog().Infow("local only")

	// The tee survives a level change, and follows the new level.
	require.NoError(t, g.configureLogLevel("debug"))
	m.Debugw("now visible")

	require.NoError(t, g.TeeLogCore(nil))
	m.Infow("after untee")
	span.End()

	require.Equal(t, []string{"hello", "now visible"}, exp.bodies())

	rec := exp.recs[0]
	require.Equal(t, span.SpanContext().TraceID(), rec.TraceID())
	require.Equal(t, span.SpanContext().SpanID(), rec.SpanID())
	var keys []string
	rec.WalkAttributes(func(kv otellog.KeyValue) bool {
		keys = append(keys, kv.Key)
		return true
	})
	require.Contains(t, keys, "k")
	require.NotContains(t, keys, "trace", "the trace field is consumed as context, not an attribute")

	// Local output renders trace ids as a plain field.
	raw, err := os.ReadFile(g.logCfg.OutputPaths[0])
	require.NoError(t, err)
	require.Contains(t, string(raw), span.SpanContext().TraceID().String())
}

func TestInitOTelExportsOnShutdown(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	t.Setenv("OTEL_METRICS_EXPORTER", "none")

	g := NewGlobalContext(nil)
	g.logCfg.OutputPaths = []string{filepath.Join(t.TempDir(), "log")}
	require.NoError(t, g.configureLogLevel("info"))
	m := NewMetaContext(context.Background(), g)

	shutdown, err := InitOTel(m, proto.ServerType_User)
	require.NoError(t, err)
	t.Cleanup(func() {
		otel.SetTracerProvider(tracenoop.NewTracerProvider())
		global.SetLoggerProvider(lognoop.NewLoggerProvider())
	})

	_, span := otel.Tracer("test").Start(context.Background(), "op")
	span.End()
	m.Infow("exported on shutdown")
	require.NoError(t, shutdown(context.Background()))

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, hits["/v1/logs"])
	require.Equal(t, 1, hits["/v1/traces"])
	require.Zero(t, hits["/v1/metrics"], "OTEL_METRICS_EXPORTER=none")
}
