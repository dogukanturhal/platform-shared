// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// ---- helpers ----------------------------------------------------------------

func init() {
	gin.SetMode(gin.TestMode)
}

// newObserverLogger returns a zap.Logger backed by an in-memory observer so that
// tests can inspect the log entries that were emitted.
func newObserverLogger() (*zap.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.DebugLevel)
	return zap.New(core), logs
}

// newTestTracer registers a real (in-process) TracerProvider and returns a tracer.
// The provider uses a no-op exporter so tests don't require an OTLP collector.
func newTestTracer(t *testing.T) trace.Tracer {
	t.Helper()
	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(nil) }) //nolint:staticcheck
	otel.SetTracerProvider(tp)
	return tp.Tracer("test-service")
}

// performRequest creates a gin engine with the given handlers and fires a GET request.
func performRequest(handlers ...gin.HandlerFunc) *httptest.ResponseRecorder {
	engine := gin.New()
	engine.GET("/test", handlers...)
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	engine.ServeHTTP(w, req)
	return w
}

// ---- tests ------------------------------------------------------------------

func TestTraceAwareLogger_InjectsTraceID(t *testing.T) {
	tracer := newTestTracer(t)
	_, span := tracer.Start(t.Context(), "test-span")
	defer span.End()

	logger, logs := newObserverLogger()
	enriched := TraceAwareLogger(logger, span)
	enriched.Info("hello")

	require.Equal(t, 1, logs.Len())
	fields := logs.All()[0].ContextMap()
	traceID, ok := fields["trace_id"]
	require.True(t, ok, "trace_id field must be present")
	assert.NotEmpty(t, traceID, "trace_id must not be empty")
	// A valid OTel trace ID is 32 hex characters.
	assert.Len(t, traceID, 32)
}

func TestTraceAwareLogger_InjectsSpanID(t *testing.T) {
	tracer := newTestTracer(t)
	_, span := tracer.Start(t.Context(), "test-span")
	defer span.End()

	logger, logs := newObserverLogger()
	enriched := TraceAwareLogger(logger, span)
	enriched.Info("hello")

	require.Equal(t, 1, logs.Len())
	fields := logs.All()[0].ContextMap()
	spanID, ok := fields["span_id"]
	require.True(t, ok, "span_id field must be present")
	assert.NotEmpty(t, spanID, "span_id must not be empty")
	// A valid OTel span ID is 16 hex characters.
	assert.Len(t, spanID, 16)
}

func TestTraceAwareLogger_NoSpan_NoCrash(t *testing.T) {
	logger, logs := newObserverLogger()

	// nil span — must return the original logger without panicking.
	enriched := TraceAwareLogger(logger, nil)
	require.NotNil(t, enriched)
	enriched.Info("no span")

	require.Equal(t, 1, logs.Len())
	// No trace_id / span_id fields should be injected.
	fields := logs.All()[0].ContextMap()
	_, hasTrace := fields["trace_id"]
	_, hasSpan := fields["span_id"]
	assert.False(t, hasTrace)
	assert.False(t, hasSpan)
}

func TestTraceAwareLogger_NoopSpan_NoCrash(t *testing.T) {
	// trace.SpanFromContext on a background context returns a no-op span with an
	// invalid SpanContext — TraceAwareLogger must handle this gracefully.
	noopSpan := trace.SpanFromContext(t.Context())

	logger, logs := newObserverLogger()
	enriched := TraceAwareLogger(logger, noopSpan)
	require.NotNil(t, enriched)
	enriched.Info("noop span")

	require.Equal(t, 1, logs.Len())
	fields := logs.All()[0].ContextMap()
	_, hasTrace := fields["trace_id"]
	assert.False(t, hasTrace, "noop span must not inject trace_id")
}

func TestTracingMiddleware_SetsHeaders(t *testing.T) {
	newTestTracer(t) // registers the SDK provider globally

	logger := zap.NewNop()
	mw := TracingMiddleware("svc", logger)

	w := performRequest(mw, func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get("X-Trace-ID"), "X-Trace-ID response header must be set")
	assert.NotEmpty(t, w.Header().Get("X-Span-ID"), "X-Span-ID response header must be set")
}

func TestTracingMiddleware_StoresLogger(t *testing.T) {
	newTestTracer(t)

	base, logs := newObserverLogger()
	mw := TracingMiddleware("svc", base)

	var capturedLogger *zap.Logger
	handler := func(c *gin.Context) {
		capturedLogger = LoggerFromContext(c)
		capturedLogger.Info("inside handler")
		c.Status(http.StatusOK)
	}

	w := performRequest(mw, handler)
	assert.Equal(t, http.StatusOK, w.Code)

	require.NotNil(t, capturedLogger)
	require.Equal(t, 1, logs.Len())

	// The log entry must carry trace_id and span_id.
	fields := logs.All()[0].ContextMap()
	assert.Contains(t, fields, "trace_id")
	assert.Contains(t, fields, "span_id")
}

func TestLoggerFromContext_ReturnsEnrichedLogger(t *testing.T) {
	newTestTracer(t)

	base, logs := newObserverLogger()
	mw := TracingMiddleware("svc", base)

	performRequest(mw, func(c *gin.Context) {
		l := LoggerFromContext(c)
		l.Warn("warn message")
		c.Status(http.StatusOK)
	})

	require.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	assert.Equal(t, zapcore.WarnLevel, entry.Level)
	assert.Equal(t, "warn message", entry.Message)

	fields := entry.ContextMap()
	assert.NotEmpty(t, fields["trace_id"])
	assert.NotEmpty(t, fields["span_id"])
}

func TestLoggerFromContext_NoMiddleware_ReturnsNop(t *testing.T) {
	// When TracingMiddleware has not been registered, LoggerFromContext must return
	// a valid (nop) logger rather than nil so callers never panic.
	engine := gin.New()
	engine.GET("/nop", func(c *gin.Context) {
		l := LoggerFromContext(c)
		require.NotNil(t, l)
		l.Info("should not panic")
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/nop", nil)
	engine.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
