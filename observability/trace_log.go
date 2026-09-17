// SPDX-License-Identifier: Apache-2.0

// Package observability provides utilities that bridge OpenTelemetry tracing with
// structured logging (zap) so that every log line emitted during a request is
// automatically annotated with the active trace_id and span_id.
package observability

import (
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

const (
	// contextKeyTraceLogger is the gin context key under which the enriched logger is stored.
	contextKeyTraceLogger = "trace_logger"
)

// TraceAwareLogger returns a new *zap.Logger that has trace_id and span_id fields injected
// from the provided span's SpanContext. If the span is nil or its SpanContext is not valid
// (e.g. a no-op span), the original logger is returned unchanged so callers never receive nil.
func TraceAwareLogger(logger *zap.Logger, span trace.Span) *zap.Logger {
	if logger == nil {
		logger = zap.NewNop()
	}
	if span == nil {
		return logger
	}

	sc := span.SpanContext()
	if !sc.IsValid() {
		return logger
	}

	return logger.With(
		zap.String("trace_id", sc.TraceID().String()),
		zap.String("span_id", sc.SpanID().String()),
	)
}

// TracingMiddleware returns a gin.HandlerFunc that:
//  1. Extracts an existing trace context from the incoming HTTP headers using the global
//     OTel propagator (W3C TraceContext + Baggage by default).
//  2. Starts a new server-side span named "<METHOD> <path>".
//  3. Enriches the provided logger with trace_id and span_id fields via TraceAwareLogger.
//  4. Stores the enriched logger in the gin.Context under the key "trace_logger".
//  5. Sets X-Trace-ID and X-Span-ID response headers for client-side correlation.
//
// The returned middleware calls c.Next() so it must be registered before route handlers.
func TracingMiddleware(serviceName string, logger *zap.Logger) gin.HandlerFunc {
	tracer := otel.Tracer(serviceName)

	return func(c *gin.Context) {
		// Extract any upstream trace context from the request headers.
		ctx := otel.GetTextMapPropagator().Extract(
			c.Request.Context(),
			propagation.HeaderCarrier(c.Request.Header),
		)

		// Compose a human-readable span name.
		spanName := c.Request.Method + " " + c.FullPath()
		if c.FullPath() == "" {
			spanName = c.Request.Method + " " + c.Request.URL.Path
		}

		// Start the server span.
		ctx, span := tracer.Start(ctx, spanName, trace.WithSpanKind(trace.SpanKindServer))
		defer span.End()

		// Propagate the updated context into the request so downstream handlers and
		// outbound clients can access the span.
		c.Request = c.Request.WithContext(ctx)

		// Build a trace-enriched logger and store it in the gin context.
		enriched := TraceAwareLogger(logger, span)
		c.Set(contextKeyTraceLogger, enriched)

		// Expose trace / span IDs as response headers for client-side debugging.
		sc := span.SpanContext()
		if sc.HasTraceID() {
			c.Header("X-Trace-ID", sc.TraceID().String())
		}
		if sc.HasSpanID() {
			c.Header("X-Span-ID", sc.SpanID().String())
		}

		c.Next()
	}
}

// LoggerFromContext retrieves the trace-aware logger stored by TracingMiddleware.
// If no enriched logger is found in the context (e.g. middleware was not registered),
// it returns a no-op logger so callers always receive a valid *zap.Logger.
func LoggerFromContext(c *gin.Context) *zap.Logger {
	if val, exists := c.Get(contextKeyTraceLogger); exists {
		if l, ok := val.(*zap.Logger); ok {
			return l
		}
	}
	return zap.NewNop()
}
