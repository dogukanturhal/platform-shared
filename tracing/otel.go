// SPDX-License-Identifier: Apache-2.0

// Package tracing provides OpenTelemetry integration for multi-tenant services.
package tracing

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"
	"go.opentelemetry.io/otel/trace"
)

// normalizeEndpoint turns "http://host:4317", "grpc://host:4317" or "host:4317"
// into a bare host:port and reports whether TLS was requested (https scheme).
func normalizeEndpoint(endpoint string) (hostPort string, secure bool) {
	endpoint = strings.TrimSpace(endpoint)
	if i := strings.Index(endpoint, "://"); i >= 0 {
		secure = strings.EqualFold(endpoint[:i], "https")
		endpoint = endpoint[i+3:]
	}
	return strings.TrimRight(endpoint, "/"), secure
}

// samplerRatio reads OTEL_TRACES_SAMPLER_ARG (0..1). Default 1.0: the
// collector tail-samples, so services export everything.
func samplerRatio() float64 {
	if v := os.Getenv("OTEL_TRACES_SAMPLER_ARG"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 && f <= 1 {
			return f
		}
	}
	return 1.0
}

// InitTracer initializes the OpenTelemetry tracer provider with an OTLP gRPC exporter.
// endpoint may be empty, in which case OTEL_EXPORTER_OTLP_TRACES_ENDPOINT /
// OTEL_EXPORTER_OTLP_ENDPOINT is used. A scheme prefix (http://) is accepted.
// The returned provider must be shut down on exit (see Shutdown).
func InitTracer(serviceName, endpoint string) (*sdktrace.TracerProvider, error) {
	ctx := context.Background()

	if endpoint == "" {
		endpoint = os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	}
	if endpoint == "" {
		endpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}
	hostPort, secure := normalizeEndpoint(endpoint)
	if hostPort == "" {
		return nil, errors.New("tracing: no OTLP endpoint configured")
	}

	opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(hostPort)}
	if !secure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	exporter, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Schemaless attributes merge cleanly with resource.Default() regardless of
	// the semconv version the SDK was built against.
	res, err := resource.Merge(
		resource.Default(),
		resource.NewSchemaless(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion("1.0.0"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter,
			sdktrace.WithBatchTimeout(5*time.Second),
			sdktrace.WithMaxExportBatchSize(512),
		),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(samplerRatio()))),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp, nil
}

// Shutdown flushes and stops the provider, bounded by timeout (default 5s).
func Shutdown(tp *sdktrace.TracerProvider, timeout time.Duration) error {
	if tp == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return tp.Shutdown(ctx)
}

// GinMiddleware returns a Gin middleware that adds OpenTelemetry tracing to HTTP requests.
func GinMiddleware(serviceName string) gin.HandlerFunc {
	tracer := otel.Tracer(serviceName)

	return func(c *gin.Context) {
		// Extract any existing trace context from incoming request headers
		ctx := otel.GetTextMapPropagator().Extract(c.Request.Context(), propagation.HeaderCarrier(c.Request.Header))

		// Start a new span for this request
		spanName := fmt.Sprintf("%s %s", c.Request.Method, c.FullPath())
		if c.FullPath() == "" {
			spanName = fmt.Sprintf("%s %s", c.Request.Method, c.Request.URL.Path)
		}

		ctx, span := tracer.Start(ctx, spanName,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				semconv.HTTPRequestMethodKey.String(c.Request.Method),
				semconv.URLFull(c.Request.URL.String()),
				semconv.HTTPRoute(c.FullPath()),
				semconv.UserAgentOriginal(c.Request.UserAgent()),
				semconv.URLScheme(c.Request.URL.Scheme),
				semconv.ServerAddress(c.Request.Host),
				attribute.String("http.client_ip", c.ClientIP()),
			),
		)
		defer span.End()

		// Store the span context in the Gin context for downstream handlers
		c.Request = c.Request.WithContext(ctx)

		// Add trace ID to response headers for debugging
		if span.SpanContext().HasTraceID() {
			c.Header("X-Trace-ID", span.SpanContext().TraceID().String())
		}

		// Process request
		c.Next()

		// Record response status
		status := c.Writer.Status()
		span.SetAttributes(semconv.HTTPResponseStatusCode(status))

		// Mark span as error if status code indicates failure
		if status >= 400 {
			span.SetAttributes(attribute.Bool("error", true))
		}
		// Per OTel HTTP semconv, only 5xx is a server-side span error.
		if status >= 500 {
			span.SetStatus(codes.Error, http.StatusText(status))
		}

		// Record any errors from the Gin context
		if len(c.Errors) > 0 {
			span.SetAttributes(attribute.String("gin.errors", c.Errors.String()))
		}
	}
}

// SpanFromContext returns the current span from a context.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// TracerFromContext returns a tracer from the global provider.
func TracerFromContext(serviceName string) trace.Tracer {
	return otel.Tracer(serviceName)
}
