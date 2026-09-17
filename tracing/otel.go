// SPDX-License-Identifier: Apache-2.0

// Package tracing provides OpenTelemetry integration for ExampleSuite platform services.
package tracing

import (
	"context"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// InitTracer initializes the OpenTelemetry tracer provider with OTLP gRPC exporter.
// It returns the tracer provider that should be shut down when the application exits.
func InitTracer(serviceName, endpoint string) (*sdktrace.TracerProvider, error) {
	ctx := context.Background()

	// Create OTLP gRPC exporter
	conn, err := grpc.NewClient(endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	exporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithGRPCConn(conn))
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Create resource with service information
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion("1.0.0"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create tracer provider with batch span processor
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter,
			sdktrace.WithBatchTimeout(5*time.Second),
			sdktrace.WithMaxExportBatchSize(512),
		),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(1.0))),
	)

	// Set as global tracer provider
	otel.SetTracerProvider(tp)

	// Set up propagator for distributed tracing context
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp, nil
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
