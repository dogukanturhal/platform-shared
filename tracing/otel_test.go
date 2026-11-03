// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestNormalizeEndpoint(t *testing.T) {
	cases := []struct {
		in     string
		host   string
		secure bool
	}{
		{"http://alloy-otlp:4317", "alloy-otlp:4317", false},
		{"https://otel.example:4317/", "otel.example:4317", true},
		{"grpc://a:1", "a:1", false},
		{"a:4317", "a:4317", false},
		{"", "", false},
	}
	for _, c := range cases {
		h, s := normalizeEndpoint(c.in)
		assert.Equal(t, c.host, h, c.in)
		assert.Equal(t, c.secure, s, c.in)
	}
}

func TestSamplerRatio(t *testing.T) {
	assert.Equal(t, 1.0, samplerRatio())
	t.Setenv("OTEL_TRACES_SAMPLER_ARG", "0.25")
	assert.Equal(t, 0.25, samplerRatio())
	t.Setenv("OTEL_TRACES_SAMPLER_ARG", "bogus")
	assert.Equal(t, 1.0, samplerRatio())
}

func TestInitTracer_NoEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	_, err := InitTracer("svc", "")
	assert.Error(t, err)
}

func TestInitTracer_HTTPSchemeAndResource(t *testing.T) {
	tp, err := InitTracer("svc-test", "http://127.0.0.1:4317")
	require.NoError(t, err, "no conflicting schema URL / scheme errors")
	defer func() { _ = Shutdown(tp, time.Second) }()

	_, span := tp.Tracer("t").Start(context.Background(), "op")
	assert.True(t, span.SpanContext().IsSampled())
	span.End()

	fields := otel.GetTextMapPropagator().Fields()
	assert.Contains(t, fields, "traceparent")
	assert.Contains(t, fields, "baggage")
}

func TestInitTracer_EnvEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4317")
	tp, err := InitTracer("svc-env", "")
	require.NoError(t, err)
	assert.NoError(t, Shutdown(tp, 200*time.Millisecond))
}

func TestGinMiddleware_5xxSetsErrorStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	defer otel.SetTracerProvider(prev)

	r := gin.New()
	r.Use(GinMiddleware("svc"))
	r.GET("/boom", func(c *gin.Context) { c.Status(http.StatusInternalServerError) })
	r.GET("/nf", func(c *gin.Context) { c.Status(http.StatusNotFound) })
	for _, p := range []string{"/boom", "/nf"} {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", p, nil))
	}
	spans := rec.Ended()
	require.Len(t, spans, 2)
	assert.Equal(t, codes.Error, spans[0].Status().Code)
	assert.Equal(t, codes.Unset, spans[1].Status().Code)
}
