// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestNew(t *testing.T) {
	m := New("test-service")
	require.NotNil(t, m)
	assert.NotNil(t, m.RequestDuration)
	assert.NotNil(t, m.RequestsTotal)
	assert.NotNil(t, m.RequestsInFlight)
	assert.NotNil(t, m.Registry)
}

func TestGinMiddleware_RecordsMetrics(t *testing.T) {
	m := New("test-service")
	router := gin.New()
	router.Use(m.GinMiddleware())
	router.GET("/api/v1/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/api/v1/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)

	// Verify metrics were collected by gathering from registry.
	families, err := m.Registry.Gather()
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, f := range families {
		names[f.GetName()] = true
	}

	assert.True(t, names["test_service_http_requests_total"], "requests_total should be registered")
	assert.True(t, names["test_service_http_request_duration_seconds"], "request_duration should be registered")
}

func TestGinMiddleware_SkipsHealthAndMetrics(t *testing.T) {
	m := New("test-svc")
	router := gin.New()
	router.Use(m.GinMiddleware())
	router.GET("/health", func(c *gin.Context) { c.String(200, "ok") })
	router.GET("/metrics", m.Handler())

	for _, path := range []string{"/health", "/metrics"} {
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "GET", path, nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, 200, w.Code)
	}
}

func TestMetricsHandler(t *testing.T) {
	m := New("test-handler")
	router := gin.New()
	router.GET("/metrics", m.Handler())

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/metrics", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "go_goroutines")
}

func TestRegisterCustomMetrics(t *testing.T) {
	m := New("custom-test")

	// Counter
	c := m.RegisterCounter(prometheus.CounterOpts{Namespace: "custom_test", Name: "my_counter", Help: "A test counter"})
	c.Inc()

	// Gauge
	g := m.RegisterGauge(prometheus.GaugeOpts{Namespace: "custom_test", Name: "my_gauge", Help: "A test gauge"})
	g.Set(42)

	// Histogram
	h := m.RegisterHistogram(prometheus.HistogramOpts{Namespace: "custom_test", Name: "my_histogram", Help: "A test histogram"})
	h.Observe(0.5)

	families, err := m.Registry.Gather()
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, f := range families {
		names[f.GetName()] = true
	}
	assert.True(t, names["custom_test_my_counter"])
	assert.True(t, names["custom_test_my_gauge"])
	assert.True(t, names["custom_test_my_histogram"])
}

func TestSanitizeName(t *testing.T) {
	assert.Equal(t, "compute_api", sanitizeName("compute-api"))
	assert.Equal(t, "quota_service", sanitizeName("quota-service"))
	assert.Equal(t, "already_ok", sanitizeName("already_ok"))
}

func TestHTTPHandler_Serves200WithRegistryMetrics(t *testing.T) {
	m := New("http-handler-test")
	// Touch a counter so the registry has at least one HELP+TYPE line.
	m.RequestsInFlight.Inc()
	m.RequestsInFlight.Dec()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.HTTPHandler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	// Service-namespaced metrics from this registry should appear; the
	// global default registry's metrics must NOT (HTTPHandler is bound
	// to the per-service Registry).
	assert.Contains(t, body, "http_handler_test_http_requests_in_flight")
}

func TestStartServer_RoundTripAndShutdown(t *testing.T) {
	m := New("startserver-test")

	// Find a free ephemeral port: bind + immediately release. This has
	// a small TOCTOU window before StartServer re-binds, but is the
	// canonical Go-testing pattern when the SUT only accepts an addr
	// string (not a pre-bound net.Listener).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	srv, errCh := m.StartServer(addr)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = ShutdownContext(srv, 1*time.Second) })

	// Poll until the listener is up. ListenAndServe runs in a goroutine
	// inside StartServer; the bind is racy with the test's first GET.
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			lastErr = nil
			break
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	require.NoError(t, lastErr, "metrics listener never came up at %s", addr)

	for _, path := range []string{"/metrics", "/healthz"} {
		resp, err := http.Get("http://" + addr + path)
		require.NoError(t, err, "GET %s", path)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "GET %s", path)
		_ = resp.Body.Close()
	}

	// Clean shutdown completes promptly + returns nil.
	require.NoError(t, ShutdownContext(srv, 1*time.Second))

	// errCh must close (no startup error). Drain with a small timeout
	// so a buggy StartServer that leaks the goroutine fails the test
	// instead of hanging it.
	select {
	case err, ok := <-errCh:
		if ok {
			t.Fatalf("unexpected error from metrics server: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("metrics server errCh did not close after Shutdown")
	}
}

func TestShutdownContext_NilServerIsNoop(t *testing.T) {
	// Defensive: ShutdownContext on a nil server returns nil (callers
	// can defer Shutdown unconditionally without nil-check).
	assert.NoError(t, ShutdownContext(nil, 100*time.Millisecond))
}
