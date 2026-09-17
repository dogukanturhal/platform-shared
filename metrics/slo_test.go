// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gatherMetricFamily gathers all metric families from reg and returns the one
// matching name, or nil if not found.
func gatherMetricFamily(t *testing.T, reg *prometheus.Registry, name string) *dto.MetricFamily {
	t.Helper()

	families, err := reg.Gather()
	require.NoError(t, err, "gathering metrics should not fail")

	for _, f := range families {
		if f.GetName() == name {
			return f
		}
	}
	return nil
}

// counterValue returns the value of the first counter sample in a MetricFamily.
func counterValue(t *testing.T, f *dto.MetricFamily) float64 {
	t.Helper()
	require.NotNil(t, f, "metric family must not be nil")
	require.NotEmpty(t, f.GetMetric(), "metric family must have at least one metric")
	return f.GetMetric()[0].GetCounter().GetValue()
}

// histogramSampleCount returns the sample count of the first histogram in a
// MetricFamily.
func histogramSampleCount(t *testing.T, f *dto.MetricFamily) uint64 {
	t.Helper()
	require.NotNil(t, f, "metric family must not be nil")
	require.NotEmpty(t, f.GetMetric(), "metric family must have at least one metric")
	return f.GetMetric()[0].GetHistogram().GetSampleCount()
}

// TestSLOCollector_NewCollector verifies that NewSLOCollector initializes all
// metric vectors and stores the sanitized namespace.
func TestSLOCollector_NewCollector(t *testing.T) {
	c := NewSLOCollector("test-service")

	require.NotNil(t, c, "collector must not be nil")
	assert.NotNil(t, c.RequestsTotal, "RequestsTotal must be initialized")
	assert.NotNil(t, c.RequestDuration, "RequestDuration must be initialized")
	assert.NotNil(t, c.ActiveRequests, "ActiveRequests must be initialized")
	assert.NotNil(t, c.ErrorRate, "ErrorRate must be initialized")
	assert.Equal(t, "test_service", c.namespace, "hyphen should be replaced with underscore")
}

// TestSLOCollector_Register verifies that all metrics are registered without
// error, and that re-registering on the same registry returns an error.
func TestSLOCollector_Register(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := NewSLOCollector("reg-test")

	err := c.Register(reg)
	require.NoError(t, err, "first registration must succeed")

	// Re-registering the same collector on the same registry must fail.
	err = c.Register(reg)
	assert.Error(t, err, "re-registration must return an error")
}

// TestSLOCollector_RecordRequest_IncrementsCounter verifies that RecordRequest
// increments the RequestsTotal counter by exactly one per call.
func TestSLOCollector_RecordRequest_IncrementsCounter(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := NewSLOCollector("counter-test")
	require.NoError(t, c.Register(reg))

	c.RecordRequest("/api/v1/orders", "GET", "OK", 50*time.Millisecond)

	f := gatherMetricFamily(t, reg, "counter_test_slo_requests_total")
	require.NotNil(t, f, "counter metric family must be present")
	assert.Equal(t, float64(1), counterValue(t, f), "counter should be incremented to 1")

	c.RecordRequest("/api/v1/orders", "GET", "OK", 30*time.Millisecond)

	f = gatherMetricFamily(t, reg, "counter_test_slo_requests_total")
	assert.Equal(t, float64(2), counterValue(t, f), "counter should be incremented to 2 after second call")
}

// TestSLOCollector_RecordRequest_ObservesHistogram verifies that RecordRequest
// increments the histogram sample count for each observation.
func TestSLOCollector_RecordRequest_ObservesHistogram(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := NewSLOCollector("hist-test")
	require.NoError(t, c.Register(reg))

	c.RecordRequest("/api/v1/items", "POST", "Created", 120*time.Millisecond)
	c.RecordRequest("/api/v1/items", "POST", "Created", 340*time.Millisecond)

	f := gatherMetricFamily(t, reg, "hist_test_slo_request_duration_seconds")
	require.NotNil(t, f, "histogram metric family must be present")
	assert.Equal(t, uint64(2), histogramSampleCount(t, f), "histogram should have 2 observations")
}

// TestSLOCollector_Middleware_RecordsMetrics verifies that the SLO middleware
// records both a counter and histogram observation when a regular route is hit.
func TestSLOCollector_Middleware_RecordsMetrics(t *testing.T) {
	gin.SetMode(gin.TestMode)

	reg := prometheus.NewRegistry()
	c := NewSLOCollector("mw-test")
	require.NoError(t, c.Register(reg))

	router := gin.New()
	router.Use(c.NewSLOMiddleware())
	router.GET("/api/v1/users", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/users", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	counterFamily := gatherMetricFamily(t, reg, "mw_test_slo_requests_total")
	require.NotNil(t, counterFamily, "requests_total family must be recorded")
	assert.Equal(t, float64(1), counterValue(t, counterFamily))

	histFamily := gatherMetricFamily(t, reg, "mw_test_slo_request_duration_seconds")
	require.NotNil(t, histFamily, "request_duration family must be recorded")
	assert.Equal(t, uint64(1), histogramSampleCount(t, histFamily))
}

// TestSLOCollector_Middleware_ExcludesHealthPath verifies that requests to
// /health are not recorded by the SLO middleware.
func TestSLOCollector_Middleware_ExcludesHealthPath(t *testing.T) {
	gin.SetMode(gin.TestMode)

	reg := prometheus.NewRegistry()
	c := NewSLOCollector("exclude-health")
	require.NoError(t, c.Register(reg))

	router := gin.New()
	router.Use(c.NewSLOMiddleware())
	router.GET("/health", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/health", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// No counter metric family should exist because health was excluded.
	f := gatherMetricFamily(t, reg, "exclude_health_slo_requests_total")
	if f != nil {
		assert.Equal(t, float64(0), counterValue(t, f), "health path must not be counted")
	}
}

// TestSLOCollector_Middleware_ExcludesMetricsPath verifies that all built-in
// excluded paths (/health, /healthz, /metrics, /ready, /readyz) are skipped by
// the middleware and produce no counter observations.
func TestSLOCollector_Middleware_ExcludesMetricsPath(t *testing.T) {
	gin.SetMode(gin.TestMode)

	excludedPaths := []string{"/health", "/healthz", "/metrics", "/ready", "/readyz"}

	for _, path := range excludedPaths {
		path := path // capture loop variable
		t.Run(path, func(t *testing.T) {
			// Use a unique namespace per sub-test to get an isolated registry.
			ns := "excl" + sanitizeName(path)
			reg := prometheus.NewRegistry()
			c := NewSLOCollector(ns)
			require.NoError(t, c.Register(reg))

			// Create a fresh router for each path to avoid duplicate-route panics.
			router := gin.New()
			router.Use(c.NewSLOMiddleware())
			router.GET(path, func(ctx *gin.Context) {
				ctx.String(http.StatusOK, "ok")
			})

			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "path %s should return 200", path)

			// No counter metric family should exist because the path was excluded.
			metricName := sanitizeName(ns) + "_slo_requests_total"
			f := gatherMetricFamily(t, reg, metricName)
			if f != nil {
				assert.Equal(t, float64(0), counterValue(t, f),
					"excluded path %s must not be counted", path)
			}
		})
	}
}

// TestSLOCollector_Middleware_HandlesUnknownRoute verifies that unmatched
// routes (404s) use the "unknown" handler label rather than the empty string.
func TestSLOCollector_Middleware_HandlesUnknownRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)

	reg := prometheus.NewRegistry()
	c := NewSLOCollector("unknown-route")
	require.NoError(t, c.Register(reg))

	router := gin.New()
	router.Use(c.NewSLOMiddleware())
	// No routes registered — every request will be a 404.

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/no-such-route", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	// The counter should have been incremented with handler="unknown".
	counterFamily := gatherMetricFamily(t, reg, "unknown_route_slo_requests_total")
	require.NotNil(t, counterFamily, "counter metric family must be present for unknown route")

	metric := counterFamily.GetMetric()
	require.NotEmpty(t, metric)

	var foundUnknown bool
	for _, m := range metric {
		for _, lp := range m.GetLabel() {
			if lp.GetName() == "handler" && lp.GetValue() == "unknown" {
				foundUnknown = true
			}
		}
	}
	assert.True(t, foundUnknown, "handler label must be 'unknown' for unmatched routes")
}

// TestSLOCollector_Middleware_CustomExcludedPath verifies that caller-supplied
// paths are excluded in addition to the built-in defaults.
func TestSLOCollector_Middleware_CustomExcludedPath(t *testing.T) {
	gin.SetMode(gin.TestMode)

	reg := prometheus.NewRegistry()
	c := NewSLOCollector("custom-exclude")
	require.NoError(t, c.Register(reg))

	router := gin.New()
	router.Use(c.NewSLOMiddleware("/ping")) // caller excludes /ping
	router.GET("/ping", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "pong")
	})
	router.GET("/api/v1/data", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"data": true})
	})

	// /ping must be excluded.
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/ping", nil)
	router.ServeHTTP(w, req)

	// /api/v1/data must be recorded.
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/data", nil)
	router.ServeHTTP(w2, req2)

	counterFamily := gatherMetricFamily(t, reg, "custom_exclude_slo_requests_total")
	require.NotNil(t, counterFamily, "counter must be recorded for non-excluded route")
	assert.Equal(t, float64(1), counterValue(t, counterFamily), "only /api/v1/data should be counted")
}

// TestSLOBuckets_HasExpectedCount verifies the SLOBuckets slice has exactly 10
// entries and the first and last values are correct.
func TestSLOBuckets_HasExpectedCount(t *testing.T) {
	assert.Len(t, SLOBuckets, 10, "SLOBuckets must have 10 entries")
	assert.Equal(t, 0.01, SLOBuckets[0], "first bucket must be 10ms (0.01s)")
	assert.Equal(t, 10.0, SLOBuckets[len(SLOBuckets)-1], "last bucket must be 10s (10.0s)")
}
