// SPDX-License-Identifier: Apache-2.0

// Package metrics provides Prometheus metrics middleware and helpers for Gin-based services.
package metrics

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

// SLOBuckets defines the latency histogram buckets for SLO tracking.
// Boundaries in seconds: 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s.
var SLOBuckets = []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0}

// defaultExcludedPaths contains paths that are always skipped by the SLO middleware
// unless the caller overrides them entirely via excludePaths.
var defaultExcludedPaths = map[string]struct{}{
	"/health":  {},
	"/healthz": {},
	"/metrics": {},
	"/ready":   {},
	"/readyz":  {},
}

// SLOCollector holds pre-defined SLO metrics for an HTTP service.
// Use NewSLOCollector to create an instance and Register to attach it
// to a prometheus.Registry before recording data.
type SLOCollector struct {
	// RequestsTotal counts all completed HTTP requests, partitioned by
	// handler route pattern, HTTP method, and response status code.
	RequestsTotal *prometheus.CounterVec

	// RequestDuration tracks the latency distribution of completed HTTP
	// requests, partitioned by handler route pattern and HTTP method.
	RequestDuration *prometheus.HistogramVec

	// ActiveRequests tracks the number of HTTP requests currently being
	// processed for each handler route pattern.
	ActiveRequests *prometheus.GaugeVec

	// ErrorRate tracks a computed error rate gauge per handler. Callers
	// may set this externally or drive it from a recording rule.
	ErrorRate *prometheus.GaugeVec

	namespace string
}

// NewSLOCollector constructs a new SLOCollector scoped to the given namespace.
// The namespace is sanitized (hyphens replaced with underscores) before use so
// that the resulting metric names are Prometheus-compliant.
// The returned collector is NOT registered yet; call Register before use.
func NewSLOCollector(namespace string) *SLOCollector {
	ns := sanitizeName(namespace)

	return &SLOCollector{
		namespace: ns,

		RequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: ns,
				Name:      "slo_requests_total",
				Help:      "Total number of HTTP requests processed, partitioned by handler, method, and status code.",
			},
			[]string{"handler", "method", "code"},
		),

		RequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: ns,
				Name:      "slo_request_duration_seconds",
				Help:      "HTTP request latency distribution in seconds, partitioned by handler and method.",
				Buckets:   SLOBuckets,
			},
			[]string{"handler", "method"},
		),

		ActiveRequests: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: ns,
				Name:      "slo_active_requests",
				Help:      "Number of HTTP requests currently being processed, partitioned by handler.",
			},
			[]string{"handler"},
		),

		ErrorRate: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: ns,
				Name:      "slo_error_rate",
				Help:      "Computed error rate (0.0–1.0) per handler. Driven by a recording rule or external updater.",
			},
			[]string{"handler"},
		),
	}
}

// Register registers all SLO metrics with the provided prometheus.Registry.
// It returns the first registration error encountered, if any.
// Calling Register more than once on the same registry will return an error
// for the already-registered metrics; create a fresh SLOCollector for each
// registry you need to support.
func (s *SLOCollector) Register(registry *prometheus.Registry) error {
	collectors := []prometheus.Collector{
		s.RequestsTotal,
		s.RequestDuration,
		s.ActiveRequests,
		s.ErrorRate,
	}
	for _, c := range collectors {
		if err := registry.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// RecordRequest increments the request counter and observes the request
// duration in the histogram. handler is the route pattern (e.g. "/api/v1/users/:id"),
// method is the HTTP verb, code is the numeric HTTP status code as a string,
// and duration is the elapsed wall-clock time for the request.
func (s *SLOCollector) RecordRequest(handler, method, code string, duration time.Duration) {
	s.RequestsTotal.WithLabelValues(handler, method, code).Inc()
	s.RequestDuration.WithLabelValues(handler, method).Observe(duration.Seconds())
}

// NewSLOMiddleware returns a gin.HandlerFunc that automatically records SLO
// metrics for every request that passes through it.
//
// Behavior:
//   - Paths listed in excludePaths (and the built-in defaults: /health,
//     /healthz, /metrics, /ready, /readyz) are skipped — no metrics are
//     recorded for those paths.
//   - The handler label is derived from c.FullPath() so that parameterised
//     routes (e.g. /users/:id) are grouped correctly. If FullPath() returns
//     an empty string (i.e. 404 / unmatched route), the label "unknown" is
//     used instead.
//   - ActiveRequests is incremented before the downstream handler runs and
//     decremented via defer so that panics do not leak the gauge.
//   - The counter and histogram are updated after the downstream handler
//     returns (or panics and recovers).
func (s *SLOCollector) NewSLOMiddleware(excludePaths ...string) gin.HandlerFunc {
	// Build the full exclusion set once at middleware construction time.
	excluded := make(map[string]struct{}, len(defaultExcludedPaths)+len(excludePaths))
	for p := range defaultExcludedPaths {
		excluded[p] = struct{}{}
	}
	for _, p := range excludePaths {
		excluded[p] = struct{}{}
	}

	return func(c *gin.Context) {
		// Skip excluded paths immediately.
		if _, skip := excluded[c.Request.URL.Path]; skip {
			c.Next()
			return
		}

		// Determine the handler label before the request runs so that we have
		// it available even if a panic occurs downstream.
		start := time.Now()

		// Use gin's route pattern for stable label cardinality.
		handler := c.FullPath()
		if handler == "" {
			handler = pathUnknown
		}

		// Track in-flight requests; dec is deferred for panic safety.
		s.ActiveRequests.WithLabelValues(handler).Inc()
		defer s.ActiveRequests.WithLabelValues(handler).Dec()

		c.Next()

		duration := time.Since(start)
		code := http.StatusText(c.Writer.Status())
		if code == "" {
			// Fallback for non-standard status codes.
			code = pathUnknown
		}
		s.RecordRequest(handler, c.Request.Method, code, duration)
	}
}
