// SPDX-License-Identifier: Apache-2.0

// Package metrics provides Prometheus metrics middleware and helpers for Gin-based services.
package metrics

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const pathUnknown = "unknown"

// Metrics holds the Prometheus metrics for a service.
type Metrics struct {
	RequestDuration  *prometheus.HistogramVec
	RequestsTotal    *prometheus.CounterVec
	RequestsInFlight prometheus.Gauge
	Registry         *prometheus.Registry
}

// New creates a new Metrics instance registered under the given service name.
func New(serviceName string) *Metrics {
	reg := prometheus.NewRegistry()
	// Register default Go and process collectors.
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	m := &Metrics{
		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: sanitizeName(serviceName),
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request duration in seconds.",
			Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, []string{"method", "path", "status"}),
		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: sanitizeName(serviceName),
			Name:      "http_requests_total",
			Help:      "Total number of HTTP requests.",
		}, []string{"method", "path", "status"}),
		RequestsInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: sanitizeName(serviceName),
			Name:      "http_requests_in_flight",
			Help:      "Number of HTTP requests currently being processed.",
		}),
		Registry: reg,
	}

	reg.MustRegister(m.RequestDuration)
	reg.MustRegister(m.RequestsTotal)
	reg.MustRegister(m.RequestsInFlight)

	return m
}

// GinMiddleware returns a Gin middleware that records request metrics.
func (m *Metrics) GinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/metrics" || c.Request.URL.Path == "/health" || c.Request.URL.Path == "/ready" {
			c.Next()
			return
		}

		m.RequestsInFlight.Inc()
		start := time.Now()

		c.Next()

		m.RequestsInFlight.Dec()
		duration := time.Since(start).Seconds()
		status := strconv.Itoa(c.Writer.Status())
		path := c.FullPath()
		if path == "" {
			path = pathUnknown
		}

		m.RequestDuration.WithLabelValues(c.Request.Method, path, status).Observe(duration)
		m.RequestsTotal.WithLabelValues(c.Request.Method, path, status).Inc()
	}
}

// Handler returns an HTTP handler for the /metrics endpoint.
func (m *Metrics) Handler() gin.HandlerFunc {
	h := promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}

// HTTPHandler returns a stdlib net/http handler for the /metrics endpoint.
//
// Use this when wiring metrics on a SEPARATE listener from the main app
// router — the canonical kube-prometheus-stack pattern is a dedicated
// metrics port (typically :9090) so authn/authz middleware on the app
// port doesn't need /metrics carve-outs and Prometheus scrapes do not
// share request-budget with user traffic.
//
// For services that wire metrics on the same Gin router as the app
// (e.g. compute-api, quota-service, network-api), use Handler() instead.
func (m *Metrics) HTTPHandler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}

// StartServer launches a dedicated HTTP server on addr that serves
// /metrics for this Metrics registry, and returns the *http.Server so
// the caller can issue Shutdown() during graceful termination.
//
// The server runs in a background goroutine; ListenAndServe errors
// (port-in-use, etc.) are reported via the returned error channel.
// Read once on startup-failure detection; the channel closes after
// Shutdown completes.
//
// Why a separate listener instead of the main router:
//   - The chart-active services chart exposes a `metrics` Service port
//     (:9090) distinct from the app `http` port. ServiceMonitor scrapes
//     :9090 — wiring metrics on the app port would require either a
//     chart change or a per-Service metricRelabeling carve-out.
//   - Industry convention (sigs.k8s.io/prometheus-operator examples,
//     kube-prometheus-stack defaults, OpenTelemetry collector pattern)
//     is metrics-on-separate-port. Keeps authn/authz on the app port
//     simple and scrape availability independent of app health.
//
// Listener hardening: ReadHeaderTimeout is set to 5s to mitigate
// Slowloris (golangci-lint G112). Body read timeout is not relevant
// for a GET-only metrics endpoint.
func (m *Metrics) StartServer(addr string) (*http.Server, <-chan error) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", m.HTTPHandler())
	// /healthz on the metrics port is informational only; the chart's
	// kubelet probes target /healthz on the app port. Useful for
	// debugging "is the metrics listener up?" via direct curl.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("metrics server on %s: %w", addr, err)
		}
	}()

	return srv, errCh
}

// ShutdownContext is a convenience for callers that want a single-call
// shutdown with a fixed timeout. Returns nil on clean shutdown or the
// wrapped Shutdown error if the deadline is exceeded.
func ShutdownContext(srv *http.Server, timeout time.Duration) error {
	if srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return srv.Shutdown(ctx)
}

// RegisterCounter registers a custom counter on this metrics registry.
func (m *Metrics) RegisterCounter(opts prometheus.CounterOpts) prometheus.Counter {
	c := prometheus.NewCounter(opts)
	m.Registry.MustRegister(c)
	return c
}

// RegisterCounterVec registers a custom counter vector on this metrics registry.
func (m *Metrics) RegisterCounterVec(opts prometheus.CounterOpts, labels []string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(opts, labels)
	m.Registry.MustRegister(c)
	return c
}

// RegisterGauge registers a custom gauge on this metrics registry.
func (m *Metrics) RegisterGauge(opts prometheus.GaugeOpts) prometheus.Gauge {
	g := prometheus.NewGauge(opts)
	m.Registry.MustRegister(g)
	return g
}

// RegisterGaugeVec registers a custom gauge vector on this metrics registry.
func (m *Metrics) RegisterGaugeVec(opts prometheus.GaugeOpts, labels []string) *prometheus.GaugeVec {
	g := prometheus.NewGaugeVec(opts, labels)
	m.Registry.MustRegister(g)
	return g
}

// RegisterHistogram registers a custom histogram on this metrics registry.
func (m *Metrics) RegisterHistogram(opts prometheus.HistogramOpts) prometheus.Histogram {
	h := prometheus.NewHistogram(opts)
	m.Registry.MustRegister(h)
	return h
}

// RegisterHistogramVec registers a custom histogram vector on this metrics registry.
func (m *Metrics) RegisterHistogramVec(opts prometheus.HistogramOpts, labels []string) *prometheus.HistogramVec {
	h := prometheus.NewHistogramVec(opts, labels)
	m.Registry.MustRegister(h)
	return h
}

// sanitizeName replaces hyphens with underscores for Prometheus metric names.
func sanitizeName(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] == '-' {
			b[i] = '_'
		}
	}
	return string(b)
}
