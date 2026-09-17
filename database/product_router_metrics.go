// SPDX-License-Identifier: Apache-2.0

package database

import (
	"github.com/prometheus/client_golang/prometheus"
)

// RouterMetrics holds Prometheus metrics for the ProductConnectionRouter.
type RouterMetrics struct {
	LookupsTotal   *prometheus.CounterVec
	LookupDuration *prometheus.HistogramVec
	PoolCreations  *prometheus.CounterVec
	PoolEvictions  *prometheus.CounterVec
	ActivePools    *prometheus.GaugeVec
	SecurityEvents *prometheus.CounterVec
}

// NewRouterMetrics creates and registers router metrics.
// Pass nil registry to use prometheus.DefaultRegisterer.
func NewRouterMetrics(reg prometheus.Registerer) *RouterMetrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}

	m := &RouterMetrics{
		LookupsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "hexxlock",
			Subsystem: "product_router",
			Name:      "lookups_total",
			Help:      "Total number of tenant database lookups by cache tier hit.",
		}, []string{"database", "isolation_mode", "cache_tier"}),

		LookupDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "hexxlock",
			Subsystem: "product_router",
			Name:      "lookup_duration_seconds",
			Help:      "Duration of tenant database lookups.",
			Buckets:   []float64{0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5},
		}, []string{"database"}),

		PoolCreations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "hexxlock",
			Subsystem: "product_router",
			Name:      "pool_creations_total",
			Help:      "Total number of tenant-specific connection pools created.",
		}, []string{"database", "isolation_mode"}),

		PoolEvictions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "hexxlock",
			Subsystem: "product_router",
			Name:      "pool_evictions_total",
			Help:      "Total number of tenant-specific connection pools evicted.",
		}, []string{"database", "reason"}),

		ActivePools: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "hexxlock",
			Subsystem: "product_router",
			Name:      "active_pools",
			Help:      "Current number of active tenant-specific connection pools.",
		}, []string{"isolation_mode"}),

		SecurityEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "hexxlock",
			Subsystem: "product_router",
			Name:      "security_events_total",
			Help:      "Security-related events (ownership mismatch, cache tampering, etc).",
		}, []string{"event_type"}),
	}

	reg.MustRegister(
		m.LookupsTotal,
		m.LookupDuration,
		m.PoolCreations,
		m.PoolEvictions,
		m.ActivePools,
		m.SecurityEvents,
	)
	return m
}

// WithMetrics sets Prometheus metrics on the router.
func WithMetrics(m *RouterMetrics) RouterOption {
	return func(r *ProductConnectionRouter) {
		r.metrics = m
	}
}
