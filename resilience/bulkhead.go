// SPDX-License-Identifier: Apache-2.0

// Package resilience provides circuit breaker, bulkhead, and retry patterns for resilient service communication.
package resilience

import (
	"context"
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// ErrBulkheadFull is returned when all concurrent slots are occupied and the context expires.
var ErrBulkheadFull = errors.New("bulkhead: all slots are occupied")

// BulkheadMetrics holds Prometheus metrics for a Bulkhead instance.
type BulkheadMetrics struct {
	// Accepted counts requests that acquired a slot.
	Accepted prometheus.Counter
	// Rejected counts requests that were rejected because all slots were occupied.
	Rejected prometheus.Counter
	// Active tracks the number of requests currently holding a slot.
	Active prometheus.Gauge
	// WaitTime observes how long callers waited to acquire a slot.
	WaitTime prometheus.Histogram
}

// Bulkhead implements the bulkhead pattern using a semaphore channel to isolate
// concurrent operations and prevent one slow resource from exhausting all goroutines.
//
// Example:
//
//	bh := resilience.NewBulkhead("db-calls", 20)
//	err := bh.Execute(ctx, func() error {
//	    return db.QueryRow(...)
//	})
type Bulkhead struct {
	name          string
	maxConcurrent int
	sem           chan struct{}
	metrics       *BulkheadMetrics
}

// NewBulkhead creates a Bulkhead that allows at most maxConcurrent simultaneous executions.
// Callers that cannot acquire a slot within the context deadline receive ErrBulkheadFull.
func NewBulkhead(name string, maxConcurrent int) *Bulkhead {
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}
	return &Bulkhead{
		name:          name,
		maxConcurrent: maxConcurrent,
		sem:           make(chan struct{}, maxConcurrent),
	}
}

// WithMetrics registers Prometheus metrics for this bulkhead on the provided registry
// and returns the same Bulkhead for chaining.
func (b *Bulkhead) WithMetrics(registry *prometheus.Registry) *Bulkhead {
	ns := sanitizeBulkheadName(b.name)

	accepted := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   "bulkhead",
		Subsystem:   ns,
		Name:        "accepted_total",
		Help:        "Total number of requests that successfully acquired a bulkhead slot.",
		ConstLabels: prometheus.Labels{"name": b.name},
	})
	rejected := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   "bulkhead",
		Subsystem:   ns,
		Name:        "rejected_total",
		Help:        "Total number of requests rejected because the bulkhead was full.",
		ConstLabels: prometheus.Labels{"name": b.name},
	})
	active := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   "bulkhead",
		Subsystem:   ns,
		Name:        "active",
		Help:        "Number of requests currently executing inside the bulkhead.",
		ConstLabels: prometheus.Labels{"name": b.name},
	})
	waitTime := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace:   "bulkhead",
		Subsystem:   ns,
		Name:        "wait_duration_seconds",
		Help:        "Time spent waiting to acquire a bulkhead slot.",
		Buckets:     []float64{0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5},
		ConstLabels: prometheus.Labels{"name": b.name},
	})

	registry.MustRegister(accepted, rejected, active, waitTime)

	b.metrics = &BulkheadMetrics{
		Accepted: accepted,
		Rejected: rejected,
		Active:   active,
		WaitTime: waitTime,
	}
	return b
}

// Acquire blocks until a slot is available or the context is canceled.
// Returns ErrBulkheadFull when the context expires before a slot becomes free.
// Callers must call Release when the work is done.
func (b *Bulkhead) Acquire(ctx context.Context) error {
	start := time.Now()

	select {
	case b.sem <- struct{}{}:
		// Slot acquired immediately.
		if b.metrics != nil {
			b.metrics.Accepted.Inc()
			b.metrics.Active.Inc()
			b.metrics.WaitTime.Observe(time.Since(start).Seconds())
		}
		return nil
	default:
		// No slot available — block until context canceled or slot freed.
	}

	select {
	case b.sem <- struct{}{}:
		if b.metrics != nil {
			b.metrics.Accepted.Inc()
			b.metrics.Active.Inc()
			b.metrics.WaitTime.Observe(time.Since(start).Seconds())
		}
		return nil
	case <-ctx.Done():
		if b.metrics != nil {
			b.metrics.Rejected.Inc()
		}
		return ErrBulkheadFull
	}
}

// Release returns a previously acquired slot back to the pool.
// Release must be called exactly once for each successful Acquire call.
// Calling Release without a prior Acquire will panic.
func (b *Bulkhead) Release() {
	<-b.sem
	if b.metrics != nil {
		b.metrics.Active.Dec()
	}
}

// Execute acquires a slot, runs fn, and releases the slot — even if fn panics.
// Returns ErrBulkheadFull when the context expires before a slot is available.
func (b *Bulkhead) Execute(ctx context.Context, fn func() error) error {
	if err := b.Acquire(ctx); err != nil {
		return err
	}
	defer b.Release()
	return fn()
}

// sanitizeBulkheadName converts hyphens to underscores so the name is valid in
// Prometheus metric identifiers.
func sanitizeBulkheadName(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] == '-' {
			b[i] = '_'
		}
	}
	return string(b)
}
