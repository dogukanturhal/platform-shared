// SPDX-License-Identifier: Apache-2.0

// Package resilience provides circuit breaker and retry patterns for resilient service communication.
package resilience

import (
	"errors"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// ErrLockNotAcquired is returned when a distributed lock cannot be acquired.
var ErrLockNotAcquired = errors.New("distributed lock: not acquired")

// ErrLockNotHeld is returned when an operation requires holding the lock but the token does not match.
var ErrLockNotHeld = errors.New("distributed lock: not held by this caller")

// SlidingWindowConfig holds configuration for a time-based sliding-window circuit breaker.
type SlidingWindowConfig struct {
	// Name is used for metrics labeling.
	Name string
	// BucketCount is the number of time buckets in the ring buffer (e.g. 10).
	BucketCount int
	// BucketDuration is the duration each bucket covers (e.g. 1s). Total window = BucketCount * BucketDuration.
	BucketDuration time.Duration
	// FailureRateThreshold is the ratio (0.0–1.0) of failures to total requests that trips the circuit.
	FailureRateThreshold float64
	// MinRequests is the minimum number of requests in the window before the failure rate is evaluated.
	MinRequests int
	// HalfOpenMaxRequests is the number of probe requests allowed in the half-open state.
	HalfOpenMaxRequests int
	// RecoveryTimeout is how long the circuit stays open before transitioning to half-open.
	RecoveryTimeout time.Duration
	// Fallback is an optional function called with the triggering error when the circuit is open.
	// If nil, ErrCircuitOpen is returned directly.
	Fallback func(error) error
}

// bucket holds aggregated outcome counts for a single time window slice.
type bucket struct {
	successes int64
	failures  int64
}

func (b *bucket) total() int64 { return b.successes + b.failures }
func (b *bucket) reset()       { b.successes = 0; b.failures = 0 }

// slidingWindowMetrics holds Prometheus instruments for a SlidingWindowCircuitBreaker.
type slidingWindowMetrics struct {
	failureRate prometheus.Gauge
	requests    *prometheus.CounterVec
	state       prometheus.Gauge
}

// SlidingWindowCircuitBreaker is a time-based sliding-window circuit breaker inspired by
// Resilience4j's TIME_BASED mode. It divides a rolling time window into fixed-duration
// buckets and evaluates the failure rate lazily on each Execute call.
//
// State machine:
//
//	Closed → Open  : when failure rate > threshold AND total >= MinRequests
//	Open   → HalfOpen : after RecoveryTimeout has elapsed
//	HalfOpen → Closed : when HalfOpenMaxRequests probes all succeed
//	HalfOpen → Open   : when any probe fails
type SlidingWindowCircuitBreaker struct {
	mu  sync.Mutex
	cfg SlidingWindowConfig

	state          State
	openedAt       time.Time // when the circuit entered Open
	halfOpenProbes int       // probes attempted in HalfOpen

	// ring buffer of time buckets
	buckets    []bucket
	bucketIdx  int       // index of the current (newest) bucket
	bucketTime time.Time // start time of the current bucket

	metrics *slidingWindowMetrics
}

// NewSlidingWindowCircuitBreaker creates a new SlidingWindowCircuitBreaker with the provided config.
// Defaults are applied for zero-valued config fields.
func NewSlidingWindowCircuitBreaker(cfg SlidingWindowConfig) *SlidingWindowCircuitBreaker {
	if cfg.Name == "" {
		cfg.Name = "default"
	}
	if cfg.BucketCount <= 0 {
		cfg.BucketCount = 10
	}
	if cfg.BucketDuration <= 0 {
		cfg.BucketDuration = time.Second
	}
	if cfg.FailureRateThreshold <= 0 {
		cfg.FailureRateThreshold = 0.5
	}
	if cfg.MinRequests <= 0 {
		cfg.MinRequests = 10
	}
	if cfg.HalfOpenMaxRequests <= 0 {
		cfg.HalfOpenMaxRequests = 5
	}
	if cfg.RecoveryTimeout <= 0 {
		cfg.RecoveryTimeout = 30 * time.Second
	}

	return &SlidingWindowCircuitBreaker{
		cfg:        cfg,
		state:      StateClosed,
		buckets:    make([]bucket, cfg.BucketCount),
		bucketIdx:  0,
		bucketTime: time.Now(),
	}
}

// WithMetrics registers Prometheus metrics for this circuit breaker on the provided registry
// and returns the same SlidingWindowCircuitBreaker for chaining.
func (sw *SlidingWindowCircuitBreaker) WithMetrics(registry *prometheus.Registry) *SlidingWindowCircuitBreaker {
	failureRate := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "sliding_cb_failure_rate",
		Help:        "Current failure rate of the sliding-window circuit breaker (0.0–1.0).",
		ConstLabels: prometheus.Labels{"name": sw.cfg.Name},
	})

	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sliding_cb_requests_total",
		Help: "Total requests processed by the sliding-window circuit breaker.",
	}, []string{"name", "result"})

	state := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "sliding_cb_state",
		Help:        "Current state of the sliding-window circuit breaker: 0=closed, 1=open, 2=half-open.",
		ConstLabels: prometheus.Labels{"name": sw.cfg.Name},
	})

	registry.MustRegister(failureRate, requests, state)

	sw.mu.Lock()
	sw.metrics = &slidingWindowMetrics{
		failureRate: failureRate,
		requests:    requests,
		state:       state,
	}
	state.Set(float64(sw.state))
	sw.mu.Unlock()

	return sw
}

// Execute runs fn through the circuit breaker. When the circuit is open and a Fallback
// is configured, the fallback is called with ErrCircuitOpen; otherwise ErrCircuitOpen is
// returned directly. Panics from fn are not recovered.
func (sw *SlidingWindowCircuitBreaker) Execute(fn func() error) error {
	sw.mu.Lock()

	// Advance time buckets before making any decision.
	sw.rotateBuckets(time.Now())

	switch sw.state {
	case StateOpen:
		if time.Since(sw.openedAt) >= sw.cfg.RecoveryTimeout {
			// Transition to HalfOpen and consume one probe slot immediately.
			sw.transitionTo(StateHalfOpen)
			sw.halfOpenProbes++
		} else {
			sw.mu.Unlock()
			if sw.metrics != nil {
				sw.metrics.requests.WithLabelValues(sw.cfg.Name, "rejected").Inc()
			}
			if sw.cfg.Fallback != nil {
				return sw.cfg.Fallback(ErrCircuitOpen)
			}
			return ErrCircuitOpen
		}

	case StateHalfOpen:
		if sw.halfOpenProbes >= sw.cfg.HalfOpenMaxRequests {
			// All probe slots consumed — keep rejecting until a result comes in.
			sw.mu.Unlock()
			if sw.cfg.Fallback != nil {
				return sw.cfg.Fallback(ErrCircuitOpen)
			}
			return ErrCircuitOpen
		}
		sw.halfOpenProbes++
	}

	sw.mu.Unlock()

	// Execute the function outside the lock.
	err := fn()

	sw.mu.Lock()
	defer sw.mu.Unlock()

	if err != nil {
		sw.recordFailureLocked()
	} else {
		sw.recordSuccessLocked()
	}

	return err
}

// GetState returns the current state of the circuit breaker.
func (sw *SlidingWindowCircuitBreaker) GetState() State {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	sw.rotateBuckets(time.Now())
	return sw.state
}

// GetFailureRate returns the current failure rate across the active sliding window.
// Returns 0.0 when there are no requests in the window.
func (sw *SlidingWindowCircuitBreaker) GetFailureRate() float64 {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	sw.rotateBuckets(time.Now())
	return sw.computeFailureRate()
}

// Reset transitions the circuit breaker back to Closed and clears all window data.
func (sw *SlidingWindowCircuitBreaker) Reset() {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	sw.transitionTo(StateClosed)
	sw.halfOpenProbes = 0
	for i := range sw.buckets {
		sw.buckets[i].reset()
	}
	sw.bucketTime = time.Now()
}

// ---- internal helpers (must be called with sw.mu held) ----

// rotateBuckets advances the ring buffer so that stale buckets are cleared.
// It is called lazily on every operation.
func (sw *SlidingWindowCircuitBreaker) rotateBuckets(now time.Time) {
	elapsed := now.Sub(sw.bucketTime)
	if elapsed < sw.cfg.BucketDuration {
		return // still within the current bucket
	}

	// How many full buckets have passed?
	steps := int(elapsed / sw.cfg.BucketDuration)
	if steps > sw.cfg.BucketCount {
		// The entire window has expired — wipe everything.
		steps = sw.cfg.BucketCount
	}

	for i := 0; i < steps; i++ {
		sw.bucketIdx = (sw.bucketIdx + 1) % sw.cfg.BucketCount
		sw.buckets[sw.bucketIdx].reset()
	}

	// Advance bucketTime by exactly (steps * BucketDuration) to stay aligned.
	sw.bucketTime = sw.bucketTime.Add(time.Duration(steps) * sw.cfg.BucketDuration)
}

// computeFailureRate calculates failures / total across all buckets.
func (sw *SlidingWindowCircuitBreaker) computeFailureRate() float64 {
	var totalF, totalS int64
	for i := range sw.buckets {
		totalF += sw.buckets[i].failures
		totalS += sw.buckets[i].successes
	}
	total := totalF + totalS
	if total == 0 {
		return 0.0
	}
	return float64(totalF) / float64(total)
}

// recordSuccessLocked updates the current bucket and evaluates state transitions.
func (sw *SlidingWindowCircuitBreaker) recordSuccessLocked() {
	sw.buckets[sw.bucketIdx].successes++

	if sw.metrics != nil {
		sw.metrics.requests.WithLabelValues(sw.cfg.Name, "success").Inc()
		sw.metrics.failureRate.Set(sw.computeFailureRate())
	}

	if sw.state == StateHalfOpen {
		// All probes have succeeded → close the circuit.
		if sw.halfOpenProbes >= sw.cfg.HalfOpenMaxRequests {
			sw.transitionTo(StateClosed)
			sw.halfOpenProbes = 0
		}
	}
}

// recordFailureLocked updates the current bucket and evaluates state transitions.
func (sw *SlidingWindowCircuitBreaker) recordFailureLocked() {
	sw.buckets[sw.bucketIdx].failures++

	if sw.metrics != nil {
		sw.metrics.requests.WithLabelValues(sw.cfg.Name, "failure").Inc()
		sw.metrics.failureRate.Set(sw.computeFailureRate())
	}

	switch sw.state {
	case StateHalfOpen:
		// Any probe failure immediately re-opens the circuit.
		sw.transitionTo(StateOpen)
		sw.halfOpenProbes = 0

	case StateClosed:
		rate := sw.computeFailureRate()
		var total int64
		for i := range sw.buckets {
			total += sw.buckets[i].total()
		}
		if total >= int64(sw.cfg.MinRequests) && rate > sw.cfg.FailureRateThreshold {
			sw.transitionTo(StateOpen)
		}
	}
}

// transitionTo moves the circuit breaker to the given state and updates metrics.
func (sw *SlidingWindowCircuitBreaker) transitionTo(newState State) {
	sw.state = newState
	if newState == StateOpen {
		sw.openedAt = time.Now()
	}
	if sw.metrics != nil {
		sw.metrics.state.Set(float64(newState))
	}
}
