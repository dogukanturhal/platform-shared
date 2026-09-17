// SPDX-License-Identifier: Apache-2.0

// Package resilience provides circuit breaker and retry patterns for resilient service communication.
package resilience

import (
	"errors"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// State represents the circuit breaker state
type State int

const (
	// StateClosed allows all requests through
	StateClosed State = iota
	// StateOpen rejects all requests
	StateOpen
	// StateHalfOpen allows limited requests to test recovery
	StateHalfOpen
)

// String returns the string representation of the state
func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// ErrCircuitOpen is returned when the circuit breaker is open
var ErrCircuitOpen = errors.New("circuit breaker is open")

// CircuitBreakerMetrics holds Prometheus metrics for a CircuitBreaker instance.
type CircuitBreakerMetrics struct {
	// StateTransitions counts transitions between states.
	StateTransitions *prometheus.CounterVec
	// StateGauge tracks the current state (0=closed, 1=open, 2=half-open).
	StateGauge prometheus.Gauge
	// Requests counts calls by result (success, failure, rejected).
	Requests *prometheus.CounterVec
}

// CircuitBreaker implements the circuit breaker pattern with three states:
// Closed (normal operation), Open (failing fast), and HalfOpen (testing recovery).
type CircuitBreaker struct {
	mu               sync.RWMutex
	name             string
	state            State
	failureCount     int
	failureThreshold int
	recoveryTimeout  time.Duration
	lastFailureTime  time.Time
	onStateChange    func(from, to State)
	metrics          *CircuitBreakerMetrics
}

// NewCircuitBreaker creates a new circuit breaker with default settings
func NewCircuitBreaker() *CircuitBreaker {
	return &CircuitBreaker{
		name:             "default",
		state:            StateClosed,
		failureCount:     0,
		failureThreshold: 5,
		recoveryTimeout:  30 * time.Second,
	}
}

// NewCircuitBreakerWithConfig creates a circuit breaker with custom settings
func NewCircuitBreakerWithConfig(failureThreshold int, recoveryTimeout time.Duration) *CircuitBreaker {
	if failureThreshold <= 0 {
		failureThreshold = 5
	}
	if recoveryTimeout <= 0 {
		recoveryTimeout = 30 * time.Second
	}
	return &CircuitBreaker{
		name:             "default",
		state:            StateClosed,
		failureCount:     0,
		failureThreshold: failureThreshold,
		recoveryTimeout:  recoveryTimeout,
	}
}

// NewCircuitBreakerNamed creates a named circuit breaker with custom settings.
// The name is used as a label in Prometheus metrics.
func NewCircuitBreakerNamed(name string, failureThreshold int, recoveryTimeout time.Duration) *CircuitBreaker {
	if failureThreshold <= 0 {
		failureThreshold = 5
	}
	if recoveryTimeout <= 0 {
		recoveryTimeout = 30 * time.Second
	}
	if name == "" {
		name = "default"
	}
	return &CircuitBreaker{
		name:             name,
		state:            StateClosed,
		failureCount:     0,
		failureThreshold: failureThreshold,
		recoveryTimeout:  recoveryTimeout,
	}
}

// WithMetrics registers Prometheus metrics for this circuit breaker on the provided registry
// and returns the same CircuitBreaker for chaining.
func (cb *CircuitBreaker) WithMetrics(registry *prometheus.Registry) *CircuitBreaker {
	transitions := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "circuit_breaker_state_transitions_total",
		Help: "Total number of circuit breaker state transitions.",
	}, []string{"name", "from", "to"})

	stateGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "circuit_breaker_state",
		Help:        "Current circuit breaker state: 0=closed, 1=open, 2=half-open.",
		ConstLabels: prometheus.Labels{"name": cb.name},
	})

	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "circuit_breaker_requests_total",
		Help: "Total number of requests processed by the circuit breaker.",
	}, []string{"name", "result"})

	registry.MustRegister(transitions, stateGauge, requests)

	cb.mu.Lock()
	cb.metrics = &CircuitBreakerMetrics{
		StateTransitions: transitions,
		StateGauge:       stateGauge,
		Requests:         requests,
	}
	// Reflect the initial state.
	stateGauge.Set(float64(cb.state))
	cb.mu.Unlock()

	return cb
}

// WithOnStateChange registers a callback that is invoked whenever the circuit breaker
// transitions between states. The callback receives the previous and new State values.
// It is called while holding the mutex; callbacks must not call back into the circuit breaker.
func (cb *CircuitBreaker) WithOnStateChange(fn func(from, to State)) *CircuitBreaker {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.onStateChange = fn
	return cb
}

// transitionState updates the circuit breaker state and fires metrics/callback.
// Must be called while holding cb.mu (write lock).
func (cb *CircuitBreaker) transitionState(newState State) {
	from := cb.state
	cb.state = newState

	if cb.metrics != nil {
		cb.metrics.StateTransitions.WithLabelValues(cb.name, from.String(), newState.String()).Inc()
		cb.metrics.StateGauge.Set(float64(newState))
	}
	if cb.onStateChange != nil {
		cb.onStateChange(from, newState)
	}
}

// Allow checks if a request should be allowed through the circuit breaker
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		// Check if recovery timeout has elapsed
		if time.Since(cb.lastFailureTime) >= cb.recoveryTimeout {
			// Transition to half-open to test recovery
			cb.transitionState(StateHalfOpen)
			return true
		}
		if cb.metrics != nil {
			cb.metrics.Requests.WithLabelValues(cb.name, "rejected").Inc()
		}
		return false
	case StateHalfOpen:
		// In half-open state, allow one request to test
		return true
	default:
		return false
	}
}

// RecordSuccess records a successful request
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.metrics != nil {
		cb.metrics.Requests.WithLabelValues(cb.name, "success").Inc()
	}

	switch cb.state {
	case StateClosed:
		// Reset failure count on success
		cb.failureCount = 0
	case StateHalfOpen:
		// Success in half-open state means service recovered
		cb.failureCount = 0
		cb.transitionState(StateClosed)
	}
}

// RecordFailure records a failed request
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.lastFailureTime = time.Now()

	if cb.metrics != nil {
		cb.metrics.Requests.WithLabelValues(cb.name, "failure").Inc()
	}

	switch cb.state {
	case StateClosed:
		cb.failureCount++
		if cb.failureCount >= cb.failureThreshold {
			// Threshold reached, open the circuit
			cb.transitionState(StateOpen)
		}
	case StateHalfOpen:
		// Failure in half-open state means service still unhealthy
		cb.failureCount = cb.failureThreshold
		cb.transitionState(StateOpen)
	}
}

// GetState returns the current circuit breaker state
func (cb *CircuitBreaker) GetState() State {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// GetFailureCount returns the current failure count
func (cb *CircuitBreaker) GetFailureCount() int {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.failureCount
}

// Reset resets the circuit breaker to its initial state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.state != StateClosed {
		cb.transitionState(StateClosed)
	}
	cb.failureCount = 0
}

// NewSlidingWindowCB creates a sliding-window (time-based) circuit breaker.
// This is a convenience factory that delegates to the SlidingWindowCircuitBreaker implementation.
func NewSlidingWindowCB(cfg SlidingWindowConfig) *SlidingWindowCircuitBreaker {
	return NewSlidingWindowCircuitBreaker(cfg)
}
