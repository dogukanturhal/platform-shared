// SPDX-License-Identifier: Apache-2.0

// Package circuitbreaker provides a shared circuit breaker implementation built on
// top of sony/gobreaker v2. It wraps gobreaker's CircuitBreaker with a functional
// options API, a named registry, Prometheus metrics, and an http.RoundTripper
// decorator so platform services can protect all outbound HTTP calls with a
// consistent, observable fault-tolerance layer.
package circuitbreaker

import (
	"regexp"
	"time"

	"github.com/sony/gobreaker/v2"
)

// validNameRe matches characters allowed in breaker names. Names are used as
// Prometheus label values, so we restrict to safe characters to prevent
// cardinality issues and label corruption.
var validNameRe = regexp.MustCompile(`[^a-zA-Z0-9_\->.:/]+`)

// defaultReadyToTrip trips the breaker after 5 consecutive failures.
func defaultReadyToTrip(counts gobreaker.Counts) bool {
	return counts.ConsecutiveFailures >= 5
}

// settings holds the configuration used to construct the underlying gobreaker.
type settings struct {
	maxRequests   uint32
	interval      time.Duration
	timeout       time.Duration
	readyToTrip   func(gobreaker.Counts) bool
	onStateChange func(name string, from, to gobreaker.State)
}

// Option is a functional option for configuring a Breaker.
type Option func(*settings)

// WithMaxRequests sets the maximum number of requests allowed to pass through
// when the breaker is in the half-open state.
func WithMaxRequests(n uint32) Option {
	return func(s *settings) { s.maxRequests = n }
}

// WithInterval sets the cyclic period during which the counts are cleared
// while the breaker is in the closed state. Zero means the counts are never
// cleared automatically.
func WithInterval(d time.Duration) Option {
	return func(s *settings) { s.interval = d }
}

// WithTimeout sets the period of the open state after which the breaker
// transitions to the half-open state.
func WithTimeout(d time.Duration) Option {
	return func(s *settings) { s.timeout = d }
}

// WithReadyToTrip replaces the default trip condition (5 consecutive failures).
func WithReadyToTrip(fn func(gobreaker.Counts) bool) Option {
	return func(s *settings) { s.readyToTrip = fn }
}

// WithOnStateChange registers a callback that is invoked on every state
// transition. The callback receives the breaker name, previous state, and
// new state.
func WithOnStateChange(fn func(name string, from, to gobreaker.State)) Option {
	return func(s *settings) { s.onStateChange = fn }
}

// Breaker wraps gobreaker.CircuitBreaker[any] and exposes a simplified API.
type Breaker struct {
	cb      *gobreaker.CircuitBreaker[any]
	name    string
	timeout time.Duration
}

// NewBreaker creates a new Breaker with the supplied options.
//
// Defaults:
//   - MaxRequests: 3
//   - Interval:    60 s
//   - Timeout:     30 s
//   - ReadyToTrip: 5 consecutive failures
//
// sanitizeName strips disallowed characters and truncates to a safe length
// for use as Prometheus label values.
func sanitizeName(name string) string {
	name = validNameRe.ReplaceAllString(name, "_")
	if len(name) > 128 {
		name = name[:128]
	}
	return name
}

// NewBreaker creates a new Breaker with the given name and options.
func NewBreaker(name string, opts ...Option) *Breaker {
	name = sanitizeName(name)
	s := &settings{
		maxRequests: 3,
		interval:    60 * time.Second,
		timeout:     30 * time.Second,
		readyToTrip: defaultReadyToTrip,
	}
	for _, o := range opts {
		o(s)
	}

	gbSettings := gobreaker.Settings{
		Name:        name,
		MaxRequests: s.maxRequests,
		Interval:    s.interval,
		Timeout:     s.timeout,
		ReadyToTrip: s.readyToTrip,
	}
	if s.onStateChange != nil {
		fn := s.onStateChange
		gbSettings.OnStateChange = func(n string, from, to gobreaker.State) {
			fn(n, from, to)
		}
	}

	return &Breaker{
		cb:      gobreaker.NewCircuitBreaker[any](gbSettings),
		name:    name,
		timeout: s.timeout,
	}
}

// Execute calls fn through the circuit breaker. When the breaker is open it
// returns gobreaker.ErrOpenState immediately. When in half-open state and the
// quota is exhausted it returns gobreaker.ErrTooManyRequests.
func (b *Breaker) Execute(fn func() (any, error)) (any, error) {
	return b.cb.Execute(fn)
}

// State returns the current state of the circuit breaker.
func (b *Breaker) State() gobreaker.State {
	return b.cb.State()
}

// Counts returns a snapshot of the internal request counters.
func (b *Breaker) Counts() gobreaker.Counts {
	return b.cb.Counts()
}

// Name returns the breaker's name.
func (b *Breaker) Name() string {
	return b.name
}

// Timeout returns the configured open-state timeout duration.
func (b *Breaker) Timeout() time.Duration {
	return b.timeout
}

// StateToString converts a gobreaker.State constant to a human-readable string.
func StateToString(s gobreaker.State) string {
	switch s {
	case gobreaker.StateClosed:
		return "closed"
	case gobreaker.StateHalfOpen:
		return "half-open"
	case gobreaker.StateOpen:
		return "open"
	default:
		return "unknown"
	}
}
