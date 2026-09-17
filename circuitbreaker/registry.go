// SPDX-License-Identifier: Apache-2.0

package circuitbreaker

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/sony/gobreaker/v2"
)

// DefaultMaxRegistrySize is the maximum number of breakers a Registry will
// hold. Beyond this limit GetOrCreate returns ErrRegistryFull.
const DefaultMaxRegistrySize = 256

// ErrRegistryFull is returned by GetOrCreate when the registry has reached
// its maximum capacity. This prevents unbounded memory growth from dynamic
// breaker names.
var ErrRegistryFull = errors.New("circuit breaker registry is full")

// BreakerStatus is a snapshot of a breaker's state and counters, suitable for
// health check endpoints and admin dashboards.
type BreakerStatus struct {
	Name   string           `json:"name"`
	State  string           `json:"state"`
	Counts gobreaker.Counts `json:"counts"`
}

// Registry holds a set of named breakers. All operations are safe for
// concurrent use. The zero value is not valid; use NewRegistry.
//
// WARNING: Breaker names must be static/bounded (e.g., service identifiers).
// Do not create breakers with dynamic names (per-request, per-tenant) as this
// will exhaust the registry and inflate Prometheus metric cardinality.
type Registry struct {
	mu      sync.Map // map[string]*Breaker
	count   atomic.Int64
	maxSize int
}

// RegistryOption configures a Registry.
type RegistryOption func(*Registry)

// WithMaxSize overrides the default maximum registry size.
func WithMaxSize(n int) RegistryOption {
	return func(r *Registry) { r.maxSize = n }
}

// NewRegistry returns an initialized, empty Registry.
func NewRegistry(opts ...RegistryOption) *Registry {
	r := &Registry{maxSize: DefaultMaxRegistrySize}
	for _, o := range opts {
		o(r)
	}
	return r
}

// GetOrCreate returns the existing breaker registered under name, or creates
// a new one with the supplied options and stores it before returning. The
// options are only applied when a new breaker is created; they are ignored for
// subsequent calls with the same name.
//
// Returns (nil, ErrRegistryFull) if the registry has reached its maximum
// capacity and name is not already registered.
func (r *Registry) GetOrCreate(name string, opts ...Option) (*Breaker, error) {
	if v, ok := r.mu.Load(name); ok {
		return v.(*Breaker), nil
	}

	// Check capacity before creating.
	if int(r.count.Load()) >= r.maxSize {
		return nil, ErrRegistryFull
	}

	b := NewBreaker(name, opts...)
	actual, loaded := r.mu.LoadOrStore(name, b)
	if !loaded {
		r.count.Add(1)
	}
	return actual.(*Breaker), nil
}

// MustGetOrCreate is like GetOrCreate but panics on ErrRegistryFull. Use this
// only for static breaker registration at startup.
func (r *Registry) MustGetOrCreate(name string, opts ...Option) *Breaker {
	b, err := r.GetOrCreate(name, opts...)
	if err != nil {
		panic("circuitbreaker: " + err.Error() + ": " + name)
	}
	return b
}

// Get returns the breaker registered under name and whether it was found.
func (r *Registry) Get(name string) (*Breaker, bool) {
	v, ok := r.mu.Load(name)
	if !ok {
		return nil, false
	}
	return v.(*Breaker), true
}

// Len returns the number of breakers in the registry.
func (r *Registry) Len() int {
	return int(r.count.Load())
}

// ListAll returns a map of every breaker's status, keyed by name.
func (r *Registry) ListAll() map[string]BreakerStatus {
	result := make(map[string]BreakerStatus)
	r.mu.Range(func(_, value any) bool {
		b := value.(*Breaker)
		result[b.name] = BreakerStatus{
			Name:   b.name,
			State:  StateToString(b.State()),
			Counts: b.Counts(),
		}
		return true
	})
	return result
}
