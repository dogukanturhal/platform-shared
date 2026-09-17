// SPDX-License-Identifier: Apache-2.0

package resilience

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// CBState holds the persisted snapshot of a CircuitBreaker.
type CBState struct {
	// State is the circuit-breaker state at the time of snapshot.
	State State `json:"state"`
	// FailureCount is the number of consecutive failures recorded.
	FailureCount int64 `json:"failure_count"`
	// LastFailure is the wall-clock time of the most recent failure.
	LastFailure time.Time `json:"last_failure"`
	// LastStateChange is the wall-clock time of the most recent state transition.
	LastStateChange time.Time `json:"last_state_change"`
}

// CircuitBreakerStore is the persistence interface for circuit-breaker state.
// Implementations must be safe for concurrent use.
type CircuitBreakerStore interface {
	// SaveState persists the state snapshot for the named breaker.
	SaveState(ctx context.Context, name string, state CBState) error
	// LoadState retrieves the state snapshot for the named breaker.
	// Returns ErrNoCBState if no snapshot exists.
	LoadState(ctx context.Context, name string) (CBState, error)
}

// ErrNoCBState is returned by LoadState when no persisted state exists.
var ErrNoCBState = fmt.Errorf("resilience: no persisted circuit-breaker state")

// RedisCircuitBreakerStore persists circuit-breaker state in Redis as JSON.
type RedisCircuitBreakerStore struct {
	client *redis.Client
	ttl    time.Duration
	prefix string
}

// NewRedisCircuitBreakerStore creates a new RedisCircuitBreakerStore.
//
//   - client – an initialized *redis.Client; must not be nil.
//   - ttl    – how long the persisted state is kept in Redis.
//     Use 0 for no expiry (keys are kept indefinitely).
//   - prefix – Redis key prefix, e.g. "circuit_breaker".
func NewRedisCircuitBreakerStore(client *redis.Client, ttl time.Duration, prefix string) *RedisCircuitBreakerStore {
	if client == nil {
		panic("resilience: redis client must not be nil")
	}
	if prefix == "" {
		prefix = "circuit_breaker"
	}
	return &RedisCircuitBreakerStore{client: client, ttl: ttl, prefix: prefix}
}

func (s *RedisCircuitBreakerStore) key(name string) string {
	return fmt.Sprintf("%s:%s", s.prefix, name)
}

// SaveState serializes state to JSON and stores it in Redis.
// The operation is best-effort: errors are surfaced but do not affect the caller's
// main flow when used via WithPersistence.
func (s *RedisCircuitBreakerStore) SaveState(ctx context.Context, name string, state CBState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("resilience: SaveState marshal: %w", err)
	}
	if s.ttl > 0 {
		return s.client.Set(ctx, s.key(name), data, s.ttl).Err()
	}
	return s.client.Set(ctx, s.key(name), data, 0).Err()
}

// LoadState retrieves and deserializes state from Redis.
// Returns ErrNoCBState when the key does not exist.
func (s *RedisCircuitBreakerStore) LoadState(ctx context.Context, name string) (CBState, error) {
	data, err := s.client.Get(ctx, s.key(name)).Bytes()
	if errors.Is(err, redis.Nil) {
		return CBState{}, ErrNoCBState
	}
	if err != nil {
		return CBState{}, fmt.Errorf("resilience: LoadState get: %w", err)
	}

	var state CBState
	if err := json.Unmarshal(data, &state); err != nil {
		return CBState{}, fmt.Errorf("resilience: LoadState unmarshal: %w", err)
	}
	return state, nil
}

// WithPersistence wires a CircuitBreakerStore into the CircuitBreaker.
//
// On creation the method attempts to restore the last known state from the store.
// On every state transition it persists the new state asynchronously (best-effort)
// so that Redis errors never block request processing.
//
// The method returns the same *CircuitBreaker for chaining.
//
// Example:
//
//	store := resilience.NewRedisCircuitBreakerStore(redisClient, 24*time.Hour, "cb")
//	cb := resilience.NewCircuitBreakerNamed("payments", 5, 30*time.Second).
//	    WithPersistence(store)
func (cb *CircuitBreaker) WithPersistence(store CircuitBreakerStore) *CircuitBreaker {
	ctx := context.Background()

	// --- restore last known state -----------------------------------------
	if saved, err := store.LoadState(ctx, cb.name); err == nil {
		cb.mu.Lock()
		cb.state = saved.State
		cb.failureCount = int(saved.FailureCount)
		cb.lastFailureTime = saved.LastFailure
		cb.mu.Unlock()
	}
	// ErrNoCBState and Redis errors are intentionally ignored here (graceful).

	// --- hook into state transitions --------------------------------------
	previous := cb.onStateChange
	cb.onStateChange = func(from, to State) {
		// Call any existing handler first
		if previous != nil {
			previous(from, to)
		}

		// Snapshot current state (must be called under the existing lock held
		// by transitionState, but we use a background goroutine to avoid
		// blocking the main call chain).
		snapshot := CBState{
			State:           to,
			FailureCount:    int64(cb.failureCount),
			LastFailure:     cb.lastFailureTime,
			LastStateChange: time.Now(),
		}
		go func() {
			// Best-effort: ignore errors so Redis failures never block callers.
			_ = store.SaveState(context.Background(), cb.name, snapshot)
		}()
	}

	return cb
}
