// SPDX-License-Identifier: Apache-2.0

package resilience

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestStore spins up a miniredis instance and returns a store + server.
func newTestStore(t *testing.T) *RedisCircuitBreakerStore {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := NewRedisCircuitBreakerStore(client, 0, "test_cb")
	return store
}

// TestCBState_SaveLoadRoundTrip verifies that a saved state can be loaded back.
func TestCBState_SaveLoadRoundTrip(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Millisecond)
	in := CBState{
		State:           StateOpen,
		FailureCount:    7,
		LastFailure:     now,
		LastStateChange: now.Add(-5 * time.Second),
	}

	require.NoError(t, store.SaveState(ctx, "svc-a", in))

	out, err := store.LoadState(ctx, "svc-a")
	require.NoError(t, err)

	assert.Equal(t, in.State, out.State)
	assert.Equal(t, in.FailureCount, out.FailureCount)
	assert.Equal(t, in.LastFailure.Unix(), out.LastFailure.Unix())
	assert.Equal(t, in.LastStateChange.Unix(), out.LastStateChange.Unix())
}

// TestCBState_LoadNonExistentKey returns ErrNoCBState.
func TestCBState_LoadNonExistentKey(t *testing.T) {
	store := newTestStore(t)
	_, err := store.LoadState(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, ErrNoCBState)
}

// TestCBState_RedisFailureSave returns an error on save when Redis is down.
func TestCBState_RedisFailureSave(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := NewRedisCircuitBreakerStore(client, 0, "test_cb")

	mr.Close() // kill Redis

	err := store.SaveState(context.Background(), "svc", CBState{State: StateClosed})
	assert.Error(t, err, "expected error when Redis is down")
}

// TestCBState_RedisFailureLoad returns an error on load when Redis is down.
func TestCBState_RedisFailureLoad(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := NewRedisCircuitBreakerStore(client, 0, "test_cb")

	mr.Close()

	_, err := store.LoadState(context.Background(), "svc")
	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrNoCBState, "Redis error should not be ErrNoCBState")
}

// TestWithPersistence_RestoresStateOnCreation verifies that prior state is
// loaded into the CircuitBreaker on creation.
func TestWithPersistence_RestoresStateOnCreation(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Pre-seed a persisted open state with 9 failures
	require.NoError(t, store.SaveState(ctx, "payment-svc", CBState{
		State:           StateOpen,
		FailureCount:    9,
		LastFailure:     time.Now().Add(-10 * time.Second),
		LastStateChange: time.Now().Add(-10 * time.Second),
	}))

	cb := NewCircuitBreakerNamed("payment-svc", 10, 30*time.Second).
		WithPersistence(store)

	// The circuit should now be open (restored from store)
	assert.Equal(t, StateOpen, cb.GetState())
}

// TestWithPersistence_PersistsStateTransition verifies that transitions are
// written to the store asynchronously.
func TestWithPersistence_PersistsStateTransition(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	cb := NewCircuitBreakerNamed("billing-svc", 2, time.Minute).
		WithPersistence(store)

	// Trigger 2 failures to open the circuit
	cb.RecordFailure()
	cb.RecordFailure()

	// Give the background goroutine a chance to persist
	time.Sleep(50 * time.Millisecond)

	saved, err := store.LoadState(ctx, "billing-svc")
	require.NoError(t, err)
	assert.Equal(t, StateOpen, saved.State)
}

// TestWithPersistence_RedisFailureGraceful verifies that Redis being down does
// not prevent the circuit breaker from working normally.
func TestWithPersistence_RedisFailureGraceful(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := NewRedisCircuitBreakerStore(client, 0, "test_cb")

	// Kill Redis before creating the breaker
	mr.Close()

	// This should not panic — graceful degradation
	cb := NewCircuitBreakerNamed("resilient-svc", 3, time.Minute).
		WithPersistence(store)

	// Breaker still starts in Closed state
	assert.Equal(t, StateClosed, cb.GetState())

	// Failures still work correctly without persistence
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()
	assert.Equal(t, StateOpen, cb.GetState())
}

// TestNewRedisCircuitBreakerStore_NilClientPanics ensures nil client panics.
func TestNewRedisCircuitBreakerStore_NilClientPanics(t *testing.T) {
	assert.Panics(t, func() {
		NewRedisCircuitBreakerStore(nil, 0, "prefix")
	})
}
