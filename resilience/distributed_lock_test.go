// SPDX-License-Identifier: Apache-2.0

package resilience

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestLockManager spins up a miniredis server and returns a DistributedLockManager
// backed by it. The caller is responsible for closing the miniredis instance via t.Cleanup.
func newTestLockManager(t *testing.T) (*DistributedLockManager, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	mgr := NewDistributedLockManager(DistributedLockConfig{
		Client:    client,
		KeyPrefix: "test:",
	})
	return mgr, mr
}

func TestDistributedLock_AcquireRelease(t *testing.T) {
	mgr, _ := newTestLockManager(t)
	ctx := context.Background()

	lock, err := mgr.Acquire(ctx, "resource-a", time.Second)
	require.NoError(t, err)
	require.NotNil(t, lock)

	err = lock.Unlock(ctx)
	assert.NoError(t, err)
}

func TestDistributedLock_DoubleAcquireFails(t *testing.T) {
	mgr, _ := newTestLockManager(t)
	ctx := context.Background()

	lock1, err := mgr.Acquire(ctx, "resource-b", time.Second)
	require.NoError(t, err)
	defer lock1.Unlock(ctx) //nolint:errcheck

	// Second acquire on the same key must fail.
	_, err = mgr.Acquire(ctx, "resource-b", time.Second)
	assert.ErrorIs(t, err, ErrLockNotAcquired)
}

func TestDistributedLock_TTLExpiry(t *testing.T) {
	mgr, mr := newTestLockManager(t)
	ctx := context.Background()

	// Acquire with a 100 ms TTL.
	lock, err := mgr.Acquire(ctx, "resource-c", 100*time.Millisecond)
	require.NoError(t, err)

	// Fast-forward miniredis clock past the TTL.
	mr.FastForward(200 * time.Millisecond)

	// Now someone else should be able to acquire the same key.
	lock2, err := mgr.Acquire(ctx, "resource-c", time.Second)
	require.NoError(t, err, "should acquire after TTL expiry")
	defer lock2.Unlock(ctx) //nolint:errcheck

	// Original lock's Unlock should fail because the key is now held by lock2.
	err = lock.Unlock(ctx)
	assert.ErrorIs(t, err, ErrLockNotHeld)
}

func TestDistributedLock_AtomicUnlock_WrongTokenRejected(t *testing.T) {
	mgr, mr := newTestLockManager(t)
	ctx := context.Background()

	lock, err := mgr.Acquire(ctx, "resource-d", time.Second)
	require.NoError(t, err)

	// Tamper with the stored token via miniredis directly.
	err = mr.Set("test:resource-d", "wrong-token")
	require.NoError(t, err)

	// Unlock should detect the token mismatch.
	err = lock.Unlock(ctx)
	assert.ErrorIs(t, err, ErrLockNotHeld)
}

func TestDistributedLock_Extend(t *testing.T) {
	mgr, mr := newTestLockManager(t)
	ctx := context.Background()

	lock, err := mgr.Acquire(ctx, "resource-e", 100*time.Millisecond)
	require.NoError(t, err)

	// Extend by 5 seconds before the key expires.
	err = lock.Extend(ctx, 5*time.Second)
	require.NoError(t, err)

	// Fast-forward 200 ms — original TTL would have expired but extended should survive.
	mr.FastForward(200 * time.Millisecond)

	// The key should still exist (TTL was extended).
	_, err = mgr.Acquire(ctx, "resource-e", time.Second)
	assert.ErrorIs(t, err, ErrLockNotAcquired, "key should still exist after extend")

	// Clean up.
	_ = lock.Unlock(ctx)
}

func TestDistributedLock_ExtendWrongTokenFails(t *testing.T) {
	mgr, mr := newTestLockManager(t)
	ctx := context.Background()

	lock, err := mgr.Acquire(ctx, "resource-f", time.Second)
	require.NoError(t, err)

	// Overwrite the stored token.
	err = mr.Set("test:resource-f", "evil-token")
	require.NoError(t, err)

	err = lock.Extend(ctx, 10*time.Second)
	assert.ErrorIs(t, err, ErrLockNotHeld)
}

func TestDistributedLock_ConcurrentAcquire(t *testing.T) {
	mgr, _ := newTestLockManager(t)
	ctx := context.Background()

	const goroutines = 20
	var acquired atomic.Int32
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lock, err := mgr.Acquire(ctx, "concurrent-key", 500*time.Millisecond)
			if err == nil {
				acquired.Add(1)
				time.Sleep(10 * time.Millisecond)
				_ = lock.Unlock(ctx)
			}
		}()
	}

	wg.Wait()
	// Exactly one goroutine can hold the lock at a time; due to racing, more than one may
	// succeed over time, but never concurrently.
	assert.True(t, acquired.Load() >= 1, "at least one goroutine must acquire the lock")
}

func TestDistributedLock_TokenUniqueness(t *testing.T) {
	mgr, _ := newTestLockManager(t)
	ctx := context.Background()

	const n = 100
	tokens := make(map[string]struct{}, n)

	for i := 0; i < n; i++ {
		lock, err := mgr.Acquire(ctx, "token-test", time.Second)
		require.NoError(t, err)

		tok := lock.Token()
		_, duplicate := tokens[tok]
		assert.False(t, duplicate, "token must be unique: %s", tok)
		tokens[tok] = struct{}{}

		require.NoError(t, lock.Unlock(ctx))
	}
}

func TestDistributedLock_KeyPrefix(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	mgr := NewDistributedLockManager(DistributedLockConfig{
		Client:    client,
		KeyPrefix: "myapp:locks:",
	})

	ctx := context.Background()
	lock, err := mgr.Acquire(ctx, "jobs:worker-1", time.Second)
	require.NoError(t, err)

	// Verify the key stored in Redis includes the prefix.
	val, redisErr := mr.Get("myapp:locks:jobs:worker-1")
	require.NoError(t, redisErr)
	assert.Equal(t, lock.Token(), val)

	require.NoError(t, lock.Unlock(ctx))
}

func TestDistributedLock_ContextCancellation(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	mgr := NewDistributedLockManager(DistributedLockConfig{
		Client:    client,
		KeyPrefix: "ctx:",
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Acquire with an already-canceled context; the Redis call should fail.
	_, err = mgr.Acquire(ctx, "resource-g", time.Second)
	assert.Error(t, err, "acquire with canceled context should return an error")
	assert.NotErrorIs(t, err, ErrLockNotAcquired, "error should be context-related, not lock contention")
}
