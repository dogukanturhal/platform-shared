// SPDX-License-Identifier: Apache-2.0

package resilience

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// Lua script for atomic unlock: only delete the key when the stored value matches the caller's token.
// Returns 1 on success, 0 if the token does not match (lock not held by this caller).
var unlockScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
else
    return 0
end
`)

// Lua script for atomic extend: only update the TTL when the stored value matches the caller's token.
// Returns 1 on success, 0 if the token does not match.
var extendScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("PEXPIRE", KEYS[1], ARGV[2])
else
    return 0
end
`)

// DistributedLockConfig holds configuration for a DistributedLockManager.
type DistributedLockConfig struct {
	// Client is the go-redis/v9 client used for all Redis operations.
	Client *redis.Client
	// KeyPrefix is prepended to every lock key, e.g. "myapp:locks:".
	KeyPrefix string
}

// DistributedLockManager creates and manages distributed locks backed by Redis.
type DistributedLockManager struct {
	client *redis.Client
	prefix string
}

// NewDistributedLockManager creates a new DistributedLockManager from the provided config.
func NewDistributedLockManager(cfg DistributedLockConfig) *DistributedLockManager {
	return &DistributedLockManager{
		client: cfg.Client,
		prefix: cfg.KeyPrefix,
	}
}

// Acquire attempts to atomically set a Redis key using SET NX PX. On success it returns a
// *DistributedLock that holds a unique fencing token. If the key already exists,
// ErrLockNotAcquired is returned.
func (m *DistributedLockManager) Acquire(ctx context.Context, key string, ttl time.Duration) (*DistributedLock, error) {
	token := uuid.New().String()
	redisKey := m.prefix + key

	ok, err := m.client.SetNX(ctx, redisKey, token, ttl).Result()
	if err != nil {
		return nil, fmt.Errorf("distributed lock acquire: %w", err)
	}
	if !ok {
		return nil, ErrLockNotAcquired
	}

	return &DistributedLock{
		key:    redisKey,
		token:  token,
		client: m.client,
	}, nil
}

// DistributedLock represents a held distributed lock. The token field is a UUID v4 that acts
// as a fencing token, ensuring that only the goroutine that acquired the lock can release or
// extend it — even if Redis replicates the key to another node.
type DistributedLock struct {
	key    string
	token  string
	client *redis.Client
}

// Token returns the fencing token associated with this lock. It can be passed to downstream
// services so they can verify the caller's authority.
func (l *DistributedLock) Token() string {
	return l.token
}

// Unlock atomically deletes the lock key only when the stored value matches this lock's token.
// Returns ErrLockNotHeld if the token does not match (e.g. the TTL expired and someone else
// re-acquired the lock).
func (l *DistributedLock) Unlock(ctx context.Context) error {
	result, err := unlockScript.Run(ctx, l.client, []string{l.key}, l.token).Int()
	if err != nil {
		return fmt.Errorf("distributed lock unlock: %w", err)
	}
	if result == 0 {
		return ErrLockNotHeld
	}
	return nil
}

// Extend atomically refreshes the lock's TTL only when the stored value matches this lock's token.
// Returns ErrLockNotHeld if the token does not match.
func (l *DistributedLock) Extend(ctx context.Context, ttl time.Duration) error {
	// PEXPIRE accepts milliseconds as an integer string.
	ttlMs := ttl.Milliseconds()
	result, err := extendScript.Run(ctx, l.client, []string{l.key}, l.token, ttlMs).Int()
	if err != nil {
		return fmt.Errorf("distributed lock extend: %w", err)
	}
	if result == 0 {
		return ErrLockNotHeld
	}
	return nil
}
