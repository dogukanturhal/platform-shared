// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// signedCacheEntry wraps a JSON payload with an HMAC-SHA256 signature to
// prevent cache poisoning attacks. If an attacker gains Redis access, they
// cannot forge valid entries without the HMAC key.
type signedCacheEntry struct {
	Payload   json.RawMessage `json:"p"`
	Signature string          `json:"s"`
}

// RedisDBInfoCache implements DBInfoCache using Redis as the L2 cache layer.
// It serializes TenantDatabaseInfo as JSON with HMAC-SHA256 integrity protection.
type RedisDBInfoCache struct {
	rdb       redis.Cmdable
	keyPrefix string
	hmacKey   []byte // 32-byte HMAC key for cache entry signing
	log       *zap.Logger
}

// NewRedisDBInfoCache creates a new Redis-backed DB info cache.
// keyPrefix is prepended to all cache keys (e.g., "dbinfo:").
// If hmacKey is nil or empty, cache entries are stored unsigned (backward compat / testing).
func NewRedisDBInfoCache(rdb redis.Cmdable, keyPrefix string, opts ...RedisDBInfoCacheOption) *RedisDBInfoCache {
	c := &RedisDBInfoCache{
		rdb:       rdb,
		keyPrefix: keyPrefix,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// RedisDBInfoCacheOption configures a RedisDBInfoCache.
type RedisDBInfoCacheOption func(*RedisDBInfoCache)

// WithHMACKey sets the HMAC-SHA256 key for cache entry signing.
func WithHMACKey(key []byte) RedisDBInfoCacheOption {
	return func(c *RedisDBInfoCache) {
		c.hmacKey = key
	}
}

// WithCacheLogger sets the logger for cache operations.
func WithCacheLogger(log *zap.Logger) RedisDBInfoCacheOption {
	return func(c *RedisDBInfoCache) {
		c.log = log
	}
}

func (c *RedisDBInfoCache) cacheKey(tenantID, databaseName string) string {
	return fmt.Sprintf("%s%s:%s", c.keyPrefix, tenantID, databaseName)
}

func (c *RedisDBInfoCache) computeHMAC(key string, payload []byte) string {
	mac := hmac.New(sha256.New, c.hmacKey)
	mac.Write([]byte(key))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// GetDBInfo retrieves cached DB info. Returns (nil, nil) on cache miss.
func (c *RedisDBInfoCache) GetDBInfo(ctx context.Context, tenantID, databaseName string) (*TenantDatabaseInfo, error) {
	key := c.cacheKey(tenantID, databaseName)
	data, err := c.rdb.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil // cache miss
	}
	if err != nil {
		return nil, fmt.Errorf("redis get: %w", err)
	}

	// No HMAC key — unsigned mode (backward compat / testing).
	if len(c.hmacKey) == 0 {
		var info TenantDatabaseInfo
		if err := json.Unmarshal(data, &info); err != nil {
			return nil, fmt.Errorf("unmarshal db info: %w", err)
		}
		return &info, nil
	}

	// HMAC is configured — verify signature before unmarshalling.
	return c.getDBInfoSigned(ctx, key, data)
}

// getDBInfoSigned verifies the HMAC signature of a signed cache entry and returns the DB info.
func (c *RedisDBInfoCache) getDBInfoSigned(ctx context.Context, key string, data []byte) (*TenantDatabaseInfo, error) {
	var signed signedCacheEntry
	if unmarshalErr := json.Unmarshal(data, &signed); unmarshalErr != nil {
		// Possibly an unsigned legacy entry — delete it and treat as cache miss.
		_ = c.rdb.Del(ctx, key).Err()
		return nil, fmt.Errorf("cache entry unmarshal: %w", unmarshalErr)
	}

	expected := c.computeHMAC(key, signed.Payload)
	if !hmac.Equal([]byte(signed.Signature), []byte(expected)) {
		// SECURITY: Cache entry tampered with. Delete and force re-lookup.
		_ = c.rdb.Del(ctx, key).Err()
		if c.log != nil {
			c.log.Error("SECURITY: cache signature mismatch, entry deleted",
				zap.String("key", key),
			)
		}
		return nil, fmt.Errorf("SECURITY: cache signature mismatch for %s", key)
	}

	var info TenantDatabaseInfo
	if err := json.Unmarshal(signed.Payload, &info); err != nil {
		return nil, fmt.Errorf("unmarshal db info: %w", err)
	}
	return &info, nil
}

// SetDBInfo stores DB info in Redis with the specified TTL.
func (c *RedisDBInfoCache) SetDBInfo(ctx context.Context, tenantID, databaseName string, info *TenantDatabaseInfo, ttl time.Duration) error {
	payload, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("marshal db info: %w", err)
	}

	key := c.cacheKey(tenantID, databaseName)

	// If HMAC is configured, sign the entry.
	if len(c.hmacKey) > 0 {
		signed := signedCacheEntry{
			Payload:   payload,
			Signature: c.computeHMAC(key, payload),
		}
		data, err := json.Marshal(signed)
		if err != nil {
			return fmt.Errorf("marshal signed entry: %w", err)
		}
		return c.rdb.Set(ctx, key, data, ttl).Err()
	}

	// Unsigned mode.
	return c.rdb.Set(ctx, key, payload, ttl).Err()
}

// DeleteDBInfo removes cached DB info for a tenant/database pair.
func (c *RedisDBInfoCache) DeleteDBInfo(ctx context.Context, tenantID, databaseName string) error {
	return c.rdb.Del(ctx, c.cacheKey(tenantID, databaseName)).Err()
}
