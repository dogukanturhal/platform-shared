// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupMiniredis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return mr, rdb
}

func TestRedisDBInfoCache_SetAndGet(t *testing.T) {
	mr, rdb := setupMiniredis(t)
	_ = mr
	cache := NewRedisDBInfoCache(rdb, "dbinfo:")

	ctx := context.Background()
	info := &TenantDatabaseInfo{
		Host:          ptr("db-host-1"),
		DatabaseName:  "hexxlock_crm",
		Schema:        "tenant_abc",
		Username:      ptr("crm_user"),
		IsolationMode: "bridge",
	}

	err := cache.SetDBInfo(ctx, "tenant-1", "hexxlock_crm", info, 5*time.Minute)
	require.NoError(t, err)

	got, err := cache.GetDBInfo(ctx, "tenant-1", "hexxlock_crm")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "bridge", got.IsolationMode)
	assert.Equal(t, "db-host-1", *got.Host)
	assert.Equal(t, "hexxlock_crm", got.DatabaseName)
	assert.Equal(t, "tenant_abc", got.Schema)
	assert.Equal(t, "crm_user", *got.Username)
}

func TestRedisDBInfoCache_GetMiss(t *testing.T) {
	_, rdb := setupMiniredis(t)
	cache := NewRedisDBInfoCache(rdb, "dbinfo:")

	got, err := cache.GetDBInfo(context.Background(), "tenant-x", "hexxlock_crm")
	require.NoError(t, err)
	assert.Nil(t, got, "cache miss should return nil, nil")
}

func TestRedisDBInfoCache_Delete(t *testing.T) {
	_, rdb := setupMiniredis(t)
	cache := NewRedisDBInfoCache(rdb, "dbinfo:")
	ctx := context.Background()

	info := &TenantDatabaseInfo{
		DatabaseName:  "hexxlock_hr",
		Schema:        "public",
		IsolationMode: "pool",
	}

	err := cache.SetDBInfo(ctx, "tenant-2", "hexxlock_hr", info, 5*time.Minute)
	require.NoError(t, err)

	got, err := cache.GetDBInfo(ctx, "tenant-2", "hexxlock_hr")
	require.NoError(t, err)
	require.NotNil(t, got)

	err = cache.DeleteDBInfo(ctx, "tenant-2", "hexxlock_hr")
	require.NoError(t, err)

	got, err = cache.GetDBInfo(ctx, "tenant-2", "hexxlock_hr")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestRedisDBInfoCache_TTLExpiry(t *testing.T) {
	mr, rdb := setupMiniredis(t)
	cache := NewRedisDBInfoCache(rdb, "dbinfo:")
	ctx := context.Background()

	info := &TenantDatabaseInfo{
		DatabaseName:  "hexxlock_crm",
		Schema:        "public",
		IsolationMode: "pool",
	}

	err := cache.SetDBInfo(ctx, "tenant-3", "hexxlock_crm", info, 1*time.Second)
	require.NoError(t, err)

	mr.FastForward(2 * time.Second)

	got, err := cache.GetDBInfo(ctx, "tenant-3", "hexxlock_crm")
	require.NoError(t, err)
	assert.Nil(t, got, "expired entry should return nil")
}

func TestRedisDBInfoCache_NilOptionalFields(t *testing.T) {
	_, rdb := setupMiniredis(t)
	cache := NewRedisDBInfoCache(rdb, "dbinfo:")
	ctx := context.Background()

	info := &TenantDatabaseInfo{
		DatabaseName:  "hexxlock_crm",
		Schema:        "public",
		IsolationMode: "pool",
	}

	err := cache.SetDBInfo(ctx, "tenant-4", "hexxlock_crm", info, 5*time.Minute)
	require.NoError(t, err)

	got, err := cache.GetDBInfo(ctx, "tenant-4", "hexxlock_crm")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Nil(t, got.Host)
	assert.Nil(t, got.Username)
	assert.Equal(t, "pool", got.IsolationMode)
}

func TestRedisDBInfoCache_KeyPrefix(t *testing.T) {
	mr, rdb := setupMiniredis(t)
	cache := NewRedisDBInfoCache(rdb, "test-prefix:")
	ctx := context.Background()

	info := &TenantDatabaseInfo{
		DatabaseName:  "hexxlock_crm",
		Schema:        "public",
		IsolationMode: "pool",
	}

	err := cache.SetDBInfo(ctx, "t1", "hexxlock_crm", info, 5*time.Minute)
	require.NoError(t, err)

	keys := mr.Keys()
	require.Len(t, keys, 1)
	assert.Equal(t, "test-prefix:t1:hexxlock_crm", keys[0])
}

func TestRedisDBInfoCache_Integration_WithRouter(t *testing.T) {
	_, rdb := setupMiniredis(t)
	cache := NewRedisDBInfoCache(rdb, "dbinfo:")
	lookup := newMockLookup()

	info := bridgeInfo("prod-host", "hexxlock_crm", "tenant_b8c9d0e1")
	lookup.SetResult(testTenantUUIDInt, "hexxlock_crm", info)

	router := NewProductConnectionRouter(nil, nil, nil,
		WithDBInfoCache(cache),
		WithLookupClient(lookup),
		WithCacheTTL(5*time.Minute),
		WithL1TTL(0), // disable L1 to test Redis integration
	)

	ctx := context.Background()

	// First call: cache miss → lookup → populates Redis.
	result, err := router.LookupDBInfo(ctx, testTenantUUIDInt, "hexxlock_crm")
	require.NoError(t, err)
	assert.Equal(t, "bridge", result.IsolationMode)
	assert.Equal(t, 1, lookup.CallCount())

	// Second call: should hit Redis cache, NOT the lookup.
	result2, err := router.LookupDBInfo(ctx, testTenantUUIDInt, "hexxlock_crm")
	require.NoError(t, err)
	assert.Equal(t, "bridge", result2.IsolationMode)
	assert.Equal(t, "prod-host", *result2.Host)
	assert.Equal(t, 1, lookup.CallCount(), "second call should hit Redis cache")

	// Invalidate → next call should hit lookup again.
	router.InvalidateDBInfo(ctx, testTenantUUIDInt, "hexxlock_crm")
	result3, err := router.LookupDBInfo(ctx, testTenantUUIDInt, "hexxlock_crm")
	require.NoError(t, err)
	assert.Equal(t, "bridge", result3.IsolationMode)
	assert.Equal(t, 2, lookup.CallCount(), "after invalidation should call lookup")
}

// ── Tests: HMAC Signed Cache ────────────────────────────────────────────────

func TestRedisDBInfoCache_HMAC_SetAndGet(t *testing.T) {
	_, rdb := setupMiniredis(t)
	hmacKey := []byte("test-hmac-key-32-bytes-long!!!!!")
	cache := NewRedisDBInfoCache(rdb, "signed:", WithHMACKey(hmacKey))
	ctx := context.Background()

	info := &TenantDatabaseInfo{
		Host:          ptr("db-host"),
		DatabaseName:  "hexxlock_crm",
		Schema:        "tenant_abc",
		IsolationMode: "bridge",
	}

	err := cache.SetDBInfo(ctx, "tenant-1", "hexxlock_crm", info, 5*time.Minute)
	require.NoError(t, err)

	got, err := cache.GetDBInfo(ctx, "tenant-1", "hexxlock_crm")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "bridge", got.IsolationMode)
	assert.Equal(t, "db-host", *got.Host)
}

func TestRedisDBInfoCache_HMAC_TamperedEntry(t *testing.T) {
	mr, rdb := setupMiniredis(t)
	hmacKey := []byte("test-hmac-key-32-bytes-long!!!!!")
	cache := NewRedisDBInfoCache(rdb, "signed:", WithHMACKey(hmacKey))
	ctx := context.Background()

	info := &TenantDatabaseInfo{
		Host:          ptr("db-host"),
		DatabaseName:  "hexxlock_crm",
		Schema:        "tenant_abc",
		IsolationMode: "bridge",
	}

	err := cache.SetDBInfo(ctx, "tenant-1", "hexxlock_crm", info, 5*time.Minute)
	require.NoError(t, err)

	// Tamper with the Redis entry directly.
	require.NoError(t, mr.Set("signed:tenant-1:hexxlock_crm", `{"p":{"database_name":"evil_db","isolation_mode":"silo"},"s":"invalid-signature"}`))

	got, err := cache.GetDBInfo(ctx, "tenant-1", "hexxlock_crm")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SECURITY")
	assert.Nil(t, got)

	// Tampered entry should be deleted.
	assert.False(t, mr.Exists("signed:tenant-1:hexxlock_crm"))
}

func TestRedisDBInfoCache_HMAC_WrongKey(t *testing.T) {
	_, rdb := setupMiniredis(t)
	ctx := context.Background()

	info := &TenantDatabaseInfo{
		DatabaseName:  "hexxlock_crm",
		IsolationMode: "pool",
	}

	// Write with key A.
	cacheA := NewRedisDBInfoCache(rdb, "signed:", WithHMACKey([]byte("key-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")))
	err := cacheA.SetDBInfo(ctx, "tenant-1", "hexxlock_crm", info, 5*time.Minute)
	require.NoError(t, err)

	// Read with key B.
	cacheB := NewRedisDBInfoCache(rdb, "signed:", WithHMACKey([]byte("key-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")))
	got, err := cacheB.GetDBInfo(ctx, "tenant-1", "hexxlock_crm")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SECURITY")
	assert.Nil(t, got)
}
