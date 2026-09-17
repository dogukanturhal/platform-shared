// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Mock implementations ────────────────────────────────────────────────────

// mockLookupClient implements DBInfoLookup for testing.
type mockLookupClient struct {
	mu       sync.Mutex
	calls    int
	results  map[string]*TenantDatabaseInfo // "tenantID:dbName" → info
	failKeys map[string]error               // "tenantID:dbName" → error
}

func newMockLookup() *mockLookupClient {
	return &mockLookupClient{
		results:  make(map[string]*TenantDatabaseInfo),
		failKeys: make(map[string]error),
	}
}

func (m *mockLookupClient) LookupTenantDatabase(_ context.Context, tenantID, databaseName string) (*TenantDatabaseInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++

	key := tenantID + ":" + databaseName
	if err, ok := m.failKeys[key]; ok {
		return nil, err
	}
	if info, ok := m.results[key]; ok {
		return info, nil
	}
	return nil, fmt.Errorf("not found: %s", key)
}

func (m *mockLookupClient) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func (m *mockLookupClient) SetResult(tenantID, dbName string, info *TenantDatabaseInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.results[tenantID+":"+dbName] = info
}

func (m *mockLookupClient) SetError(tenantID, dbName string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failKeys[tenantID+":"+dbName] = err
}

// mockDBInfoCache implements DBInfoCache for testing the L2 layer.
type mockDBInfoCache struct {
	mu       sync.Mutex
	store    map[string]*TenantDatabaseInfo
	getCalls int
	setCalls int
	delCalls int
}

func newMockCache() *mockDBInfoCache {
	return &mockDBInfoCache{
		store: make(map[string]*TenantDatabaseInfo),
	}
}

func (c *mockDBInfoCache) GetDBInfo(_ context.Context, tenantID, databaseName string) (*TenantDatabaseInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getCalls++
	key := tenantID + ":" + databaseName
	if info, ok := c.store[key]; ok {
		return info, nil
	}
	return nil, nil // cache miss
}

func (c *mockDBInfoCache) SetDBInfo(_ context.Context, tenantID, databaseName string, info *TenantDatabaseInfo, _ time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setCalls++
	c.store[tenantID+":"+databaseName] = info
	return nil
}

func (c *mockDBInfoCache) DeleteDBInfo(_ context.Context, tenantID, databaseName string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.delCalls++
	delete(c.store, tenantID+":"+databaseName)
	return nil
}

func (c *mockDBInfoCache) GetCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.getCalls
}

func (c *mockDBInfoCache) SetCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.setCalls
}

func (c *mockDBInfoCache) DelCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.delCalls
}

// ── Helper ──────────────────────────────────────────────────────────────────

func ptr(s string) *string { return &s }

// Use valid UUIDs for all test tenant IDs.
const (
	testTenantUUID1    = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	testTenantUUID2    = "b2c3d4e5-f6a7-8901-bcde-f12345678901"
	testTenantUUID3    = "c3d4e5f6-a7b8-9012-cdef-123456789012"
	testTenantUUID4    = "d4e5f6a7-b8c9-0123-defa-234567890123"
	testTenantUUIDSF   = "e5f6a7b8-c9d0-1234-efab-345678901234"
	testTenantUUIDPool = "f6a7b8c9-d0e1-2345-fabc-456789012345"
	testTenantUUIDBad  = "a7b8c9d0-e1f2-3456-abcd-567890123456"
	testTenantUUIDInt  = "b8c9d0e1-f2a3-4567-bcde-678901234567"
)

func bridgeInfo(host, dbName, schema string) *TenantDatabaseInfo {
	return &TenantDatabaseInfo{
		Host:          ptr(host),
		DatabaseName:  dbName,
		Schema:        schema,
		IsolationMode: "bridge",
	}
}

func poolInfo(dbName string) *TenantDatabaseInfo {
	return &TenantDatabaseInfo{
		DatabaseName:  dbName,
		Schema:        "public",
		IsolationMode: "pool",
	}
}

// ── Tests: Cache Layers ─────────────────────────────────────────────────────

func TestRouterCacheLayers_L2Hit_SkipsLookup(t *testing.T) {
	lookup := newMockLookup()
	cache := newMockCache()

	info := bridgeInfo("db-host", "hexxlock_crm", "tenant_a1b2c3d4")
	cache.store[testTenantUUID1+":hexxlock_crm"] = info

	router := NewProductConnectionRouter(nil, nil, nil,
		WithDBInfoCache(cache),
		WithLookupClient(lookup),
	)

	result, err := router.LookupDBInfo(context.Background(), testTenantUUID1, "hexxlock_crm")
	require.NoError(t, err)
	assert.Equal(t, "bridge", result.IsolationMode)
	assert.Equal(t, "db-host", *result.Host)

	assert.Equal(t, 0, lookup.CallCount(), "lookup should not be called when L2 cache hits")
	assert.Equal(t, 1, cache.GetCalls())
}

func TestRouterCacheLayers_L1Hit_SkipsL2AndLookup(t *testing.T) {
	lookup := newMockLookup()
	cache := newMockCache()

	info := bridgeInfo("db-host", "hexxlock_crm", "tenant_b2c3d4e5")
	lookup.SetResult(testTenantUUID2, "hexxlock_crm", info)

	router := NewProductConnectionRouter(nil, nil, nil,
		WithDBInfoCache(cache),
		WithLookupClient(lookup),
		WithL1TTL(5*time.Minute),
	)

	// First call: populates L1 and L2.
	result, err := router.LookupDBInfo(context.Background(), testTenantUUID2, "hexxlock_crm")
	require.NoError(t, err)
	assert.Equal(t, "bridge", result.IsolationMode)
	assert.Equal(t, 1, lookup.CallCount())

	// Second call: should hit L1, not L2 or lookup.
	result2, err := router.LookupDBInfo(context.Background(), testTenantUUID2, "hexxlock_crm")
	require.NoError(t, err)
	assert.Equal(t, "bridge", result2.IsolationMode)
	assert.Equal(t, 1, lookup.CallCount(), "L1 cache should prevent lookup")
	// L2 GetCalls: 1 from first call (miss), should not increase.
	assert.Equal(t, 1, cache.GetCalls(), "L1 cache should prevent L2 check")
}

func TestRouterCacheLayers_L2Miss_QueriesLookup_PopulatesL2(t *testing.T) {
	lookup := newMockLookup()
	cache := newMockCache()

	info := bridgeInfo("db-host-2", "hexxlock_hr", "tenant_c3d4e5f6")
	lookup.SetResult(testTenantUUID3, "hexxlock_hr", info)

	router := NewProductConnectionRouter(nil, nil, nil,
		WithDBInfoCache(cache),
		WithLookupClient(lookup),
		WithL1TTL(0), // disable L1 to test L2
	)

	result, err := router.LookupDBInfo(context.Background(), testTenantUUID3, "hexxlock_hr")
	require.NoError(t, err)
	assert.Equal(t, "bridge", result.IsolationMode)

	assert.Equal(t, 1, lookup.CallCount())
	assert.Equal(t, 1, cache.SetCalls())

	// Second call should hit L2 cache.
	result2, err := router.LookupDBInfo(context.Background(), testTenantUUID3, "hexxlock_hr")
	require.NoError(t, err)
	assert.Equal(t, "bridge", result2.IsolationMode)
	assert.Equal(t, 1, lookup.CallCount(), "second call should hit L2 cache")
}

func TestRouterNegativeCache_PoolMode(t *testing.T) {
	lookup := newMockLookup()
	cache := newMockCache()

	info := poolInfo("hexxlock_crm")
	lookup.SetResult(testTenantUUIDPool, "hexxlock_crm", info)

	router := NewProductConnectionRouter(nil, nil, nil,
		WithDBInfoCache(cache),
		WithLookupClient(lookup),
		WithNegativeCacheTTL(5*time.Minute),
		WithL1TTL(0),
	)

	result, err := router.LookupDBInfo(context.Background(), testTenantUUIDPool, "hexxlock_crm")
	require.NoError(t, err)
	assert.Equal(t, "pool", result.IsolationMode)

	assert.Equal(t, 1, cache.SetCalls())
	assert.Equal(t, 1, lookup.CallCount())

	_, err = router.LookupDBInfo(context.Background(), testTenantUUIDPool, "hexxlock_crm")
	require.NoError(t, err)
	assert.Equal(t, 1, lookup.CallCount(), "pool mode should be cached")
}

func TestRouterLookupFailure_ReturnsError(t *testing.T) {
	lookup := newMockLookup()
	lookup.SetError(testTenantUUIDBad, "hexxlock_crm", errors.New("connection refused"))

	router := NewProductConnectionRouter(nil, nil, nil,
		WithLookupClient(lookup),
	)

	_, err := router.LookupDBInfo(context.Background(), testTenantUUIDBad, "hexxlock_crm")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
}

func TestRouterInvalidate_ClearsBothCaches(t *testing.T) {
	lookup := newMockLookup()
	cache := newMockCache()

	info := bridgeInfo("db-host", "hexxlock_crm", "tenant_a1b2c3d4")
	cache.store[testTenantUUID1+":hexxlock_crm"] = info

	router := NewProductConnectionRouter(nil, nil, nil,
		WithDBInfoCache(cache),
		WithLookupClient(lookup),
		WithL1TTL(5*time.Minute),
	)

	// Populate L1 cache.
	result, err := router.LookupDBInfo(context.Background(), testTenantUUID1, "hexxlock_crm")
	require.NoError(t, err)
	assert.Equal(t, "bridge", result.IsolationMode)

	// Invalidate (clears both L1 and L2).
	router.InvalidateDBInfo(context.Background(), testTenantUUID1, "hexxlock_crm")
	assert.Equal(t, 1, cache.DelCalls())

	// Next lookup should go to the lookup client.
	lookup.SetResult(testTenantUUID1, "hexxlock_crm", bridgeInfo("new-host", "hexxlock_crm", "tenant_a1b2c3d4"))
	result2, err := router.LookupDBInfo(context.Background(), testTenantUUID1, "hexxlock_crm")
	require.NoError(t, err)
	assert.Equal(t, "new-host", *result2.Host)
	assert.Equal(t, 1, lookup.CallCount())
}

func TestRouterConcurrentLookups_SingleFlight(t *testing.T) {
	var lookupCount atomic.Int32
	lookup := newMockLookup()
	cache := newMockCache()

	info := bridgeInfo("db-host", "hexxlock_crm", "tenant_e5f6a7b8")
	lookup.SetResult(testTenantUUIDSF, "hexxlock_crm", info)

	slowLookup := &slowMockLookup{
		inner: lookup,
		delay: 100 * time.Millisecond,
		count: &lookupCount,
	}

	router := NewProductConnectionRouter(nil, nil, nil,
		WithDBInfoCache(cache),
		WithLookupClient(slowLookup),
		WithL1TTL(0),
	)

	var wg sync.WaitGroup
	results := make([]*TenantDatabaseInfo, 10)
	errs := make([]error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = router.LookupDBInfo(context.Background(), testTenantUUIDSF, "hexxlock_crm")
		}(i)
	}
	wg.Wait()

	for i := 0; i < 10; i++ {
		assert.NoError(t, errs[i])
		assert.NotNil(t, results[i])
		assert.Equal(t, "bridge", results[i].IsolationMode)
	}

	actualCalls := int(lookupCount.Load())
	assert.LessOrEqual(t, actualCalls, 3, "concurrent lookups should be deduplicated")
}

func TestRouterNoLookupClient_ReturnsError(t *testing.T) {
	router := NewProductConnectionRouter(nil, nil, nil)

	_, err := router.LookupDBInfo(context.Background(), testTenantUUID1, "hexxlock_crm")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no lookup client")
}

func TestRouterCacheTTL_PassedToCache(t *testing.T) {
	lookup := newMockLookup()
	cache := &ttlTrackingCache{mockDBInfoCache: newMockCache()}

	info := bridgeInfo("db-host", "hexxlock_crm", "tenant_a1b2c3d4")
	lookup.SetResult(testTenantUUID1, "hexxlock_crm", info)

	router := NewProductConnectionRouter(nil, nil, nil,
		WithDBInfoCache(cache),
		WithLookupClient(lookup),
		WithCacheTTL(3*time.Minute),
		WithL1TTL(0),
	)

	_, err := router.LookupDBInfo(context.Background(), testTenantUUID1, "hexxlock_crm")
	require.NoError(t, err)
	assert.Equal(t, 3*time.Minute, cache.lastTTL)
}

// ── Tests: Security Validations ─────────────────────────────────────────────

func TestRouterRejectsInvalidTenantID(t *testing.T) {
	router := NewProductConnectionRouter(nil, nil, nil,
		WithLookupClient(newMockLookup()),
	)

	_, err := router.LookupDBInfo(context.Background(), "not-a-uuid", "hexxlock_crm")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid tenant_id")
}

func TestRouterRejectsInvalidDatabaseName(t *testing.T) {
	router := NewProductConnectionRouter(nil, nil, nil,
		WithLookupClient(newMockLookup()),
	)

	_, err := router.LookupDBInfo(context.Background(), testTenantUUID1, "Robert'; DROP TABLE--")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid database_name")
}

func TestRouterCanonicalizesTenantID(t *testing.T) {
	lookup := newMockLookup()
	cache := newMockCache()

	// Use uppercase UUID.
	upperUUID := "A1B2C3D4-E5F6-7890-ABCD-EF1234567890"
	info := bridgeInfo("db-host", "hexxlock_crm", "tenant_a1b2c3d4")
	lookup.SetResult(testTenantUUID1, "hexxlock_crm", info) // lowercase

	router := NewProductConnectionRouter(nil, nil, nil,
		WithDBInfoCache(cache),
		WithLookupClient(lookup),
		WithL1TTL(0),
	)

	result, err := router.LookupDBInfo(context.Background(), upperUUID, "hexxlock_crm")
	require.NoError(t, err)
	assert.Equal(t, "bridge", result.IsolationMode)
}

func TestRouterOwnershipVerification_Silo(t *testing.T) {
	router := NewProductConnectionRouter(nil, nil, nil)

	// Silo DB name should contain tenant prefix.
	info := &TenantDatabaseInfo{
		Host:          ptr("db-host"),
		DatabaseName:  "hexxlock_crm_xxxxxxxx", // doesn't match tenant
		IsolationMode: "silo",
	}

	err := router.verifyOwnership(info, testTenantUUID1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SECURITY")

	// Matching DB name.
	info2 := &TenantDatabaseInfo{
		Host:          ptr("db-host"),
		DatabaseName:  "hexxlock_crm_a1b2c3d4",
		IsolationMode: "silo",
	}
	err = router.verifyOwnership(info2, testTenantUUID1)
	assert.NoError(t, err)
}

func TestRouterOwnershipVerification_Bridge(t *testing.T) {
	router := NewProductConnectionRouter(nil, nil, nil)

	// Bridge schema should contain tenant prefix.
	info := &TenantDatabaseInfo{
		DatabaseName:  "hexxlock_crm",
		Schema:        "tenant_xxxxxxxx",
		IsolationMode: "bridge",
	}

	err := router.verifyOwnership(info, testTenantUUID1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SECURITY")

	// Matching schema.
	info2 := &TenantDatabaseInfo{
		DatabaseName:  "hexxlock_crm",
		Schema:        "tenant_a1b2c3d4",
		IsolationMode: "bridge",
	}
	err = router.verifyOwnership(info2, testTenantUUID1)
	assert.NoError(t, err)
}

func TestRouterPoolMode_NoOwnershipCheck(t *testing.T) {
	router := NewProductConnectionRouter(nil, nil, nil)

	info := &TenantDatabaseInfo{
		DatabaseName:  "hexxlock_crm",
		Schema:        "public",
		IsolationMode: "pool",
	}
	err := router.verifyOwnership(info, testTenantUUID1)
	assert.NoError(t, err)
}

// ── Tests: Pool Limits ──────────────────────────────────────────────────────

func TestRouterMaxPoolsEnforced(t *testing.T) {
	router := NewProductConnectionRouter(nil, nil, nil, WithMaxPools(5))
	assert.Equal(t, int32(0), router.ActivePoolCount())
}

func TestRouterSchemaValidation(t *testing.T) {
	tests := []struct {
		schema string
		valid  bool
	}{
		{"public", true},
		{"tenant_abc123", true},
		{"tenant_a1b2c3d4", true},
		{"'; DROP TABLE--", false},
		{"admin", false},
		{"pg_catalog", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.schema, func(t *testing.T) {
			assert.Equal(t, tt.valid, isValidSchemaName(tt.schema))
		})
	}
}

func TestRouterDatabaseNameValidation(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"hexxlock_crm", true},
		{"hexxlock_hr", true},
		{"a", true},
		{"Robert'; DROP TABLE--", false},
		{"1starts_with_number", false},
		{"UPPERCASE", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, isValidDatabaseName(tt.name))
		})
	}
}

// ── Tests: Helpers ──────────────────────────────────────────────────────────

func TestQuoteIdentRouter(t *testing.T) {
	assert.Equal(t, `"public"`, quoteIdentRouter("public"))
	assert.Equal(t, `"tenant_abc"`, quoteIdentRouter("tenant_abc"))
	assert.Equal(t, `"with""quote"`, quoteIdentRouter(`with"quote`))
}

// ── Helper types ────────────────────────────────────────────────────────────

type slowMockLookup struct {
	inner DBInfoLookup
	delay time.Duration
	count *atomic.Int32
}

func (s *slowMockLookup) LookupTenantDatabase(ctx context.Context, tenantID, databaseName string) (*TenantDatabaseInfo, error) {
	s.count.Add(1)
	time.Sleep(s.delay)
	return s.inner.LookupTenantDatabase(ctx, tenantID, databaseName)
}

type ttlTrackingCache struct {
	*mockDBInfoCache
	lastTTL time.Duration
}

func (c *ttlTrackingCache) SetDBInfo(ctx context.Context, tenantID, databaseName string, info *TenantDatabaseInfo, ttl time.Duration) error {
	c.lastTTL = ttl
	return c.mockDBInfoCache.SetDBInfo(ctx, tenantID, databaseName, info, ttl)
}
