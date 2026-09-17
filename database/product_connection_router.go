// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

// ── Validation ─────────────────────────────────────────────────────────────

const (
	isolationModePool         = "pool"
	isolationModeBridge       = "bridge"
	isolationModeSilo         = "silo"
	isolationModePublicSchema = "public"
)

var (
	validDBNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	validSchemaRe = regexp.MustCompile(`^(public|tenant_[a-z0-9_]{1,55})$`)
)

func isValidDatabaseName(name string) bool {
	return validDBNameRe.MatchString(name)
}

func isValidSchemaName(schema string) bool {
	return validSchemaRe.MatchString(schema)
}

// canonicalTenantID validates and returns a canonical lowercase UUID string.
func canonicalTenantID(tenantID string) (string, error) {
	parsed, err := uuid.Parse(tenantID)
	if err != nil {
		return "", fmt.Errorf("invalid tenant_id: must be a valid UUID")
	}
	return parsed.String(), nil
}

// ── Interfaces ──────────────────────────────────────────────────────────────

// DBInfoLookup resolves tenant database connection info from an authoritative
// source (e.g., Falcon-ID internal HTTP endpoint).
type DBInfoLookup interface {
	LookupTenantDatabase(ctx context.Context, tenantID, databaseName string) (*TenantDatabaseInfo, error)
}

// DBInfoCache provides an L2 cache layer (typically Redis) for tenant database
// info, sitting between in-memory singleflight dedup and the remote lookup.
type DBInfoCache interface {
	GetDBInfo(ctx context.Context, tenantID, databaseName string) (*TenantDatabaseInfo, error)
	SetDBInfo(ctx context.Context, tenantID, databaseName string, info *TenantDatabaseInfo, ttl time.Duration) error
	DeleteDBInfo(ctx context.Context, tenantID, databaseName string) error
}

// ── Cached pool entry ───────────────────────────────────────────────────────

// cachedPool stores a connection pool alongside its isolation metadata.
type cachedPool struct {
	pool          *pgxpool.Pool
	isolationMode string
	schema        string
	tenantID      string
	lastUsed      atomic.Int64 // unix nano
}

func (cp *cachedPool) touch() {
	cp.lastUsed.Store(time.Now().UnixNano())
}

// ── L1 cache entry ──────────────────────────────────────────────────────────

type l1InfoEntry struct {
	info      *TenantDatabaseInfo
	expiresAt time.Time
}

// ── Options ─────────────────────────────────────────────────────────────────

// RouterOption configures a ProductConnectionRouter.
type RouterOption func(*ProductConnectionRouter)

// WithDBInfoCache sets the L2 cache implementation (e.g., Redis).
func WithDBInfoCache(cache DBInfoCache) RouterOption {
	return func(r *ProductConnectionRouter) {
		r.dbInfoCache = cache
	}
}

// WithLookupClient sets the lookup client used when L2 cache misses.
func WithLookupClient(lookup DBInfoLookup) RouterOption {
	return func(r *ProductConnectionRouter) {
		r.dbInfoLookup = lookup
	}
}

// WithCacheTTL sets the TTL for cached DB info entries. Default: 5 minutes.
func WithCacheTTL(ttl time.Duration) RouterOption {
	return func(r *ProductConnectionRouter) {
		r.cacheTTL = ttl
	}
}

// WithNegativeCacheTTL sets the TTL for negative-cached entries (pool-mode
// tenants that don't need dedicated connections). Default: equals cacheTTL.
func WithNegativeCacheTTL(ttl time.Duration) RouterOption {
	return func(r *ProductConnectionRouter) {
		r.negativeCacheTTL = ttl
	}
}

// WithL1TTL sets the TTL for L1 in-process cache entries. Default: 30 seconds.
func WithL1TTL(ttl time.Duration) RouterOption {
	return func(r *ProductConnectionRouter) {
		r.l1TTL = ttl
	}
}

// WithMaxPools sets the maximum number of concurrent silo/bridge pools. Default: 200.
func WithMaxPools(n int) RouterOption {
	return func(r *ProductConnectionRouter) {
		r.maxPools = int32(n) //nolint:gosec // caller-controlled bounded value
	}
}

// TierPoolConfig controls per-tier connection pool sizes.
type TierPoolConfig struct {
	BridgeMaxConns int32
	BridgeMinConns int32
	SiloMaxConns   int32
	SiloMinConns   int32
}

// WithTierPoolConfig sets per-tier pool sizing. Defaults: bridge=5, silo=10.
func WithTierPoolConfig(cfg TierPoolConfig) RouterOption {
	return func(r *ProductConnectionRouter) {
		r.tierPoolCfg = cfg
	}
}

// ── Router ──────────────────────────────────────────────────────────────────

// ProductConnectionRouter resolves "which database should tenant X connect to
// for CRM?" at runtime. It mirrors the pattern used by RealmConnectionRouter.
//
// Lookup order for LookupDBInfo:
//  1. L1 in-process cache (sync.Map, 30s TTL)
//  2. L2 cache (Redis via DBInfoCache, 5min TTL)
//  3. Remote lookup (Falcon-ID via DBInfoLookup)
//  4. Error (no fallback at info level)
//
// Lookup order for GetPool:
//  1. In-memory pool cache (sync.Map)
//  2. LookupDBInfo → create dedicated pool (bridge/silo)
//  3. Default pool fallback (pool mode)
type ProductConnectionRouter struct {
	defaultPools map[string]*pgxpool.Pool // database_name → default shared pool
	lookupClient *ProductDBLookupClient   // legacy direct client (backward compat)
	pools        sync.Map                 // "tenantID:dbName" → *cachedPool
	poolCount    atomic.Int32             // active pool count for limit enforcement
	mu           sync.Mutex               // serializes pool creation
	log          *zap.Logger

	// L1 in-process cache.
	l1Cache sync.Map // "tenantID:dbName" → *l1InfoEntry
	l1TTL   time.Duration

	// L2 cache layer.
	dbInfoLookup     DBInfoLookup
	dbInfoCache      DBInfoCache
	cacheTTL         time.Duration
	negativeCacheTTL time.Duration
	sfGroup          singleflight.Group // dedup concurrent lookups for same key

	// Pool limits.
	maxPools    int32
	tierPoolCfg TierPoolConfig

	// Observability.
	metrics *RouterMetrics
}

// NewProductConnectionRouter creates a new connection router.
// The first three positional args preserve backward compatibility.
// Use functional options (WithDBInfoCache, WithLookupClient, etc.) to configure
// the L2 cache layer.
func NewProductConnectionRouter(
	defaultPools map[string]*pgxpool.Pool,
	lookupClient *ProductDBLookupClient,
	log *zap.Logger,
	opts ...RouterOption,
) *ProductConnectionRouter {
	if defaultPools == nil {
		defaultPools = make(map[string]*pgxpool.Pool)
	}
	r := &ProductConnectionRouter{
		defaultPools: defaultPools,
		lookupClient: lookupClient,
		log:          log,
		cacheTTL:     5 * time.Minute,
		l1TTL:        30 * time.Second,
		maxPools:     200,
		tierPoolCfg: TierPoolConfig{
			BridgeMaxConns: 5,
			BridgeMinConns: 1,
			SiloMaxConns:   10,
			SiloMinConns:   1,
		},
	}
	for _, opt := range opts {
		opt(r)
	}
	if r.negativeCacheTTL == 0 {
		r.negativeCacheTTL = r.cacheTTL
	}
	return r
}

// ── Info-level lookup (testable, no pgxpool dependency) ─────────────────────

// LookupDBInfo resolves tenant database info through L1 → L2 cache → remote lookup.
// This is the pure-info layer that doesn't create connection pools.
func (r *ProductConnectionRouter) LookupDBInfo(ctx context.Context, tenantID, databaseName string) (*TenantDatabaseInfo, error) {
	// SECURITY: Validate inputs.
	canonical, err := canonicalTenantID(tenantID)
	if err != nil {
		return nil, err
	}
	tenantID = canonical

	if !isValidDatabaseName(databaseName) {
		return nil, fmt.Errorf("invalid database_name: must match ^[a-z][a-z0-9_]{0,62}$")
	}

	key := tenantID + ":" + databaseName
	lookupStart := time.Now()

	// Check L1 in-process cache first.
	if info := r.checkL1Cache(key, databaseName, lookupStart); info != nil {
		return info, nil
	}

	// Check L2 cache (Redis).
	if info := r.checkL2Cache(ctx, key, tenantID, databaseName, lookupStart); info != nil {
		return info, nil
	}

	// No cache hit — do remote lookup with singleflight dedup.
	if r.dbInfoLookup == nil {
		return nil, fmt.Errorf("no lookup client configured")
	}

	result, err, _ := r.sfGroup.Do(key, func() (interface{}, error) {
		info, err := r.dbInfoLookup.LookupTenantDatabase(ctx, tenantID, databaseName)
		if err != nil {
			return nil, err
		}

		// Populate L2 cache.
		if r.dbInfoCache != nil {
			ttl := r.cacheTTL
			if info.IsolationMode == isolationModePool && r.negativeCacheTTL > 0 {
				ttl = r.negativeCacheTTL
			}
			_ = r.dbInfoCache.SetDBInfo(ctx, tenantID, databaseName, info, ttl)
		}

		// Populate L1.
		r.l1Cache.Store(key, &l1InfoEntry{
			info:      info,
			expiresAt: time.Now().Add(r.l1TTL),
		})

		return info, nil
	})

	if err != nil {
		return nil, err
	}

	info := result.(*TenantDatabaseInfo)
	if r.metrics != nil {
		r.metrics.LookupsTotal.WithLabelValues(databaseName, info.IsolationMode, "remote").Inc()
		r.metrics.LookupDuration.WithLabelValues(databaseName).Observe(time.Since(lookupStart).Seconds())
	}
	return info, nil
}

// checkL1Cache checks the in-process L1 cache and returns the cached info on hit.
func (r *ProductConnectionRouter) checkL1Cache(key, databaseName string, lookupStart time.Time) *TenantDatabaseInfo {
	entry, ok := r.l1Cache.Load(key)
	if !ok {
		return nil
	}
	l1 := entry.(*l1InfoEntry)
	if !time.Now().Before(l1.expiresAt) {
		r.l1Cache.Delete(key)
		return nil
	}
	if r.log != nil {
		r.log.Debug("L1 cache hit", zap.String("key", key))
	}
	if r.metrics != nil {
		r.metrics.LookupsTotal.WithLabelValues(databaseName, l1.info.IsolationMode, "l1").Inc()
		r.metrics.LookupDuration.WithLabelValues(databaseName).Observe(time.Since(lookupStart).Seconds())
	}
	return l1.info
}

// checkL2Cache checks the Redis L2 cache and returns the cached info on hit,
// also populating L1 for future requests.
func (r *ProductConnectionRouter) checkL2Cache(ctx context.Context, key, tenantID, databaseName string, lookupStart time.Time) *TenantDatabaseInfo {
	if r.dbInfoCache == nil {
		return nil
	}
	info, err := r.dbInfoCache.GetDBInfo(ctx, tenantID, databaseName)
	if err != nil || info == nil {
		return nil
	}
	if r.log != nil {
		r.log.Debug("L2 cache hit", zap.String("key", key))
	}
	r.l1Cache.Store(key, &l1InfoEntry{
		info:      info,
		expiresAt: time.Now().Add(r.l1TTL),
	})
	if r.metrics != nil {
		r.metrics.LookupsTotal.WithLabelValues(databaseName, info.IsolationMode, "l2").Inc()
		r.metrics.LookupDuration.WithLabelValues(databaseName).Observe(time.Since(lookupStart).Seconds())
	}
	return info
}

// InvalidateDBInfo removes cached DB info from both L1 and L2 caches.
func (r *ProductConnectionRouter) InvalidateDBInfo(ctx context.Context, tenantID, databaseName string) {
	canonical, err := canonicalTenantID(tenantID)
	if err == nil {
		tenantID = canonical
	}

	key := tenantID + ":" + databaseName

	// Clear L1.
	r.l1Cache.Delete(key)

	// Clear L2.
	if r.dbInfoCache != nil {
		_ = r.dbInfoCache.DeleteDBInfo(ctx, tenantID, databaseName)
	}
}

// StartL1CleanupLoop starts a background goroutine that periodically evicts
// expired L1 cache entries. Call cancel on the returned context to stop.
func (r *ProductConnectionRouter) StartL1CleanupLoop(ctx context.Context) {
	interval := r.l1TTL * 5
	if interval < time.Minute {
		interval = time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				r.l1Cache.Range(func(key, value interface{}) bool {
					entry := value.(*l1InfoEntry)
					if now.After(entry.expiresAt) {
						r.l1Cache.Delete(key)
					}
					return true
				})
			}
		}
	}()
}

// ── Pool-level methods ──────────────────────────────────────────────────────

// GetPool returns the database connection pool for a given tenant and database name.
// It checks the cache first, then queries Falcon-ID, and falls back to the default pool.
func (r *ProductConnectionRouter) GetPool(ctx context.Context, tenantID, databaseName string) (*pgxpool.Pool, error) {
	// SECURITY: Validate inputs.
	canonical, err := canonicalTenantID(tenantID)
	if err != nil {
		return nil, err
	}
	tenantID = canonical

	if !isValidDatabaseName(databaseName) {
		return nil, fmt.Errorf("invalid database_name: must match ^[a-z][a-z0-9_]{0,62}$")
	}

	cacheKey := tenantID + ":" + databaseName

	// Fast path: check pool cache.
	if cp, ok := r.pools.Load(cacheKey); ok {
		cached := cp.(*cachedPool)
		cached.touch()
		return cached.pool, nil
	}

	// Try info lookup (L1 → L2 cache → remote) if available.
	if pool := r.tryLookupPool(ctx, cacheKey, tenantID, databaseName); pool != nil {
		return pool, nil
	}

	// Fallback: return the default pool for this database.
	if pool, ok := r.defaultPools[databaseName]; ok {
		return pool, nil
	}

	return nil, fmt.Errorf("no pool available for database %s (tenant %s)", databaseName, tenantID)
}

// GetPoolInfo returns the pool along with its isolation metadata. This is used
// by the middleware to determine what per-connection setup is needed.
func (r *ProductConnectionRouter) GetPoolInfo(ctx context.Context, tenantID, databaseName string) (*pgxpool.Pool, string, string, error) {
	canonical, err := canonicalTenantID(tenantID)
	if err != nil {
		return nil, "", "", err
	}
	tenantID = canonical

	if !isValidDatabaseName(databaseName) {
		return nil, "", "", fmt.Errorf("invalid database_name")
	}

	cacheKey := tenantID + ":" + databaseName

	// Check cached pool with metadata.
	if cp, ok := r.pools.Load(cacheKey); ok {
		cached := cp.(*cachedPool)
		cached.touch()
		return cached.pool, cached.isolationMode, cached.schema, nil
	}

	// Lookup and create via dbInfoLookup if available.
	if r.dbInfoLookup != nil {
		if pool, mode, schema, ok := r.lookupAndCreatePool(ctx, cacheKey, tenantID, databaseName); ok {
			return pool, mode, schema, nil
		}
	}

	// Fallback to default pool (pool mode).
	if pool, ok := r.defaultPools[databaseName]; ok {
		return pool, isolationModePool, isolationModePublicSchema, nil
	}

	return nil, "", "", fmt.Errorf("no pool available for database %s (tenant %s)", databaseName, tenantID)
}

// lookupAndCreatePool resolves DB info and creates a pool; returns (pool, mode, schema, true) on success.
func (r *ProductConnectionRouter) lookupAndCreatePool(ctx context.Context, cacheKey, tenantID, databaseName string) (*pgxpool.Pool, string, string, bool) {
	info, err := r.LookupDBInfo(ctx, tenantID, databaseName)
	if err != nil || info.Host == nil || info.IsolationMode == isolationModePool {
		return nil, "", "", false
	}
	pool, createErr := r.getOrCreatePool(ctx, cacheKey, info, tenantID)
	if createErr != nil {
		return nil, "", "", false
	}
	if cp, ok := r.pools.Load(cacheKey); ok {
		cached := cp.(*cachedPool)
		return pool, cached.isolationMode, cached.schema, true
	}
	return pool, info.IsolationMode, info.Schema, true
}

// tryLookupPool attempts to resolve a pool via dbInfoLookup (modern) or lookupClient (legacy).
// Returns nil when no dedicated pool is available (caller should fall through to defaultPools).
func (r *ProductConnectionRouter) tryLookupPool(ctx context.Context, cacheKey, tenantID, databaseName string) *pgxpool.Pool {
	if r.dbInfoLookup != nil {
		return r.tryModernLookup(ctx, cacheKey, tenantID, databaseName)
	}
	if r.lookupClient != nil {
		return r.tryLegacyLookup(ctx, cacheKey, tenantID, databaseName)
	}
	return nil
}

// tryModernLookup uses the L1/L2/remote dbInfoLookup path to resolve a pool.
func (r *ProductConnectionRouter) tryModernLookup(ctx context.Context, cacheKey, tenantID, databaseName string) *pgxpool.Pool {
	info, err := r.LookupDBInfo(ctx, tenantID, databaseName)
	if err != nil {
		if r.log != nil {
			r.log.Warn("Tenant database lookup failed, falling back to default pool",
				zap.String("tenant_id", tenantID),
				zap.String("database", databaseName),
				zap.Error(err),
			)
		}
		return nil
	}
	if info.Host == nil || info.IsolationMode == isolationModePool {
		return nil
	}
	pool, err := r.getOrCreatePool(ctx, cacheKey, info, tenantID)
	if err != nil {
		if r.log != nil {
			r.log.Error("Failed to create tenant-specific pool, falling back",
				zap.String("tenant_id", tenantID),
				zap.String("database", databaseName),
				zap.Error(err),
			)
		}
		return nil
	}
	return pool
}

// tryLegacyLookup uses the direct HTTP lookupClient path (no L2 cache) to resolve a pool.
func (r *ProductConnectionRouter) tryLegacyLookup(ctx context.Context, cacheKey, tenantID, databaseName string) *pgxpool.Pool {
	info, err := r.lookupClient.LookupTenantDatabase(ctx, tenantID, databaseName)
	if err != nil {
		if r.log != nil {
			r.log.Warn("Tenant database lookup failed, falling back to default pool",
				zap.String("tenant_id", tenantID),
				zap.String("database", databaseName),
				zap.Error(err),
			)
		}
		return nil
	}
	if info.Host == nil || info.IsolationMode == isolationModePool {
		return nil
	}
	pool, err := r.getOrCreatePool(ctx, cacheKey, info, tenantID)
	if err != nil {
		if r.log != nil {
			r.log.Error("Failed to create tenant-specific pool, falling back",
				zap.String("tenant_id", tenantID),
				zap.String("database", databaseName),
				zap.Error(err),
			)
		}
		return nil
	}
	return pool
}

// getOrCreatePool creates a pool for a tenant-specific database, using double-checked locking.
func (r *ProductConnectionRouter) getOrCreatePool(ctx context.Context, cacheKey string, info *TenantDatabaseInfo, requestingTenantID string) (*pgxpool.Pool, error) {
	// Double-check: another goroutine may have created the pool.
	if cp, ok := r.pools.Load(cacheKey); ok {
		cached := cp.(*cachedPool)
		cached.touch()
		return cached.pool, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check again under lock.
	if cp, ok := r.pools.Load(cacheKey); ok {
		cached := cp.(*cachedPool)
		cached.touch()
		return cached.pool, nil
	}

	// SECURITY: Verify schema name to prevent SQL injection via search_path.
	if info.Schema != "" && !isValidSchemaName(info.Schema) {
		return nil, fmt.Errorf("SECURITY: invalid schema name %q for tenant %s", info.Schema, requestingTenantID)
	}

	// SECURITY: Verify ownership — returned DB info must match the requesting tenant.
	if err := r.verifyOwnership(info, requestingTenantID); err != nil {
		return nil, err
	}

	// SECURITY: Enforce pool count limit.
	if r.poolCount.Load() >= r.maxPools {
		evicted := r.evictLRUPool()
		if !evicted {
			return nil, fmt.Errorf("pool limit reached (%d); cannot create new connection for %s", r.maxPools, cacheKey)
		}
	}

	// Build connection string.
	var connString string
	if info.ConnectionString != nil && *info.ConnectionString != "" {
		// Silo mode: use decrypted connection string from Falcon-ID.
		connString = *info.ConnectionString
	} else {
		// Bridge mode: connect to shared DB, search_path set per-connection via AfterConnect.
		connString = fmt.Sprintf("host=%s dbname=%s", *info.Host, info.DatabaseName)
		if info.Username != nil {
			connString += fmt.Sprintf(" user=%s", *info.Username)
		}
	}

	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("parse pool config: %w", err)
	}

	// Apply tier-specific pool sizes.
	switch info.IsolationMode {
	case isolationModeBridge:
		poolConfig.MaxConns = r.tierPoolCfg.BridgeMaxConns
		poolConfig.MinConns = r.tierPoolCfg.BridgeMinConns
	case isolationModeSilo:
		poolConfig.MaxConns = r.tierPoolCfg.SiloMaxConns
		poolConfig.MinConns = r.tierPoolCfg.SiloMinConns
	}

	// Bridge mode: set search_path on every new connection via AfterConnect.
	// This ensures every connection in the pool uses the correct schema,
	// regardless of when it was created or recycled.
	if info.IsolationMode == isolationModeBridge && info.Schema != "" && info.Schema != isolationModePublicSchema {
		schema := info.Schema // capture for closure
		poolConfig.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			_, err := conn.Exec(ctx, fmt.Sprintf("SET search_path TO %s, public", quoteIdentRouter(schema)))
			return err
		}
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	cp := &cachedPool{
		pool:          pool,
		isolationMode: info.IsolationMode,
		schema:        info.Schema,
		tenantID:      requestingTenantID,
	}
	cp.touch()

	r.pools.Store(cacheKey, cp)
	r.poolCount.Add(1)

	if r.log != nil {
		r.log.Info("Created tenant-specific database pool",
			zap.String("cache_key", cacheKey),
			zap.String("isolation", info.IsolationMode),
			zap.Int32("active_pools", r.poolCount.Load()),
		)
	}

	if r.metrics != nil {
		r.metrics.PoolCreations.WithLabelValues(info.DatabaseName, info.IsolationMode).Inc()
		r.metrics.ActivePools.WithLabelValues(info.IsolationMode).Inc()
	}

	return pool, nil
}

// verifyOwnership ensures the returned DB info belongs to the requesting tenant.
func (r *ProductConnectionRouter) verifyOwnership(info *TenantDatabaseInfo, requestingTenantID string) error {
	switch info.IsolationMode {
	case isolationModeSilo:
		return r.verifySiloOwnership(info, requestingTenantID)
	case isolationModeBridge:
		return r.verifyBridgeOwnership(info, requestingTenantID)
	}
	return nil
}

// verifySiloOwnership checks that a silo database name contains the tenant's slug prefix.
func (r *ProductConnectionRouter) verifySiloOwnership(info *TenantDatabaseInfo, requestingTenantID string) error {
	if len(requestingTenantID) < 8 || info.DatabaseName == "" {
		return nil
	}
	prefix := requestingTenantID[:8]
	if containsSubstring(info.DatabaseName, prefix) {
		return nil
	}
	if r.log != nil {
		r.log.Error("SECURITY: silo database ownership mismatch",
			zap.String("tenant_id", requestingTenantID),
			zap.String("database_name", info.DatabaseName),
		)
	}
	if r.metrics != nil {
		r.metrics.SecurityEvents.WithLabelValues("ownership_mismatch").Inc()
	}
	return fmt.Errorf("SECURITY: silo database name %q does not match tenant %s", info.DatabaseName, requestingTenantID)
}

// verifyBridgeOwnership checks that a bridge schema name contains the tenant's slug prefix.
func (r *ProductConnectionRouter) verifyBridgeOwnership(info *TenantDatabaseInfo, requestingTenantID string) error {
	if info.Schema == "" || info.Schema == isolationModePublicSchema || len(requestingTenantID) < 8 {
		return nil
	}
	prefix := requestingTenantID[:8]
	if containsSubstring(info.Schema, prefix) {
		return nil
	}
	if r.log != nil {
		r.log.Error("SECURITY: bridge schema ownership mismatch",
			zap.String("tenant_id", requestingTenantID),
			zap.String("schema", info.Schema),
		)
	}
	if r.metrics != nil {
		r.metrics.SecurityEvents.WithLabelValues("ownership_mismatch").Inc()
	}
	return fmt.Errorf("SECURITY: bridge schema %q does not match tenant %s", info.Schema, requestingTenantID)
}

// evictLRUPool evicts the least-recently-used pool. Returns true if a pool was evicted.
func (r *ProductConnectionRouter) evictLRUPool() bool {
	var oldestKey interface{}
	oldestTime := time.Now().UnixNano()

	r.pools.Range(func(key, value interface{}) bool {
		cp := value.(*cachedPool)
		lastUsed := cp.lastUsed.Load()
		if lastUsed < oldestTime {
			oldestTime = lastUsed
			oldestKey = key
		}
		return true
	})

	if oldestKey == nil {
		return false
	}
	cp, ok := r.pools.LoadAndDelete(oldestKey)
	if !ok {
		return false
	}
	evicted := cp.(*cachedPool)
	evicted.pool.Close()
	r.poolCount.Add(-1)
	if r.log != nil {
		r.log.Info("Evicted LRU tenant database pool",
			zap.String("key", oldestKey.(string)),
			zap.Int32("active_pools", r.poolCount.Load()),
		)
	}
	if r.metrics != nil {
		r.metrics.PoolEvictions.WithLabelValues(evicted.isolationMode, "lru").Inc()
		r.metrics.ActivePools.WithLabelValues(evicted.isolationMode).Dec()
	}
	return true
}

// InvalidatePool removes a cached pool for a tenant and database.
func (r *ProductConnectionRouter) InvalidatePool(tenantID, databaseName string) {
	canonical, err := canonicalTenantID(tenantID)
	if err == nil {
		tenantID = canonical
	}

	cacheKey := tenantID + ":" + databaseName
	if cp, ok := r.pools.LoadAndDelete(cacheKey); ok {
		invalidated := cp.(*cachedPool)
		invalidated.pool.Close()
		r.poolCount.Add(-1)
		if r.log != nil {
			r.log.Info("Invalidated tenant database pool",
				zap.String("tenant_id", tenantID),
				zap.String("database", databaseName),
			)
		}
		if r.metrics != nil {
			r.metrics.PoolEvictions.WithLabelValues(invalidated.isolationMode, "invalidate").Inc()
			r.metrics.ActivePools.WithLabelValues(invalidated.isolationMode).Dec()
		}
	}
}

// CloseAll closes all cached tenant-specific pools.
func (r *ProductConnectionRouter) CloseAll() {
	r.pools.Range(func(key, value interface{}) bool {
		value.(*cachedPool).pool.Close()
		r.pools.Delete(key)
		return true
	})
	r.poolCount.Store(0)
	if r.log != nil {
		r.log.Info("Closed all tenant-specific database pools")
	}
}

// ActivePoolCount returns the number of active tenant-specific pools.
func (r *ProductConnectionRouter) ActivePoolCount() int32 {
	return r.poolCount.Load()
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// quoteIdentRouter quotes a PostgreSQL identifier to prevent injection.
func quoteIdentRouter(name string) string {
	// Double any existing double-quotes, then wrap in double-quotes.
	result := make([]byte, 0, len(name)+2)
	result = append(result, '"')
	for i := 0; i < len(name); i++ {
		if name[i] == '"' {
			result = append(result, '"', '"')
		} else {
			result = append(result, name[i])
		}
	}
	result = append(result, '"')
	return string(result)
}
