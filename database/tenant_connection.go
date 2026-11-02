// SPDX-License-Identifier: Apache-2.0

// Package database provides multi-tenant database connection management for Go services.
// It supports three isolation strategies: shared (RLS), schema-per-tenant, and database-per-tenant.
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// Circuit breaker errors
var (
	ErrCircuitOpen     = errors.New("circuit breaker is open")
	ErrCircuitHalfOpen = errors.New("circuit breaker is half-open, limiting requests")
	ErrTenantSuspended = errors.New("tenant connection is suspended")
)

// IsolationStrategy defines the database isolation level
type IsolationStrategy string

// StrategyShared and its siblings define the database isolation strategy levels.
const (
	StrategyShared   IsolationStrategy = "shared"   // Shared DB with RLS
	StrategySchema   IsolationStrategy = "schema"   // Schema per tenant
	StrategyDatabase IsolationStrategy = "database" // Database per tenant
)

const schemaPublic = "public"

// TenantConnectionInfo contains connection details for a tenant
type TenantConnectionInfo struct {
	TenantID     uuid.UUID         `json:"tenant_id"`
	Strategy     IsolationStrategy `json:"strategy"`
	DatabaseName string            `json:"database_name"`
	SchemaName   string            `json:"schema_name"`
	Host         string            `json:"host"`
	Port         int               `json:"port"`
	Status       string            `json:"status"`
}

// TenantConnectionManager manages database connections for multiple tenants
type TenantConnectionManager struct {
	masterDB       *sql.DB
	masterDSN      string
	redis          *redis.Client
	pools          sync.Map // map[uuid.UUID]*sql.DB
	config         ConnectionConfig
	cachePrefix    string
	cacheTTL       time.Duration
	circuitBreaker *CircuitBreakerManager
	suspendedMap   sync.Map // map[uuid.UUID]bool - tracks suspended tenants
}

// ConnectionConfig holds configuration for connection management
type ConnectionConfig struct {
	MasterDSN    string
	MaxOpenConns int
	MaxIdleConns int
	ConnMaxLife  time.Duration
	ConnMaxIdle  time.Duration
	CachePrefix  string
	CacheTTL     time.Duration
	DefaultHost  string
	DefaultPort  int
}

// DefaultConnectionConfig returns default configuration values
func DefaultConnectionConfig() ConnectionConfig {
	return ConnectionConfig{
		MaxOpenConns: 10,
		MaxIdleConns: 5,
		ConnMaxLife:  30 * time.Minute,
		ConnMaxIdle:  5 * time.Minute,
		CachePrefix:  "tenant:conn:",
		CacheTTL:     5 * time.Minute,
		DefaultHost:  "postgres-master",
		DefaultPort:  5432,
	}
}

// CircuitState represents the state of a circuit breaker
type CircuitState int32

// CircuitClosed and its siblings define the circuit breaker states.
const (
	CircuitClosed   CircuitState = iota // Normal operation
	CircuitOpen                         // Blocking all requests
	CircuitHalfOpen                     // Testing recovery
)

func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreakerConfig holds configuration for the circuit breaker
type CircuitBreakerConfig struct {
	// FailureThreshold - consecutive failures before opening
	FailureThreshold int
	// SuccessThreshold - consecutive successes in half-open to close
	SuccessThreshold int
	// ResetTimeout - time to wait before transitioning from open to half-open
	ResetTimeout time.Duration
	// HalfOpenMaxRequests - max concurrent requests in half-open state
	HalfOpenMaxRequests int
}

// DefaultCircuitBreakerConfig returns default circuit breaker configuration
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		FailureThreshold:    5,
		SuccessThreshold:    2,
		ResetTimeout:        30 * time.Second,
		HalfOpenMaxRequests: 1,
	}
}

// TenantCircuitBreaker manages circuit breaker state for a single tenant
type TenantCircuitBreaker struct {
	tenantID         uuid.UUID
	state            int32 // atomic, CircuitState
	failureCount     int32 // atomic
	successCount     int32 // atomic
	lastFailure      time.Time
	lastStateChange  time.Time
	halfOpenRequests int32 // atomic
	config           CircuitBreakerConfig
	mu               sync.RWMutex
}

// NewTenantCircuitBreaker creates a new circuit breaker for a tenant
func NewTenantCircuitBreaker(tenantID uuid.UUID, config CircuitBreakerConfig) *TenantCircuitBreaker {
	return &TenantCircuitBreaker{
		tenantID:        tenantID,
		state:           int32(CircuitClosed),
		config:          config,
		lastStateChange: time.Now(),
	}
}

// State returns the current circuit state
func (cb *TenantCircuitBreaker) State() CircuitState {
	return CircuitState(atomic.LoadInt32(&cb.state))
}

// AllowRequest checks if a request should be allowed
func (cb *TenantCircuitBreaker) AllowRequest() error {
	state := cb.State()

	switch state {
	case CircuitClosed:
		return nil

	case CircuitOpen:
		// Check if reset timeout has elapsed
		cb.mu.RLock()
		shouldTransition := time.Since(cb.lastStateChange) >= cb.config.ResetTimeout
		cb.mu.RUnlock()

		if shouldTransition {
			cb.transitionTo(CircuitHalfOpen)
			// Allow this request
			if atomic.AddInt32(&cb.halfOpenRequests, 1) <= int32(cb.config.HalfOpenMaxRequests) { //nolint:gosec // bounded config value
				return nil
			}
			atomic.AddInt32(&cb.halfOpenRequests, -1)
			return ErrCircuitHalfOpen
		}
		return ErrCircuitOpen

	case CircuitHalfOpen:
		// Allow limited requests
		if atomic.AddInt32(&cb.halfOpenRequests, 1) <= int32(cb.config.HalfOpenMaxRequests) { //nolint:gosec // bounded config value
			return nil
		}
		atomic.AddInt32(&cb.halfOpenRequests, -1)
		return ErrCircuitHalfOpen
	}

	return nil
}

// RecordSuccess records a successful request
func (cb *TenantCircuitBreaker) RecordSuccess() {
	state := cb.State()

	switch state {
	case CircuitClosed:
		// Reset failure count on success
		atomic.StoreInt32(&cb.failureCount, 0)

	case CircuitHalfOpen:
		atomic.AddInt32(&cb.halfOpenRequests, -1)
		count := atomic.AddInt32(&cb.successCount, 1)
		if int(count) >= cb.config.SuccessThreshold {
			cb.transitionTo(CircuitClosed)
		}
	}
}

// RecordFailure records a failed request
func (cb *TenantCircuitBreaker) RecordFailure() {
	state := cb.State()

	cb.mu.Lock()
	cb.lastFailure = time.Now()
	cb.mu.Unlock()

	switch state {
	case CircuitClosed:
		count := atomic.AddInt32(&cb.failureCount, 1)
		if int(count) >= cb.config.FailureThreshold {
			cb.transitionTo(CircuitOpen)
		}

	case CircuitHalfOpen:
		atomic.AddInt32(&cb.halfOpenRequests, -1)
		cb.transitionTo(CircuitOpen)
	}
}

// Reset resets the circuit breaker to closed state
func (cb *TenantCircuitBreaker) Reset() {
	cb.transitionTo(CircuitClosed)
}

// ForceOpen forces the circuit to open state
func (cb *TenantCircuitBreaker) ForceOpen() {
	cb.transitionTo(CircuitOpen)
}

func (cb *TenantCircuitBreaker) transitionTo(newState CircuitState) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	oldState := CircuitState(atomic.LoadInt32(&cb.state))
	if oldState == newState {
		return
	}

	atomic.StoreInt32(&cb.state, int32(newState))
	cb.lastStateChange = time.Now()
	atomic.StoreInt32(&cb.failureCount, 0)
	atomic.StoreInt32(&cb.successCount, 0)
	atomic.StoreInt32(&cb.halfOpenRequests, 0)
}

// GetStats returns circuit breaker statistics
func (cb *TenantCircuitBreaker) GetStats() CircuitBreakerStats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return CircuitBreakerStats{
		TenantID:        cb.tenantID,
		State:           cb.State(),
		FailureCount:    int(atomic.LoadInt32(&cb.failureCount)),
		SuccessCount:    int(atomic.LoadInt32(&cb.successCount)),
		LastFailure:     cb.lastFailure,
		LastStateChange: cb.lastStateChange,
	}
}

// CircuitBreakerStats contains circuit breaker statistics
type CircuitBreakerStats struct {
	TenantID        uuid.UUID    `json:"tenant_id"`
	State           CircuitState `json:"state"`
	FailureCount    int          `json:"failure_count"`
	SuccessCount    int          `json:"success_count"`
	LastFailure     time.Time    `json:"last_failure,omitempty"`
	LastStateChange time.Time    `json:"last_state_change"`
}

// CircuitBreakerManager manages circuit breakers for all tenants
type CircuitBreakerManager struct {
	breakers sync.Map // map[uuid.UUID]*TenantCircuitBreaker
	config   CircuitBreakerConfig
}

// NewCircuitBreakerManager creates a new circuit breaker manager
func NewCircuitBreakerManager(config CircuitBreakerConfig) *CircuitBreakerManager {
	return &CircuitBreakerManager{
		config: config,
	}
}

// GetBreaker returns the circuit breaker for a tenant
func (m *CircuitBreakerManager) GetBreaker(tenantID uuid.UUID) *TenantCircuitBreaker {
	if breaker, ok := m.breakers.Load(tenantID); ok {
		return breaker.(*TenantCircuitBreaker)
	}

	breaker := NewTenantCircuitBreaker(tenantID, m.config)
	actual, _ := m.breakers.LoadOrStore(tenantID, breaker)
	return actual.(*TenantCircuitBreaker)
}

// RemoveBreaker removes the circuit breaker for a tenant
func (m *CircuitBreakerManager) RemoveBreaker(tenantID uuid.UUID) {
	m.breakers.Delete(tenantID)
}

// ResetAll resets all circuit breakers
func (m *CircuitBreakerManager) ResetAll() {
	m.breakers.Range(func(_, value interface{}) bool {
		breaker := value.(*TenantCircuitBreaker)
		breaker.Reset()
		return true
	})
}

// GetAllStats returns statistics for all circuit breakers
func (m *CircuitBreakerManager) GetAllStats() []CircuitBreakerStats {
	var stats []CircuitBreakerStats
	m.breakers.Range(func(_, value interface{}) bool {
		breaker := value.(*TenantCircuitBreaker)
		stats = append(stats, breaker.GetStats())
		return true
	})
	return stats
}

// NewTenantConnectionManager creates a new connection manager
func NewTenantConnectionManager(masterDB *sql.DB, masterDSN string, redis *redis.Client, config ConnectionConfig) *TenantConnectionManager {
	if config.CachePrefix == "" {
		config.CachePrefix = "tenant:conn:"
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute
	}

	return &TenantConnectionManager{
		masterDB:       masterDB,
		masterDSN:      masterDSN,
		redis:          redis,
		config:         config,
		cachePrefix:    config.CachePrefix,
		cacheTTL:       config.CacheTTL,
		circuitBreaker: NewCircuitBreakerManager(DefaultCircuitBreakerConfig()),
	}
}

// NewTenantConnectionManagerWithCircuitBreaker creates a connection manager with custom circuit breaker config
func NewTenantConnectionManagerWithCircuitBreaker(
	masterDB *sql.DB,
	masterDSN string,
	redis *redis.Client,
	config ConnectionConfig,
	cbConfig CircuitBreakerConfig,
) *TenantConnectionManager {
	if config.CachePrefix == "" {
		config.CachePrefix = "tenant:conn:"
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute
	}

	return &TenantConnectionManager{
		masterDB:       masterDB,
		masterDSN:      masterDSN,
		redis:          redis,
		config:         config,
		cachePrefix:    config.CachePrefix,
		cacheTTL:       config.CacheTTL,
		circuitBreaker: NewCircuitBreakerManager(cbConfig),
	}
}

// GetConnection returns a database connection for the specified tenant
func (m *TenantConnectionManager) GetConnection(ctx context.Context, tenantID uuid.UUID) (*sql.DB, error) {
	// Check if tenant is suspended
	if suspended, _ := m.suspendedMap.Load(tenantID); suspended != nil && suspended.(bool) {
		return nil, ErrTenantSuspended
	}

	// Check circuit breaker
	if m.circuitBreaker != nil {
		breaker := m.circuitBreaker.GetBreaker(tenantID)
		if err := breaker.AllowRequest(); err != nil {
			return nil, fmt.Errorf("connection blocked: %w", err)
		}
	}

	// Check pool cache first
	if pool, ok := m.pools.Load(tenantID); ok {
		db := pool.(*sql.DB)
		// Verify connection is still valid
		if err := db.PingContext(ctx); err == nil {
			if m.circuitBreaker != nil {
				m.circuitBreaker.GetBreaker(tenantID).RecordSuccess()
			}
			return db, nil
		}
		// Connection invalid, record failure and remove from cache
		if m.circuitBreaker != nil {
			m.circuitBreaker.GetBreaker(tenantID).RecordFailure()
		}
		m.pools.Delete(tenantID)
	}

	// Load tenant connection info
	info, err := m.getTenantConnectionInfo(ctx, tenantID)
	if err != nil {
		if m.circuitBreaker != nil {
			m.circuitBreaker.GetBreaker(tenantID).RecordFailure()
		}
		return nil, fmt.Errorf("failed to get tenant connection info: %w", err)
	}

	// Create connection based on strategy
	var db *sql.DB
	switch info.Strategy {
	case StrategyShared:
		// Use master DB - caller must set tenant context
		if m.circuitBreaker != nil {
			m.circuitBreaker.GetBreaker(tenantID).RecordSuccess()
		}
		return m.masterDB, nil

	case StrategySchema:
		db, err = m.createSchemaConnection(ctx, info)
		if err != nil {
			if m.circuitBreaker != nil {
				m.circuitBreaker.GetBreaker(tenantID).RecordFailure()
			}
			return nil, fmt.Errorf("failed to create schema connection: %w", err)
		}

	case StrategyDatabase:
		db, err = m.createDatabaseConnection(ctx, info)
		if err != nil {
			if m.circuitBreaker != nil {
				m.circuitBreaker.GetBreaker(tenantID).RecordFailure()
			}
			return nil, fmt.Errorf("failed to create database connection: %w", err)
		}

	default:
		// Default to shared strategy
		if m.circuitBreaker != nil {
			m.circuitBreaker.GetBreaker(tenantID).RecordSuccess()
		}
		return m.masterDB, nil
	}

	// Cache the connection pool
	m.pools.Store(tenantID, db)

	if m.circuitBreaker != nil {
		m.circuitBreaker.GetBreaker(tenantID).RecordSuccess()
	}

	return db, nil
}

// GetConnectionWithContext returns a connection with tenant context set (for shared strategy)
func (m *TenantConnectionManager) GetConnectionWithContext(ctx context.Context, tenantID uuid.UUID) (*sql.Conn, error) {
	db, err := m.GetConnection(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetConnectionWithContext: GetConnection failed: %w", err)
	}

	// Get a single connection
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection: %w", err)
	}

	// Get tenant info to check strategy
	info, err := m.getTenantConnectionInfo(ctx, tenantID)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("GetConnectionWithContext: %w", err)
	}

	// For shared strategy, set tenant context
	if info.Strategy == StrategyShared {
		if err := m.SetTenantContext(ctx, conn, tenantID); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("failed to set tenant context: %w", err)
		}
	}

	return conn, nil
}

// SetTenantContext sets the current tenant ID in the database session.
// Uses set_config() instead of SET because PostgreSQL's SET command does not
// support parameterized queries ($1) via the pgx extended query protocol.
func (m *TenantConnectionManager) SetTenantContext(ctx context.Context, conn *sql.Conn, tenantID uuid.UUID) error {
	_, err := conn.ExecContext(ctx, "SELECT set_config('app.current_tenant_id', $1, false)", tenantID.String())
	if err != nil {
		return fmt.Errorf("SetTenantContext: ExecContext failed: %w", err)
	}
	return nil
}

// SetTenantContextOnDB sets tenant context on a regular DB (for transactions).
// Uses set_config() instead of SET because PostgreSQL's SET command does not
// support parameterized queries ($1) via the pgx extended query protocol.
func (m *TenantConnectionManager) SetTenantContextOnDB(ctx context.Context, db *sql.DB, tenantID uuid.UUID) error {
	_, err := db.ExecContext(ctx, "SELECT set_config('app.current_tenant_id', $1, false)", tenantID.String())
	if err != nil {
		return fmt.Errorf("SetTenantContextOnDB: ExecContext failed: %w", err)
	}
	return nil
}

// ClearTenantContext clears the tenant context from the session
func (m *TenantConnectionManager) ClearTenantContext(ctx context.Context, conn *sql.Conn) error {
	_, err := conn.ExecContext(ctx, "RESET app.current_tenant_id")
	if err != nil {
		return fmt.Errorf("ClearTenantContext: ExecContext failed: %w", err)
	}
	return nil
}

// GetTenantInfo returns the connection info for a tenant
func (m *TenantConnectionManager) GetTenantInfo(ctx context.Context, tenantID uuid.UUID) (*TenantConnectionInfo, error) {
	return m.getTenantConnectionInfo(ctx, tenantID)
}

// InvalidateCache removes tenant connection info from cache
func (m *TenantConnectionManager) InvalidateCache(ctx context.Context, tenantID uuid.UUID) error {
	// Remove from Redis cache
	if m.redis != nil {
		key := m.cachePrefix + tenantID.String()
		if err := m.redis.Del(ctx, key).Err(); err != nil {
			return fmt.Errorf("InvalidateCache: %w", err)
		}
	}

	// Remove from connection pool
	if pool, ok := m.pools.LoadAndDelete(tenantID); ok {
		db := pool.(*sql.DB)
		// Don't close master DB
		if db != m.masterDB {
			return db.Close()
		}
	}

	return nil
}

// CloseConnection closes a tenant's database connection
func (m *TenantConnectionManager) CloseConnection(tenantID uuid.UUID) error {
	if pool, ok := m.pools.LoadAndDelete(tenantID); ok {
		db := pool.(*sql.DB)
		// Don't close master DB
		if db != m.masterDB {
			return db.Close()
		}
	}
	return nil
}

// CloseAll closes all tenant connections (except master)
func (m *TenantConnectionManager) CloseAll() {
	m.pools.Range(func(key, value interface{}) bool {
		db := value.(*sql.DB)
		if db != m.masterDB {
			_ = db.Close()
		}
		m.pools.Delete(key)
		return true
	})
}

// Internal methods

func (m *TenantConnectionManager) getTenantConnectionInfo(ctx context.Context, tenantID uuid.UUID) (*TenantConnectionInfo, error) {
	// Try Redis cache first
	if m.redis != nil {
		key := m.cachePrefix + tenantID.String()
		data, err := m.redis.Get(ctx, key).Bytes()
		if err == nil {
			var info TenantConnectionInfo
			if json.Unmarshal(data, &info) == nil {
				return &info, nil
			}
		}
	}

	// Query database
	info, err := m.loadTenantConnectionFromDB(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("getTenantConnectionInfo: loadTenantConnectionFromDB failed: %w", err)
	}

	// Cache the result
	if m.redis != nil && info != nil {
		key := m.cachePrefix + tenantID.String()
		if data, err := json.Marshal(info); err == nil {
			m.redis.Set(ctx, key, data, m.cacheTTL)
		}
	}

	return info, nil
}

func (m *TenantConnectionManager) loadTenantConnectionFromDB(ctx context.Context, tenantID uuid.UUID) (*TenantConnectionInfo, error) {
	query := `
		SELECT tenant_id, strategy, database_name, schema_name, host, port, status
		FROM tenant_databases
		WHERE tenant_id = $1
	`

	var info TenantConnectionInfo
	err := m.masterDB.QueryRowContext(ctx, query, tenantID).Scan(
		&info.TenantID,
		&info.Strategy,
		&info.DatabaseName,
		&info.SchemaName,
		&info.Host,
		&info.Port,
		&info.Status,
	)

	if err == sql.ErrNoRows {
		// Return default shared strategy for tenants not yet provisioned
		return &TenantConnectionInfo{
			TenantID:     tenantID,
			Strategy:     StrategyShared,
			DatabaseName: "hexxlock_master",
			SchemaName:   schemaPublic,
			Host:         m.config.DefaultHost,
			Port:         m.config.DefaultPort,
			Status:       "ready",
		}, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load tenant connection: %w", err)
	}

	if info.Status != "ready" {
		return nil, fmt.Errorf("tenant database not ready: %s", info.Status)
	}

	return &info, nil
}

func (m *TenantConnectionManager) createSchemaConnection(ctx context.Context, info *TenantConnectionInfo) (*sql.DB, error) {
	// Build DSN with search_path
	dsn := m.buildDSN(info.DatabaseName, info.SchemaName, info.Host, info.Port)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("createSchemaConnection: Open failed: %w", err)
	}

	// Configure pool
	db.SetMaxOpenConns(m.config.MaxOpenConns)
	db.SetMaxIdleConns(m.config.MaxIdleConns)
	db.SetConnMaxLifetime(m.config.ConnMaxLife)
	db.SetConnMaxIdleTime(m.config.ConnMaxIdle)

	// Verify connection
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

func (m *TenantConnectionManager) createDatabaseConnection(ctx context.Context, info *TenantConnectionInfo) (*sql.DB, error) {
	// Build DSN for dedicated database
	dsn := m.buildDSN(info.DatabaseName, "", info.Host, info.Port)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("createDatabaseConnection: Open failed: %w", err)
	}

	// Configure pool
	db.SetMaxOpenConns(m.config.MaxOpenConns)
	db.SetMaxIdleConns(m.config.MaxIdleConns)
	db.SetConnMaxLifetime(m.config.ConnMaxLife)
	db.SetConnMaxIdleTime(m.config.ConnMaxIdle)

	// Verify connection
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

func (m *TenantConnectionManager) buildDSN(database, schema, host string, port int) string {
	// masterDSN is normally a URL: postgres://user:pass@host:port/dbname?params
	u, err := url.Parse(m.masterDSN)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return buildKeyValueDSN(m.masterDSN, database, schema, host, port)
	}

	if database != "" {
		u.Path = "/" + database
		u.RawPath = ""
	}

	if host != "" || port > 0 {
		h, p := u.Hostname(), u.Port()
		if host != "" {
			var hp string
			h, hp = splitHostPort(host)
			if hp != "" {
				p = hp
			}
		}
		if port > 0 {
			p = strconv.Itoa(port)
		}
		if p != "" {
			u.Host = net.JoinHostPort(h, p)
		} else if strings.Contains(h, ":") {
			u.Host = "[" + h + "]"
		} else {
			u.Host = h
		}
	}

	if schema != "" && schema != schemaPublic {
		q := u.Query()
		q.Set("search_path", schema+",public")
		u.RawQuery = q.Encode()
	}

	return u.String()
}

// splitHostPort splits "host", "host:port", "[v6]:port", "[v6]" or a bare IPv6
// literal into host (no brackets) and port (possibly empty).
func splitHostPort(hostport string) (host, port string) {
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		return h, p
	}
	return strings.Trim(hostport, "[]"), ""
}

// buildKeyValueDSN handles a key=value master DSN by appending overrides;
// later keys win in libpq/pgx.
func buildKeyValueDSN(base, database, schema, host string, port int) string {
	quote := func(v string) string {
		return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v) + "'"
	}
	dsn := base
	if database != "" {
		dsn += " dbname=" + quote(database)
	}
	if host != "" {
		h, p := splitHostPort(host)
		dsn += " host=" + quote(h)
		if p != "" && port <= 0 {
			dsn += " port=" + p
		}
	}
	if port > 0 {
		dsn += " port=" + strconv.Itoa(port)
	}
	if schema != "" && schema != schemaPublic {
		dsn += " search_path=" + quote(schema+",public")
	}
	return dsn
}

// TenantTx wraps a transaction with tenant context
type TenantTx struct {
	*sql.Tx
	tenantID uuid.UUID
	strategy IsolationStrategy
}

// BeginTenantTx starts a transaction with tenant context set
func (m *TenantConnectionManager) BeginTenantTx(ctx context.Context, tenantID uuid.UUID, opts *sql.TxOptions) (*TenantTx, error) {
	db, err := m.GetConnection(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("BeginTenantTx: GetConnection failed: %w", err)
	}

	info, err := m.getTenantConnectionInfo(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("BeginTenantTx: getTenantConnectionInfo failed: %w", err)
	}

	tx, err := db.BeginTx(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("BeginTenantTx: BeginTx failed: %w", err)
	}

	// Set tenant context for shared strategy.
	// Uses set_config() with is_local=true so the setting is scoped to this transaction.
	if info.Strategy == StrategyShared {
		if _, err := tx.ExecContext(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", tenantID.String()); err != nil {
			_ = tx.Rollback()
			return nil, fmt.Errorf("failed to set tenant context: %w", err)
		}
	}

	return &TenantTx{
		Tx:       tx,
		tenantID: tenantID,
		strategy: info.Strategy,
	}, nil
}

// TenantID returns the tenant ID for this transaction
func (tx *TenantTx) TenantID() uuid.UUID {
	return tx.tenantID
}

// Strategy returns the isolation strategy
func (tx *TenantTx) Strategy() IsolationStrategy {
	return tx.strategy
}

// Tenant suspension, circuit breaker operations, pool stats, metrics, and
// enhanced connection manager are in tenant_connection_ops.go
