// SPDX-License-Identifier: Apache-2.0

// Package database provides multi-tenant database connection management for Go services.
// This file contains tenant suspension, circuit breaker operations, pool stats,
// metrics, and the enhanced connection manager with health checking.
package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// ============================================
// ENHANCED METHODS FOR CIRCUIT BREAKER AND SUSPENSION
// ============================================

// SuspendTenant marks a tenant as suspended, blocking all connection attempts
func (m *TenantConnectionManager) SuspendTenant(ctx context.Context, tenantID uuid.UUID) error {
	m.suspendedMap.Store(tenantID, true)

	// Close existing connection if any
	if err := m.InvalidateCache(ctx, tenantID); err != nil {
		return fmt.Errorf("failed to invalidate cache: %w", err)
	}

	// Open circuit breaker
	if m.circuitBreaker != nil {
		m.circuitBreaker.GetBreaker(tenantID).ForceOpen()
	}

	return nil
}

// ResumeTenant removes suspension for a tenant
func (m *TenantConnectionManager) ResumeTenant(_ context.Context, tenantID uuid.UUID) error {
	m.suspendedMap.Delete(tenantID)

	// Reset circuit breaker
	if m.circuitBreaker != nil {
		m.circuitBreaker.GetBreaker(tenantID).Reset()
	}

	return nil
}

// IsTenantSuspended checks if a tenant is suspended
func (m *TenantConnectionManager) IsTenantSuspended(tenantID uuid.UUID) bool {
	if suspended, ok := m.suspendedMap.Load(tenantID); ok {
		return suspended.(bool)
	}
	return false
}

// EvictPool removes a tenant's connection pool from cache without closing it
func (m *TenantConnectionManager) EvictPool(_ context.Context, tenantID uuid.UUID) error {
	if pool, ok := m.pools.LoadAndDelete(tenantID); ok {
		db := pool.(*sql.DB)
		// Don't close master DB
		if db != m.masterDB {
			return db.Close()
		}
	}
	return nil
}

// GetCircuitBreakerStats returns circuit breaker statistics for a tenant
func (m *TenantConnectionManager) GetCircuitBreakerStats(tenantID uuid.UUID) *CircuitBreakerStats {
	if m.circuitBreaker == nil {
		return nil
	}
	stats := m.circuitBreaker.GetBreaker(tenantID).GetStats()
	return &stats
}

// GetAllCircuitBreakerStats returns statistics for all circuit breakers
func (m *TenantConnectionManager) GetAllCircuitBreakerStats() []CircuitBreakerStats {
	if m.circuitBreaker == nil {
		return nil
	}
	return m.circuitBreaker.GetAllStats()
}

// ResetCircuitBreaker resets the circuit breaker for a tenant
func (m *TenantConnectionManager) ResetCircuitBreaker(tenantID uuid.UUID) {
	if m.circuitBreaker != nil {
		m.circuitBreaker.GetBreaker(tenantID).Reset()
	}
}

// ResetAllCircuitBreakers resets all circuit breakers
func (m *TenantConnectionManager) ResetAllCircuitBreakers() {
	if m.circuitBreaker != nil {
		m.circuitBreaker.ResetAll()
	}
}

// GetCircuitState returns the circuit state for a tenant
func (m *TenantConnectionManager) GetCircuitState(tenantID uuid.UUID) CircuitState {
	if m.circuitBreaker == nil {
		return CircuitClosed
	}
	return m.circuitBreaker.GetBreaker(tenantID).State()
}

// RecordConnectionFailure manually records a connection failure
func (m *TenantConnectionManager) RecordConnectionFailure(tenantID uuid.UUID) {
	if m.circuitBreaker != nil {
		m.circuitBreaker.GetBreaker(tenantID).RecordFailure()
	}
}

// RecordConnectionSuccess manually records a connection success
func (m *TenantConnectionManager) RecordConnectionSuccess(tenantID uuid.UUID) {
	if m.circuitBreaker != nil {
		m.circuitBreaker.GetBreaker(tenantID).RecordSuccess()
	}
}

// GetPoolStats returns connection pool statistics for a tenant
func (m *TenantConnectionManager) GetPoolStats(tenantID uuid.UUID) *sql.DBStats {
	if pool, ok := m.pools.Load(tenantID); ok {
		db := pool.(*sql.DB)
		stats := db.Stats()
		return &stats
	}
	return nil
}

// GetAllPoolStats returns connection pool statistics for all tenants
func (m *TenantConnectionManager) GetAllPoolStats() map[uuid.UUID]*sql.DBStats {
	stats := make(map[uuid.UUID]*sql.DBStats)
	m.pools.Range(func(key, value interface{}) bool {
		tenantID := key.(uuid.UUID)
		db := value.(*sql.DB)
		s := db.Stats()
		stats[tenantID] = &s
		return true
	})
	return stats
}

// ConnectionManagerMetrics holds metrics for the connection manager
type ConnectionManagerMetrics struct {
	TotalPools       int                     `json:"total_pools"`
	SuspendedTenants int                     `json:"suspended_tenants"`
	CircuitBreakers  []CircuitBreakerStats   `json:"circuit_breakers,omitempty"`
	PoolStats        map[string]*sql.DBStats `json:"pool_stats,omitempty"`
}

// GetMetrics returns overall metrics for the connection manager
func (m *TenantConnectionManager) GetMetrics() *ConnectionManagerMetrics {
	metrics := &ConnectionManagerMetrics{
		CircuitBreakers: m.GetAllCircuitBreakerStats(),
		PoolStats:       make(map[string]*sql.DBStats),
	}

	// Count pools
	m.pools.Range(func(key, value interface{}) bool {
		metrics.TotalPools++
		tenantID := key.(uuid.UUID)
		db := value.(*sql.DB)
		stats := db.Stats()
		metrics.PoolStats[tenantID.String()] = &stats
		return true
	})

	// Count suspended tenants
	m.suspendedMap.Range(func(_, value interface{}) bool {
		if suspended := value.(bool); suspended {
			metrics.SuspendedTenants++
		}
		return true
	})

	return metrics
}

// EnhancedTenantConnectionManager extends TenantConnectionManager with additional features
type EnhancedTenantConnectionManager struct {
	*TenantConnectionManager
	healthChecker *HealthChecker
}

// NewEnhancedTenantConnectionManager creates an enhanced connection manager
func NewEnhancedTenantConnectionManager(
	masterDB *sql.DB,
	masterDSN string,
	redis *redis.Client,
	config ConnectionConfig,
	cbConfig CircuitBreakerConfig,
	healthConfig HealthCheckerConfig,
) *EnhancedTenantConnectionManager {
	tcm := NewTenantConnectionManagerWithCircuitBreaker(masterDB, masterDSN, redis, config, cbConfig)
	healthChecker := NewHealthChecker(tcm, healthConfig)

	return &EnhancedTenantConnectionManager{
		TenantConnectionManager: tcm,
		healthChecker:           healthChecker,
	}
}

// StartHealthChecker starts the background health checker
func (m *EnhancedTenantConnectionManager) StartHealthChecker(ctx context.Context) {
	if m.healthChecker != nil {
		m.healthChecker.Start(ctx)
	}
}

// StopHealthChecker stops the background health checker
func (m *EnhancedTenantConnectionManager) StopHealthChecker() {
	if m.healthChecker != nil {
		m.healthChecker.Stop()
	}
}

// GetHealthChecker returns the health checker instance
func (m *EnhancedTenantConnectionManager) GetHealthChecker() *HealthChecker {
	return m.healthChecker
}

// RegisterTenantForHealthCheck registers a tenant for health monitoring
func (m *EnhancedTenantConnectionManager) RegisterTenantForHealthCheck(tenantID uuid.UUID) {
	if m.healthChecker != nil {
		m.healthChecker.RegisterTenant(tenantID)
	}
}

// UnregisterTenantFromHealthCheck removes a tenant from health monitoring
func (m *EnhancedTenantConnectionManager) UnregisterTenantFromHealthCheck(tenantID uuid.UUID) {
	if m.healthChecker != nil {
		m.healthChecker.UnregisterTenant(tenantID)
	}
}

// GetTenantHealthStatus returns the health status for a tenant
func (m *EnhancedTenantConnectionManager) GetTenantHealthStatus(tenantID uuid.UUID) *HealthCheckResult {
	if m.healthChecker != nil {
		return m.healthChecker.GetHealthStatus(tenantID)
	}
	return nil
}

// PerformHealthCheck performs an immediate health check for a tenant
func (m *EnhancedTenantConnectionManager) PerformHealthCheck(ctx context.Context, tenantID uuid.UUID) (*HealthCheckResult, error) {
	if m.healthChecker != nil {
		return m.healthChecker.ForceHealthCheck(ctx, tenantID)
	}
	return nil, fmt.Errorf("health checker not initialized")
}
