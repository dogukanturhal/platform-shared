// SPDX-License-Identifier: Apache-2.0

// Package database provides multi-tenant and multi-database connection management.
// This file implements control plane / data plane database separation.
package database

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq" // PostgreSQL driver
)

// MultiDBConfig holds configuration for dual database connections
type MultiDBConfig struct {
	// ControlPlaneURL is the connection string for the control plane database
	// This database contains: packages, modules catalog, resource tiers, payment configs
	ControlPlaneURL string

	// DataPlaneURL is the connection string for the data plane database
	// This database contains: tenant subscriptions, tenant modules, billing history
	DataPlaneURL string

	// Connection pool settings
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// DefaultMultiDBConfig returns sensible defaults for database configuration
func DefaultMultiDBConfig() MultiDBConfig {
	return MultiDBConfig{
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: 5 * time.Minute,
		ConnMaxIdleTime: 1 * time.Minute,
	}
}

// MultiDBManager manages connections to both control plane and data plane databases
type MultiDBManager struct {
	controlPlane *sqlx.DB
	dataPlane    *sqlx.DB
	config       MultiDBConfig
}

// NewMultiDBManager creates a new multi-database manager
// If controlPlaneURL is empty, it falls back to using dataPlaneURL for both
func NewMultiDBManager(cfg MultiDBConfig) (*MultiDBManager, error) {
	m := &MultiDBManager{
		config: cfg,
	}

	// Connect to data plane (required)
	if cfg.DataPlaneURL == "" {
		return nil, fmt.Errorf("DataPlaneURL is required")
	}

	dataDB, err := sqlx.Connect("postgres", cfg.DataPlaneURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to data plane database: %w", err)
	}
	m.configureDB(dataDB)
	m.dataPlane = dataDB
	log.Println("Connected to data plane database")

	// Connect to control plane (optional - falls back to data plane)
	if cfg.ControlPlaneURL != "" && cfg.ControlPlaneURL != cfg.DataPlaneURL {
		controlDB, err := sqlx.Connect("postgres", cfg.ControlPlaneURL)
		if err != nil {
			// Log warning but don't fail - fall back to data plane
			log.Printf("Warning: Failed to connect to control plane database: %v. Using data plane as fallback.", err)
			m.controlPlane = dataDB
		} else {
			m.configureDB(controlDB)
			m.controlPlane = controlDB
			log.Println("Connected to control plane database")
		}
	} else {
		// No control plane URL specified, use data plane for both
		m.controlPlane = dataDB
		log.Println("Using data plane database for control plane operations (fallback mode)")
	}

	return m, nil
}

// configureDB applies connection pool settings to a database
func (m *MultiDBManager) configureDB(db *sqlx.DB) {
	if m.config.MaxOpenConns > 0 {
		db.SetMaxOpenConns(m.config.MaxOpenConns)
	}
	if m.config.MaxIdleConns > 0 {
		db.SetMaxIdleConns(m.config.MaxIdleConns)
	}
	if m.config.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(m.config.ConnMaxLifetime)
	}
	if m.config.ConnMaxIdleTime > 0 {
		db.SetConnMaxIdleTime(m.config.ConnMaxIdleTime)
	}
}

// ControlPlane returns the control plane database connection
// Use this for: packages, modules catalog, resource tiers, addon products, payment provider configs
func (m *MultiDBManager) ControlPlane() *sqlx.DB {
	return m.controlPlane
}

// DataPlane returns the data plane database connection
// Use this for: tenant subscriptions, tenant modules, billing history, tenant data
func (m *MultiDBManager) DataPlane() *sqlx.DB {
	return m.dataPlane
}

// HealthCheck verifies both database connections are healthy
func (m *MultiDBManager) HealthCheck(ctx context.Context) error {
	// Check data plane
	if err := m.dataPlane.PingContext(ctx); err != nil {
		return fmt.Errorf("data plane database unhealthy: %w", err)
	}

	// Check control plane (if different from data plane)
	if m.controlPlane != m.dataPlane {
		if err := m.controlPlane.PingContext(ctx); err != nil {
			return fmt.Errorf("control plane database unhealthy: %w", err)
		}
	}

	return nil
}

// Close closes all database connections
func (m *MultiDBManager) Close() error {
	var lastErr error

	// Close data plane
	if err := m.dataPlane.Close(); err != nil {
		lastErr = fmt.Errorf("failed to close data plane connection: %w", err)
	}

	// Close control plane (if different from data plane)
	if m.controlPlane != m.dataPlane {
		if err := m.controlPlane.Close(); err != nil {
			lastErr = fmt.Errorf("failed to close control plane connection: %w", err)
		}
	}

	return lastErr
}

// IsSeparated returns true if control plane and data plane are separate databases
func (m *MultiDBManager) IsSeparated() bool {
	return m.controlPlane != m.dataPlane
}

// Stats returns connection pool statistics for both databases
func (m *MultiDBManager) Stats() MultiDBStats {
	stats := MultiDBStats{
		DataPlane: m.dataPlane.Stats(),
	}

	if m.controlPlane != m.dataPlane {
		stats.ControlPlane = m.controlPlane.Stats()
		stats.IsSeparated = true
	} else {
		stats.ControlPlane = stats.DataPlane
		stats.IsSeparated = false
	}

	return stats
}

// MultiDBStats holds statistics for both database connections
type MultiDBStats struct {
	ControlPlane interface{} // sql.DBStats
	DataPlane    interface{} // sql.DBStats
	IsSeparated  bool
}

// BeginControlPlaneTx begins a transaction on the control plane database
func (m *MultiDBManager) BeginControlPlaneTx(ctx context.Context) (*sqlx.Tx, error) {
	return m.controlPlane.BeginTxx(ctx, nil)
}

// BeginDataPlaneTx begins a transaction on the data plane database
func (m *MultiDBManager) BeginDataPlaneTx(ctx context.Context) (*sqlx.Tx, error) {
	return m.dataPlane.BeginTxx(ctx, nil)
}

// WithControlPlane executes a function with the control plane database
func (m *MultiDBManager) WithControlPlane(fn func(db *sqlx.DB) error) error {
	return fn(m.controlPlane)
}

// WithDataPlane executes a function with the data plane database
func (m *MultiDBManager) WithDataPlane(fn func(db *sqlx.DB) error) error {
	return fn(m.dataPlane)
}

// WithBoth executes a function that needs both databases
// The function receives control plane first, then data plane
func (m *MultiDBManager) WithBoth(fn func(controlDB, dataDB *sqlx.DB) error) error {
	return fn(m.controlPlane, m.dataPlane)
}

// MustNewMultiDBManager creates a new manager or uses log.Fatal on error.
// Useful for application startup where failure should terminate the process.
func MustNewMultiDBManager(cfg MultiDBConfig) *MultiDBManager {
	m, err := NewMultiDBManager(cfg)
	if err != nil {
		log.Fatalf("failed to create multi-db manager: %v", err)
	}
	return m
}

// NewMultiDBManagerFromEnv creates a MultiDBManager from common environment variable names
// controlPlaneEnvKey: environment variable name for control plane URL (e.g., "CONTROL_PLANE_DB_URL")
// dataPlaneEnvKey: environment variable name for data plane URL (e.g., "DATABASE_URL")
func NewMultiDBManagerFromEnv(controlPlaneURL, dataPlaneURL string) (*MultiDBManager, error) {
	cfg := DefaultMultiDBConfig()
	cfg.ControlPlaneURL = controlPlaneURL
	cfg.DataPlaneURL = dataPlaneURL
	return NewMultiDBManager(cfg)
}
