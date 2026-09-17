// SPDX-License-Identifier: Apache-2.0

// Package database provides shared database connection pool configuration
// for all Go platform services. It supports both database/sql and pgxpool connections.
package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolConfig holds database connection pool parameters.
// Values can be loaded from environment variables or used with defaults.
type PoolConfig struct {
	// MaxOpenConns is the maximum number of open connections to the database.
	MaxOpenConns int

	// MaxIdleConns is the maximum number of idle connections in the pool.
	MaxIdleConns int

	// ConnMaxLifetime is the maximum amount of time a connection may be reused.
	ConnMaxLifetime time.Duration

	// ConnMaxIdleTime is the maximum amount of time a connection may be idle.
	ConnMaxIdleTime time.Duration

	// HealthCheckPeriod is the interval between health checks for pgxpool connections.
	HealthCheckPeriod time.Duration
}

// DefaultPoolConfig returns a PoolConfig with sensible defaults suitable
// for most platform services.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxOpenConns:      50,
		MaxIdleConns:      10,
		ConnMaxLifetime:   5 * time.Minute,
		ConnMaxIdleTime:   1 * time.Minute,
		HealthCheckPeriod: 1 * time.Minute,
	}
}

// LoadPoolConfig reads pool configuration from environment variables, falling
// back to defaults for any value not set. Environment variables:
//
//	DB_MAX_OPEN_CONNS    - maximum open connections (default: 50)
//	DB_MAX_IDLE_CONNS    - maximum idle connections (default: 10)
//	DB_CONN_MAX_LIFETIME - connection max lifetime (default: 5m)
//	DB_CONN_MAX_IDLE_TIME - connection max idle time (default: 1m)
//	DB_HEALTH_CHECK_PERIOD - health check period for pgxpool (default: 1m)
func LoadPoolConfig() PoolConfig {
	defaults := DefaultPoolConfig()

	return PoolConfig{
		MaxOpenConns:      getEnvInt("DB_MAX_OPEN_CONNS", defaults.MaxOpenConns),
		MaxIdleConns:      getEnvInt("DB_MAX_IDLE_CONNS", defaults.MaxIdleConns),
		ConnMaxLifetime:   getEnvDuration("DB_CONN_MAX_LIFETIME", defaults.ConnMaxLifetime),
		ConnMaxIdleTime:   getEnvDuration("DB_CONN_MAX_IDLE_TIME", defaults.ConnMaxIdleTime),
		HealthCheckPeriod: getEnvDuration("DB_HEALTH_CHECK_PERIOD", defaults.HealthCheckPeriod),
	}
}

// Apply configures the given *sql.DB connection pool with the values from
// this PoolConfig. This is used by services that connect via database/sql.
func (c PoolConfig) Apply(db *sql.DB) {
	db.SetMaxOpenConns(c.MaxOpenConns)
	db.SetMaxIdleConns(c.MaxIdleConns)
	db.SetConnMaxLifetime(c.ConnMaxLifetime)
	db.SetConnMaxIdleTime(c.ConnMaxIdleTime)
}

// ApplyToPgxPool configures the given *pgxpool.Config with the values from
// this PoolConfig. This is used by services that connect via pgxpool.
func (c PoolConfig) ApplyToPgxPool(config *pgxpool.Config) {
	config.MaxConns = int32(c.MaxOpenConns) //nolint:gosec // pool sizes are bounded
	config.MinConns = int32(c.MaxIdleConns) //nolint:gosec // pool sizes are bounded
	config.MaxConnLifetime = c.ConnMaxLifetime
	config.MaxConnIdleTime = c.ConnMaxIdleTime
	config.HealthCheckPeriod = c.HealthCheckPeriod
}

// String returns a human-readable summary of the pool configuration,
// useful for startup logging.
func (c PoolConfig) String() string {
	return fmt.Sprintf(
		"PoolConfig{MaxOpenConns: %d, MaxIdleConns: %d, ConnMaxLifetime: %s, ConnMaxIdleTime: %s, HealthCheckPeriod: %s}",
		c.MaxOpenConns,
		c.MaxIdleConns,
		c.ConnMaxLifetime,
		c.ConnMaxIdleTime,
		c.HealthCheckPeriod,
	)
}

// getEnvInt reads an integer from the named environment variable.
// If the variable is not set or cannot be parsed, the fallback value is returned.
func getEnvInt(key string, fallback int) int {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(val)
	if err != nil {
		log.Printf("WARNING: invalid integer for %s=%q, using default %d: %v", key, val, fallback, err) // #nosec G706 -- key is from a known env var name, not user-supplied input
		return fallback
	}

	return parsed
}

// getEnvDuration reads a time.Duration from the named environment variable.
// The value should be a string parseable by time.ParseDuration (e.g. "5m", "30s", "1h").
// If the variable is not set or cannot be parsed, the fallback value is returned.
func getEnvDuration(key string, fallback time.Duration) time.Duration {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}

	parsed, err := time.ParseDuration(val)
	if err != nil {
		log.Printf("WARNING: invalid duration for %s=%q, using default %s: %v", key, val, fallback, err) // #nosec G706 -- key is from a known env var name, not user-supplied input
		return fallback
	}

	return parsed
}
