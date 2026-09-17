// SPDX-License-Identifier: Apache-2.0

// Package database provides RLS (Row Level Security) middleware for PostgreSQL
package database

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/platform-shared/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jmoiron/sqlx"
)

// setConfigSQL uses set_config() instead of SET because PostgreSQL's SET command
// does not support parameterized queries ($1) via the extended query protocol.
// pgx uses the extended protocol by default, causing SET $1 to fail silently.
//
// set_config(setting, value, is_local):
//   - is_local=false → session-scoped (like SET)
//   - is_local=true  → transaction-scoped (like SET LOCAL)
const (
	setConfigSQL      = "SELECT set_config('app.current_tenant_id', $1, false)"
	setConfigLocalSQL = "SELECT set_config('app.current_tenant_id', $1, true)"
)

// RLSMiddleware creates a Gin middleware that sets app.current_tenant_id for PostgreSQL RLS.
// This middleware MUST be applied AFTER auth middleware OR tenant extractor middleware.
//
// CRITICAL: For each request with a tenant_id in context (from JWT or X-Tenant-ID header),
// this middleware acquires a connection and executes:
//
//	SELECT set_config('app.current_tenant_id', '<tenant_uuid>', false)
//
// This is REQUIRED for Row Level Security (RLS) policies that filter by:
//
//	tenant_id = current_setting('app.current_tenant_id', true)::UUID
//
// WITHOUT this middleware, RLS policies will block ALL rows, causing 0-row queries.
//
// Usage:
//
//	router.Use(authMiddleware.RequireAuth())
//	router.Use(database.RLSMiddleware(db))
//	router.POST("/api/resource", handler.Create)
//
// Supports: *sql.DB, *sqlx.DB, *pgxpool.Pool
func RLSMiddleware(db interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract tenant ID from context (set by auth middleware or TenantExtractor)
		tenantIDVal, exists := c.Get(auth.TenantIDKey)
		if !exists {
			// Try alternate key "tenant_id" (used by some services)
			tenantIDVal, exists = c.Get("tenant_id")
			if !exists {
				// No tenant ID - skip RLS setting (for system-level/public endpoints)
				c.Next()
				return
			}
		}

		tenantID, ok := tenantIDVal.(uuid.UUID)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Invalid tenant ID type in context",
			})
			return
		}

		// Skip nil UUID (system context)
		if tenantID == uuid.Nil {
			c.Next()
			return
		}

		// Set tenant context on the database connection
		// IMPORTANT: We must acquire a connection for the request lifecycle
		var err error
		switch v := db.(type) {
		case *sql.DB:
			conn, connErr := v.Conn(c.Request.Context())
			if connErr != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to acquire database connection",
				})
				return
			}
			defer func() { _ = conn.Close() }()

			_, err = conn.ExecContext(c.Request.Context(), setConfigSQL, tenantID.String())
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to set tenant context for RLS",
				})
				return
			}
			c.Set("db_conn", conn)

		case *sqlx.DB:
			conn, connErr := v.Conn(c.Request.Context())
			if connErr != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to acquire database connection",
				})
				return
			}
			defer func() { _ = conn.Close() }()

			_, err = conn.ExecContext(c.Request.Context(), setConfigSQL, tenantID.String())
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to set tenant context for RLS",
				})
				return
			}
			c.Set("db_conn", conn)

		case *pgxpool.Pool:
			conn, connErr := v.Acquire(c.Request.Context())
			if connErr != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to acquire database connection",
				})
				return
			}
			defer conn.Release()

			_, err = conn.Exec(c.Request.Context(), setConfigSQL, tenantID.String())
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to set tenant context for RLS",
				})
				return
			}
			c.Set("pgx_conn", conn)

		default:
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Unsupported database type for RLS middleware",
			})
			return
		}

		c.Next()
	}
}

// RLSMiddlewarePgxPool creates RLS middleware specifically for pgxpool.Pool
// This is a convenience function for services using pgx
func RLSMiddlewarePgxPool(pool *pgxpool.Pool) gin.HandlerFunc {
	return RLSMiddleware(pool)
}

// SetRLSContext sets app.current_tenant_id on a sql.DB connection for RLS
// Uses set_config with is_local=true for transaction-scoped setting
func SetRLSContext(ctx context.Context, db *sql.DB, tenantID uuid.UUID) error {
	_, err := db.ExecContext(ctx, setConfigLocalSQL, tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set app.current_tenant_id: %w", err)
	}
	return nil
}

// SetRLSContextSQLX sets app.current_tenant_id on a sqlx.DB connection for RLS
func SetRLSContextSQLX(ctx context.Context, db *sqlx.DB, tenantID uuid.UUID) error {
	_, err := db.ExecContext(ctx, setConfigLocalSQL, tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set app.current_tenant_id: %w", err)
	}
	return nil
}

// SetRLSContextPgx sets app.current_tenant_id on a pgxpool connection for RLS
func SetRLSContextPgx(ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID) error {
	_, err := pool.Exec(ctx, setConfigLocalSQL, tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set app.current_tenant_id: %w", err)
	}
	return nil
}

// WithTenantContext wraps a database operation with RLS context using a transaction.
// Use this in repositories when RLS middleware is not available (e.g., background jobs).
// Uses set_config with is_local=true so the setting is scoped to the transaction.
//
// Example:
//
//	err := database.WithTenantContext(ctx, r.db, tenantID, func(tx *sql.Tx) error {
//	    return tx.QueryRowContext(ctx, "SELECT * FROM table WHERE id = $1", id).Scan(&result)
//	})
func WithTenantContext(ctx context.Context, db *sql.DB, tenantID uuid.UUID, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, setConfigLocalSQL, tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set app.current_tenant_id: %w", err)
	}

	if err := fn(tx); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// WithTenantContextSQLX wraps a database operation with RLS context for sqlx.DB
func WithTenantContextSQLX(ctx context.Context, db *sqlx.DB, tenantID uuid.UUID, fn func(tx *sqlx.Tx) error) error {
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, setConfigLocalSQL, tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set app.current_tenant_id: %w", err)
	}

	if err := fn(tx); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// WithTenantContextPgx wraps a database operation with RLS context for pgxpool
func WithTenantContextPgx(ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID, fn func(tx pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, setConfigLocalSQL, tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set app.current_tenant_id: %w", err)
	}

	if err := fn(tx); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// TenantAwareDB wraps a database connection and automatically sets RLS context
type TenantAwareDB struct {
	db       *sqlx.DB
	tenantID uuid.UUID
}

// NewTenantAwareDB creates a database wrapper that automatically sets RLS context
func NewTenantAwareDB(db *sqlx.DB, tenantID uuid.UUID) *TenantAwareDB {
	return &TenantAwareDB{
		db:       db,
		tenantID: tenantID,
	}
}

// Exec executes a query with tenant context set
func (t *TenantAwareDB) Exec(query string, args ...interface{}) (sql.Result, error) {
	var result sql.Result
	err := WithTenantContextSQLX(context.Background(), t.db, t.tenantID, func(tx *sqlx.Tx) error {
		var execErr error
		result, execErr = tx.ExecContext(context.Background(), query, args...)
		return execErr
	})
	return result, err
}

// ExecContext executes a query with tenant context set
func (t *TenantAwareDB) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	var result sql.Result
	err := WithTenantContextSQLX(ctx, t.db, t.tenantID, func(tx *sqlx.Tx) error {
		var execErr error
		result, execErr = tx.ExecContext(ctx, query, args...)
		return execErr
	})
	return result, err
}

// Query executes a query with tenant context set
func (t *TenantAwareDB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	var rows *sql.Rows
	err := WithTenantContextSQLX(context.Background(), t.db, t.tenantID, func(tx *sqlx.Tx) error {
		var queryErr error
		rows, queryErr = tx.QueryContext(context.Background(), query, args...)
		return queryErr
	})
	return rows, err
}

// QueryContext executes a query with tenant context set
func (t *TenantAwareDB) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	var rows *sql.Rows
	err := WithTenantContextSQLX(ctx, t.db, t.tenantID, func(tx *sqlx.Tx) error {
		var queryErr error
		rows, queryErr = tx.QueryContext(ctx, query, args...)
		return queryErr
	})
	return rows, err
}

// Get executes a GET query with tenant context (sqlx specific)
func (t *TenantAwareDB) Get(dest interface{}, query string, args ...interface{}) error {
	return WithTenantContextSQLX(context.Background(), t.db, t.tenantID, func(tx *sqlx.Tx) error {
		return tx.Get(dest, query, args...)
	})
}

// GetContext executes a GET query with tenant context (sqlx specific)
func (t *TenantAwareDB) GetContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
	return WithTenantContextSQLX(ctx, t.db, t.tenantID, func(tx *sqlx.Tx) error {
		return tx.GetContext(ctx, dest, query, args...)
	})
}

// Select executes a SELECT query with tenant context (sqlx specific)
func (t *TenantAwareDB) Select(dest interface{}, query string, args ...interface{}) error {
	return WithTenantContextSQLX(context.Background(), t.db, t.tenantID, func(tx *sqlx.Tx) error {
		return tx.Select(dest, query, args...)
	})
}

// SelectContext executes a SELECT query with tenant context (sqlx specific)
func (t *TenantAwareDB) SelectContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
	return WithTenantContextSQLX(ctx, t.db, t.tenantID, func(tx *sqlx.Tx) error {
		return tx.SelectContext(ctx, dest, query, args...)
	})
}
