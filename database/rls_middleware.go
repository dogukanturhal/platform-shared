// SPDX-License-Identifier: Apache-2.0

// Package database provides RLS (Row Level Security) tenant-context helpers for PostgreSQL.
package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jmoiron/sqlx"
)

// setConfigLocalSQL uses set_config() instead of SET LOCAL because PostgreSQL's SET
// command does not support parameterized queries ($1) via the extended query
// protocol. pgx uses the extended protocol by default, causing SET $1 to fail
// silently.
//
// set_config(setting, value, is_local):
//   - is_local=false → session-scoped (like SET). REMOVED from this package: a
//     session-scoped setting is undefined behaviour under PgBouncer transaction
//     pooling (the default for every consumer of this package — see
//     the GitOps repository/environments/*/cnpg/manifests/pooler-example-app-pg.yaml).
//     Under transaction pooling a client's logical connection is rebound to a
//     different backend server connection per transaction/autocommit statement,
//     so a session-scoped set_config() has no guaranteed relationship to the
//     backend that serves the caller's NEXT statement. It can (a) not persist,
//     giving a fail-closed 0-row RLS result, or (b) persist on a backend that a
//     DIFFERENT tenant's request is subsequently assigned, giving a fail-open
//     cross-tenant data leak once RLS is enabled. There is no way to make
//     is_local=false safe here short of pinning one physical backend connection
//     per request outside the pooler, which defeats the pooler's purpose.
//   - is_local=true  → transaction-scoped (like SET LOCAL). This is the only safe
//     form under transaction pooling: the setting and the query that depends on
//     it are guaranteed to run against the same backend because they are the
//     same transaction. Every helper in this file uses this form exclusively.
const setConfigLocalSQL = "SELECT set_config('app.current_tenant_id', $1, true)"

// WithTenantContext wraps a database operation with RLS context using a transaction.
// Uses set_config with is_local=true so the setting is scoped to the transaction —
// the only form that is safe when the underlying connection is served through a
// PgBouncer transaction-mode pooler (see setConfigLocalSQL doc above). This is the
// canonical way to run tenant-scoped queries in this codebase: there is no
// request-scoped "RLS middleware" in this package, because a middleware that sets
// context on a connection ahead of the query that will actually use it cannot be
// made safe under transaction pooling (the query is not guaranteed to land on the
// same backend). Call this (or WithTenantContextSQLX / WithTenantContextPgx)
// directly from the repository method that runs the tenant-scoped query.
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

// WithTenantContextSQLX wraps a database operation with RLS context for sqlx.DB.
// See WithTenantContext for the transaction-pooling rationale.
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

// WithTenantContextPgx wraps a database operation with RLS context for pgxpool.
// See WithTenantContext for the transaction-pooling rationale.
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
// (transaction-scoped, via WithTenantContextSQLX) around every operation.
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
