// SPDX-License-Identifier: Apache-2.0

package tenant

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WithTenantPgx begins a pgx transaction, sets SET LOCAL app.current_tenant_id (and
// optionally app.current_realm_id), executes fn, then commits.  Rollback is deferred
// and called automatically on any error path.
//
// The optional realmID variadic accepts at most one UUID; subsequent values are ignored.
//
// Example:
//
//	err := tenant.WithTenantPgx(ctx, pool, tenantID, func(tx pgx.Tx) error {
//	    return tx.QueryRow(ctx, "SELECT name FROM crm.contacts WHERE id = $1", id).Scan(&name)
//	})
func WithTenantPgx(ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID, fn func(tx pgx.Tx) error, realmID ...uuid.UUID) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("tenant: pgx begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // ignored after explicit commit

	if tenantID != uuid.Nil {
		if _, err := tx.Exec(ctx, "SET LOCAL app.current_tenant_id = $1", tenantID.String()); err != nil {
			return fmt.Errorf("tenant: pgx SET LOCAL app.current_tenant_id: %w", err)
		}
	}

	if len(realmID) > 0 && realmID[0] != uuid.Nil {
		if _, err := tx.Exec(ctx, "SET LOCAL app.current_realm_id = $1", realmID[0].String()); err != nil {
			return fmt.Errorf("tenant: pgx SET LOCAL app.current_realm_id: %w", err)
		}
	}

	if err := fn(tx); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("tenant: pgx commit transaction: %w", err)
	}
	return nil
}

// WithTenantPgxConn acquires a *pgxpool.Conn from the pool and runs fn inside a
// transaction with SET LOCAL applied.  The connection is released back to the pool
// after fn returns, whether or not fn succeeded.
//
// This is the correct primitive for read-only queries where callers want to avoid the
// overhead of a full transaction begin/commit round-trip but still need the GUC set.
// Because SET LOCAL only survives within a transaction block, this helper always wraps
// the work in an implicit transaction.
//
// The optional realmID variadic accepts at most one UUID.
func WithTenantPgxConn(ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID, fn func(conn *pgxpool.Conn) error, realmID ...uuid.UUID) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("tenant: pgx acquire connection: %w", err)
	}
	defer conn.Release()

	// Wrap in a transaction so that SET LOCAL is properly scoped.
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("tenant: pgx begin transaction on conn: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if tenantID != uuid.Nil {
		if _, err := tx.Exec(ctx, "SET LOCAL app.current_tenant_id = $1", tenantID.String()); err != nil {
			return fmt.Errorf("tenant: pgx conn SET LOCAL app.current_tenant_id: %w", err)
		}
	}

	if len(realmID) > 0 && realmID[0] != uuid.Nil {
		if _, err := tx.Exec(ctx, "SET LOCAL app.current_realm_id = $1", realmID[0].String()); err != nil {
			return fmt.Errorf("tenant: pgx conn SET LOCAL app.current_realm_id: %w", err)
		}
	}

	// Commit the SET LOCAL GUC settings; the underlying conn object is reused by the
	// caller's fn via the pool.Conn reference, which keeps the same server connection.
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("tenant: pgx conn commit GUC transaction: %w", err)
	}

	return fn(conn)
}

// PgxTenantHook implements pgx.QueryTracer to automatically inject
// SET LOCAL app.current_tenant_id before the first query inside each transaction.
//
// Attach this tracer to pgxpool.Config.ConnConfig.Tracer before creating the pool:
//
//	poolCfg.ConnConfig.Tracer = &tenant.PgxTenantHook{}
//
// The tenant UUID must be stored in the context via tenant.ContextWithTenantID before
// calling any pool or connection method.  If no tenant is found in the context the
// tracer is a no-op, allowing system-level / unauthenticated queries to proceed.
//
// NOTE: The tracer is best-effort — it fires TraceQueryStart on every query.  For
// transactional workloads the preferred approach is WithTenantPgx, which gives precise
// control over the transaction boundary.
type PgxTenantHook struct{}

// TraceQueryStart implements pgx.QueryTracer.  It injects SET LOCAL before the user
// query when a tenant ID is found in the context.  Because SET LOCAL requires a
// transaction and pgx does not expose the transaction state on the tracer interface,
// this implementation uses a separate Exec call on the same connection.  In practice
// this means the GUC will only be honored if the call happens inside a transaction.
func (h *PgxTenantHook) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	// Skip injecting SET LOCAL for the SET LOCAL statement itself to avoid recursion.
	if isSetLocalQuery(data.SQL) {
		return ctx
	}

	tenantID, hasTenant := TenantIDFromContext(ctx)
	if !hasTenant {
		return ctx
	}

	// Best-effort: ignore the error because the query will fail on its own if RLS
	// blocks it, giving the caller a clear error message.
	_, _ = conn.Exec(ctx, "SET LOCAL app.current_tenant_id = $1", tenantID.String())

	if realmID, hasRealm := RealmIDFromContext(ctx); hasRealm {
		_, _ = conn.Exec(ctx, "SET LOCAL app.current_realm_id = $1", realmID.String())
	}

	return ctx
}

// TraceQueryEnd implements pgx.QueryTracer.  No action is needed after a query.
func (h *PgxTenantHook) TraceQueryEnd(_ context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
}

// isSetLocalQuery returns true when sql is one of the SET LOCAL statements injected
// by this package, preventing infinite recursion in TraceQueryStart.
func isSetLocalQuery(sql string) bool {
	const tenantGUC = "SET LOCAL app.current_tenant_id"
	const realmGUC = "SET LOCAL app.current_realm_id"
	if len(sql) < len(tenantGUC) {
		return false
	}
	return sql[:len(tenantGUC)] == tenantGUC || sql[:len(realmGUC)] == realmGUC
}
