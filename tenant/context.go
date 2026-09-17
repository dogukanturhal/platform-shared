// SPDX-License-Identifier: Apache-2.0

// Package tenant provides reusable tenant-context primitives for HexxLock business
// modules.  It extracts the SET LOCAL pattern that Row Level Security (RLS) policies
// depend on into a standalone library so that services such as CRM, HR, Finance, etc.
// can enforce tenant isolation without importing anything from falcon-id.
//
// Typical usage in a repository layer (background job or test helper):
//
//	err := tenant.WithTenantSQLX(ctx, db, tenantID, func(tx *sqlx.Tx) error {
//	    return tx.GetContext(ctx, &record, "SELECT * FROM crm.contacts WHERE id = $1", id)
//	})
//
// For HTTP handlers the Gin middleware wrappers in gin_middleware.go are more ergonomic.
package tenant

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

// Context key constants shared across gin middleware, repository helpers, and
// service-to-service HTTP calls.  The values deliberately match the keys used by
// the shared auth package so that both sources of tenant identity are interchangeable.
const (
	// TenantIDKey is the gin.Context / standard-context key for the tenant UUID.
	TenantIDKey = "tenant_id"
	// RealmIDKey is the gin.Context / standard-context key for the realm UUID.
	RealmIDKey = "realm_id"
)

// stdContextKey is an unexported type used as a key in standard context.Context to
// prevent collisions with third-party packages that also store values by string.
type stdContextKey string

const (
	tenantIDCtxKey stdContextKey = TenantIDKey
	realmIDCtxKey  stdContextKey = RealmIDKey
)

// Execer is the minimal database interface satisfied by *sql.DB, *sql.Conn,
// *sql.Tx, *sqlx.DB, and *sqlx.Tx.  Accept this interface in repository helpers
// rather than concrete types so callers can pass either a plain connection or a
// transaction without code changes.
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

// SetLocalTenant executes:
//
//	SET LOCAL app.current_tenant_id = '<tenantID>'
//
// on the provided execer.  SET LOCAL scopes the GUC to the current transaction,
// which is the correct isolation unit for RLS policies.  If tenantID is uuid.Nil
// the call is a no-op so that system-level contexts (no tenant) pass through safely.
//
// The execer must be a connection or transaction that is already inside an open
// transaction; SET LOCAL has no effect outside a transaction block.
func SetLocalTenant(ctx context.Context, execer Execer, tenantID uuid.UUID) error {
	if tenantID == uuid.Nil {
		return nil
	}
	if _, err := execer.ExecContext(ctx, "SET LOCAL app.current_tenant_id = $1", tenantID.String()); err != nil {
		return fmt.Errorf("tenant: failed to SET LOCAL app.current_tenant_id: %w", err)
	}
	return nil
}

// SetLocalRealm executes:
//
//	SET LOCAL app.current_realm_id = '<realmID>'
//
// on the provided execer.  This is optional; only call it when RLS policies also
// filter on realm.  If realmID is uuid.Nil the call is a no-op.
func SetLocalRealm(ctx context.Context, execer Execer, realmID uuid.UUID) error {
	if realmID == uuid.Nil {
		return nil
	}
	if _, err := execer.ExecContext(ctx, "SET LOCAL app.current_realm_id = $1", realmID.String()); err != nil {
		return fmt.Errorf("tenant: failed to SET LOCAL app.current_realm_id: %w", err)
	}
	return nil
}

// WithTenantSQL wraps fn in a *sql.Tx with SET LOCAL applied for RLS.  It commits
// on success and rolls back on any error returned by fn or by the SET LOCAL calls.
// The optional realmID variadic accepts at most one value; subsequent values are ignored.
func WithTenantSQL(ctx context.Context, db *sql.DB, tenantID uuid.UUID, fn func(tx *sql.Tx) error, realmID ...uuid.UUID) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("tenant: begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback error is intentionally ignored after commit

	if err := SetLocalTenant(ctx, tx, tenantID); err != nil {
		return err
	}
	if len(realmID) > 0 {
		if err := SetLocalRealm(ctx, tx, realmID[0]); err != nil {
			return err
		}
	}

	if err := fn(tx); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("tenant: commit transaction: %w", err)
	}
	return nil
}

// ContextWithTenantID stores tenantID in a standard context.Context so it can be
// threaded through non-HTTP code paths (background workers, gRPC handlers, etc.).
// Retrieve it with TenantIDFromContext.
func ContextWithTenantID(ctx context.Context, tenantID uuid.UUID) context.Context {
	return context.WithValue(ctx, tenantIDCtxKey, tenantID)
}

// ContextWithRealmID stores realmID in a standard context.Context.
// Retrieve it with RealmIDFromContext.
func ContextWithRealmID(ctx context.Context, realmID uuid.UUID) context.Context {
	return context.WithValue(ctx, realmIDCtxKey, realmID)
}

// TenantIDFromContext retrieves the tenant UUID stored by ContextWithTenantID.
// Returns uuid.Nil, false when no value is present.
func TenantIDFromContext(ctx context.Context) (uuid.UUID, bool) { //nolint:revive // public API stability
	v := ctx.Value(tenantIDCtxKey)
	if v == nil {
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok && id != uuid.Nil
}

// RealmIDFromContext retrieves the realm UUID stored by ContextWithRealmID.
// Returns uuid.Nil, false when no value is present.
func RealmIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	v := ctx.Value(realmIDCtxKey)
	if v == nil {
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok && id != uuid.Nil
}
