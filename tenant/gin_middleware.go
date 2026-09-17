// SPDX-License-Identifier: Apache-2.0

package tenant

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jmoiron/sqlx"
)

// Header name used for service-to-service calls that pass the tenant identity
// without a full JWT (e.g. internal background workers, cron jobs).
const headerXTenantID = "X-Tenant-ID"

// --- Tenant ID extraction --------------------------------------------------

// ExtractTenantID is a Gin middleware that attempts to populate TenantIDKey in the
// gin context from the following sources, in priority order:
//
//  1. An existing TenantIDKey value already set by upstream auth middleware (e.g.
//     the shared/auth JWT middleware, which stores tenant_id from JWT claims).
//  2. The X-Tenant-ID HTTP header (for internal service-to-service calls that do
//     not carry a full JWT).
//
// The middleware is intentionally lenient: if neither source provides a valid UUID
// it simply calls c.Next() without aborting.  Use RequireTenantID when the endpoint
// must have a tenant.
func ExtractTenantID() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Fast path: upstream auth middleware already set tenant_id.
		if _, exists := c.Get(TenantIDKey); exists {
			c.Next()
			return
		}

		// Slow path: check header (internal service-to-service calls).
		headerVal := c.GetHeader(headerXTenantID)
		if headerVal != "" {
			if id, err := uuid.Parse(headerVal); err == nil && id != uuid.Nil {
				c.Set(TenantIDKey, id)
			}
		}

		c.Next()
	}
}

// RequireTenantID is like ExtractTenantID but aborts with HTTP 400 Bad Request if
// a valid, non-nil tenant UUID is not available after extraction.
func RequireTenantID() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try to extract first (same logic as ExtractTenantID).
		if _, exists := c.Get(TenantIDKey); !exists {
			headerVal := c.GetHeader(headerXTenantID)
			if headerVal != "" {
				if id, err := uuid.Parse(headerVal); err == nil && id != uuid.Nil {
					c.Set(TenantIDKey, id)
				}
			}
		}

		if _, ok := GetTenantID(c); !ok {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "tenant_id is required but was not provided",
				"code":  "TENANT_ID_MISSING",
			})
			return
		}

		c.Next()
	}
}

// GetTenantID retrieves the tenant UUID from the gin.Context.  It handles both the
// uuid.UUID type (set by this package and the shared auth middleware) and a raw
// string (set by some older middleware layers).
// Returns uuid.Nil, false when not set or when the stored value is uuid.Nil.
func GetTenantID(c *gin.Context) (uuid.UUID, bool) {
	val, exists := c.Get(TenantIDKey)
	if !exists {
		return uuid.Nil, false
	}
	switch v := val.(type) {
	case uuid.UUID:
		if v == uuid.Nil {
			return uuid.Nil, false
		}
		return v, true
	case string:
		id, err := uuid.Parse(v)
		if err != nil || id == uuid.Nil {
			return uuid.Nil, false
		}
		return id, true
	}
	return uuid.Nil, false
}

// GetRealmID retrieves the realm UUID from the gin.Context.
// Returns uuid.Nil, false when not set or when the stored value is uuid.Nil.
func GetRealmID(c *gin.Context) (uuid.UUID, bool) {
	val, exists := c.Get(RealmIDKey)
	if !exists {
		return uuid.Nil, false
	}
	switch v := val.(type) {
	case uuid.UUID:
		if v == uuid.Nil {
			return uuid.Nil, false
		}
		return v, true
	case string:
		id, err := uuid.Parse(v)
		if err != nil || id == uuid.Nil {
			return uuid.Nil, false
		}
		return id, true
	}
	return uuid.Nil, false
}

// --- RLS middleware (sqlx) -------------------------------------------------

// RLSMiddlewareSqlx creates a Gin middleware that, for every request that carries a
// tenant_id in the gin context, acquires a *sql.Conn from the sqlx pool and executes:
//
//	SET LOCAL app.current_tenant_id = '<tenantID>'
//	SET LOCAL app.current_realm_id  = '<realmID>'   (when realm_id is present)
//
// The acquired connection is stored under the "db_conn" key so that handler code can
// retrieve it via c.MustGet("db_conn").(*sql.Conn) and reuse the same connection
// that has the GUC set.
//
// If no tenant_id is present the middleware is a no-op and delegates to c.Next(),
// allowing public / system-level endpoints to coexist on the same router group.
//
// IMPORTANT: Handlers that retrieve "db_conn" must NOT close it; the middleware owns
// the connection lifecycle and will close it via defer after c.Next() returns.
func RLSMiddlewareSqlx(db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, ok := GetTenantID(c)
		if !ok {
			c.Next()
			return
		}

		conn, err := db.Conn(c.Request.Context())
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "failed to acquire database connection",
				"code":  "DB_CONN_ERROR",
			})
			return
		}
		defer conn.Close() //nolint:errcheck

		if err := SetLocalTenant(c.Request.Context(), conn, tenantID); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "failed to set tenant context for RLS",
				"code":  "RLS_SET_TENANT_ERROR",
			})
			return
		}

		if realmID, hasRealm := GetRealmID(c); hasRealm {
			if err := SetLocalRealm(c.Request.Context(), conn, realmID); err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "failed to set realm context for RLS",
					"code":  "RLS_SET_REALM_ERROR",
				})
				return
			}
		}

		// Expose the tenant-scoped connection so handlers can reuse it.
		c.Set("db_conn", conn)
		c.Next()
	}
}

// --- RLS middleware (pgx) --------------------------------------------------

// RLSMiddlewarePgx creates a Gin middleware equivalent to RLSMiddlewareSqlx but for
// a *pgxpool.Pool.  It acquires a *pgxpool.Conn, executes SET LOCAL inside a short
// BEGIN…COMMIT block to establish the GUC, then stores the connection under the
// "pgx_conn" key for handler reuse.
//
// NOTE: pgx SET LOCAL only persists within a transaction block.  The middleware
// begins a transaction, applies the GUC, and commits.  Subsequent queries from
// handler code that use the same acquired connection will see the GUC for the
// lifetime of that connection checkout from the pool.  If the handler opens a new
// transaction it should re-apply the GUC (or use WithTenantPgx).
func RLSMiddlewarePgx(pool *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, ok := GetTenantID(c)
		if !ok {
			c.Next()
			return
		}

		conn, err := pool.Acquire(c.Request.Context())
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "failed to acquire pgx connection",
				"code":  "DB_CONN_ERROR",
			})
			return
		}
		defer conn.Release()

		// Apply GUC inside a transaction block (required for SET LOCAL).
		tx, err := conn.Begin(c.Request.Context())
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "failed to begin pgx transaction for RLS",
				"code":  "DB_TX_ERROR",
			})
			return
		}

		if _, err := tx.Exec(c.Request.Context(), "SET LOCAL app.current_tenant_id = $1", tenantID.String()); err != nil {
			_ = tx.Rollback(c.Request.Context())
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "failed to set tenant context for RLS",
				"code":  "RLS_SET_TENANT_ERROR",
			})
			return
		}

		if realmID, hasRealm := GetRealmID(c); hasRealm {
			if _, err := tx.Exec(c.Request.Context(), "SET LOCAL app.current_realm_id = $1", realmID.String()); err != nil {
				_ = tx.Rollback(c.Request.Context())
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "failed to set realm context for RLS",
					"code":  "RLS_SET_REALM_ERROR",
				})
				return
			}
		}

		if err := tx.Commit(c.Request.Context()); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "failed to commit RLS GUC transaction",
				"code":  "DB_TX_COMMIT_ERROR",
			})
			return
		}

		// Expose the tenant-scoped connection so handlers can reuse it.
		c.Set("pgx_conn", conn)
		c.Next()
	}
}
