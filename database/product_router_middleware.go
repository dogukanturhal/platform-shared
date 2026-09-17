// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/platform-shared/auth"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ── Context keys ────────────────────────────────────────────────────────────

// ProductDBContextKey is the context key for ProductDBContext.
type ProductDBContextKey struct{}

// ProductDBContext carries the resolved database connection and isolation info
// for the current request. Retrieved via GetProductDBContext().
type ProductDBContext struct {
	Pool          *pgxpool.Pool
	Conn          *pgxpool.Conn // acquired connection with tenant context set (pool/bridge modes)
	IsolationMode string        // "pool", "bridge", "silo"
	Schema        string
	TenantID      string
}

// ── TenantScopedPool ────────────────────────────────────────────────────────

// TenantScopedPool wraps a pgxpool.Pool and ensures RLS context is always set
// for pool-mode tenants. This is a fail-closed wrapper: callers cannot
// accidentally use a pool-mode connection without RLS being active.
type TenantScopedPool struct {
	Pool          *pgxpool.Pool
	TenantID      string
	IsolationMode string
	Schema        string
}

// Acquire gets a connection with the appropriate tenant context already applied.
// For pool mode: sets RLS via set_config(). For bridge mode: sets search_path.
// For silo mode: returns the connection directly (tenant is isolated by DB).
func (p *TenantScopedPool) Acquire(ctx context.Context) (*pgxpool.Conn, error) {
	conn, err := p.Pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}

	switch p.IsolationMode {
	case "pool":
		// SECURITY: Always set RLS context for pool-mode connections.
		_, err := conn.Exec(ctx, "SELECT set_config('app.current_tenant_id', $1, false)", p.TenantID)
		if err != nil {
			conn.Release()
			return nil, fmt.Errorf("failed to set RLS context: %w", err)
		}
	case "bridge":
		// Set search_path for bridge-mode connections. AfterConnect in the pool
		// config handles new connections, but this ensures correctness for
		// recycled connections that might have been reset.
		if p.Schema != "" && p.Schema != schemaPublic {
			_, err := conn.Exec(ctx, fmt.Sprintf("SET search_path TO %s, "+schemaPublic, quoteIdentRouter(p.Schema)))
			if err != nil {
				conn.Release()
				return nil, fmt.Errorf("failed to set search_path: %w", err)
			}
		}
	case "silo":
		// No per-connection setup needed — tenant is isolated at the DB level.
	}

	return conn, nil
}

// ── Middleware ───────────────────────────────────────────────────────────────

// ProductRouterMiddleware creates a Gin middleware that resolves the correct
// database connection for the current tenant and stores it in the request
// context. Business services use this instead of manually calling the router.
//
// The middleware:
//  1. Extracts tenant_id from context (set by auth middleware)
//  2. Calls router.GetPoolInfo() to resolve isolation mode + pool
//  3. Acquires a connection with appropriate tenant context
//  4. Stores ProductDBContext in the gin/request context
//  5. Releases the connection after the request completes
//
// Usage:
//
//	router.Use(authMiddleware.RequireAuth())
//	router.Use(database.ProductRouterMiddleware(connRouter, "hexxlock_crm"))
//	router.POST("/api/resource", handler.Create)
func ProductRouterMiddleware(router *ProductConnectionRouter, databaseName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract tenant ID from context (set by auth middleware).
		tenantIDVal, exists := c.Get(auth.TenantIDKey)
		if !exists {
			tenantIDVal, exists = c.Get("tenant_id")
			if !exists {
				// No tenant ID — skip (for system-level/public endpoints).
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

		// Skip nil UUID (system context).
		if tenantID == uuid.Nil {
			c.Next()
			return
		}

		tenantIDStr := tenantID.String()

		// Resolve pool + isolation mode.
		pool, isolationMode, schema, err := router.GetPoolInfo(c.Request.Context(), tenantIDStr, databaseName)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to resolve tenant database",
			})
			return
		}

		// Create scoped pool for fail-closed acquisition.
		scoped := &TenantScopedPool{
			Pool:          pool,
			TenantID:      tenantIDStr,
			IsolationMode: isolationMode,
			Schema:        schema,
		}

		// Acquire a connection with tenant context applied.
		conn, err := scoped.Acquire(c.Request.Context())
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to acquire tenant database connection",
			})
			return
		}
		defer conn.Release()

		// Store in context.
		dbCtx := &ProductDBContext{
			Pool:          pool,
			Conn:          conn,
			IsolationMode: isolationMode,
			Schema:        schema,
			TenantID:      tenantIDStr,
		}

		c.Set("product_db_ctx", dbCtx)
		ctx := context.WithValue(c.Request.Context(), ProductDBContextKey{}, dbCtx)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// GetProductDBContext retrieves the ProductDBContext from a Gin context.
func GetProductDBContext(c *gin.Context) (*ProductDBContext, bool) {
	if val, exists := c.Get("product_db_ctx"); exists {
		if dbCtx, ok := val.(*ProductDBContext); ok {
			return dbCtx, true
		}
	}
	return nil, false
}

// GetProductDBContextFromContext retrieves ProductDBContext from a standard context.
func GetProductDBContextFromContext(ctx context.Context) (*ProductDBContext, bool) {
	if val := ctx.Value(ProductDBContextKey{}); val != nil {
		if dbCtx, ok := val.(*ProductDBContext); ok {
			return dbCtx, true
		}
	}
	return nil, false
}
