// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// TenantContextKey is the context key for tenant connection info
type TenantContextKey struct{}

// TenantDBKey is the context key for tenant database connection
type TenantDBKey struct{}

// TenantMiddlewareConfig holds configuration for tenant middleware
type TenantMiddlewareConfig struct {
	// HeaderName is the header containing tenant ID (default: X-Tenant-ID)
	HeaderName string
	// RequireTenant if true, returns 401 if no tenant found
	RequireTenant bool
	// ConnectionManager is the tenant connection manager
	ConnectionManager *TenantConnectionManager
}

// TenantMiddleware creates a Gin middleware that extracts tenant ID and sets up connection
func TenantMiddleware(config TenantMiddlewareConfig) gin.HandlerFunc {
	if config.HeaderName == "" {
		config.HeaderName = "X-Tenant-ID"
	}

	return func(c *gin.Context) {
		var tenantIDStr string

		// SECURITY: Priority order for tenant ID extraction:
		// 1. JWT claims (most trusted - from authenticated token)
		// 2. X-Tenant-ID header (for authenticated API calls)
		// NOTE: Query parameters are NOT accepted for security reasons
		//       (visible in logs, Referer headers, browser history)

		// First, try to extract from JWT claims (set by auth middleware)
		if claims, exists := c.Get("claims"); exists {
			if claimsMap, ok := claims.(map[string]interface{}); ok {
				if tid, ok := claimsMap["tenant_id"].(string); ok {
					tenantIDStr = tid
				}
			}
		}

		// Fall back to header only if not in JWT claims
		if tenantIDStr == "" {
			tenantIDStr = c.GetHeader(config.HeaderName)
		}

		if tenantIDStr == "" {
			if config.RequireTenant {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "Tenant ID required",
				})
				return
			}
			c.Next()
			return
		}

		// Parse tenant ID
		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Invalid tenant ID format",
			})
			return
		}

		// Store tenant ID in context
		c.Set("tenant_id", tenantID)

		// If connection manager is provided, get tenant info
		if config.ConnectionManager != nil {
			info, err := config.ConnectionManager.GetTenantInfo(c.Request.Context(), tenantID)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to get tenant info",
				})
				return
			}
			c.Set("tenant_info", info)

			// Store in request context for downstream use
			ctx := context.WithValue(c.Request.Context(), TenantContextKey{}, info)
			c.Request = c.Request.WithContext(ctx)
		}

		c.Next()
	}
}

// GetTenantID extracts tenant ID from Gin context
func GetTenantID(c *gin.Context) (uuid.UUID, bool) {
	if val, exists := c.Get("tenant_id"); exists {
		if tenantID, ok := val.(uuid.UUID); ok {
			return tenantID, true
		}
	}
	return uuid.Nil, false
}

// GetTenantInfo extracts tenant connection info from Gin context
func GetTenantInfo(c *gin.Context) (*TenantConnectionInfo, bool) {
	if val, exists := c.Get("tenant_info"); exists {
		if info, ok := val.(*TenantConnectionInfo); ok {
			return info, true
		}
	}
	return nil, false
}

// GetTenantInfoFromContext extracts tenant info from standard context
func GetTenantInfoFromContext(ctx context.Context) (*TenantConnectionInfo, bool) {
	if val := ctx.Value(TenantContextKey{}); val != nil {
		if info, ok := val.(*TenantConnectionInfo); ok {
			return info, true
		}
	}
	return nil, false
}

// GetTenantIDFromContext extracts tenant ID from standard context
func GetTenantIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	info, ok := GetTenantInfoFromContext(ctx)
	if !ok {
		return uuid.Nil, false
	}
	return info.TenantID, true
}

// TenantDBMiddleware creates middleware that obtains a tenant database connection
// and sets it in the context. Use with TenantMiddleware.
func TenantDBMiddleware(connManager *TenantConnectionManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, ok := GetTenantID(c)
		if !ok {
			c.Next()
			return
		}

		// Get tenant info
		info, err := connManager.GetTenantInfo(c.Request.Context(), tenantID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get tenant database info",
			})
			return
		}

		// For shared strategy, get a connection with tenant context set
		if info.Strategy == StrategyShared {
			conn, err := connManager.GetConnectionWithContext(c.Request.Context(), tenantID)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to get tenant connection",
				})
				return
			}

			// Store connection in context
			ctx := context.WithValue(c.Request.Context(), TenantDBKey{}, conn)
			c.Request = c.Request.WithContext(ctx)

			// Ensure connection is returned after request
			defer func() {
				_ = connManager.ClearTenantContext(c.Request.Context(), conn)
				_ = conn.Close()
			}()
		} else {
			// For schema/database strategies, just get the DB
			db, err := connManager.GetConnection(c.Request.Context(), tenantID)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to get tenant database",
				})
				return
			}

			ctx := context.WithValue(c.Request.Context(), TenantDBKey{}, db)
			c.Request = c.Request.WithContext(ctx)
		}

		c.Next()
	}
}

// RequireTenant is a middleware that ensures a tenant ID is present
func RequireTenant() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, ok := GetTenantID(c); !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Tenant context required",
			})
			return
		}
		c.Next()
	}
}

// TenantScope wraps a function call with tenant database context
// Useful for background jobs or non-HTTP contexts
func TenantScope(ctx context.Context, connManager *TenantConnectionManager, tenantID uuid.UUID, fn func(ctx context.Context) error) error {
	info, err := connManager.GetTenantInfo(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("TenantScope: GetTenantInfo failed: %w", err)
	}

	// Add tenant info to context
	ctx = context.WithValue(ctx, TenantContextKey{}, info)

	// For shared strategy, set up connection with tenant context
	if info.Strategy == StrategyShared {
		conn, err := connManager.GetConnectionWithContext(ctx, tenantID)
		if err != nil {
			return fmt.Errorf("TenantScope: GetConnectionWithContext failed: %w", err)
		}
		defer func() {
			_ = connManager.ClearTenantContext(ctx, conn)
			_ = conn.Close()
		}()

		ctx = context.WithValue(ctx, TenantDBKey{}, conn)
	} else {
		db, err := connManager.GetConnection(ctx, tenantID)
		if err != nil {
			return fmt.Errorf("TenantScope: GetConnection failed: %w", err)
		}
		ctx = context.WithValue(ctx, TenantDBKey{}, db)
	}

	return fn(ctx)
}
