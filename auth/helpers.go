// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// GetCurrentUser extracts the current user from the gin context
func GetCurrentUser(c *gin.Context) *CurrentUser {
	if user, exists := c.Get(CurrentUserKey); exists {
		if currentUser, ok := user.(*CurrentUser); ok {
			return currentUser
		}
	}
	return nil
}

// GetTenantID extracts the tenant ID from the gin context
// Returns the tenant ID and a boolean indicating if it was found
//
// Deprecated: Use middleware.GetTenantID from platform-services/shared/middleware instead.
// This function is maintained for backward compatibility but delegates to the newer implementation.
func GetTenantID(c *gin.Context) (uuid.UUID, bool) {
	// Delegate to the newer middleware package implementation
	// Import: "github.com/dogukanturhal/platform-shared/middleware"
	// New code should use: middleware.GetTenantID(c)

	// First try to get from context (set by middleware)
	if tenantID, exists := c.Get(TenantIDKey); exists {
		switch v := tenantID.(type) {
		case uuid.UUID:
			return v, true
		case string:
			if id, err := uuid.Parse(v); err == nil {
				return id, true
			}
		}
	}

	// Try to get from current user
	if user := GetCurrentUser(c); user != nil {
		if user.TenantID != uuid.Nil {
			return user.TenantID, true
		}
	}

	return uuid.Nil, false
}

// MustGetTenantID extracts the tenant ID from context or aborts the request.
// Use this only when you're certain the tenant middleware has run.
// Note: This function aborts the request with 500 error instead of panicking.
//
// Deprecated: Use middleware.RequireTenantID from platform-services/shared/middleware instead.
// The newer function provides better error handling with standardized error responses.
// This function is maintained for backward compatibility.
func MustGetTenantID(c *gin.Context) uuid.UUID {
	tenantID, ok := GetTenantID(c)
	if !ok {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "tenant ID not found in context",
			"code":  "TENANT_CONTEXT_MISSING",
		})
		return uuid.Nil
	}
	return tenantID
}

// GetUserID extracts the user ID from the gin context
//
// Deprecated: Use middleware.GetUserID or middleware.RequireUserID from platform-services/shared/middleware instead.
// The newer functions provide consistent error handling and return values.
// This function is maintained for backward compatibility.
func GetUserID(c *gin.Context) *uuid.UUID {
	// Delegate to the newer middleware package for new code
	// Import: "github.com/dogukanturhal/platform-shared/middleware"
	// New code should use: middleware.GetUserID(c) or middleware.RequireUserID(c)

	// First try direct context value
	if userID, exists := c.Get(UserIDKey); exists {
		switch v := userID.(type) {
		case uuid.UUID:
			return &v
		case string:
			if id, err := uuid.Parse(v); err == nil {
				return &id
			}
		}
	}

	// Try to get from current user
	if user := GetCurrentUser(c); user != nil {
		if user.ID != uuid.Nil {
			return &user.ID
		}
	}

	return nil
}

// GetSessionID extracts the session ID from the gin context
func GetSessionID(c *gin.Context) *uuid.UUID {
	if sessionID, exists := c.Get(SessionIDKey); exists {
		switch v := sessionID.(type) {
		case uuid.UUID:
			return &v
		case string:
			if id, err := uuid.Parse(v); err == nil {
				return &id
			}
		}
	}

	// Try to get from current user
	if user := GetCurrentUser(c); user != nil {
		if user.SessionID != uuid.Nil {
			return &user.SessionID
		}
	}

	return nil
}

// GetClaims extracts the JWT claims from the gin context
func GetClaims(c *gin.Context) *Claims {
	if claims, exists := c.Get(ClaimsKey); exists {
		if jwtClaims, ok := claims.(*Claims); ok {
			return jwtClaims
		}
	}
	return nil
}

// GetAuthMethod returns the authentication method used
func GetAuthMethod(c *gin.Context) AuthMethod {
	if method, exists := c.Get(AuthMethodKey); exists {
		if authMethod, ok := method.(AuthMethod); ok {
			return authMethod
		}
	}
	return ""
}

// IsServiceAuth returns true if the current request is authenticated via service API key
func IsServiceAuth(c *gin.Context) bool {
	return GetAuthMethod(c) == AuthMethodAPIKey
}

// IsJWTAuth returns true if the current request is authenticated via JWT
func IsJWTAuth(c *gin.Context) bool {
	return GetAuthMethod(c) == AuthMethodJWT
}

// IsImpersonated returns true if the current user is being impersonated
func IsImpersonated(c *gin.Context) bool {
	_, exists := c.Get(ImpersonatorIDKey)
	return exists
}

// GetImpersonatorID returns the ID of the admin impersonating the current user
func GetImpersonatorID(c *gin.Context) *uuid.UUID {
	if impID, exists := c.Get(ImpersonatorIDKey); exists {
		switch v := impID.(type) {
		case uuid.UUID:
			return &v
		case string:
			if id, err := uuid.Parse(v); err == nil {
				return &id
			}
		}
	}
	return nil
}

// HasPermission checks if the current user has a specific permission
func HasPermission(c *gin.Context, permission string) bool {
	user := GetCurrentUser(c)
	if user == nil {
		return false
	}
	return user.HasPermission(permission)
}

// HasRole checks if the current user has a specific role
func HasRole(c *gin.Context, role string) bool {
	user := GetCurrentUser(c)
	if user == nil {
		return false
	}
	return user.HasRole(role)
}

// HasAnyPermission checks if the current user has any of the specified permissions
func HasAnyPermission(c *gin.Context, permissions ...string) bool {
	user := GetCurrentUser(c)
	if user == nil {
		return false
	}
	return user.HasAnyPermission(permissions...)
}

// HasAllPermissions checks if the current user has all specified permissions
func HasAllPermissions(c *gin.Context, permissions ...string) bool {
	user := GetCurrentUser(c)
	if user == nil {
		return false
	}
	return user.HasAllPermissions(permissions...)
}

// GetServiceName returns the authenticated service name from the context.
// Returns an empty string if the request was not authenticated via a scoped API key.
func GetServiceName(c *gin.Context) string {
	if name, exists := c.Get(ServiceNameKey); exists {
		if s, ok := name.(string); ok {
			return s
		}
	}
	// Fallback: check the CurrentUser's ServiceName field
	if user := GetCurrentUser(c); user != nil {
		return user.ServiceName
	}
	return ""
}
