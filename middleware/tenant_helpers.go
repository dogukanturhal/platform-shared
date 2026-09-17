// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/platform-shared/errors"
	"github.com/dogukanturhal/platform-shared/response"
)

// Context key constants used for storing tenant and user information in Gin context.
const (
	TenantIDKey = "tenant_id"
	UserIDKey   = "user_id"
)

// RequireTenantID extracts tenant ID from context or aborts with error response.
// Returns the tenant ID and true if successful, uuid.Nil and false if tenant context is missing.
// This function automatically handles the error response, so the caller should return immediately if ok is false.
func RequireTenantID(c *gin.Context) (uuid.UUID, bool) {
	tenantID, exists := c.Get(TenantIDKey)
	if !exists {
		// Try extracting from header as fallback
		tenantIDStr := c.GetHeader("X-Tenant-ID")
		if tenantIDStr != "" {
			parsed, err := uuid.Parse(tenantIDStr)
			if err == nil && parsed != uuid.Nil {
				return parsed, true
			}
		}

		response.Error(c, errors.BadRequest("tenant context required"))
		return uuid.Nil, false
	}

	id, ok := tenantID.(uuid.UUID)
	if !ok || id == uuid.Nil {
		response.Error(c, errors.BadRequest("invalid tenant context"))
		return uuid.Nil, false
	}

	return id, true
}

// RequireUserID extracts user ID from context or aborts with error response.
// Returns the user ID and true if successful, uuid.Nil and false if user context is missing.
func RequireUserID(c *gin.Context) (uuid.UUID, bool) {
	userID, exists := c.Get(UserIDKey)
	if !exists {
		// Try extracting from header as fallback
		userIDStr := c.GetHeader("X-User-ID")
		if userIDStr != "" {
			parsed, err := uuid.Parse(userIDStr)
			if err == nil && parsed != uuid.Nil {
				return parsed, true
			}
		}

		response.Error(c, errors.Unauthorized("user context required"))
		return uuid.Nil, false
	}

	id, ok := userID.(uuid.UUID)
	if !ok || id == uuid.Nil {
		response.Error(c, errors.Unauthorized("invalid user context"))
		return uuid.Nil, false
	}

	return id, true
}

// RequireParamUUID parses a URL parameter as UUID or aborts with error response.
// Returns the UUID and true if successful, uuid.Nil and false if parsing fails.
func RequireParamUUID(c *gin.Context, param string) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param(param))
	if err != nil || id == uuid.Nil {
		response.Error(c, errors.BadRequest(fmt.Sprintf("invalid %s", param)))
		return uuid.Nil, false
	}
	return id, true
}

// RequireQueryUUID parses a query parameter as UUID or aborts with error response.
// Returns the UUID and true if successful, uuid.Nil and false if parsing fails.
func RequireQueryUUID(c *gin.Context, param string) (uuid.UUID, bool) {
	idStr := c.Query(param)
	if idStr == "" {
		response.Error(c, errors.BadRequest(fmt.Sprintf("%s is required", param)))
		return uuid.Nil, false
	}

	id, err := uuid.Parse(idStr)
	if err != nil || id == uuid.Nil {
		response.Error(c, errors.BadRequest(fmt.Sprintf("invalid %s", param)))
		return uuid.Nil, false
	}
	return id, true
}

// GetTenantID safely extracts tenant ID from context without aborting.
// Returns the tenant ID and true if found, uuid.Nil and false otherwise.
func GetTenantID(c *gin.Context) (uuid.UUID, bool) {
	tenantID, exists := c.Get(TenantIDKey)
	if !exists {
		return uuid.Nil, false
	}
	id, ok := tenantID.(uuid.UUID)
	if !ok {
		return uuid.Nil, false
	}
	return id, true
}

// GetUserID safely extracts user ID from context without aborting.
// Returns the user ID and true if found, uuid.Nil and false otherwise.
func GetUserID(c *gin.Context) (uuid.UUID, bool) {
	userID, exists := c.Get(UserIDKey)
	if !exists {
		return uuid.Nil, false
	}
	id, ok := userID.(uuid.UUID)
	if !ok {
		return uuid.Nil, false
	}
	return id, true
}

// RequireTenantIDPtr is a legacy helper for services that expect *uuid.UUID.
//
// Deprecated: Use RequireTenantID instead and pass the value directly.
func RequireTenantIDPtr(c *gin.Context) (*uuid.UUID, bool) {
	tenantID, ok := RequireTenantID(c)
	if !ok {
		return nil, false
	}
	return &tenantID, true
}

// GetTenantIDPtr is a legacy helper for services that expect *uuid.UUID.
//
// Deprecated: Use GetTenantID instead.
func GetTenantIDPtr(c *gin.Context) *uuid.UUID {
	tenantID, ok := GetTenantID(c)
	if !ok {
		return nil
	}
	return &tenantID
}

// GetUserIDPtr safely extracts user ID from context and returns a pointer.
// Returns nil if not found. Used for optional user context.
func GetUserIDPtr(c *gin.Context) *uuid.UUID {
	userID, ok := GetUserID(c)
	if !ok {
		return nil
	}
	return &userID
}
