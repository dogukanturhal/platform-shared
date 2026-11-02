// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// bearerTokenKey stores the raw bearer token of a JWT-authenticated request so
// a PermissionChecker can forward it to the identity provider. It is private on
// purpose: it must never be logged, serialized or exposed to handlers.
const bearerTokenKey = "auth.bearer_token"

// PermissionQuery describes one permission lookup for a user JWT whose token
// carried no (or insufficient) `permissions` claim.
type PermissionQuery struct {
	UserID      uuid.UUID
	TenantID    uuid.UUID
	Bearer      string // caller's own access token; forward it, never log it
	Permissions []string
}

// PermissionChecker resolves permissions that are not present in the token
// claims (for example against falcon-id's /authorize/batch). Implementations
// return one entry per permission they could evaluate; a missing entry means
// "not granted". Any error makes the middleware fail closed with 503.
type PermissionChecker interface {
	CheckPermissions(ctx context.Context, q PermissionQuery) (map[string]bool, error)
}

// checkViaResolver consults the configured PermissionChecker for a user JWT
// whose claim check failed. handled is false when the resolver does not apply
// (no checker, service/machine token, no user, no bearer) so the caller keeps
// today's behaviour. When handled is true the caller must not fall through.
func (m *Middleware) checkViaResolver(c *gin.Context, user *CurrentUser, permissions []string, all bool) (allowed, handled bool) {
	if m.config == nil || m.config.PermissionChecker == nil {
		return false, false
	}
	if user.TokenType == "service" || user.ID == uuid.Nil {
		return false, false
	}
	bearer, _ := c.Get(bearerTokenKey)
	token, _ := bearer.(string)
	if token == "" {
		return false, false
	}

	res, err := m.config.PermissionChecker.CheckPermissions(c.Request.Context(), PermissionQuery{
		UserID:      user.ID,
		TenantID:    user.TenantID,
		Bearer:      token,
		Permissions: permissions,
	})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "AUTH_PERMISSION_UNAVAILABLE",
				"message": "Permission check temporarily unavailable",
			},
		})
		return false, true
	}

	if all {
		for _, p := range permissions {
			if !res[p] {
				return false, false
			}
		}
		return true, false
	}
	for _, p := range permissions {
		if res[p] {
			return true, false
		}
	}
	return false, false
}
