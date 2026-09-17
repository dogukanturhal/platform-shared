// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"strings"

	"github.com/google/uuid"
)

// Context keys for storing auth information in gin.Context
const (
	CurrentUserKey            = "current_user"
	CurrentSessionKey         = "current_session"
	TenantIDKey               = "tenant_id"
	UserIDKey                 = "user_id"
	SessionIDKey              = "session_id"
	ImpersonatorIDKey         = "impersonator_id"
	ImpersonationSessionIDKey = "impersonation_session_id"
	AuthMethodKey             = "auth_method"
	ClaimsKey                 = "claims"
	ServiceNameKey            = "service_name"
)

// Method represents the authentication method used.
type Method = AuthMethod

// AuthMethod represents the authentication method used
type AuthMethod string //nolint:revive // public API stability; used across services

// Authentication method constants.
const (
	AuthMethodJWT            AuthMethod = "jwt"
	AuthMethodAPIKey         AuthMethod = "api_key"
	AuthMethodServiceAccount AuthMethod = "service_account"
)

// CurrentUser represents the authenticated user context
type CurrentUser struct {
	ID               uuid.UUID  `json:"id"`
	TenantID         uuid.UUID  `json:"tenant_id"`
	Username         string     `json:"username"`
	Email            string     `json:"email"`
	Roles            []string   `json:"roles"`
	Permissions      []string   `json:"permissions"`
	SessionID        uuid.UUID  `json:"session_id"`
	ServiceAccountID *uuid.UUID `json:"service_account_id,omitempty"`
	AuthMethod       AuthMethod `json:"auth_method"`
	// ServiceName identifies the calling service when authenticated via a scoped API key.
	// Empty for JWT-authenticated users and legacy single-key service auth.
	ServiceName string `json:"service_name,omitempty"`
	// TokenType mirrors claims.TokenType the JWT validator stamps.
	// Values:
	//   "service"        — OAuth2 client_credentials grant (sub == client_id)
	//   "platform_admin" — platform admin token
	//   ""               — regular user token
	// Authorization sites branch on this to decide whether to honour
	// caller-supplied tenant_ids (service tokens) or lock to the JWT's
	// tenant_id claim (user tokens).
	TokenType string `json:"token_type,omitempty"`
}

// HasPermission checks if the user has a specific permission
func (u *CurrentUser) HasPermission(permission string) bool {
	for _, p := range u.Permissions {
		if p == permission || p == "*" {
			return true
		}
		// Check wildcard permissions (e.g., "core:users:*" matches "core:users:read")
		if matchWildcard(p, permission) {
			return true
		}
	}
	return false
}

// HasRole checks if the user has a specific role
func (u *CurrentUser) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyPermission checks if the user has any of the specified permissions
func (u *CurrentUser) HasAnyPermission(permissions ...string) bool {
	for _, p := range permissions {
		if u.HasPermission(p) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if the user has all specified permissions
func (u *CurrentUser) HasAllPermissions(permissions ...string) bool {
	for _, p := range permissions {
		if !u.HasPermission(p) {
			return false
		}
	}
	return true
}

// HasAnyRole checks if the user has any of the specified roles
func (u *CurrentUser) HasAnyRole(roles ...string) bool {
	for _, r := range roles {
		if u.HasRole(r) {
			return true
		}
	}
	return false
}

// HasAllRoles checks if the user has all specified roles
func (u *CurrentUser) HasAllRoles(roles ...string) bool {
	for _, r := range roles {
		if !u.HasRole(r) {
			return false
		}
	}
	return true
}

// IsServiceAccount returns true if this user is a service account
func (u *CurrentUser) IsServiceAccount() bool {
	return u.ServiceAccountID != nil || u.AuthMethod == AuthMethodServiceAccount
}

// IsAPIKeyAuth returns true if this user was authenticated via an API key
func (u *CurrentUser) IsAPIKeyAuth() bool {
	return u.AuthMethod == AuthMethodAPIKey
}

// matchWildcard checks if a permission pattern matches a target permission
// Enhanced wildcard matching supporting patterns like:
// - "core:users:*" matches "core:users:read", "core:users:write"
// - "core:*:read" matches "core:users:read", "core:roles:read"
// - "*:users:*" matches "core:users:read", "admin:users:write"
// - "core:*" matches "core:users", "core:roles" (2-part patterns)
func matchWildcard(pattern, permission string) bool {
	// Split both by colon delimiter
	patternParts := strings.Split(pattern, ":")
	permParts := strings.Split(permission, ":")

	// Handle trailing wildcard with prefix matching (e.g., "core:users:*" or "core:*")
	// This allows patterns with fewer parts than the permission
	if len(patternParts) > 0 && patternParts[len(patternParts)-1] == "*" {
		// If pattern ends with *, it can match any number of additional parts
		if len(permParts) < len(patternParts)-1 {
			return false
		}
		// Check all parts before the final *
		for i := 0; i < len(patternParts)-1; i++ {
			if patternParts[i] != "*" && patternParts[i] != permParts[i] {
				return false
			}
		}
		return true
	}

	// For non-trailing wildcards, parts count must match exactly
	if len(patternParts) != len(permParts) {
		return false
	}

	// Compare each part - "*" matches any single part
	for i, p := range patternParts {
		if p != "*" && p != permParts[i] {
			return false
		}
	}
	return true
}

// NewCurrentUserFromClaims creates a CurrentUser from JWT claims
func NewCurrentUserFromClaims(claims *Claims) *CurrentUser {
	authMethod := AuthMethodJWT
	if claims.IsServiceAccount() {
		authMethod = AuthMethodServiceAccount
	}

	return &CurrentUser{
		ID:               claims.UserID,
		TenantID:         claims.TenantID,
		Username:         claims.Username,
		Email:            claims.Email,
		Roles:            claims.Roles,
		Permissions:      claims.Permissions,
		SessionID:        claims.SessionID,
		ServiceAccountID: claims.ServiceAccountID,
		AuthMethod:       authMethod,
		// Propagate TokenType so downstream handlers can distinguish
		// machine principals (client_credentials JWTs) from user JWTs
		// without re-parsing the raw token.
		TokenType: claims.TokenType,
	}
}
