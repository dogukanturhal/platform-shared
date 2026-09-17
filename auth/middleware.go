// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/platform-shared/errors"
	sharedLogger "github.com/dogukanturhal/platform-shared/logger"
)

// legacyKeyWarningOnce ensures the deprecation warning for INTERNAL_API_KEY is
// logged at most once per process lifetime to avoid log spam.
var (
	legacyKeyWarningOnce   sync.Once
	legacyKeyWarningLogger *zap.Logger
)

func init() {
	// Initialize logger for legacy key warnings
	// Use a non-crashing fallback if initialization fails
	var err error
	legacyKeyWarningLogger, err = sharedLogger.NewLogger("info", "production")
	if err != nil {
		legacyKeyWarningLogger = zap.NewNop()
	}
}

// Middleware provides authentication middleware for Gin
type Middleware struct {
	config    *Config
	validator *TokenValidator
}

// NewMiddleware creates a new authentication middleware
func NewMiddleware(config *Config) *Middleware {
	return &Middleware{
		config:    config,
		validator: NewTokenValidator(config),
	}
}

// RequireAuth returns a middleware that requires valid authentication
// Supports both JWT tokens and API keys for service-to-service communication
func (m *Middleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// First, try API key authentication (for service-to-service)
		if m.tryAPIKeyAuth(c) {
			c.Next()
			return
		}

		// Then, try JWT authentication
		if m.tryJWTAuth(c) {
			c.Next()
			return
		}

		// Finally, try proxy-header authentication (APISIX-injected headers)
		if m.tryProxyAuth(c) {
			c.Next()
			return
		}

		// No valid authentication found
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"error": gin.H{
				"code":    string(errors.ErrCodeAuthMissingToken),
				"message": "Authorization required",
			},
		})
	}
}

// OptionalAuth returns a middleware that extracts user info if available
// but doesn't require authentication
func (m *Middleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try API key first
		if m.tryAPIKeyAuth(c) {
			c.Next()
			return
		}

		// Try JWT
		m.tryJWTAuth(c)

		// Continue regardless of auth status
		c.Next()
	}
}

// RequirePermission returns a middleware that requires specific permissions
func (m *Middleware) RequirePermission(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := GetCurrentUser(c)
		if user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error": gin.H{
					"code":    string(errors.ErrCodeAuthMissingToken),
					"message": "Authentication required",
				},
			})
			return
		}

		// Check if user has any of the required permissions
		if !user.HasAnyPermission(permissions...) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"success": false,
				"error": gin.H{
					"code":    string(errors.ErrCodeAuthPermissionDenied),
					"message": "Permission denied: " + strings.Join(permissions, " or ") + " required",
				},
			})
			return
		}

		c.Next()
	}
}

// RequireAllPermissions returns a middleware that requires ALL specified permissions
func (m *Middleware) RequireAllPermissions(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := GetCurrentUser(c)
		if user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error": gin.H{
					"code":    string(errors.ErrCodeAuthMissingToken),
					"message": "Authentication required",
				},
			})
			return
		}

		// Check if user has all required permissions
		if !user.HasAllPermissions(permissions...) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"success": false,
				"error": gin.H{
					"code":    string(errors.ErrCodeAuthPermissionDenied),
					"message": "Permission denied: all of " + strings.Join(permissions, ", ") + " required",
				},
			})
			return
		}

		c.Next()
	}
}

// RequireRole returns a middleware that requires specific roles
func (m *Middleware) RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := GetCurrentUser(c)
		if user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error": gin.H{
					"code":    string(errors.ErrCodeAuthMissingToken),
					"message": "Authentication required",
				},
			})
			return
		}

		// Check if user has any of the required roles
		if !user.HasAnyRole(roles...) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"success": false,
				"error": gin.H{
					"code":    string(errors.ErrCodeAuthPermissionDenied),
					"message": "Role required: " + strings.Join(roles, " or "),
				},
			})
			return
		}

		c.Next()
	}
}

// RequireServiceAuth returns a middleware that only allows service-to-service auth
func (m *Middleware) RequireServiceAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !m.tryAPIKeyAuth(c) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error": gin.H{
					"code":    string(errors.ErrCodeAuthInvalidToken),
					"message": "Valid service API key required",
				},
			})
			return
		}
		c.Next()
	}
}

// RequireTenant returns a middleware that requires tenant context
func (m *Middleware) RequireTenant() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, ok := GetTenantID(c)
		if !ok || tenantID.String() == "00000000-0000-0000-0000-000000000000" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error": gin.H{
					"code":    string(errors.ErrCodeAuthTenantMismatch),
					"message": "Tenant context required",
				},
			})
			return
		}
		c.Next()
	}
}

// tryJWTAuth attempts JWT authentication and sets context if successful.
// It checks the Authorization header first, then falls back to the
// hexxlock_access_token HttpOnly cookie (used by browser-based clients).
func (m *Middleware) tryJWTAuth(c *gin.Context) bool {
	var tokenString string

	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		// Skip if this looks like an API key
		if strings.HasPrefix(authHeader, "ApiKey ") {
			return false
		}

		// Extract bearer token
		var err error
		tokenString, err = ExtractBearerToken(authHeader)
		if err != nil {
			return false
		}
	} else {
		// Fallback: check HttpOnly cookie (browser-based auth)
		cookie, err := c.Cookie("hexxlock_access_token")
		if err != nil || cookie == "" {
			return false
		}
		tokenString = cookie
	}

	// Skip if token looks like an API key (hxk_ prefix)
	if strings.HasPrefix(tokenString, "hxk_") {
		return false
	}

	// Validate token
	claims, err := m.validator.ValidateAccessToken(tokenString)
	if err != nil {
		return false
	}

	// Set context values
	m.setContextFromClaims(c, claims)
	return true
}

// tryAPIKeyAuth attempts API key authentication and sets context if successful.
//
// It checks incoming keys in the following order:
//  1. Scoped service API keys (ServiceAPIKeys map) -- constant-time comparison,
//     grants only the explicitly configured permissions for the matched service.
//  2. Legacy single INTERNAL_API_KEY (deprecated) -- constant-time comparison,
//     grants a restricted "legacy-service" permission set and logs a deprecation
//     warning so operators can migrate to scoped keys.
//
// The wildcard "*" permission is never granted to API-key-authenticated callers.
func (m *Middleware) tryAPIKeyAuth(c *gin.Context) bool {
	apiKey := m.extractAPIKey(c)
	if apiKey == "" {
		return false
	}

	// --- Phase 1: Try scoped service API keys (preferred) ---
	if matched, ok := m.authenticateScopedKey(apiKey); ok {
		m.setServiceContext(c, matched.ServiceName, matched.Permissions)
		return true
	}

	// --- Phase 2: Legacy single-key fallback (deprecated) ---
	if m.authenticateLegacyKey(apiKey) {
		legacyKeyWarningOnce.Do(func() {
			legacyKeyWarningLogger.Warn("[SECURITY][DEPRECATED] Request authenticated using legacy INTERNAL_API_KEY",
				zap.String("message", "Migrate to per-service scoped keys via SERVICE_API_KEYS env var. Legacy key support will be removed in a future release."),
				zap.String("path", c.Request.URL.Path))
		})
		// Grant a minimal, non-wildcard permission set for backward compatibility.
		// Services relying on the legacy key get basic internal-service permissions
		// but NOT the dangerous wildcard "*".
		legacyPermissions := []string{
			"internal:service:read",
			"internal:service:write",
		}
		m.setServiceContext(c, "legacy-internal", legacyPermissions)
		return true
	}

	return false
}

// authenticateScopedKey checks the provided API key against all configured
// scoped service API keys using constant-time comparison to prevent timing attacks.
// Returns the matched ServiceAPIKey and true if found, or zero-value and false otherwise.
func (m *Middleware) authenticateScopedKey(apiKey string) (ServiceAPIKey, bool) {
	if len(m.config.ServiceAPIKeys) == 0 {
		return ServiceAPIKey{}, false
	}

	apiKeyBytes := []byte(apiKey)

	// Iterate all configured keys to prevent timing leaks that could reveal
	// which keys exist. We always compare against every key.
	var matched ServiceAPIKey
	found := false
	for _, sak := range m.config.ServiceAPIKeys {
		if subtle.ConstantTimeCompare(apiKeyBytes, []byte(sak.Key)) == 1 {
			matched = ServiceAPIKey{
				Key:         sak.Key,
				ServiceName: sak.ServiceName,
				Permissions: sak.Permissions,
			}
			found = true
			// Do NOT break early -- continue iterating to keep constant-time behavior
			// across the full key set. The cost is negligible for typical key counts.
		}
	}

	return matched, found
}

// authenticateLegacyKey validates the provided key against the deprecated
// single INTERNAL_API_KEY using constant-time comparison.
func (m *Middleware) authenticateLegacyKey(apiKey string) bool {
	if m.config.InternalAPIKey == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(apiKey), []byte(m.config.InternalAPIKey)) == 1
}

// setServiceContext populates the gin context with service authentication details.
// It sets the auth method, service name, tenant ID (if provided), and the CurrentUser
// with the provided scoped permissions.
func (m *Middleware) setServiceContext(c *gin.Context, serviceName string, permissions []string) {
	c.Set(AuthMethodKey, AuthMethodAPIKey)
	c.Set(ServiceNameKey, serviceName)

	// Try to extract tenant from header for service-to-service calls
	if tenantIDStr := c.GetHeader("X-Tenant-ID"); tenantIDStr != "" {
		if tenantID, err := parseUUID(tenantIDStr); err == nil {
			c.Set(TenantIDKey, tenantID)
		}
	}

	// Determine roles for the service user.
	// When APISIX gateway forwards requests with X-User-Role (set by forward-auth
	// after JWT validation), trust that role alongside the default "service" role.
	// This allows gateway-proxied requests to pass role-based access checks.
	roles := []string{"service"}
	if gatewayRole := c.GetHeader("X-User-Role"); gatewayRole != "" {
		roles = append(roles, gatewayRole)
	}

	// Create a service user with scoped permissions -- never wildcard
	serviceUser := &CurrentUser{
		AuthMethod:  AuthMethodAPIKey,
		Roles:       roles,
		Permissions: permissions,
		ServiceName: serviceName,
	}

	// Also set user ID from gateway headers if available
	if userIDStr := c.GetHeader("X-User-ID"); userIDStr != "" {
		if userID, err := parseUUID(userIDStr); err == nil {
			serviceUser.ID = userID
		}
	}

	c.Set(CurrentUserKey, serviceUser)
}

// extractAPIKey extracts an API key from the request
func (m *Middleware) extractAPIKey(c *gin.Context) string {
	// Check X-API-Key header
	if apiKey := c.GetHeader("X-API-Key"); apiKey != "" {
		return apiKey
	}

	// Check Authorization header with ApiKey prefix
	authHeader := c.GetHeader("Authorization")
	if strings.HasPrefix(authHeader, "ApiKey ") {
		return strings.TrimPrefix(authHeader, "ApiKey ")
	}

	// Check Bearer token for API key format (hxk_ prefix)
	if strings.HasPrefix(authHeader, "Bearer hxk_") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	return ""
}

// tryProxyAuth authenticates from trusted reverse-proxy headers.
// When TrustProxyHeaders is enabled, APISIX injects X-User-ID and X-Tenant-ID
// after JWT validation. APISIX global rules strip these headers from external
// requests, so they can only be set by the gateway itself.
func (m *Middleware) tryProxyAuth(c *gin.Context) bool {
	if !m.config.TrustProxyHeaders {
		return false
	}

	userIDStr := c.GetHeader("X-User-ID")
	tenantIDStr := c.GetHeader("X-Tenant-ID")
	if userIDStr == "" || tenantIDStr == "" {
		return false
	}

	userID, err := parseUUID(userIDStr)
	if err != nil {
		return false
	}

	tenantID, err := parseUUID(tenantIDStr)
	if err != nil {
		return false
	}

	// Build roles from X-User-Roles header (comma-separated)
	var roles []string
	if rolesStr := c.GetHeader("X-User-Roles"); rolesStr != "" {
		roles = strings.Split(rolesStr, ",")
	}

	currentUser := &CurrentUser{
		ID:          userID,
		TenantID:    tenantID,
		Roles:       roles,
		Permissions: []string{"*"},
		AuthMethod:  AuthMethodJWT,
	}

	c.Set(CurrentUserKey, currentUser)
	c.Set(TenantIDKey, tenantID)
	c.Set(UserIDKey, userID)
	c.Set(AuthMethodKey, AuthMethodJWT)

	return true
}

// setContextFromClaims sets gin context values from JWT claims
func (m *Middleware) setContextFromClaims(c *gin.Context, claims *Claims) {
	// Create CurrentUser from claims
	currentUser := NewCurrentUserFromClaims(claims)

	// Set all context values
	c.Set(CurrentUserKey, currentUser)
	c.Set(ClaimsKey, claims)
	c.Set(TenantIDKey, claims.TenantID)
	c.Set(UserIDKey, claims.UserID)
	c.Set(SessionIDKey, claims.SessionID)
	c.Set(AuthMethodKey, AuthMethodJWT)

	// Set impersonation context if present
	if claims.ImpersonatorID != nil {
		c.Set(ImpersonatorIDKey, *claims.ImpersonatorID)
	}
	if claims.ImpersonationSessionID != nil {
		c.Set(ImpersonationSessionIDKey, *claims.ImpersonationSessionID)
	}
}

// parseUUID is a helper to parse UUID strings with proper validation
// It returns a uuid.UUID value and an error if parsing fails
func parseUUID(s string) (uuid.UUID, error) {
	// Handle empty input explicitly
	if s == "" {
		return uuid.Nil, ErrTokenInvalid("UUID cannot be empty")
	}

	// Trim whitespace to prevent padding attacks
	s = strings.TrimSpace(s)

	// After trimming, check if we're left with an empty string
	if s == "" {
		return uuid.Nil, ErrTokenInvalid("UUID cannot be empty")
	}

	// Use google/uuid library for RFC 4122 compliant validation
	parsed, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, ErrTokenInvalid("invalid UUID format")
	}

	// Reject nil UUID explicitly - often indicates an error condition
	if parsed == uuid.Nil {
		return uuid.Nil, ErrTokenInvalid("UUID cannot be nil (00000000-0000-0000-0000-000000000000)")
	}

	return parsed, nil
}
