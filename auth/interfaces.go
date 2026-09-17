// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// PermissionResolver interface for permission cache operations (v1 tokens)
type PermissionResolver interface {
	// CheckPermission checks if a session has a specific permission
	CheckPermission(ctx context.Context, sessionID, tenantID uuid.UUID, permission string) (bool, error)

	// GetUserEffectivePermissions loads all effective permissions for a session
	GetUserEffectivePermissions(ctx context.Context, sessionID, tenantID uuid.UUID, roles []string) ([]string, error)

	// InvalidatePermissions invalidates the permission cache for a session
	InvalidatePermissions(ctx context.Context, sessionID uuid.UUID) error
}

// SpiceDBResolver interface for SpiceDB-based permission resolution (v2 tokens)
// This resolver is used when SpiceDB is enabled and the user has a v2 token
type SpiceDBResolver interface {
	// CheckPermission checks if a user has a permission on a resource
	// Permission format: "module.action" or "resource:id.action"
	CheckPermission(ctx context.Context, tenantID, userID uuid.UUID, permission string) (bool, error)

	// CheckResourcePermission checks if a user has a permission on a specific resource (ReBAC)
	// This is the primary method for fine-grained resource-level access control
	CheckResourcePermission(ctx context.Context, tenantID, userID uuid.UUID, resourceType, resourceID, action string) (bool, error)

	// CheckAnyPermission checks if user has ANY of the specified permissions
	CheckAnyPermission(ctx context.Context, tenantID, userID uuid.UUID, permissions []string) (bool, error)

	// CheckAllPermissions checks if user has ALL of the specified permissions
	CheckAllPermissions(ctx context.Context, tenantID, userID uuid.UUID, permissions []string) (bool, error)

	// FilterAccessibleResources filters a list of resources to only those the user can access
	// Returns the IDs of resources the user has the specified permission on
	FilterAccessibleResources(ctx context.Context, tenantID, userID uuid.UUID, resourceType string, resourceIDs []string, action string) ([]string, error)

	// IsAvailable returns true if SpiceDB is healthy and available
	IsAvailable() bool
}

// HybridResolver combines SpiceDB and Redis-based permission resolution
// Uses SpiceDB as primary with fallback to Redis for graceful degradation
type HybridResolver interface {
	// CheckPermission checks permission using best available method (SpiceDB preferred)
	CheckPermission(ctx context.Context, tenantID, userID, sessionID uuid.UUID, permission string) (allowed bool, source string, err error)

	// CheckResourcePermission checks resource-level permission (SpiceDB only, no fallback)
	CheckResourcePermission(ctx context.Context, tenantID, userID uuid.UUID, resourceType, resourceID, action string) (allowed bool, err error)

	// FilterAccessibleResources filters resources using SpiceDB
	FilterAccessibleResources(ctx context.Context, tenantID, userID uuid.UUID, resourceType string, resourceIDs []string, action string) ([]string, error)

	// GetResolverStatus returns the current status of underlying resolvers
	GetResolverStatus() ResolverStatus
}

// ResolverStatus contains status information about permission resolvers
type ResolverStatus struct {
	SpiceDBAvailable bool   `json:"spicedb_available"`
	RedisAvailable   bool   `json:"redis_available"`
	PreferredSource  string `json:"preferred_source"` // "spicedb" or "redis"
}

// SessionResolver interface for session cache operations
type SessionResolver interface {
	// GetSession retrieves full session details from cache
	GetSession(ctx context.Context, sessionID uuid.UUID) (*CachedSession, error)

	// InvalidateSession invalidates a session in the cache
	InvalidateSession(ctx context.Context, sessionID uuid.UUID) error
}

// CachedSession represents session data stored in Redis
type CachedSession struct {
	SessionID   uuid.UUID `json:"session_id"`
	UserID      uuid.UUID `json:"user_id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	Roles       []string  `json:"roles"`
	RealmID     uuid.UUID `json:"realm_id,omitempty"`
	RealmSlug   string    `json:"realm_slug,omitempty"`
	RealmType   string    `json:"realm_type,omitempty"`
	RoleVersion int       `json:"role_version"` // For cache invalidation
	DeviceInfo  string    `json:"device_info,omitempty"`
	IPAddress   string    `json:"ip_address,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	LastActive  time.Time `json:"last_active"`
}

// IsExpired checks if the session has expired
func (s *CachedSession) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsActive checks if the session is still valid
func (s *CachedSession) IsActive() bool {
	return !s.IsExpired()
}
