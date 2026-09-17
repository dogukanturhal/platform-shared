# Minimal Token Support - Implementation Summary

## Overview

The shared auth middleware now supports both **legacy (v0)** and **minimal (v1)** JWT tokens with Redis-based permission resolution.

## Token Versions

### Legacy Token (v0)
- **Size**: ~2KB
- **Contains**: All user data, roles, permissions embedded
- **Use Case**: Backward compatibility
- **Permission Check**: Local (from token)

### Minimal Token (v1)
- **Size**: ~300 bytes
- **Contains**: Only essential claims (user_id, session_id, tenant_id, roles)
- **Use Case**: New authentication flow, reduced token size
- **Permission Check**: Redis cache lookup

## Key Changes

### 1. New Claims Structure

```go
// MinimalClaims - v1 token format
type MinimalClaims struct {
    jwt.RegisteredClaims
    SessionID string   `json:"sid"`
    TenantID  string   `json:"tid"`
    RealmID   string   `json:"rid,omitempty"`
    Roles     []string `json:"roles"`
    Scope     string   `json:"scp,omitempty"`
    Version   int      `json:"v"` // Always 1 for minimal tokens
}

// ParsedClaims - Unified interface for both token versions
type ParsedClaims interface {
    GetUserID() uuid.UUID
    GetSessionID() uuid.UUID
    GetTenantID() uuid.UUID
    GetRealmID() uuid.UUID
    GetRoles() []string
    GetTokenVersion() int
    IsMinimalToken() bool
    GetUsername() string
    GetEmail() string
    GetExpiresAt() int64
}
```

### 2. Permission Resolution Interfaces

```go
// PermissionResolver - Redis-based permission cache
type PermissionResolver interface {
    CheckPermission(ctx context.Context, sessionID, tenantID uuid.UUID, permission string) (bool, error)
    GetUserEffectivePermissions(ctx context.Context, sessionID, tenantID uuid.UUID, roles []string) ([]string, error)
    InvalidatePermissions(ctx context.Context, sessionID uuid.UUID) error
}

// SessionResolver - Redis-based session cache
type SessionResolver interface {
    GetSession(ctx context.Context, sessionID uuid.UUID) (*CachedSession, error)
    InvalidateSession(ctx context.Context, sessionID uuid.UUID) error
}
```

### 3. Updated CurrentUser

```go
type CurrentUser struct {
    // Existing fields...
    ID          uuid.UUID
    TenantID    uuid.UUID
    Username    string
    Email       string
    Roles       []string
    Permissions []string
    SessionID   uuid.UUID

    // New fields for minimal token support
    TokenVersion      int  // 0 = legacy, 1 = minimal
    RoleVersion       int  // For cache invalidation
    PermissionsLoaded bool // True if permissions resolved from cache
}

// HasPermissionWithCache - Redis-aware permission check
func (u *CurrentUser) HasPermissionWithCache(ctx context.Context, permission string, cache PermissionResolver) (bool, error)

// LazyLoadPermissions - Load permissions from Redis if needed
func (u *CurrentUser) LazyLoadPermissions(ctx context.Context, permCache PermissionResolver) error
```

### 4. Updated Middleware Configuration

```go
config := &auth.Config{
    JWTSecret:       "your-secret",
    PermissionCache: permissionResolver, // Implement PermissionResolver interface
    SessionCache:    sessionResolver,    // Implement SessionResolver interface
}

middleware := auth.NewMiddleware(config)
```

### 5. Gateway Auth Headers

New headers from APISIX:

```
X-User-ID: <uuid>
X-Tenant-ID: <uuid>
X-Session-ID: <uuid>          # NEW
X-User-Roles: role1,role2     # Changed from X-User-Role
X-Role-Version: 1             # NEW - for cache invalidation
X-Username: john              # NEW
X-User-Email: john@example.com # NEW
X-Realm-ID: <uuid>
X-Realm-Slug: main
X-Realm-Type: tenant
```

## Usage Examples

### Basic Usage (Backward Compatible)

```go
// Existing code continues to work
r.Use(authMiddleware.RequireAuth())
r.Use(authMiddleware.RequirePermission("core:users:read"))

// Permission check in handlers
user := auth.GetCurrentUser(c)
if user.HasPermission("core:users:write") {
    // Handle write operation
}
```

### With Permission Cache (Optimal for Minimal Tokens)

```go
// In your service initialization
permCache := NewRedisPermissionCache(redisClient)
sessionCache := NewRedisSessionCache(redisClient)

config := &auth.Config{
    JWTSecret:       os.Getenv("JWT_SECRET"),
    PermissionCache: permCache,
    SessionCache:    sessionCache,
}

middleware := auth.NewMiddleware(config)

// Use middleware normally
r.Use(middleware.RequireAuth())
r.Use(middleware.RequirePermission("core:users:read"))
```

### Explicit Permission Check with Cache

```go
func MyHandler(c *gin.Context) {
    user := auth.GetCurrentUser(c)
    permCache := getPermissionCacheFromContext(c) // Your implementation

    hasPermission, err := user.HasPermissionWithCache(
        c.Request.Context(),
        "core:sensitive:action",
        permCache,
    )

    if err != nil {
        c.JSON(500, gin.H{"error": "Permission check failed"})
        return
    }

    if !hasPermission {
        c.JSON(403, gin.H{"error": "Permission denied"})
        return
    }

    // Process request
}
```

## Migration Guide

### For Service Developers

**No changes required** if:
- You use `RequireAuth()` middleware
- You use `RequirePermission()` middleware
- You check permissions via `user.HasPermission()`

**Optional optimization** (recommended for minimal tokens):
- Inject `PermissionCache` and `SessionCache` into middleware config
- Use `user.HasPermissionWithCache()` for explicit checks

### For Platform Team

**Required changes**:
1. Implement `PermissionResolver` interface (Redis-based)
2. Implement `SessionResolver` interface (Redis-based)
3. Update APISIX to forward new headers
4. Update IAM service to issue minimal tokens
5. Deploy Redis cache layer

## Performance Considerations

### Legacy Token (v0)
- **Pros**: No external dependencies, all data in token
- **Cons**: Large token size (~2KB), more bandwidth
- **Permission Check**: O(1) local check

### Minimal Token (v1)
- **Pros**: Small token size (~300 bytes), reduced bandwidth
- **Cons**: Requires Redis cache lookup
- **Permission Check**: O(1) Redis cache lookup (~1ms)

### Caching Strategy

```go
// Permission cache keys
session:permissions:{session_id}:{tenant_id} → []string (all permissions)
session:permission:{session_id}:{tenant_id}:{permission} → bool (single check)

// TTL: Match token expiry (15 minutes)
// Invalidation: On role change, permission change, or logout
```

## Error Handling

```go
// Permission check with error handling
hasPermission, err := user.HasPermissionWithCache(ctx, perm, cache)
if err != nil {
    // Log error (don't expose details to user)
    log.Printf("Permission check error: %v", err)

    // Return 500 - cache failure is a system error
    return errors.NewAPIError("PERMISSION_CHECK_FAILED", 500, "Permission check failed")
}

if !hasPermission {
    // Return 403 - user doesn't have permission
    return errors.NewAPIError("PERMISSION_DENIED", 403, "Permission denied")
}
```

## Testing

### Unit Tests

```go
func TestMinimalTokenValidation(t *testing.T) {
    config := &auth.Config{
        JWTSecret: "test-secret",
    }
    validator := auth.NewTokenValidator(config)

    // Test minimal token parsing
    token := createMinimalToken()
    claims, err := validator.ValidateAccessToken(token)

    assert.NoError(t, err)
    assert.True(t, claims.IsMinimalToken())
    assert.Equal(t, 1, claims.GetTokenVersion())
}
```

### Integration Tests

```go
func TestPermissionCheckWithCache(t *testing.T) {
    // Setup mock cache
    mockCache := &MockPermissionCache{
        permissions: map[string]bool{
            "core:users:read": true,
        },
    }

    user := &auth.CurrentUser{
        TokenVersion: 1,
        SessionID:    uuid.New(),
        TenantID:     uuid.New(),
    }

    hasPermission, err := user.HasPermissionWithCache(
        context.Background(),
        "core:users:read",
        mockCache,
    )

    assert.NoError(t, err)
    assert.True(t, hasPermission)
}
```

## Monitoring

Key metrics to track:

```go
// Permission cache hit rate
permission_cache_hits / permission_cache_total

// Permission check latency
histogram(permission_check_duration_ms)

// Cache failures
counter(permission_cache_errors)

// Token version distribution
gauge(token_version_0_count) // Legacy
gauge(token_version_1_count) // Minimal
```

## Rollout Strategy

### Phase 1: Deploy Infrastructure
1. Deploy Redis cache layer
2. Implement PermissionResolver and SessionResolver
3. Deploy updated shared auth library
4. Update all services to inject cache dependencies

### Phase 2: Dual Token Support
1. IAM issues both v0 (legacy) and v1 (minimal) tokens
2. All services support both token versions
3. Monitor metrics and error rates

### Phase 3: Migrate to Minimal Tokens
1. Gradually increase percentage of v1 tokens issued
2. Monitor cache performance and adjust TTLs
3. Eventually deprecate v0 tokens

### Phase 4: Cleanup
1. Remove v0 token support
2. Simplify code paths
3. Update documentation

## Security Considerations

1. **Token Verification**: Both token versions are cryptographically verified
2. **Cache Poisoning**: Use authenticated Redis connections
3. **Cache Invalidation**: Invalidate on role/permission changes
4. **Session Validation**: Check session expiry from cache
5. **Permission Scope**: Maintain least-privilege principle

## Troubleshooting

### Common Issues

**Issue**: Permission check fails with "session not found"
```
Solution: Ensure session cache is populated when token is issued
```

**Issue**: Permission check is slow
```
Solution: Check Redis latency, ensure proper indexing, adjust TTLs
```

**Issue**: Permissions not updating after role change
```
Solution: Ensure cache invalidation is triggered on role changes
```

## References

- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [Redis Caching Patterns](https://redis.io/topics/patterns)
- [IAM Service Documentation](../iam/README.md)
