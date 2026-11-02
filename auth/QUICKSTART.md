# Auth Middleware - Quick Start Guide

## For Service Developers

### Basic Setup (Backward Compatible)

No changes required if you're already using the auth middleware:

```go
import "github.com/dogukanturhal/platform-shared/auth"

// Your existing code continues to work
config := auth.LoadFromEnv()
middleware := auth.NewMiddleware(config)

router.Use(middleware.RequireAuth())
router.Use(middleware.RequirePermission("core:users:read"))
```

### Advanced Setup (Minimal Token Support)

To support minimal tokens with Redis-based permission resolution:

```go
import (
    "github.com/dogukanturhal/platform-shared/auth"
    "github.com/go-redis/redis/v8"
)

// 1. Initialize Redis client
redisClient := redis.NewClient(&redis.Options{
    Addr:     os.Getenv("REDIS_URL"),
    Password: os.Getenv("REDIS_PASSWORD"),
    DB:       0,
})

// 2. Create cache implementations
permCache := NewRedisPermissionCache(redisClient, 15*time.Minute)
sessionCache := NewRedisSessionCache(redisClient, 15*time.Minute)

// 3. Configure auth middleware
config := &auth.Config{
    JWTSecret:       os.Getenv("JWT_SECRET"),
    PermissionCache: permCache,
    SessionCache:    sessionCache,
}

middleware := auth.NewMiddleware(config)

// 4. Use middleware as before
router.Use(middleware.RequireAuth())
router.Use(middleware.RequirePermission("core:users:read"))
```

### Implementing Cache Interfaces

See `/platform-services/shared/auth/examples/redis_cache_example.go` for a complete example.

#### PermissionResolver

```go
type PermissionResolver interface {
    CheckPermission(ctx context.Context, sessionID, tenantID uuid.UUID, permission string) (bool, error)
    GetUserEffectivePermissions(ctx context.Context, sessionID, tenantID uuid.UUID, roles []string) ([]string, error)
    InvalidatePermissions(ctx context.Context, sessionID uuid.UUID) error
}
```

#### SessionResolver

```go
type SessionResolver interface {
    GetSession(ctx context.Context, sessionID uuid.UUID) (*CachedSession, error)
    InvalidateSession(ctx context.Context, sessionID uuid.UUID) error
}
```

### Using in Handlers

```go
func MyHandler(c *gin.Context) {
    // Get current user (works with both token versions)
    user := auth.GetCurrentUser(c)
    if user == nil {
        c.JSON(401, gin.H{"error": "Unauthorized"})
        return
    }

    // Check permission (automatic token version detection)
    if !user.HasPermission("core:users:write") {
        c.JSON(403, gin.H{"error": "Permission denied"})
        return
    }

    // For explicit cache-based check (optimal for minimal tokens)
    permCache := getPermissionCacheFromContext(c)
    hasPermission, err := user.HasPermissionWithCache(
        c.Request.Context(),
        "core:sensitive:action",
        permCache,
    )
    if err != nil {
        c.JSON(500, gin.H{"error": "Permission check failed"})
        return
    }

    // Your business logic
}
```

## Token Format Detection

The middleware automatically detects token version:

### Legacy Token (v0)
```json
{
    "user_id": "...",
    "tenant_id": "...",
    "session_id": "...",
    "username": "john",
    "email": "john@example.com",
    "roles": ["admin"],
    "permissions": ["core:*"]
}
```

### Minimal Token (v1)
```json
{
    "sub": "...",     // user_id
    "sid": "...",     // session_id
    "tid": "...",     // tenant_id
    "roles": ["admin"],
    "v": 1            // version indicator
}
```

## Migration Checklist

### Phase 1: Deploy Infrastructure
- [ ] Set up Redis cache cluster
- [ ] Implement PermissionResolver interface
- [ ] Implement SessionResolver interface
- [ ] Update service configuration

### Phase 2: Update Services
- [ ] Update auth middleware configuration
- [ ] Inject cache dependencies
- [ ] Test with legacy tokens
- [ ] Deploy to staging

### Phase 3: Enable Minimal Tokens
- [ ] IAM starts issuing minimal tokens
- [ ] Monitor cache performance
- [ ] Test with production traffic
- [ ] Monitor error rates

### Phase 4: Cleanup
- [ ] All services using minimal tokens
- [ ] Remove legacy token support (optional)
- [ ] Update documentation

## Environment Variables

```bash
# Required
JWT_SECRET=your-jwt-secret-key-here

# Optional
JWT_ISSUER=hexxlock-iam
JWT_REQUIRE_VALID_ISSUER=false
INTERNAL_API_KEY=your-internal-api-key
ACCESS_TOKEN_EXPIRY_MINUTES=15

# Redis (for minimal token support)
REDIS_URL=localhost:6379
REDIS_PASSWORD=
REDIS_DB=0
```

## Testing

### Unit Tests

```bash
cd platform-services/shared/auth
go test -v
```

### Integration Tests

```bash
# With mock cache
go test -v -run TestIntegration

# With real Redis
REDIS_URL=localhost:6379 go test -v -tags=integration
```

## Common Issues

### "Session not found" error

**Cause**: Minimal token used but session not in cache

**Solution**: Ensure IAM service populates session cache when issuing tokens

### Permission check is slow

**Cause**: Redis latency or no cache configured

**Solution**:
- Check Redis performance
- Ensure PermissionCache is configured
- Verify network connectivity

### Permissions not updating

**Cause**: Cache not invalidated after role change

**Solution**: Call `InvalidatePermissions()` when roles/permissions change

## Performance Tips

1. **Use Redis Pipelining**: Batch multiple permission checks
2. **Cache Single Checks**: Cache individual permission results
3. **Monitor Cache Hit Rate**: Aim for >95% hit rate
4. **Set Appropriate TTL**: Match token expiry (15 minutes)
5. **Use Redis Cluster**: For high-availability deployments

## Monitoring

Key metrics to track:

```go
// Token version distribution
auth_token_version_0_total  // Legacy
auth_token_version_1_total  // Minimal

// Permission check latency
auth_permission_check_duration_seconds

// Cache performance
auth_permission_cache_hits_total
auth_permission_cache_misses_total
auth_permission_cache_errors_total
```

## Support

- **Documentation**: See `README_MINIMAL_TOKEN.md` for detailed documentation
- **Examples**: See `examples/redis_cache_example.go` for implementation examples
- **Issues**: Create an issue in the ExampleSuite repository
- **Questions**: Contact the Platform Team

## References

- [Auth Middleware Implementation](/platform-services/shared/auth/)
- [Minimal Token Documentation](/platform-services/shared/auth/README_MINIMAL_TOKEN.md)
- [Redis Cache Example](/platform-services/shared/auth/examples/redis_cache_example.go)
- [IAM Service Documentation](/platform-services/iam/README.md)
