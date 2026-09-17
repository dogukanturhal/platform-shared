// SPDX-License-Identifier: Apache-2.0

// Package examples provides reference implementations for auth caching patterns.
package examples

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/dogukanturhal/platform-shared/auth"
)

// RedisPermissionCache implements auth.PermissionResolver
type RedisPermissionCache struct {
	client *redis.Client
	ttl    time.Duration
}

// NewRedisPermissionCache creates a new Redis-based permission cache
func NewRedisPermissionCache(client *redis.Client, ttl time.Duration) *RedisPermissionCache {
	return &RedisPermissionCache{
		client: client,
		ttl:    ttl,
	}
}

// CheckPermission checks if a session has a specific permission
func (c *RedisPermissionCache) CheckPermission(ctx context.Context, sessionID, tenantID uuid.UUID, permission string) (bool, error) {
	// Try single permission cache first (optimization)
	key := fmt.Sprintf("session:permission:%s:%s:%s", sessionID, tenantID, permission)
	result, err := c.client.Get(ctx, key).Result()
	if err == nil {
		return result == "1", nil
	}

	// If not cached, load all permissions and check
	permissions, err := c.GetUserEffectivePermissions(ctx, sessionID, tenantID, nil)
	if err != nil {
		return false, fmt.Errorf("CheckPermission: GetUserEffectivePermissions failed: %w", err)
	}

	// Check permission locally
	hasPermission := false
	for _, p := range permissions {
		if p == permission || p == "*" {
			hasPermission = true
			break
		}
		// Check wildcard patterns
		if matchPermission(p, permission) {
			hasPermission = true
			break
		}
	}

	// Cache the result for faster subsequent checks
	value := "0"
	if hasPermission {
		value = "1"
	}
	c.client.Set(ctx, key, value, c.ttl)

	return hasPermission, nil
}

// GetUserEffectivePermissions loads all effective permissions for a session
func (c *RedisPermissionCache) GetUserEffectivePermissions(ctx context.Context, sessionID, tenantID uuid.UUID, roles []string) ([]string, error) {
	key := fmt.Sprintf("session:permissions:%s:%s", sessionID, tenantID)

	// Try to get from cache
	result, err := c.client.Get(ctx, key).Result()
	if err == nil {
		var permissions []string
		if err := json.Unmarshal([]byte(result), &permissions); err == nil {
			return permissions, nil
		}
	}

	// If not cached, compute effective permissions from roles
	// This would typically call the IAM service or query the database
	permissions := c.computeEffectivePermissions(ctx, tenantID, roles)

	// Cache the result
	data, _ := json.Marshal(permissions)
	c.client.Set(ctx, key, data, c.ttl)

	return permissions, nil
}

// InvalidatePermissions invalidates the permission cache for a session
func (c *RedisPermissionCache) InvalidatePermissions(ctx context.Context, sessionID uuid.UUID) error {
	// Delete all permission-related keys for this session
	pattern := fmt.Sprintf("session:permission*:%s:*", sessionID)
	keys, err := c.client.Keys(ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("InvalidatePermissions: %w", err)
	}

	if len(keys) > 0 {
		return c.client.Del(ctx, keys...).Err()
	}

	return nil
}

// computeEffectivePermissions computes permissions from roles
// This is a simplified example - real implementation would query IAM service
func (c *RedisPermissionCache) computeEffectivePermissions(ctx context.Context, tenantID uuid.UUID, roles []string) []string {
	permissions := make([]string, 0)

	for _, role := range roles {
		// Get permissions for this role from cache or database
		roleKey := fmt.Sprintf("role:permissions:%s:%s", tenantID, role)
		result, err := c.client.Get(ctx, roleKey).Result()
		if err == nil {
			var rolePerms []string
			if err := json.Unmarshal([]byte(result), &rolePerms); err == nil {
				permissions = append(permissions, rolePerms...)
			}
		}
	}

	// Remove duplicates
	permissions = deduplicate(permissions)

	return permissions
}

// RedisSessionCache implements auth.SessionResolver
type RedisSessionCache struct {
	client *redis.Client
	ttl    time.Duration
}

// NewRedisSessionCache creates a new Redis-based session cache
func NewRedisSessionCache(client *redis.Client, ttl time.Duration) *RedisSessionCache {
	return &RedisSessionCache{
		client: client,
		ttl:    ttl,
	}
}

// GetSession retrieves full session details from cache
func (c *RedisSessionCache) GetSession(ctx context.Context, sessionID uuid.UUID) (*auth.CachedSession, error) {
	key := fmt.Sprintf("session:%s", sessionID)

	result, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("session not found: %s", sessionID)
		}
		return nil, fmt.Errorf("GetSession: %w", err)
	}

	var session auth.CachedSession
	if err := json.Unmarshal([]byte(result), &session); err != nil {
		return nil, fmt.Errorf("GetSession: %w", err)
	}

	// Validate session hasn't expired
	if session.IsExpired() {
		// Clean up expired session
		c.client.Del(ctx, key)
		return nil, fmt.Errorf("session expired: %s", sessionID)
	}

	return &session, nil
}

// InvalidateSession invalidates a session in the cache
func (c *RedisSessionCache) InvalidateSession(ctx context.Context, sessionID uuid.UUID) error {
	key := fmt.Sprintf("session:%s", sessionID)
	return c.client.Del(ctx, key).Err()
}

// SetSession stores a session in the cache (helper method for IAM service)
func (c *RedisSessionCache) SetSession(ctx context.Context, session *auth.CachedSession) error {
	key := fmt.Sprintf("session:%s", session.SessionID)

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("SetSession: Marshal failed: %w", err)
	}

	// Calculate TTL based on session expiry
	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		ttl = c.ttl
	}

	return c.client.Set(ctx, key, data, ttl).Err()
}

// Helper functions

func matchPermission(pattern, permission string) bool {
	// Simplified wildcard matching
	// Real implementation should use the matchWildcard function from context.go
	if pattern == "*" {
		return true
	}
	// Add more sophisticated wildcard matching here
	return pattern == permission
}

func deduplicate(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(slice))

	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

// ExampleUsage demonstrates how to wire the Redis-backed auth caches in a service.
func ExampleUsage() {
	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	// Create cache implementations
	_ = NewRedisPermissionCache(redisClient, 15*time.Minute)
	_ = NewRedisSessionCache(redisClient, 15*time.Minute)

	// Configure auth middleware
	config := &auth.Config{
		JWTSecret: "your-jwt-secret",
	}

	middleware := auth.NewMiddleware(config)

	// Use in Gin routes
	_ = middleware // Use in your router setup
}
