// SPDX-License-Identifier: Apache-2.0

// Package middleware provides shared middleware components for Gin-based services.
//
// # Rate Limiter Middleware
//
// The rate limiter implements distributed rate limiting using Redis with a sliding window algorithm.
// It supports configurable limits per endpoint, IP-based and API-key-based rate limiting, and
// graceful degradation when Redis is unavailable.
//
// Basic Usage:
//
//	redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
//	cfg := middleware.RateLimiterConfig{
//	    RedisClient:   redisClient,
//	    KeyPrefix:     "myservice:ratelimit",
//	    DefaultLimit:  100,
//	    DefaultWindow: time.Minute,
//	    SkipOnError:   true,
//	}
//	router.Use(middleware.NewRateLimiter(cfg))
//
// IP-based Rate Limiting:
//
//	cfg := middleware.RateLimiterConfig{
//	    RedisClient:  redisClient,
//	    KeyExtractor: middleware.IPBasedKeyExtractor(),
//	}
//	router.Use(middleware.NewRateLimiter(cfg))
//
// API Key-based Rate Limiting:
//
//	cfg := middleware.RateLimiterConfig{
//	    RedisClient:  redisClient,
//	    KeyExtractor: middleware.APIKeyBasedKeyExtractor("X-API-Key"),
//	}
//	router.Use(middleware.NewRateLimiter(cfg))
//
// Per-Endpoint Custom Limits:
//
//	rules := map[string]struct{Limit int; Window time.Duration}{
//	    "/api/auth/login":    {Limit: 5, Window: time.Minute},
//	    "/api/auth/register": {Limit: 3, Window: 5 * time.Minute},
//	}
//	cfg := middleware.RateLimiterConfig{
//	    RedisClient:    redisClient,
//	    LimitExtractor: middleware.PerEndpointLimitExtractor(rules),
//	}
//	router.Use(middleware.NewRateLimiter(cfg))
//
// Tenant-based Rate Limiting:
//
//	cfg := middleware.RateLimiterConfig{
//	    RedisClient:  redisClient,
//	    KeyExtractor: middleware.TenantBasedKeyExtractor("tenant_id"),
//	}
//	router.Use(middleware.NewRateLimiter(cfg))
//
// Response Headers:
//
// The middleware sets the following headers on all responses:
//   - X-RateLimit-Limit: Maximum requests allowed in the window
//   - X-RateLimit-Remaining: Requests remaining in the current window
//   - X-RateLimit-Reset: Unix timestamp when the window resets
//   - Retry-After: Seconds to wait before retrying (only on 429 responses)
//
// Error Handling:
//
// When Redis is unavailable, behavior depends on SkipOnError:
//   - SkipOnError=true: Allows requests through (graceful degradation)
//   - SkipOnError=false: Rejects requests with 503 Service Unavailable
package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// RateLimiterConfig contains configuration for the rate limiter middleware
type RateLimiterConfig struct {
	// RedisClient is the Redis client for distributed rate limiting
	RedisClient *redis.Client

	// KeyPrefix is the prefix for Redis keys (e.g., "service:ratelimit")
	KeyPrefix string

	// DefaultLimit is the default number of requests allowed per window
	DefaultLimit int

	// DefaultWindow is the default time window for rate limiting
	DefaultWindow time.Duration

	// SkipOnError determines whether to allow requests when Redis is unavailable
	// If true, requests pass through when Redis is down (graceful degradation)
	// If false, requests are rejected with 503 Service Unavailable
	SkipOnError bool

	// KeyExtractor is an optional function to extract the rate limit key from the context
	// If nil, defaults to IP-based rate limiting
	// Example: func(c *gin.Context) string { return c.GetHeader("X-API-Key") }
	KeyExtractor func(*gin.Context) string

	// LimitExtractor is an optional function to extract custom limits per request
	// If nil, uses DefaultLimit and DefaultWindow
	// Return limit=0 to skip rate limiting for the request
	LimitExtractor func(*gin.Context) (limit int, window time.Duration)
}

// DefaultRateLimiterConfig returns a default configuration
func DefaultRateLimiterConfig(redisClient *redis.Client) RateLimiterConfig {
	return RateLimiterConfig{
		RedisClient:    redisClient,
		KeyPrefix:      "ratelimit",
		DefaultLimit:   100,
		DefaultWindow:  time.Minute,
		SkipOnError:    true,
		KeyExtractor:   nil,
		LimitExtractor: nil,
	}
}

// RateLimitResult contains the result of a rate limit check.
type RateLimitResult struct {
	allowed    bool
	remaining  int
	resetAt    time.Time
	retryAfter time.Duration
}

// rateLimitResult is an alias for backward-compat within this package.
type rateLimitResult = RateLimitResult

// slidingWindowScript is a Lua script for atomic sliding window rate limiting
var slidingWindowScript = redis.NewScript(`
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])

-- Remove old entries outside the window
local window_start = now - window
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

-- Count current requests in window
local count = redis.call('ZCARD', key)

if count >= limit then
    -- Get the oldest request to calculate reset time
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local reset_at = now
    if #oldest > 0 then
        reset_at = tonumber(oldest[2]) + window
    end
    return {0, 0, reset_at, count}
end

-- Add current request with unique member (timestamp + random)
local member = now .. ':' .. math.random(1000000)
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, math.ceil(window / 1000) + 1)

local remaining = limit - count - 1
local reset_at = now + window

return {1, remaining, reset_at, count + 1}
`)

// NewRateLimiter creates a new rate limiting middleware
func NewRateLimiter(cfg RateLimiterConfig) gin.HandlerFunc {
	// Validate configuration
	if cfg.RedisClient == nil {
		panic("RateLimiterConfig.RedisClient is required")
	}
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "ratelimit"
	}
	if cfg.DefaultLimit <= 0 {
		cfg.DefaultLimit = 100
	}
	if cfg.DefaultWindow <= 0 {
		cfg.DefaultWindow = time.Minute
	}

	return func(c *gin.Context) {
		// Extract the rate limit key
		key := extractKey(c, cfg.KeyExtractor)

		// Extract custom limits if provided
		limit := cfg.DefaultLimit
		window := cfg.DefaultWindow
		if cfg.LimitExtractor != nil {
			customLimit, customWindow := cfg.LimitExtractor(c)
			if customLimit == 0 {
				// Skip rate limiting for this request
				c.Next()
				return
			}
			if customLimit > 0 {
				limit = customLimit
			}
			if customWindow > 0 {
				window = customWindow
			}
		}

		// Check rate limit
		result, err := checkRateLimit(c.Request.Context(), cfg.RedisClient, cfg.KeyPrefix, key, limit, window)
		if err != nil {
			// Redis error - apply graceful degradation policy
			if cfg.SkipOnError {
				// Allow request to pass through
				c.Next()
				return
			}
			// Reject request with 503
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"success": false,
				"error":   "Rate limiting service temporarily unavailable",
			})
			return
		}

		// Set rate limit headers
		c.Header("X-RateLimit-Limit", strconv.Itoa(limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(result.remaining))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(result.resetAt.Unix(), 10))

		// Check if rate limit exceeded
		if !result.allowed {
			retryAfterSeconds := int64(result.retryAfter.Seconds())
			if retryAfterSeconds < 1 {
				retryAfterSeconds = 1
			}
			c.Header("Retry-After", strconv.FormatInt(retryAfterSeconds, 10))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"success":     false,
				"error":       "Rate limit exceeded",
				"retry_after": result.resetAt.Unix(),
			})
			return
		}

		c.Next()
	}
}

// extractKey extracts the rate limiting key from the request
func extractKey(c *gin.Context, keyExtractor func(*gin.Context) string) string {
	if keyExtractor != nil {
		return keyExtractor(c)
	}

	// Default to IP-based rate limiting
	// Try to get the real IP from X-Forwarded-For header
	ip := c.ClientIP()

	// Add path to key for per-endpoint rate limiting
	path := c.Request.URL.Path

	return fmt.Sprintf("ip:%s:path:%s", ip, path)
}

// checkRateLimit performs the rate limit check using Redis sliding window
func checkRateLimit(ctx context.Context, client *redis.Client, prefix, key string, limit int, window time.Duration) (*rateLimitResult, error) {
	fullKey := fmt.Sprintf("%s:%s", prefix, key)
	now := time.Now().UnixMilli()
	windowMs := window.Milliseconds()

	// Execute the Lua script
	result, err := slidingWindowScript.Run(ctx, client, []string{fullKey}, now, windowMs, limit).Slice()
	if err != nil {
		return nil, fmt.Errorf("rate limit script error: %w", err)
	}

	allowed := result[0].(int64) == 1
	remaining := int(result[1].(int64))
	resetTs := result[2].(int64)

	resetAt := time.UnixMilli(resetTs)
	var retryAfter time.Duration
	if !allowed {
		retryAfter = time.Until(resetAt)
		if retryAfter < 0 {
			retryAfter = 0
		}
	}

	return &rateLimitResult{
		allowed:    allowed,
		remaining:  remaining,
		resetAt:    resetAt,
		retryAfter: retryAfter,
	}, nil
}

// IPBasedKeyExtractor creates a key extractor that uses only the IP address
func IPBasedKeyExtractor() func(*gin.Context) string {
	return func(c *gin.Context) string {
		return fmt.Sprintf("ip:%s", c.ClientIP())
	}
}

// APIKeyBasedKeyExtractor creates a key extractor that uses the API key from a header
func APIKeyBasedKeyExtractor(headerName string) func(*gin.Context) string {
	if headerName == "" {
		headerName = "X-API-Key"
	}
	return func(c *gin.Context) string {
		apiKey := c.GetHeader(headerName)
		if apiKey == "" {
			// Fallback to IP if no API key
			return fmt.Sprintf("ip:%s", c.ClientIP())
		}
		return fmt.Sprintf("apikey:%s", apiKey)
	}
}

// UserBasedKeyExtractor creates a key extractor that uses the user ID from context
func UserBasedKeyExtractor(contextKey string) func(*gin.Context) string {
	if contextKey == "" {
		contextKey = "user_id"
	}
	return func(c *gin.Context) string {
		userID, exists := c.Get(contextKey)
		if !exists || userID == nil {
			// Fallback to IP if no user ID
			return fmt.Sprintf("ip:%s", c.ClientIP())
		}
		return fmt.Sprintf("user:%v", userID)
	}
}

// TenantBasedKeyExtractor creates a key extractor that uses the tenant ID from context
func TenantBasedKeyExtractor(contextKey string) func(*gin.Context) string {
	if contextKey == "" {
		contextKey = "tenant_id"
	}
	return func(c *gin.Context) string {
		tenantID, exists := c.Get(contextKey)
		if !exists || tenantID == nil {
			// Fallback to IP if no tenant ID
			return fmt.Sprintf("ip:%s", c.ClientIP())
		}
		return fmt.Sprintf("tenant:%v", tenantID)
	}
}

// PerEndpointLimitExtractor creates a limit extractor based on endpoint patterns
func PerEndpointLimitExtractor(rules map[string]struct {
	Limit  int
	Window time.Duration
},
) func(*gin.Context) (int, time.Duration) {
	return func(c *gin.Context) (int, time.Duration) {
		path := c.Request.URL.Path
		if rule, exists := rules[path]; exists {
			return rule.Limit, rule.Window
		}
		return 0, 0 // Use default limits
	}
}

// ResetRateLimit resets the rate limit for a specific key
// Useful for testing or admin overrides
func ResetRateLimit(ctx context.Context, client *redis.Client, prefix, key string) error {
	fullKey := fmt.Sprintf("%s:%s", prefix, key)
	return client.Del(ctx, fullKey).Err()
}

// GetRateLimitStatus returns the current rate limit status without incrementing
func GetRateLimitStatus(ctx context.Context, client *redis.Client, prefix, key string, limit int, window time.Duration) (*RateLimitResult, error) {
	fullKey := fmt.Sprintf("%s:%s", prefix, key)
	now := time.Now().UnixMilli()
	windowStart := now - window.Milliseconds()

	// Count current requests in window
	count, err := client.ZCount(ctx, fullKey, fmt.Sprint(windowStart), fmt.Sprint(now)).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("GetRateLimitStatus: ZCount failed: %w", err)
	}

	remaining := limit - int(count)
	if remaining < 0 {
		remaining = 0
	}

	resetAt := time.Now().Add(window)
	allowed := remaining > 0

	return &rateLimitResult{
		allowed:   allowed,
		remaining: remaining,
		resetAt:   resetAt,
	}, nil
}
