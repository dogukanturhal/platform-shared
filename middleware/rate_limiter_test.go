// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

const testRemoteAddr = "192.168.1.1:1234"

// setupTestRedis creates a test Redis client
// For actual tests, use a real Redis instance or redis-mock
func setupTestRedis(t *testing.T) *redis.Client {
	t.Helper()

	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   15, // Use a separate DB for testing
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		t.Skipf("Redis not available: %v", err)
	}

	// Clean up test DB
	client.FlushDB(ctx)

	// Register cleanup
	t.Cleanup(func() {
		client.FlushDB(context.Background())
		_ = client.Close()
	})

	return client
}

func TestNewRateLimiter_PanicOnNilClient(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when RedisClient is nil")
		}
	}()

	cfg := RateLimiterConfig{
		RedisClient: nil,
	}
	NewRateLimiter(cfg)
}

func TestRateLimiter_BasicFunctionality(t *testing.T) {
	client := setupTestRedis(t)
	gin.SetMode(gin.TestMode)

	cfg := RateLimiterConfig{
		RedisClient:   client,
		KeyPrefix:     "test",
		DefaultLimit:  5,
		DefaultWindow: time.Second,
		SkipOnError:   false,
	}

	router := gin.New()
	router.Use(NewRateLimiter(cfg))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Test that first 5 requests succeed
	for i := 0; i < 5; i++ {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
		req.RemoteAddr = testRemoteAddr
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d failed with status %d, expected 200", i+1, w.Code)
		}

		// Check rate limit headers
		if w.Header().Get("X-RateLimit-Limit") != "5" {
			t.Errorf("Expected X-RateLimit-Limit: 5, got %s", w.Header().Get("X-RateLimit-Limit"))
		}
	}

	// 6th request should be rate limited
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.RemoteAddr = testRemoteAddr
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w.Code)
	}

	if w.Header().Get("Retry-After") == "" {
		t.Error("Expected Retry-After header to be set")
	}
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	client := setupTestRedis(t)
	gin.SetMode(gin.TestMode)

	cfg := RateLimiterConfig{
		RedisClient:   client,
		KeyPrefix:     "test",
		DefaultLimit:  2,
		DefaultWindow: time.Second,
		SkipOnError:   false,
	}

	router := gin.New()
	router.Use(NewRateLimiter(cfg))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Test IP 1
	for i := 0; i < 2; i++ {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
		req.RemoteAddr = testRemoteAddr
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("IP1 request %d failed with status %d", i+1, w.Code)
		}
	}

	// 3rd request from IP 1 should fail
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.RemoteAddr = testRemoteAddr
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429 for IP1, got %d", w.Code)
	}

	// Test IP 2 should still work
	for i := 0; i < 2; i++ {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.2:1234"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("IP2 request %d failed with status %d", i+1, w.Code)
		}
	}
}

func TestRateLimiter_WindowReset(t *testing.T) {
	client := setupTestRedis(t)
	gin.SetMode(gin.TestMode)

	cfg := RateLimiterConfig{
		RedisClient:   client,
		KeyPrefix:     "test",
		DefaultLimit:  2,
		DefaultWindow: 500 * time.Millisecond,
		SkipOnError:   false,
	}

	router := gin.New()
	router.Use(NewRateLimiter(cfg))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Consume the limit
	for i := 0; i < 2; i++ {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
		req.RemoteAddr = testRemoteAddr
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d failed with status %d", i+1, w.Code)
		}
	}

	// Should be rate limited
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.RemoteAddr = testRemoteAddr
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w.Code)
	}

	// Wait for window to expire
	time.Sleep(600 * time.Millisecond)

	// Should work again
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.RemoteAddr = testRemoteAddr
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 after window reset, got %d", w.Code)
	}
}

func TestRateLimiter_CustomKeyExtractor(t *testing.T) {
	client := setupTestRedis(t)
	gin.SetMode(gin.TestMode)

	cfg := RateLimiterConfig{
		RedisClient:   client,
		KeyPrefix:     "test",
		DefaultLimit:  2,
		DefaultWindow: time.Second,
		SkipOnError:   false,
		KeyExtractor:  APIKeyBasedKeyExtractor("X-API-Key"),
	}

	router := gin.New()
	router.Use(NewRateLimiter(cfg))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Test with API key 1
	for i := 0; i < 2; i++ {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
		req.Header.Set("X-API-Key", "key-123")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d with key-123 failed with status %d", i+1, w.Code)
		}
	}

	// 3rd request with same key should fail
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("X-API-Key", "key-123")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429 for key-123, got %d", w.Code)
	}

	// Different API key should work
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("X-API-Key", "key-456")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for key-456, got %d", w.Code)
	}
}

func TestRateLimiter_CustomLimitExtractor(t *testing.T) {
	client := setupTestRedis(t)
	gin.SetMode(gin.TestMode)

	cfg := RateLimiterConfig{
		RedisClient:   client,
		KeyPrefix:     "test",
		DefaultLimit:  5,
		DefaultWindow: time.Second,
		SkipOnError:   false,
		LimitExtractor: PerEndpointLimitExtractor(map[string]struct {
			Limit  int
			Window time.Duration
		}{
			"/restricted": {Limit: 2, Window: time.Second},
		}),
	}

	router := gin.New()
	router.Use(NewRateLimiter(cfg))
	router.GET("/restricted", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "restricted"})
	})
	router.GET("/normal", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "normal"})
	})

	// Test restricted endpoint with limit of 2
	for i := 0; i < 2; i++ {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/restricted", nil)
		req.RemoteAddr = testRemoteAddr
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Restricted request %d failed with status %d", i+1, w.Code)
		}

		if w.Header().Get("X-RateLimit-Limit") != "2" {
			t.Errorf("Expected X-RateLimit-Limit: 2, got %s", w.Header().Get("X-RateLimit-Limit"))
		}
	}

	// 3rd request should fail
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/restricted", nil)
	req.RemoteAddr = testRemoteAddr
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429 for restricted endpoint, got %d", w.Code)
	}

	// Normal endpoint should use default limit of 5
	for i := 0; i < 5; i++ {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/normal", nil)
		req.RemoteAddr = testRemoteAddr
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Normal request %d failed with status %d", i+1, w.Code)
		}
	}
}

func TestRateLimiter_SkipOnError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create client with invalid address
	invalidClient := redis.NewClient(&redis.Options{
		Addr: "invalid:6379",
	})

	cfg := RateLimiterConfig{
		RedisClient:   invalidClient,
		KeyPrefix:     "test",
		DefaultLimit:  5,
		DefaultWindow: time.Second,
		SkipOnError:   true, // Allow requests when Redis is down
	}

	router := gin.New()
	router.Use(NewRateLimiter(cfg))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.RemoteAddr = testRemoteAddr
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should succeed because SkipOnError is true
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 when SkipOnError is true, got %d", w.Code)
	}
}

func TestRateLimiter_FailOnError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create client with invalid address
	invalidClient := redis.NewClient(&redis.Options{
		Addr: "invalid:6379",
	})

	cfg := RateLimiterConfig{
		RedisClient:   invalidClient,
		KeyPrefix:     "test",
		DefaultLimit:  5,
		DefaultWindow: time.Second,
		SkipOnError:   false, // Reject requests when Redis is down
	}

	router := gin.New()
	router.Use(NewRateLimiter(cfg))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.RemoteAddr = testRemoteAddr
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should fail with 503 because SkipOnError is false
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503 when SkipOnError is false, got %d", w.Code)
	}
}

func TestRateLimiter_Headers(t *testing.T) {
	client := setupTestRedis(t)
	gin.SetMode(gin.TestMode)

	cfg := RateLimiterConfig{
		RedisClient:   client,
		KeyPrefix:     "test",
		DefaultLimit:  5,
		DefaultWindow: time.Second,
		SkipOnError:   false,
	}

	router := gin.New()
	router.Use(NewRateLimiter(cfg))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.RemoteAddr = testRemoteAddr
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	// Check headers
	if limit := w.Header().Get("X-RateLimit-Limit"); limit != "5" {
		t.Errorf("Expected X-RateLimit-Limit: 5, got %s", limit)
	}

	if remaining := w.Header().Get("X-RateLimit-Remaining"); remaining != "4" {
		t.Errorf("Expected X-RateLimit-Remaining: 4, got %s", remaining)
	}

	if reset := w.Header().Get("X-RateLimit-Reset"); reset == "" {
		t.Error("Expected X-RateLimit-Reset header to be set")
	}
}

func TestResetRateLimit(t *testing.T) {
	client := setupTestRedis(t)
	gin.SetMode(gin.TestMode)

	cfg := RateLimiterConfig{
		RedisClient:   client,
		KeyPrefix:     "test",
		DefaultLimit:  2,
		DefaultWindow: time.Second,
		SkipOnError:   false,
	}

	router := gin.New()
	router.Use(NewRateLimiter(cfg))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Consume the limit
	for i := 0; i < 2; i++ {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
		req.RemoteAddr = testRemoteAddr
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d failed with status %d", i+1, w.Code)
		}
	}

	// Should be rate limited
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.RemoteAddr = testRemoteAddr
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w.Code)
	}

	// Reset the rate limit
	key := "ip:192.168.1.1:path:/test"
	err := ResetRateLimit(context.Background(), client, "test", key)
	if err != nil {
		t.Fatalf("Failed to reset rate limit: %v", err)
	}

	// Should work again
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.RemoteAddr = testRemoteAddr
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 after reset, got %d", w.Code)
	}
}

func TestGetRateLimitStatus(t *testing.T) {
	client := setupTestRedis(t)
	ctx := context.Background()

	// Simulate some requests
	key := "test:ip:192.168.1.1"
	now := time.Now().UnixMilli()
	client.ZAdd(ctx, key, redis.Z{Score: float64(now), Member: fmt.Sprintf("%d:1", now)})

	status, err := GetRateLimitStatus(ctx, client, "test", "ip:192.168.1.1", 5, time.Second)
	if err != nil {
		t.Fatalf("GetRateLimitStatus failed: %v", err)
	}

	if !status.allowed {
		t.Error("Expected allowed to be true")
	}

	if status.remaining != 4 {
		t.Errorf("Expected remaining to be 4, got %d", status.remaining)
	}
}

func TestKeyExtractors(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name         string
		extractor    func(*gin.Context) string
		setupContext func(*gin.Context)
		expectedKey  string
	}{
		{
			name:      "IPBasedKeyExtractor",
			extractor: IPBasedKeyExtractor(),
			setupContext: func(_ *gin.Context) {
				// ClientIP will be extracted from RemoteAddr
			},
			expectedKey: "ip:",
		},
		{
			name:      "UserBasedKeyExtractor",
			extractor: UserBasedKeyExtractor("user_id"),
			setupContext: func(c *gin.Context) {
				c.Set("user_id", "user-123")
			},
			expectedKey: "user:user-123",
		},
		{
			name:      "TenantBasedKeyExtractor",
			extractor: TenantBasedKeyExtractor("tenant_id"),
			setupContext: func(c *gin.Context) {
				c.Set("tenant_id", "tenant-456")
			},
			expectedKey: "tenant:tenant-456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
			tt.setupContext(c)

			key := tt.extractor(c)
			if key != tt.expectedKey {
				// For IP-based, we can't predict the exact IP, so just check prefix
				if tt.name == "IPBasedKeyExtractor" && len(key) > 3 && key[:3] == "ip:" {
					return
				}
				t.Errorf("Expected key to contain %s, got %s", tt.expectedKey, key)
			}
		})
	}
}
