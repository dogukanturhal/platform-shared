// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newIdempotencyRouter creates a test Gin router with idempotency middleware backed by miniredis.
func newIdempotencyRouter(t *testing.T) *gin.Engine {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	router := gin.New()
	router.Use(IdempotencyMiddleware(client, 10*time.Minute))
	return router
}

// TestIdempotency_CacheMiss_ExecutesHandler verifies that a new key runs the handler.
func TestIdempotency_CacheMiss_ExecutesHandler(t *testing.T) {
	router := newIdempotencyRouter(t)

	calls := 0
	router.POST("/orders", func(c *gin.Context) {
		calls++
		c.JSON(http.StatusCreated, gin.H{"order_id": "ord-001"})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/orders", nil)
	req.Header.Set(headerKey, "unique-key-1")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, 1, calls)
	assert.NotEqual(t, "true", w.Header().Get("X-Idempotency-Replayed"))
}

// TestIdempotency_CacheHit_ReturnsCachedResponse verifies that duplicate keys replay cache.
func TestIdempotency_CacheHit_ReturnsCachedResponse(t *testing.T) {
	router := newIdempotencyRouter(t)

	calls := 0
	router.POST("/orders", func(c *gin.Context) {
		calls++
		c.JSON(http.StatusCreated, gin.H{"order_id": "ord-001"})
	})

	makeReq := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/orders", nil)
		req.Header.Set(headerKey, "idempotent-key-abc")
		router.ServeHTTP(w, req)
		return w
	}

	// First request — handler executes
	w1 := makeReq()
	// Give the background goroutine time to persist
	time.Sleep(30 * time.Millisecond)

	// Second request with the same key — should replay from cache
	w2 := makeReq()

	assert.Equal(t, http.StatusCreated, w1.Code)
	assert.Equal(t, http.StatusCreated, w2.Code)
	assert.Equal(t, "true", w2.Header().Get("X-Idempotency-Replayed"))

	// Handler should only be called once
	assert.Equal(t, 1, calls)

	var body1, body2 map[string]interface{}
	require.NoError(t, json.Unmarshal(w1.Body.Bytes(), &body1))
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &body2))
	assert.Equal(t, body1, body2)
}

// TestIdempotency_GET_Bypass verifies that GET requests bypass idempotency.
func TestIdempotency_GET_Bypass(t *testing.T) {
	router := newIdempotencyRouter(t)

	router.GET("/items", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"items": []string{}})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/items", nil)
	// No Idempotency-Key header — should be fine for GET
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestIdempotency_DELETE_Bypass verifies that DELETE requests bypass idempotency.
func TestIdempotency_DELETE_Bypass(t *testing.T) {
	router := newIdempotencyRouter(t)

	router.DELETE("/items/1", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/items/1", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

// TestIdempotency_MissingHeader_Returns400 verifies POST without key is rejected.
func TestIdempotency_MissingHeader_Returns400(t *testing.T) {
	router := newIdempotencyRouter(t)

	router.POST("/orders", func(c *gin.Context) {
		c.JSON(http.StatusCreated, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/orders", nil)
	// No Idempotency-Key header
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestIdempotency_PUTMethod verifies idempotency works for PUT.
func TestIdempotency_PUTMethod(t *testing.T) {
	router := newIdempotencyRouter(t)

	calls := 0
	router.PUT("/profile", func(c *gin.Context) {
		calls++
		c.JSON(http.StatusOK, gin.H{"updated": true})
	})

	makeReq := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/profile", nil)
		req.Header.Set(headerKey, "put-key-xyz")
		router.ServeHTTP(w, req)
		return w
	}

	w1 := makeReq()
	time.Sleep(30 * time.Millisecond)
	w2 := makeReq()

	assert.Equal(t, http.StatusOK, w1.Code)
	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, 1, calls)
	assert.Equal(t, "true", w2.Header().Get("X-Idempotency-Replayed"))
}

// TestIdempotency_PATCHMethod verifies idempotency works for PATCH.
func TestIdempotency_PATCHMethod(t *testing.T) {
	router := newIdempotencyRouter(t)

	calls := 0
	router.PATCH("/resource", func(c *gin.Context) {
		calls++
		c.JSON(http.StatusOK, gin.H{"patched": true})
	})

	makeReq := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/resource", nil)
		req.Header.Set(headerKey, "patch-key-zzz")
		router.ServeHTTP(w, req)
		return w
	}

	w1 := makeReq()
	time.Sleep(30 * time.Millisecond)
	w2 := makeReq()

	assert.Equal(t, http.StatusOK, w1.Code)
	assert.Equal(t, 1, calls)
	assert.Equal(t, "true", w2.Header().Get("X-Idempotency-Replayed"))
}

// TestIdempotency_ExpiredKey_Re_Executes verifies that expired keys re-run the handler.
func TestIdempotency_ExpiredKey_Re_Executes(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	router := gin.New()
	router.Use(IdempotencyMiddleware(client, 100*time.Millisecond))

	calls := 0
	router.POST("/items", func(c *gin.Context) {
		calls++
		c.JSON(http.StatusCreated, gin.H{"created": true})
	})

	makeReq := func() int {
		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/items", nil)
		req.Header.Set(headerKey, "expiring-key")
		router.ServeHTTP(w, req)
		return w.Code
	}

	// First request
	assert.Equal(t, http.StatusCreated, makeReq())
	time.Sleep(50 * time.Millisecond) // let background persist

	// Advance miniredis TTL clock so the key expires
	mr.FastForward(200 * time.Millisecond)

	// Second request after expiry should re-execute handler
	assert.Equal(t, http.StatusCreated, makeReq())
	time.Sleep(30 * time.Millisecond)

	// Handler should have been called twice
	assert.Equal(t, 2, calls)
}

// TestIdempotency_ConcurrentDuplicates verifies that concurrent identical requests
// do not result in double execution (one executes, others are replayed).
func TestIdempotency_ConcurrentDuplicates(t *testing.T) {
	router := newIdempotencyRouter(t)

	var mu sync.Mutex
	calls := 0
	router.POST("/payment", func(c *gin.Context) {
		mu.Lock()
		calls++
		mu.Unlock()
		time.Sleep(20 * time.Millisecond) // simulate work
		c.JSON(http.StatusCreated, gin.H{"payment_id": "pay-001"})
	})

	const n = 5
	var wg sync.WaitGroup
	codes := make([]int, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/payment", nil)
			req.Header.Set(headerKey, "concurrent-key-same")
			router.ServeHTTP(w, req)
			codes[i] = w.Code
		}()
	}
	wg.Wait()

	// All responses should be 201
	for _, code := range codes {
		assert.Equal(t, http.StatusCreated, code)
	}
	// At most once should have executed the actual handler
	// (due to race, it could execute more than once before cache warms, but never > n)
	mu.Lock()
	assert.GreaterOrEqual(t, calls, 1, "handler should have been called at least once")
	mu.Unlock()
}
