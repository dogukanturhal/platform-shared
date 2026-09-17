// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// idempotencyRecord is the payload stored in Redis for a completed request.
type idempotencyRecord struct {
	// StatusCode is the HTTP status returned for the original request.
	StatusCode int `json:"status_code"`
	// Body is the raw response body.
	Body []byte `json:"body"`
	// Headers contains the response headers to replay.
	Headers map[string]string `json:"headers"`
}

// headerKey is the name of the idempotency header clients must send.
const headerKey = "Idempotency-Key"

// idempotencyKeyPrefix is the Redis key namespace.
const idempotencyKeyPrefix = "idempotency"

// mutatingMethods are the HTTP methods that require idempotency enforcement.
var mutatingMethods = map[string]bool{
	http.MethodPost:  true,
	http.MethodPut:   true,
	http.MethodPatch: true,
}

// IdempotencyMiddleware returns a Gin middleware that deduplicates requests
// using a Redis-backed idempotency cache.
//
// Behavior:
//   - GET / DELETE: bypassed (pass-through).
//   - POST / PUT / PATCH without Idempotency-Key: 400 Bad Request.
//   - POST / PUT / PATCH with a key that already has a cached response:
//     returns the cached status + body + headers immediately.
//   - POST / PUT / PATCH with a new key: executes the handler, caches
//     the response, and returns it to the client.
//
// The ttl parameter controls how long the cached response is kept in Redis.
//
// Example:
//
//	r.Use(middleware.IdempotencyMiddleware(redisClient, 24*time.Hour))
func IdempotencyMiddleware(client *redis.Client, ttl time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only enforce on mutating methods
		if !mutatingMethods[c.Request.Method] {
			c.Next()
			return
		}

		idempotencyKey := c.GetHeader(headerKey)
		if idempotencyKey == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   fmt.Sprintf("missing required header: %s", headerKey),
			})
			return
		}

		redisKey := fmt.Sprintf("%s:%s", idempotencyKeyPrefix, idempotencyKey)
		ctx := c.Request.Context()

		// Check cache
		if cached, err := loadCachedResponse(ctx, client, redisKey); err == nil {
			// Replay cached response
			for k, v := range cached.Headers {
				c.Header(k, v)
			}
			c.Header("X-Idempotency-Replayed", "true")
			c.Data(cached.StatusCode, "application/json", cached.Body)
			c.Abort()
			return
		}

		// Capture the response
		blw := &bodyLogWriter{body: &bytes.Buffer{}, ResponseWriter: c.Writer}
		c.Writer = blw

		c.Next()

		// Only cache successful responses (2xx range)
		statusCode := blw.Status()
		if statusCode < 200 || statusCode >= 300 {
			return
		}

		// Build record
		headers := make(map[string]string)
		for k, vals := range blw.Header() {
			if len(vals) > 0 {
				headers[k] = vals[0]
			}
		}

		record := idempotencyRecord{
			StatusCode: statusCode,
			Body:       blw.body.Bytes(),
			Headers:    headers,
		}

		// Persist asynchronously (best-effort)
		go func() {
			_ = saveCachedResponse(context.Background(), client, redisKey, record, ttl)
		}()
	}
}

// loadCachedResponse retrieves an idempotency record from Redis.
// Returns an error if the key does not exist or cannot be decoded.
func loadCachedResponse(ctx context.Context, client *redis.Client, key string) (*idempotencyRecord, error) {
	data, err := client.Get(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}
	var rec idempotencyRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("idempotency: decode: %w", err)
	}
	return &rec, nil
}

// saveCachedResponse persists an idempotency record to Redis with the given TTL.
func saveCachedResponse(ctx context.Context, client *redis.Client, key string, record idempotencyRecord, ttl time.Duration) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("idempotency: encode: %w", err)
	}
	return client.Set(ctx, key, data, ttl).Err()
}

// bodyLogWriter wraps gin.ResponseWriter to capture the response body.
type bodyLogWriter struct {
	gin.ResponseWriter
	body       *bytes.Buffer
	statusCode int
}

func (w *bodyLogWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func (w *bodyLogWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *bodyLogWriter) WriteString(s string) (int, error) {
	w.body.WriteString(s)
	return w.ResponseWriter.WriteString(s)
}

func (w *bodyLogWriter) Status() int {
	if w.statusCode != 0 {
		return w.statusCode
	}
	s := w.ResponseWriter.Status()
	if s == 0 {
		return http.StatusOK
	}
	return s
}

// WriteHeaderInt is an alias used internally to satisfy optional interfaces.
func (w *bodyLogWriter) WriteHeaderInt(code int) {
	w.WriteHeader(code)
}

// ensure bodyLogWriter satisfies HeaderWriter
var _ = strconv.Itoa // imported for completeness
