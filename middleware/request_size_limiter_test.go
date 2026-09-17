// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupSizeLimiterRouter(config ...RequestSizeLimiterConfig) *gin.Engine {
	router := gin.New()
	router.Use(RequestSizeLimiter(config...))

	router.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.PUT("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	return router
}

func TestRequestSizeLimiter_AllowsSmallRequests(t *testing.T) {
	router := setupSizeLimiterRouter()

	body := bytes.NewBufferString(`{"name":"test"}`)
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/test", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestRequestSizeLimiter_RejectsLargeContentLength(t *testing.T) {
	router := setupSizeLimiterRouter(RequestSizeLimiterConfig{
		MaxBodySize: 1024, // 1KB
	})

	// Create a request with Content-Length larger than the limit
	body := bytes.NewBufferString(strings.Repeat("x", 2048))
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/test", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected status 413, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["error"] != "REQUEST_ENTITY_TOO_LARGE" {
		t.Errorf("expected error code REQUEST_ENTITY_TOO_LARGE, got %v", resp["error"])
	}
}

func TestRequestSizeLimiter_SkipsGETRequests(t *testing.T) {
	router := setupSizeLimiterRouter(RequestSizeLimiterConfig{
		MaxBodySize: 1, // 1 byte
	})

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200 for GET request, got %d", w.Code)
	}
}

func TestRequestSizeLimiter_AllowsRequestsAtExactLimit(t *testing.T) {
	limit := int64(100)
	router := setupSizeLimiterRouter(RequestSizeLimiterConfig{
		MaxBodySize: limit,
	})

	body := bytes.NewBufferString(strings.Repeat("x", int(limit)))
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/test", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200 for request at exact limit, got %d", w.Code)
	}
}

func TestRequestSizeLimiter_CustomErrorMessage(t *testing.T) {
	customMessage := "Upload too big"
	router := setupSizeLimiterRouter(RequestSizeLimiterConfig{
		MaxBodySize:  1024,
		ErrorMessage: customMessage,
	})

	body := bytes.NewBufferString(strings.Repeat("x", 2048))
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/test", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["message"] != customMessage {
		t.Errorf("expected custom message %q, got %q", customMessage, resp["message"])
	}
}

func TestRequestSizeLimiter_DefaultConfig(t *testing.T) {
	cfg := DefaultRequestSizeLimiterConfig()

	if cfg.MaxBodySize != DefaultMaxBodySize {
		t.Errorf("expected default max body size %d, got %d", DefaultMaxBodySize, cfg.MaxBodySize)
	}

	if cfg.MaxBodySize != 10*1024*1024 {
		t.Errorf("expected 10MB default, got %d bytes", cfg.MaxBodySize)
	}
}

func TestRequestSizeLimiter_LargeUploadConfig(t *testing.T) {
	cfg := LargeUploadRequestSizeLimiterConfig()

	if cfg.MaxBodySize != LargeUploadMaxBodySize {
		t.Errorf("expected large upload max body size %d, got %d", LargeUploadMaxBodySize, cfg.MaxBodySize)
	}

	if cfg.MaxBodySize != 50*1024*1024 {
		t.Errorf("expected 50MB upload limit, got %d bytes", cfg.MaxBodySize)
	}
}

func TestRequestSizeLimiter_NegativeMaxBodySizeUsesDefault(t *testing.T) {
	router := setupSizeLimiterRouter(RequestSizeLimiterConfig{
		MaxBodySize: -1,
	})

	// A small request should pass since it falls back to the 10MB default
	body := bytes.NewBufferString(`{"test": true}`)
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/test", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200 with negative config (fallback to default), got %d", w.Code)
	}
}

func TestRequestSizeLimiter_PUTRequestsAreChecked(t *testing.T) {
	router := setupSizeLimiterRouter(RequestSizeLimiterConfig{
		MaxBodySize: 1024,
	})

	body := bytes.NewBufferString(strings.Repeat("x", 2048))
	req, _ := http.NewRequestWithContext(context.Background(), "PUT", "/test", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected status 413 for oversized PUT, got %d", w.Code)
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{500, "500B"},
		{1024, "1KB"},
		{1024 * 1024, "1MB"},
		{10 * 1024 * 1024, "10MB"},
		{50 * 1024 * 1024, "50MB"},
		{1024 * 1024 * 1024, "1.0GB"},
	}

	for _, tt := range tests {
		result := formatBytes(tt.input)
		if result != tt.expected {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}
