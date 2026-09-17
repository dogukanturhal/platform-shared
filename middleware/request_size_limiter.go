// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

const (
	// DefaultMaxBodySize is the default maximum request body size (10MB)
	DefaultMaxBodySize int64 = 10 * 1024 * 1024

	// LargeUploadMaxBodySize is the maximum size for file upload routes (50MB)
	LargeUploadMaxBodySize int64 = 50 * 1024 * 1024
)

// RequestSizeLimiterConfig contains configuration for the request size limiter middleware
type RequestSizeLimiterConfig struct {
	// MaxBodySize is the maximum allowed request body size in bytes.
	// Default: 10MB (10 * 1024 * 1024)
	MaxBodySize int64

	// ErrorMessage is the message returned when the request body exceeds the limit.
	// If empty, a default message including the limit will be used.
	ErrorMessage string
}

// DefaultRequestSizeLimiterConfig returns the default configuration with a 10MB limit
func DefaultRequestSizeLimiterConfig() RequestSizeLimiterConfig {
	return RequestSizeLimiterConfig{
		MaxBodySize:  DefaultMaxBodySize,
		ErrorMessage: "",
	}
}

// LargeUploadRequestSizeLimiterConfig returns configuration for file upload routes with a 50MB limit
func LargeUploadRequestSizeLimiterConfig() RequestSizeLimiterConfig {
	return RequestSizeLimiterConfig{
		MaxBodySize:  LargeUploadMaxBodySize,
		ErrorMessage: "",
	}
}

// RequestSizeLimiter returns a middleware that rejects requests whose body
// exceeds the configured maximum size. It checks the Content-Length header
// first for an early rejection, then wraps the request body with
// http.MaxBytesReader to enforce the limit during actual reading.
//
// Usage:
//
//	router := gin.New()
//
//	// Default 10MB limit for all routes
//	router.Use(middleware.RequestSizeLimiter())
//
//	// 50MB limit for file upload routes
//	uploadGroup := router.Group("/api/v1/documents")
//	uploadGroup.Use(middleware.RequestSizeLimiter(middleware.LargeUploadRequestSizeLimiterConfig()))
func RequestSizeLimiter(config ...RequestSizeLimiterConfig) gin.HandlerFunc {
	cfg := DefaultRequestSizeLimiterConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	if cfg.MaxBodySize <= 0 {
		cfg.MaxBodySize = DefaultMaxBodySize
	}

	errorMessage := cfg.ErrorMessage
	if errorMessage == "" {
		errorMessage = fmt.Sprintf(
			"Request body too large. Maximum allowed size is %s",
			formatBytes(cfg.MaxBodySize),
		)
	}

	return func(c *gin.Context) {
		// Skip size check for methods that typically have no body
		if c.Request.Method == http.MethodGet ||
			c.Request.Method == http.MethodHead ||
			c.Request.Method == http.MethodOptions ||
			c.Request.Method == http.MethodDelete {
			c.Next()
			return
		}

		// Early rejection based on Content-Length header if present.
		// Note: Content-Length may not be set (e.g., chunked transfer encoding),
		// so we also enforce via MaxBytesReader below.
		if c.Request.ContentLength > cfg.MaxBodySize {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error":   "REQUEST_ENTITY_TOO_LARGE",
				"message": errorMessage,
				"details": map[string]interface{}{
					"maxAllowedBytes": cfg.MaxBodySize,
					"contentLength":   c.Request.ContentLength,
				},
			})
			return
		}

		// Wrap the request body with MaxBytesReader to enforce the limit
		// during actual reading. This handles cases where Content-Length
		// is missing or inaccurate (e.g., chunked transfers).
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, cfg.MaxBodySize)

		c.Next()
	}
}

// formatBytes converts a byte count to a human-readable string
func formatBytes(bytes int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)

	switch {
	case bytes >= gb:
		return strconv.FormatFloat(float64(bytes)/float64(gb), 'f', 1, 64) + "GB"
	case bytes >= mb:
		return strconv.FormatFloat(float64(bytes)/float64(mb), 'f', 0, 64) + "MB"
	case bytes >= kb:
		return strconv.FormatFloat(float64(bytes)/float64(kb), 'f', 0, 64) + "KB"
	default:
		return strconv.FormatInt(bytes, 10) + "B"
	}
}
