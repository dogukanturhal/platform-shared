// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestRequestID_GeneratesNewID(t *testing.T) {
	router := gin.New()
	router.Use(RequestID())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"request_id": c.GetString("request_id")})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.NotEmpty(t, w.Header().Get("X-Request-ID"))
}

func TestRequestID_PreservesClientID(t *testing.T) {
	router := gin.New()
	router.Use(RequestID())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"request_id": c.GetString("request_id")})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.Header.Set("X-Request-ID", "client-123")
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "client-123", w.Header().Get("X-Request-ID"))
}

func TestCorrelationID_GeneratesNewChain(t *testing.T) {
	router := gin.New()
	router.Use(CorrelationID("compute-api"))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"correlation_id":    c.GetString("correlation_id"),
			"correlation_chain": c.GetString("correlation_chain"),
		})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.NotEmpty(t, w.Header().Get("X-Correlation-ID"))
	assert.Equal(t, "compute-api", w.Header().Get("X-Correlation-Chain"))
}

func TestCorrelationID_AppendsToExistingChain(t *testing.T) {
	router := gin.New()
	router.Use(CorrelationID("network-api"))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, nil)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.Header.Set("X-Correlation-ID", "corr-abc")
	req.Header.Set("X-Correlation-Chain", "gateway,compute-api")
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "corr-abc", w.Header().Get("X-Correlation-ID"))
	assert.Equal(t, "gateway,compute-api,network-api", w.Header().Get("X-Correlation-Chain"))
}
