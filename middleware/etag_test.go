// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// newETagRouter is a test helper that builds a Gin engine with the ETag middleware.
func newETagRouter() *gin.Engine {
	r := gin.New()
	r.Use(ETag())
	return r
}

func TestETag_GET_SetsETagHeader(t *testing.T) {
	r := newETagRouter()
	r.GET("/items", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"id": "1"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/items", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	etag := w.Header().Get("ETag")
	assert.NotEmpty(t, etag, "ETag header must be set")
	assert.Contains(t, etag, "sha256:", "ETag must use sha256 scheme")
}

func TestETag_GET_MatchingIfNoneMatch_Returns304(t *testing.T) {
	r := newETagRouter()
	r.GET("/items", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"id": "1"})
	})

	// First request — obtain the ETag.
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/items", nil)
	r.ServeHTTP(w1, req1)
	require.Equal(t, http.StatusOK, w1.Code)
	etag := w1.Header().Get("ETag")
	require.NotEmpty(t, etag)

	// Second request with matching If-None-Match — expect 304.
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/items", nil)
	req2.Header.Set("If-None-Match", etag)
	r.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusNotModified, w2.Code)
}

func TestETag_GET_NonMatchingIfNoneMatch_Returns200(t *testing.T) {
	r := newETagRouter()
	r.GET("/items", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"id": "1"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/items", nil)
	req.Header.Set("If-None-Match", `"sha256:000000"`)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get("ETag"))
}

func TestETag_PUT_MatchingIfMatch_Succeeds(t *testing.T) {
	r := newETagRouter()
	const responseBody = `{"id":"1","name":"updated"}`

	r.PUT("/items/:id", func(c *gin.Context) {
		c.String(http.StatusOK, responseBody)
	})

	// Compute the ETag the handler will produce.
	expectedETag := computeETag([]byte(responseBody))

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, "/items/1", nil)
	req.Header.Set("If-Match", expectedETag)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestETag_PUT_NonMatchingIfMatch_Returns412(t *testing.T) {
	r := newETagRouter()
	r.PUT("/items/:id", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"id": "1"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, "/items/1", nil)
	req.Header.Set("If-Match", `"sha256:stale-etag"`)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusPreconditionFailed, w.Code)
}

func TestETag_POST_DoesNotSetETag(t *testing.T) {
	r := newETagRouter()
	r.POST("/items", func(c *gin.Context) {
		c.JSON(http.StatusCreated, gin.H{"id": "2"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "/items", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Empty(t, w.Header().Get("ETag"), "POST responses must not carry an ETag")
}

func TestETag_DELETE_NoIfMatch_Passes(t *testing.T) {
	r := newETagRouter()
	r.DELETE("/items/:id", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete, "/items/1", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestETag_GET_HandlerError_NoETagSet(t *testing.T) {
	r := newETagRouter()
	r.GET("/boom", func(c *gin.Context) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/boom", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, w.Header().Get("ETag"), "error responses must not carry an ETag")
}
