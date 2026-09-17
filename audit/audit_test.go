// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// mockLogger collects audit entries for assertion.
type mockLogger struct {
	mu      sync.Mutex
	entries []*Entry
}

func (m *mockLogger) Log(e *Entry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
}

func (m *mockLogger) last() *Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.entries) == 0 {
		return nil
	}
	return m.entries[len(m.entries)-1]
}

func (m *mockLogger) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

func TestMiddleware_LogsMutations(t *testing.T) {
	ml := &mockLogger{}
	router := gin.New()
	router.Use(Middleware(Config{ServiceName: "test-svc", Logger: ml, SkipReadOps: true}))
	router.POST("/api/v1/things", func(c *gin.Context) {
		c.JSON(201, gin.H{"id": "123"})
	})

	body := bytes.NewBufferString(`{"name":"test"}`)
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/things", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "req-abc")
	router.ServeHTTP(w, req)

	assert.Equal(t, 201, w.Code)
	require.Equal(t, 1, ml.count())

	e := ml.last()
	assert.Equal(t, "CREATE", e.Action)
	assert.Equal(t, "test-svc", e.ServiceName)
	assert.Equal(t, "POST", e.Method)
	assert.Equal(t, "/api/v1/things", e.Path)
	assert.Equal(t, 201, e.StatusCode)
	assert.Equal(t, "req-abc", e.RequestID)
	assert.NotEmpty(t, e.ID)
	assert.True(t, e.DurationMs >= 0)
}

func TestMiddleware_SkipsGET(t *testing.T) {
	ml := &mockLogger{}
	router := gin.New()
	router.Use(Middleware(Config{ServiceName: "test-svc", Logger: ml, SkipReadOps: true}))
	router.GET("/api/v1/things", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/api/v1/things", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, 0, ml.count())
}

func TestMiddleware_CapturesDeleteAction(t *testing.T) {
	ml := &mockLogger{}
	router := gin.New()
	router.Use(Middleware(Config{ServiceName: "test-svc", Logger: ml}))
	router.DELETE("/api/v1/things/:id", func(c *gin.Context) {
		c.Status(204)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "DELETE", "/api/v1/things/abc-123", nil)
	router.ServeHTTP(w, req)

	require.Equal(t, 1, ml.count())
	e := ml.last()
	assert.Equal(t, "DELETE", e.Action)
	assert.Equal(t, "abc-123", e.ResourceID)
	assert.Equal(t, "things", e.ResourceType)
}

func TestMiddleware_ExtractsTenantAndUser(t *testing.T) {
	ml := &mockLogger{}
	router := gin.New()
	// Simulate auth middleware setting context values.
	router.Use(func(c *gin.Context) {
		tenantID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
		c.Set("tenant_id", tenantID)
		c.Set("user_id", "user-42")
		c.Set("user_email", "admin@test.com")
		c.Next()
	})
	router.Use(Middleware(Config{ServiceName: "test-svc", Logger: ml}))
	router.PUT("/api/v1/things/:id", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	body := bytes.NewBufferString(`{"name":"updated"}`)
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "PUT", "/api/v1/things/xyz", body)
	router.ServeHTTP(w, req)

	require.Equal(t, 1, ml.count())
	e := ml.last()
	assert.Equal(t, "UPDATE", e.Action)
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", e.TenantID)
	assert.Equal(t, "user-42", e.UserID)
	assert.Equal(t, "admin@test.com", e.UserEmail)
}

func TestSanitizeBody_RedactsSensitiveFields(t *testing.T) {
	input := `{"name":"test","password":"secret123","api_key":"abc","token":"xyz"}`
	result := sanitizeBody([]byte(input))

	var obj map[string]interface{}
	require.NoError(t, json.Unmarshal(result, &obj))
	assert.Equal(t, "test", obj["name"])
	assert.Equal(t, "[REDACTED]", obj["password"])
	assert.Equal(t, "[REDACTED]", obj["api_key"])
	assert.Equal(t, "[REDACTED]", obj["token"])
}

func TestSanitizeBody_NonJSON(t *testing.T) {
	result := sanitizeBody([]byte("not json"))
	assert.Nil(t, result)
}

func TestSanitizeBody_Empty(t *testing.T) {
	result := sanitizeBody(nil)
	assert.Nil(t, result)
}

func TestExtractResourceType(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/api/v1/compute/workloads/:id", "workloads"},
		{"/api/v1/compute/workloads", "workloads"},
		{"/api/v1/network/vnets/:id/subnets", "subnets"},
		{"/api/v1/quota/tenants/:tenant_id/dashboard", "dashboard"},
		{"", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractResourceType(tt.path))
		})
	}
}
