// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRequireTenantID_ValidContext tests RequireTenantID with valid tenant context
func TestRequireTenantID_ValidContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name        string
		tenantID    uuid.UUID
		expectNil   bool
		expectAbort bool
	}{
		{
			name:        "valid tenant UUID in context",
			tenantID:    uuid.MustParse("f47ac10b-58cc-4372-a567-0e02b2c3d479"),
			expectNil:   false,
			expectAbort: false,
		},
		{
			name:        "different valid UUID",
			tenantID:    uuid.MustParse("a1b2c3d4-e5f6-4789-0abc-def012345678"),
			expectNil:   false,
			expectAbort: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set(TenantIDKey, tt.tenantID)

			tenantID, ok := RequireTenantID(c)

			if tt.expectNil {
				assert.True(t, tenantID == uuid.Nil, "expected nil UUID")
				assert.False(t, ok, "expected ok=false")
			} else {
				assert.Equal(t, tt.tenantID, tenantID)
				assert.True(t, ok, "expected ok=true")
			}

			if tt.expectAbort {
				assert.True(t, c.IsAborted(), "expected context to be aborted")
			} else {
				assert.False(t, c.IsAborted(), "expected context NOT to be aborted")
			}
		})
	}
}

// TestRequireTenantID_MissingContext tests RequireTenantID when tenant context is missing
func TestRequireTenantID_MissingContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("no tenant in context, no header", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)

		tenantID, ok := RequireTenantID(c)

		assert.Equal(t, uuid.Nil, tenantID)
		assert.False(t, ok)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("no tenant in context, valid header", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		validTenantID := uuid.MustParse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
		c.Request = httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
		c.Request.Header.Set("X-Tenant-ID", validTenantID.String())

		tenantID, ok := RequireTenantID(c)

		assert.Equal(t, validTenantID, tenantID)
		assert.True(t, ok)
		assert.False(t, c.IsAborted())
	})

	t.Run("no tenant in context, invalid header", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
		c.Request.Header.Set("X-Tenant-ID", "invalid-uuid")

		tenantID, ok := RequireTenantID(c)

		assert.Equal(t, uuid.Nil, tenantID)
		assert.False(t, ok)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("no tenant in context, nil UUID in header", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
		c.Request.Header.Set("X-Tenant-ID", "00000000-0000-0000-0000-000000000000")

		tenantID, ok := RequireTenantID(c)

		assert.Equal(t, uuid.Nil, tenantID)
		assert.False(t, ok)
	})
}

// TestRequireTenantID_InvalidContext tests RequireTenantID with invalid context values
func TestRequireTenantID_InvalidContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name         string
		contextValue interface{}
		expectAbort  bool
		expectCode   int
	}{
		{
			name:         "nil UUID in context",
			contextValue: uuid.Nil,
			expectAbort:  true,
			expectCode:   http.StatusBadRequest,
		},
		{
			name:         "wrong type - string",
			contextValue: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			expectAbort:  true,
			expectCode:   http.StatusBadRequest,
		},
		{
			name:         "wrong type - int",
			contextValue: 12345,
			expectAbort:  true,
			expectCode:   http.StatusBadRequest,
		},
		{
			name:         "wrong type - nil",
			contextValue: nil,
			expectAbort:  true,
			expectCode:   http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set(TenantIDKey, tt.contextValue)

			tenantID, ok := RequireTenantID(c)

			assert.Equal(t, uuid.Nil, tenantID)
			assert.False(t, ok)
			assert.Equal(t, tt.expectCode, w.Code)
		})
	}
}

// TestRequireUserID_ValidContext tests RequireUserID with valid user context
func TestRequireUserID_ValidContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	userID := uuid.MustParse("a1b2c3d4-e5f6-4789-0abc-def012345678")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(UserIDKey, userID)

	resultID, ok := RequireUserID(c)

	assert.Equal(t, userID, resultID)
	assert.True(t, ok)
	assert.False(t, c.IsAborted())
}

// TestRequireUserID_MissingContext tests RequireUserID when user context is missing
func TestRequireUserID_MissingContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("no user in context, no header", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)

		userID, ok := RequireUserID(c)

		assert.Equal(t, uuid.Nil, userID)
		assert.False(t, ok)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("no user in context, valid header", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		validUserID := uuid.MustParse("a1b2c3d4-e5f6-4789-0abc-def012345678")
		c.Request = httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
		c.Request.Header.Set("X-User-ID", validUserID.String())

		userID, ok := RequireUserID(c)

		assert.Equal(t, validUserID, userID)
		assert.True(t, ok)
		assert.False(t, c.IsAborted())
	})
}

// TestRequireParamUUID_ValidParam tests RequireParamUUID with valid UUID parameters
func TestRequireParamUUID_ValidParam(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validUUID := uuid.MustParse("f47ac10b-58cc-4372-a567-0e02b2c3d479")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: validUUID.String()}}

	resultID, ok := RequireParamUUID(c, "id")

	assert.Equal(t, validUUID, resultID)
	assert.True(t, ok)
	assert.False(t, c.IsAborted())
}

// TestRequireParamUUID_InvalidParam tests RequireParamUUID with invalid parameters
func TestRequireParamUUID_InvalidParam(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		paramValue string
		expectCode int
	}{
		{
			name:       "invalid UUID format",
			paramValue: "invalid-uuid",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "empty string",
			paramValue: "",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "nil UUID",
			paramValue: "00000000-0000-0000-0000-000000000000",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "SQL injection attempt",
			paramValue: "' OR '1'='1",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "36 random chars",
			paramValue: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			expectCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
			c.Params = gin.Params{{Key: "id", Value: tt.paramValue}}

			resultID, ok := RequireParamUUID(c, "id")

			assert.Equal(t, uuid.Nil, resultID)
			assert.False(t, ok)
			assert.Equal(t, tt.expectCode, w.Code)
		})
	}
}

// TestRequireQueryUUID_ValidQuery tests RequireQueryUUID with valid query parameters
func TestRequireQueryUUID_ValidQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validUUID := uuid.MustParse("f47ac10b-58cc-4372-a567-0e02b2c3d479")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(context.Background(), "GET", "/?tenant_id="+validUUID.String(), nil)

	resultID, ok := RequireQueryUUID(c, "tenant_id")

	assert.Equal(t, validUUID, resultID)
	assert.True(t, ok)
	assert.False(t, c.IsAborted())
}

// TestRequireQueryUUID_InvalidQuery tests RequireQueryUUID with invalid query parameters
func TestRequireQueryUUID_InvalidQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		queryValue string
		expectCode int
		expectMsg  string
	}{
		{
			name:       "missing query parameter",
			queryValue: "",
			expectCode: http.StatusBadRequest,
			expectMsg:  "required",
		},
		{
			name:       "invalid UUID format",
			queryValue: "invalid-uuid",
			expectCode: http.StatusBadRequest,
			expectMsg:  "invalid",
		},
		{
			name:       "nil UUID",
			queryValue: "00000000-0000-0000-0000-000000000000",
			expectCode: http.StatusBadRequest,
			expectMsg:  "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			url := "/test"
			if tt.queryValue != "" {
				url += "?id=" + tt.queryValue
			}
			c.Request = httptest.NewRequestWithContext(context.Background(), "GET", url, nil)

			resultID, ok := RequireQueryUUID(c, "id")

			assert.Equal(t, uuid.Nil, resultID)
			assert.False(t, ok)
			assert.Equal(t, tt.expectCode, w.Code)
		})
	}
}

// TestGetTenantID_SafeExtraction tests GetTenantID non-aborting extraction
func TestGetTenantID_SafeExtraction(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("valid tenant ID", func(t *testing.T) {
		validUUID := uuid.MustParse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set(TenantIDKey, validUUID)

		tenantID, ok := GetTenantID(c)

		assert.Equal(t, validUUID, tenantID)
		assert.True(t, ok)
		assert.False(t, c.IsAborted(), "GetTenantID should not abort")
	})

	t.Run("missing tenant ID", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		tenantID, ok := GetTenantID(c)

		assert.Equal(t, uuid.Nil, tenantID)
		assert.False(t, ok)
		assert.False(t, c.IsAborted(), "GetTenantID should not abort")
	})

	t.Run("wrong type", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set(TenantIDKey, "not-a-uuid")

		tenantID, ok := GetTenantID(c)

		assert.Equal(t, uuid.Nil, tenantID)
		assert.False(t, ok)
		assert.False(t, c.IsAborted(), "GetTenantID should not abort")
	})
}

// TestRequireTenantIDPtr_PointerConversion tests RequireTenantIDPtr legacy helper
func TestRequireTenantIDPtr_PointerConversion(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("valid tenant returns pointer", func(t *testing.T) {
		validUUID := uuid.MustParse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set(TenantIDKey, validUUID)

		tenantIDPtr, ok := RequireTenantIDPtr(c)

		require.True(t, ok)
		require.NotNil(t, tenantIDPtr)
		assert.Equal(t, validUUID, *tenantIDPtr)
	})

	t.Run("missing tenant returns nil", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)

		tenantIDPtr, ok := RequireTenantIDPtr(c)

		assert.False(t, ok)
		assert.Nil(t, tenantIDPtr)
	})
}

// TestGetTenantIDPtr_LegacyHelper tests GetTenantIDPtr legacy helper
func TestGetTenantIDPtr_LegacyHelper(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("valid tenant returns pointer", func(t *testing.T) {
		validUUID := uuid.MustParse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set(TenantIDKey, validUUID)

		tenantIDPtr := GetTenantIDPtr(c)

		require.NotNil(t, tenantIDPtr)
		assert.Equal(t, validUUID, *tenantIDPtr)
	})

	t.Run("missing tenant returns nil", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		tenantIDPtr := GetTenantIDPtr(c)

		assert.Nil(t, tenantIDPtr)
		assert.False(t, c.IsAborted(), "GetTenantIDPtr should not abort")
	})
}

// TestGetUserIDPtr_OptionalContext tests GetUserIDPtr for optional user context
func TestGetUserIDPtr_OptionalContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("valid user returns pointer", func(t *testing.T) {
		validUUID := uuid.MustParse("a1b2c3d4-e5f6-4789-0abc-def012345678")
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set(UserIDKey, validUUID)

		userIDPtr := GetUserIDPtr(c)

		require.NotNil(t, userIDPtr)
		assert.Equal(t, validUUID, *userIDPtr)
	})

	t.Run("missing user returns nil", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		userIDPtr := GetUserIDPtr(c)

		assert.Nil(t, userIDPtr)
	})
}

// TestTenantHelpers_ConcurrentAccess tests thread safety of helper functions
func TestTenantHelpers_ConcurrentAccess(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("concurrent RequireTenantID calls", func(t *testing.T) {
		validUUID := uuid.MustParse("f47ac10b-58cc-4372-a567-0e02b2c3d479")

		// Run 100 concurrent requests
		done := make(chan bool)
		for i := 0; i < 100; i++ {
			go func() {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Set(TenantIDKey, validUUID)

				tenantID, ok := RequireTenantID(c)

				assert.Equal(t, validUUID, tenantID)
				assert.True(t, ok)
				done <- true
			}()
		}

		// Wait for all to complete
		for i := 0; i < 100; i++ {
			<-done
		}
	})
}

// TestTenantHelpers_SecurityVulnerabilities tests security edge cases
func TestTenantHelpers_SecurityVulnerabilities(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("tenant isolation bypass attempts via header", func(t *testing.T) {
		maliciousHeaders := []string{
			"'; DROP TABLE tenants; --",
			"1' OR '1'='1",
			"../../../etc/passwd",
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		}

		for _, header := range maliciousHeaders {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
			c.Request.Header.Set("X-Tenant-ID", header)

			tenantID, ok := RequireTenantID(c)

			assert.Equal(t, uuid.Nil, tenantID, "malicious header should be rejected: %s", header)
			assert.False(t, ok)
		}
	})

	t.Run("type confusion attack", func(t *testing.T) {
		// Attempt to set tenant ID as different type
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		// Try to set as string instead of UUID
		c.Set(TenantIDKey, "f47ac10b-58cc-4372-a567-0e02b2c3d479")

		tenantID, ok := RequireTenantID(c)

		assert.Equal(t, uuid.Nil, tenantID)
		assert.False(t, ok)
	})
}
