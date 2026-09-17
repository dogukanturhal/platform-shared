// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// TestRequirePermission_SinglePermission tests RequirePermission with single permission checks
func TestRequirePermission_SinglePermission(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name            string
		userPermissions []string
		requiredPerm    string
		expectCode      int
		expectAbort     bool
	}{
		{
			name:            "exact permission match",
			userPermissions: []string{"core:users:read"},
			requiredPerm:    "core:users:read",
			expectCode:      http.StatusOK,
			expectAbort:     false,
		},
		{
			name:            "wildcard permission grants access",
			userPermissions: []string{"*"},
			requiredPerm:    "core:users:read",
			expectCode:      http.StatusOK,
			expectAbort:     false,
		},
		{
			name:            "namespace wildcard grants access",
			userPermissions: []string{"core:users:*"},
			requiredPerm:    "core:users:read",
			expectCode:      http.StatusOK,
			expectAbort:     false,
		},
		{
			name:            "permission denied - no match",
			userPermissions: []string{"core:roles:read"},
			requiredPerm:    "core:users:read",
			expectCode:      http.StatusForbidden,
			expectAbort:     true,
		},
		{
			name:            "permission denied - empty permissions",
			userPermissions: []string{},
			requiredPerm:    "core:users:read",
			expectCode:      http.StatusForbidden,
			expectAbort:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			router := gin.New()

			config := &Config{JWTSecret: "test-secret"}
			middleware := NewMiddleware(config)

			// Set up user in middleware
			currentUser := &CurrentUser{
				ID:          uuid.New(),
				TenantID:    uuid.New(),
				Permissions: tt.userPermissions,
				AuthMethod:  AuthMethodJWT,
			}

			router.Use(func(c *gin.Context) {
				c.Set(CurrentUserKey, currentUser)
				c.Next()
			})

			router.GET("/test", middleware.RequirePermission(tt.requiredPerm), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectCode, w.Code)
		})
	}
}

// TestRequirePermission_WildcardPatterns tests wildcard permission matching
func TestRequirePermission_WildcardPatterns(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name            string
		userPermissions []string
		requiredPerm    string
		expectAccess    bool
	}{
		{
			name:            "trailing wildcard - 3 parts",
			userPermissions: []string{"core:users:*"},
			requiredPerm:    "core:users:read",
			expectAccess:    true,
		},
		{
			name:            "trailing wildcard - 2 parts",
			userPermissions: []string{"core:*"},
			requiredPerm:    "core:users",
			expectAccess:    true,
		},
		{
			name:            "trailing wildcard - matches multiple parts",
			userPermissions: []string{"core:*"},
			requiredPerm:    "core:users:read",
			expectAccess:    true,
		},
		{
			name:            "middle wildcard",
			userPermissions: []string{"core:*:read"},
			requiredPerm:    "core:users:read",
			expectAccess:    true,
		},
		{
			name:            "middle wildcard - different resource",
			userPermissions: []string{"core:*:read"},
			requiredPerm:    "core:roles:read",
			expectAccess:    true,
		},
		{
			name:            "middle wildcard - no match on action",
			userPermissions: []string{"core:*:read"},
			requiredPerm:    "core:users:write",
			expectAccess:    false,
		},
		{
			name:            "prefix wildcard",
			userPermissions: []string{"*:users:read"},
			requiredPerm:    "core:users:read",
			expectAccess:    true,
		},
		{
			name:            "prefix wildcard - different namespace",
			userPermissions: []string{"*:users:read"},
			requiredPerm:    "admin:users:read",
			expectAccess:    true,
		},
		{
			name:            "multiple wildcards",
			userPermissions: []string{"*:*:read"},
			requiredPerm:    "core:users:read",
			expectAccess:    true,
		},
		{
			name:            "global wildcard",
			userPermissions: []string{"*"},
			requiredPerm:    "any:permission:here",
			expectAccess:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			currentUser := &CurrentUser{
				ID:          uuid.New(),
				TenantID:    uuid.New(),
				Permissions: tt.userPermissions,
			}

			hasAccess := currentUser.HasPermission(tt.requiredPerm)
			assert.Equal(t, tt.expectAccess, hasAccess)
		})
	}
}

// TestRequirePermission_MultiplePermissions tests RequirePermission with OR logic
func TestRequirePermission_MultiplePermissions(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name            string
		userPermissions []string
		requiredPerms   []string
		expectAccess    bool
	}{
		{
			name:            "has first permission",
			userPermissions: []string{"core:users:read"},
			requiredPerms:   []string{"core:users:read", "core:users:write"},
			expectAccess:    true,
		},
		{
			name:            "has second permission",
			userPermissions: []string{"core:users:write"},
			requiredPerms:   []string{"core:users:read", "core:users:write"},
			expectAccess:    true,
		},
		{
			name:            "has both permissions",
			userPermissions: []string{"core:users:read", "core:users:write"},
			requiredPerms:   []string{"core:users:read", "core:users:write"},
			expectAccess:    true,
		},
		{
			name:            "has neither permission",
			userPermissions: []string{"core:roles:read"},
			requiredPerms:   []string{"core:users:read", "core:users:write"},
			expectAccess:    false,
		},
		{
			name:            "wildcard satisfies any required permission",
			userPermissions: []string{"core:users:*"},
			requiredPerms:   []string{"core:users:read", "core:users:write", "core:users:delete"},
			expectAccess:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			router := gin.New()

			currentUser := &CurrentUser{
				ID:          uuid.New(),
				TenantID:    uuid.New(),
				Permissions: tt.userPermissions,
			}
			// Inject user via middleware so the request context has it
			router.Use(func(c *gin.Context) {
				c.Set(CurrentUserKey, currentUser)
				c.Next()
			})

			config := &Config{JWTSecret: "test-secret"}
			mw := NewMiddleware(config)

			router.GET("/test", mw.RequirePermission(tt.requiredPerms...), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
			router.ServeHTTP(w, req)

			if tt.expectAccess {
				assert.Equal(t, http.StatusOK, w.Code)
			} else {
				assert.Equal(t, http.StatusForbidden, w.Code)
			}
		})
	}
}

// TestRequireAllPermissions_ANDLogic tests RequireAllPermissions with AND logic
func TestRequireAllPermissions_ANDLogic(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name            string
		userPermissions []string
		requiredPerms   []string
		expectAccess    bool
	}{
		{
			name:            "has all required permissions",
			userPermissions: []string{"core:users:read", "core:users:write"},
			requiredPerms:   []string{"core:users:read", "core:users:write"},
			expectAccess:    true,
		},
		{
			name:            "has only one of two required permissions",
			userPermissions: []string{"core:users:read"},
			requiredPerms:   []string{"core:users:read", "core:users:write"},
			expectAccess:    false,
		},
		{
			name:            "wildcard satisfies all",
			userPermissions: []string{"*"},
			requiredPerms:   []string{"core:users:read", "core:users:write", "admin:roles:read"},
			expectAccess:    true,
		},
		{
			name:            "namespace wildcard satisfies multiple in namespace",
			userPermissions: []string{"core:users:*"},
			requiredPerms:   []string{"core:users:read", "core:users:write"},
			expectAccess:    true,
		},
		{
			name:            "namespace wildcard does NOT satisfy cross-namespace",
			userPermissions: []string{"core:users:*"},
			requiredPerms:   []string{"core:users:read", "admin:users:read"},
			expectAccess:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			router := gin.New()

			currentUser := &CurrentUser{
				ID:          uuid.New(),
				TenantID:    uuid.New(),
				Permissions: tt.userPermissions,
			}
			// Inject user via middleware so the request context has it
			router.Use(func(c *gin.Context) {
				c.Set(CurrentUserKey, currentUser)
				c.Next()
			})

			config := &Config{JWTSecret: "test-secret"}
			mw := NewMiddleware(config)

			router.GET("/test", mw.RequireAllPermissions(tt.requiredPerms...), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
			router.ServeHTTP(w, req)

			if tt.expectAccess {
				assert.Equal(t, http.StatusOK, w.Code)
			} else {
				assert.Equal(t, http.StatusForbidden, w.Code)
			}
		})
	}
}

// TestRequirePermission_APIKeyAuth tests permission checks with API key authentication
func TestRequirePermission_APIKeyAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name         string
		apiKeyPerms  []string
		requiredPerm string
		expectAccess bool
	}{
		{
			name:         "API key with exact permission",
			apiKeyPerms:  []string{"internal:service:read"},
			requiredPerm: "internal:service:read",
			expectAccess: true,
		},
		{
			name:         "API key without required permission",
			apiKeyPerms:  []string{"internal:service:read"},
			requiredPerm: "core:users:write",
			expectAccess: false,
		},
		{
			name:         "API key with scoped wildcard",
			apiKeyPerms:  []string{"internal:*"},
			requiredPerm: "internal:service:read",
			expectAccess: true,
		},
		{
			name:         "API key should NOT have global wildcard",
			apiKeyPerms:  []string{"internal:service:read"},
			requiredPerm: "any:permission:here",
			expectAccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			router := gin.New()

			// Simulate API key authentication by injecting user via middleware
			currentUser := &CurrentUser{
				AuthMethod:  AuthMethodAPIKey,
				Permissions: tt.apiKeyPerms,
				ServiceName: "test-service",
				Roles:       []string{"service"},
			}
			router.Use(func(c *gin.Context) {
				c.Set(CurrentUserKey, currentUser)
				c.Next()
			})

			config := &Config{JWTSecret: "test-secret"}
			mw := NewMiddleware(config)

			router.GET("/test", mw.RequirePermission(tt.requiredPerm), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
			router.ServeHTTP(w, req)

			if tt.expectAccess {
				assert.Equal(t, http.StatusOK, w.Code)
			} else {
				assert.Equal(t, http.StatusForbidden, w.Code)
			}
		})
	}
}

// TestRequirePermission_NoUser tests permission check without authenticated user
func TestRequirePermission_NoUser(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	router := gin.New()

	// No user in context — no injection middleware
	config := &Config{JWTSecret: "test-secret"}
	mw := NewMiddleware(config)

	var aborted bool
	router.GET("/test", mw.RequirePermission("core:users:read"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	// Check abort via a middleware that runs after
	router.Use(func(c *gin.Context) {
		c.Next()
		aborted = c.IsAborted()
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	_ = aborted // abort flag is internal to gin; status code check is sufficient
}

// TestRequireRole_RoleChecks tests RequireRole middleware
func TestRequireRole_RoleChecks(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name         string
		userRoles    []string
		requiredRole string
		expectAccess bool
	}{
		{
			name:         "has required role",
			userRoles:    []string{"admin"},
			requiredRole: "admin",
			expectAccess: true,
		},
		{
			name:         "does not have required role",
			userRoles:    []string{"user"},
			requiredRole: "admin",
			expectAccess: false,
		},
		{
			name:         "has multiple roles including required",
			userRoles:    []string{"user", "admin", "manager"},
			requiredRole: "admin",
			expectAccess: true,
		},
		{
			name:         "no roles",
			userRoles:    []string{},
			requiredRole: "admin",
			expectAccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			router := gin.New()

			currentUser := &CurrentUser{
				ID:       uuid.New(),
				TenantID: uuid.New(),
				Roles:    tt.userRoles,
			}
			// Inject user via middleware so the request context has it
			router.Use(func(c *gin.Context) {
				c.Set(CurrentUserKey, currentUser)
				c.Next()
			})

			config := &Config{JWTSecret: "test-secret"}
			mw := NewMiddleware(config)

			router.GET("/test", mw.RequireRole(tt.requiredRole), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
			router.ServeHTTP(w, req)

			if tt.expectAccess {
				assert.Equal(t, http.StatusOK, w.Code)
			} else {
				assert.Equal(t, http.StatusForbidden, w.Code)
			}
		})
	}
}

// TestCurrentUser_PermissionHelpers tests CurrentUser permission helper methods
func TestCurrentUser_PermissionHelpers(t *testing.T) {
	t.Run("HasPermission", func(t *testing.T) {
		user := &CurrentUser{
			Permissions: []string{"core:users:read", "core:users:write"},
		}

		assert.True(t, user.HasPermission("core:users:read"))
		assert.True(t, user.HasPermission("core:users:write"))
		assert.False(t, user.HasPermission("core:users:delete"))
	})

	t.Run("HasAnyPermission", func(t *testing.T) {
		user := &CurrentUser{
			Permissions: []string{"core:users:read"},
		}

		assert.True(t, user.HasAnyPermission("core:users:read", "core:users:write"))
		assert.False(t, user.HasAnyPermission("core:users:write", "core:users:delete"))
	})

	t.Run("HasAllPermissions", func(t *testing.T) {
		user := &CurrentUser{
			Permissions: []string{"core:users:read", "core:users:write"},
		}

		assert.True(t, user.HasAllPermissions("core:users:read", "core:users:write"))
		assert.False(t, user.HasAllPermissions("core:users:read", "core:users:delete"))
	})

	t.Run("HasRole", func(t *testing.T) {
		user := &CurrentUser{
			Roles: []string{"admin", "manager"},
		}

		assert.True(t, user.HasRole("admin"))
		assert.True(t, user.HasRole("manager"))
		assert.False(t, user.HasRole("user"))
	})

	t.Run("HasAnyRole", func(t *testing.T) {
		user := &CurrentUser{
			Roles: []string{"admin"},
		}

		assert.True(t, user.HasAnyRole("admin", "manager"))
		assert.False(t, user.HasAnyRole("user", "guest"))
	})

	t.Run("HasAllRoles", func(t *testing.T) {
		user := &CurrentUser{
			Roles: []string{"admin", "manager"},
		}

		assert.True(t, user.HasAllRoles("admin", "manager"))
		assert.False(t, user.HasAllRoles("admin", "user"))
	})
}

// TestMatchWildcard_EdgeCases tests wildcard matching edge cases
func TestMatchWildcard_EdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		permission string
		expect     bool
	}{
		{
			name:       "empty pattern",
			pattern:    "",
			permission: "core:users:read",
			expect:     false,
		},
		{
			name:       "empty permission",
			pattern:    "core:users:read",
			permission: "",
			expect:     false,
		},
		{
			name:       "both empty",
			pattern:    "",
			permission: "",
			expect:     true,
		},
		{
			name:       "single part pattern",
			pattern:    "core",
			permission: "core",
			expect:     true,
		},
		{
			name:       "single part wildcard",
			pattern:    "*",
			permission: "anything",
			expect:     true,
		},
		{
			name:       "different part counts",
			pattern:    "core:users",
			permission: "core:users:read",
			expect:     false,
		},
		{
			name:       "trailing wildcard allows more parts",
			pattern:    "core:*",
			permission: "core:users:read:extra",
			expect:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchWildcard(tt.pattern, tt.permission)
			assert.Equal(t, tt.expect, result)
		})
	}
}

// TestRequirePermission_SecurityVulnerabilities tests security edge cases
func TestRequirePermission_SecurityVulnerabilities(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("permission injection attempt", func(t *testing.T) {
		w := httptest.NewRecorder()
		router := gin.New()

		config := &Config{JWTSecret: "test-secret"}
		middleware := NewMiddleware(config)

		router.Use(func(c *gin.Context) {
			// Setup user in context before middleware runs
			currentUser := &CurrentUser{
				ID:          uuid.New(),
				TenantID:    uuid.New(),
				Permissions: []string{"core:users:read*"},
			}
			c.Set(CurrentUserKey, currentUser)
			c.Next()
		})

		router.GET("/test", middleware.RequirePermission("core:users:read:sensitive"), func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
		router.ServeHTTP(w, req)

		// Should be denied - "read*" is not a valid wildcard
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("empty permission string", func(t *testing.T) {
		user := &CurrentUser{
			Permissions: []string{"core:users:read"},
		}

		// Empty permission should not match anything
		assert.False(t, user.HasPermission(""))
	})

	t.Run("nil permissions array", func(t *testing.T) {
		user := &CurrentUser{
			Permissions: nil,
		}

		assert.False(t, user.HasPermission("core:users:read"))
	})
}

// BenchmarkHasPermission benchmarks permission checking
func BenchmarkHasPermission(b *testing.B) {
	user := &CurrentUser{
		Permissions: []string{
			"core:users:read",
			"core:users:write",
			"core:roles:read",
			"admin:*",
			"billing:invoices:*",
		},
	}

	b.Run("exact match", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = user.HasPermission("core:users:read")
		}
	})

	b.Run("wildcard match", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = user.HasPermission("admin:users:delete")
		}
	})

	b.Run("no match", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = user.HasPermission("nonexistent:permission:here")
		}
	})
}
