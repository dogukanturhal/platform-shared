// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"testing"

	"github.com/google/uuid"
)

func TestCurrentUser_HasPermission(t *testing.T) {
	// User without global wildcard for specific permission tests
	user := &CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Permissions: []string{
			"subscription:admin",
			"payment:read",
			"core:users:*",
		},
	}

	tests := []struct {
		name       string
		permission string
		want       bool
	}{
		{"Exact match", "subscription:admin", true},
		{"Exact match 2", "payment:read", true},
		{"No match", "payment:write", false},
		{"Wildcard matches sub-permission", "core:users:read", true},
		{"Wildcard matches any sub-permission", "core:users:write", true},
		{"Wildcard doesn't match different prefix", "core:roles:read", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := user.HasPermission(tt.permission); got != tt.want {
				t.Errorf("HasPermission(%s) = %v, want %v", tt.permission, got, tt.want)
			}
		})
	}

	// Test global wildcard separately
	superAdmin := &CurrentUser{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		Permissions: []string{"*"},
	}
	if !superAdmin.HasPermission("anything:at:all") {
		t.Error("Global wildcard should match any permission")
	}
}

func TestCurrentUser_HasRole(t *testing.T) {
	user := &CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Roles:    []string{"admin", "manager"},
	}

	tests := []struct {
		name string
		role string
		want bool
	}{
		{"Has admin", "admin", true},
		{"Has manager", "manager", true},
		{"Doesn't have user", "user", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := user.HasRole(tt.role); got != tt.want {
				t.Errorf("HasRole(%s) = %v, want %v", tt.role, got, tt.want)
			}
		})
	}
}

func TestCurrentUser_HasAnyPermission(t *testing.T) {
	user := &CurrentUser{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		Permissions: []string{"read", "write"},
	}

	tests := []struct {
		name        string
		permissions []string
		want        bool
	}{
		{"Has one of them", []string{"read", "delete"}, true},
		{"Has none", []string{"delete", "admin"}, false},
		{"Has both", []string{"read", "write"}, true},
		{"Empty list", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := user.HasAnyPermission(tt.permissions...); got != tt.want {
				t.Errorf("HasAnyPermission(%v) = %v, want %v", tt.permissions, got, tt.want)
			}
		})
	}
}

func TestCurrentUser_HasAllPermissions(t *testing.T) {
	user := &CurrentUser{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		Permissions: []string{"read", "write"},
	}

	tests := []struct {
		name        string
		permissions []string
		want        bool
	}{
		{"Has all", []string{"read", "write"}, true},
		{"Missing one", []string{"read", "delete"}, false},
		{"Has one", []string{"read"}, true},
		{"Empty list", []string{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := user.HasAllPermissions(tt.permissions...); got != tt.want {
				t.Errorf("HasAllPermissions(%v) = %v, want %v", tt.permissions, got, tt.want)
			}
		})
	}
}

func TestMatchWildcard(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		permission string
		want       bool
	}{
		// Trailing wildcard tests
		{"Trailing wildcard matches", "core:users:*", "core:users:read", true},
		{"Trailing wildcard matches write", "core:users:*", "core:users:write", true},
		{"Trailing wildcard doesn't match different prefix", "core:users:*", "core:roles:read", false},
		{"Two-part trailing wildcard", "core:*", "core:users", true},
		{"Two-part trailing wildcard matches deeper", "core:*", "core:users:read", true},

		// Middle wildcard tests
		{"Middle wildcard matches", "core:*:read", "core:users:read", true},
		{"Middle wildcard matches roles", "core:*:read", "core:roles:read", true},
		{"Middle wildcard doesn't match wrong action", "core:*:read", "core:users:write", false},

		// Leading wildcard tests
		{"Leading wildcard matches", "*:users:read", "core:users:read", true},
		{"Leading wildcard matches admin", "*:users:read", "admin:users:read", true},

		// Exact match (no wildcard)
		{"Exact match", "core:users:read", "core:users:read", true},
		{"Exact no match", "core:users:read", "core:users:write", false},

		// Part count mismatch (non-trailing wildcard)
		{"Different part counts", "core:users", "core:users:read", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchWildcard(tt.pattern, tt.permission); got != tt.want {
				t.Errorf("matchWildcard(%s, %s) = %v, want %v", tt.pattern, tt.permission, got, tt.want)
			}
		})
	}
}

func TestNewCurrentUserFromClaims(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	sessionID := uuid.New()

	claims := &Claims{
		TenantID:    tenantID,
		UserID:      userID,
		Username:    "testuser",
		Email:       "test@example.com",
		Roles:       []string{"admin"},
		Permissions: []string{"read", "write"},
		SessionID:   sessionID,
	}

	user := NewCurrentUserFromClaims(claims)

	if user.ID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, user.ID)
	}

	if user.TenantID != tenantID {
		t.Errorf("Expected tenant ID %s, got %s", tenantID, user.TenantID)
	}

	if user.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got %s", user.Username)
	}

	if user.AuthMethod != AuthMethodJWT {
		t.Errorf("Expected auth method JWT, got %s", user.AuthMethod)
	}
}

func TestNewCurrentUserFromClaims_ServiceAccount(t *testing.T) {
	tenantID := uuid.New()
	serviceAccountID := uuid.New()

	claims := &Claims{
		TenantID:         tenantID,
		ServiceAccountID: &serviceAccountID,
		TokenType:        "service_account",
	}

	user := NewCurrentUserFromClaims(claims)

	if user.AuthMethod != AuthMethodServiceAccount {
		t.Errorf("Expected auth method ServiceAccount, got %s", user.AuthMethod)
	}

	if user.ServiceAccountID == nil || *user.ServiceAccountID != serviceAccountID {
		t.Error("Expected service account ID to be set")
	}
}
