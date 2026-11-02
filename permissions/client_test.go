// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.uber.org/zap"
)

func TestRegisterModule_Success(t *testing.T) {
	var receivedReq registerModuleRequest
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/internal/v1/permissions/register", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "test-api-key", r.Header.Get("X-Internal-Key"))
		assert.Equal(t, "billing", r.Header.Get("X-Service-Name"))

		receivedHeaders = r.Header

		err := json.NewDecoder(r.Body).Decode(&receivedReq)
		require.NoError(t, err)

		resp := registerModuleResponse{
			Module:     receivedReq.Module,
			Registered: 15,
			Updated:    0,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-api-key", "billing", zap.NewNop())
	err := client.RegisterModule(context.Background(), "billing", []PermissionDef{
		{Resource: "invoices", Actions: StandardCRUD(), Description: "Invoice management"},
		{Resource: "subscriptions", Actions: StandardCRUD(), Description: "Subscription management"},
		{Resource: "payments", Actions: StandardCRUD(), Description: "Payment management"},
	})

	require.NoError(t, err)
	assert.Equal(t, "billing", receivedReq.Module)
	assert.Len(t, receivedReq.Permissions, 3)
	assert.Equal(t, "invoices", receivedReq.Permissions[0].Resource)
	assert.Equal(t, StandardCRUD(), receivedReq.Permissions[0].Actions)
	assert.NotEmpty(t, receivedHeaders.Get("X-Internal-Key"))
}

func TestRegisterModule_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-api-key", "billing", zap.NewNop())
	err := client.RegisterModule(context.Background(), "billing", []PermissionDef{
		{Resource: "invoices", Actions: StandardCRUD()},
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestRegisterModule_SkipsWhenMissingConfig(t *testing.T) {
	// Missing URL
	client := NewClient("", "test-api-key", "billing", zap.NewNop())
	err := client.RegisterModule(context.Background(), "billing", []PermissionDef{
		{Resource: "invoices", Actions: StandardCRUD()},
	})
	assert.NoError(t, err)

	// Missing API key
	client = NewClient("http://localhost:8080", "", "billing", zap.NewNop())
	err = client.RegisterModule(context.Background(), "billing", []PermissionDef{
		{Resource: "invoices", Actions: StandardCRUD()},
	})
	assert.NoError(t, err)
}

func TestRegisterModule_ConnectionRefused(t *testing.T) {
	client := NewClient("http://localhost:1", "test-api-key", "billing", zap.NewNop())
	err := client.RegisterModule(context.Background(), "billing", []PermissionDef{
		{Resource: "invoices", Actions: StandardCRUD()},
	})
	assert.Error(t, err)
}

func TestStandardCRUD(t *testing.T) {
	actions := StandardCRUD()
	assert.Equal(t, []string{"create", "read", "update", "delete", "*"}, actions)
}

func TestLoadManifest_Valid(t *testing.T) {
	const yaml = `
module: billing
permissions:
  - resource: invoices
    actions: [create, read, update, delete]
    description: Invoice management
  - resource: payments
    actions: [create, read]
    description: Payment processing
`
	dir := t.TempDir()
	path := filepath.Join(dir, "permissions.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o600))

	m, err := LoadManifest(path)
	require.NoError(t, err)
	assert.Equal(t, "billing", m.Module)
	require.Len(t, m.Permissions, 2)
	assert.Equal(t, "invoices", m.Permissions[0].Resource)
	assert.Equal(t, []string{"create", "read", "update", "delete"}, m.Permissions[0].Actions)
	assert.Equal(t, "Invoice management", m.Permissions[0].Description)
	assert.Equal(t, "payments", m.Permissions[1].Resource)
}

func TestLoadManifest_MissingFile(t *testing.T) {
	_, err := LoadManifest("/nonexistent/path/permissions.yaml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read manifest")
}

func TestLoadManifest_MissingModule(t *testing.T) {
	const yaml = `
permissions:
  - resource: invoices
    actions: [read]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "permissions.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o600))

	_, err := LoadManifest(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "module field is required")
}

func TestLoadManifest_MissingResource(t *testing.T) {
	const yaml = `
module: billing
permissions:
  - actions: [read]
    description: Missing resource field
`
	dir := t.TempDir()
	path := filepath.Join(dir, "permissions.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o600))

	_, err := LoadManifest(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing resource field")
}

func TestLoadManifest_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "permissions.yaml")
	require.NoError(t, os.WriteFile(path, []byte("not: valid: yaml: ["), 0o600))

	_, err := LoadManifest(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse manifest")
}

func TestRegisterFromManifest_Success(t *testing.T) {
	const yaml = `
module: notification
permissions:
  - resource: notifications
    actions: [create, read, update, delete]
    description: Notification management
`
	dir := t.TempDir()
	path := filepath.Join(dir, "permissions.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o600))

	var receivedReq registerModuleRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&receivedReq))
		resp := registerModuleResponse{Module: receivedReq.Module, Registered: 1}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key", "notification-service", zap.NewNop())
	err := client.RegisterFromManifest(context.Background(), path)
	require.NoError(t, err)
	assert.Equal(t, "notification", receivedReq.Module)
	require.Len(t, receivedReq.Permissions, 1)
	assert.Equal(t, "notifications", receivedReq.Permissions[0].Resource)
}

func TestRegisterFromManifest_BadPath(t *testing.T) {
	client := NewClient("http://localhost:1", "test-key", "billing", zap.NewNop())
	err := client.RegisterFromManifest(context.Background(), "/no/such/file.yaml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "load manifest")
}

func TestRegisterWithRetry_SucceedsOnFirstAttempt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := registerModuleResponse{Module: "billing", Registered: 1}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key", "billing", zap.NewNop())
	err := client.RegisterWithRetry(context.Background(), "billing", []PermissionDef{
		{Resource: "invoices", Actions: StandardCRUD()},
	})
	assert.NoError(t, err)
}

func TestRegisterWithRetry_ReturnsErrorAfterExhaustion(t *testing.T) {
	// Use a server that always returns 500.
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"unavailable"}`))
	}))
	defer server.Close()

	// Patch backoff to zero so the test doesn't sleep for minutes.
	// We do this by exercising the function directly with a cancelled context
	// after the first attempt so that subsequent sleeps return ctx.Err().
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	client := NewClient(server.URL, "test-key", "billing", zap.NewNop())
	err := client.RegisterWithRetry(ctx, "billing", []PermissionDef{
		{Resource: "invoices", Actions: StandardCRUD()},
	})
	// Must fail — either context-cancelled or all attempts exhausted.
	assert.Error(t, err)
}

func TestRegisterWithRetry_CancelledContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	client := NewClient(server.URL, "test-key", "billing", zap.NewNop())
	err := client.RegisterWithRetry(ctx, "billing", []PermissionDef{
		{Resource: "invoices", Actions: StandardCRUD()},
	})
	// May fail with context cancelled or http error depending on timing.
	assert.Error(t, err)
}

func TestParseManifest_Valid(t *testing.T) {
	m, err := ParseManifest([]byte("module: billing\npermissions:\n  - resource: invoices\n    actions: [create, read]\n    description: Invoices\n"), "embedded")
	require.NoError(t, err)
	assert.Equal(t, "billing", m.Module)
	require.Len(t, m.Permissions, 1)
	assert.Equal(t, []string{"create", "read"}, m.Permissions[0].Actions)
}

func TestParseManifest_Invalid(t *testing.T) {
	_, err := ParseManifest([]byte("permissions: []\n"), "embedded")
	require.ErrorContains(t, err, "module field is required")

	_, err = ParseManifest([]byte("module: x\npermissions:\n  - actions: [read]\n"), "embedded")
	require.ErrorContains(t, err, "missing resource")

	_, err = ParseManifest([]byte("module: [unclosed"), "embedded")
	require.ErrorContains(t, err, "parse manifest")
}

func TestRegisterFromManifestBytes(t *testing.T) {
	var got registerModuleRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(registerModuleResponse{Module: got.Module, Registered: 1})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-api-key", "billing", zap.NewNop())
	err := client.RegisterFromManifestBytes(context.Background(), []byte("module: billing\npermissions:\n  - resource: invoices\n    actions: [read]\n"))
	require.NoError(t, err)
	assert.Equal(t, "billing", got.Module)
	require.Len(t, got.Permissions, 1)
	assert.Equal(t, "invoices", got.Permissions[0].Resource)

	err = client.RegisterFromManifestBytes(context.Background(), []byte("permissions: []\n"))
	require.ErrorContains(t, err, "load manifest")
}
