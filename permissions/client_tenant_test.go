// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

// Registration must carry X-Tenant-ID; without it Falcon-ID's ExtractTenant
// middleware answers 400 and every service silently starts with no permissions
// registered.
func TestRegisterModule_SendsTenantHeader(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Tenant-ID")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"module":"m","registered":1,"updated":0}`))
	}))
	defer srv.Close()

	c := NewClientWithHTTPClient(srv.URL, "svc", srv.Client(), zap.NewNop())
	c.logger = zap.NewNop()
	if err := c.RegisterModule(context.Background(), "m", []PermissionDef{{Resource: "r", Actions: []string{"read"}}}); err != nil {
		t.Fatalf("RegisterModule: %v", err)
	}
	if got == "" {
		t.Fatal("X-Tenant-ID was not sent")
	}
	if got != defaultPlatformTenantID {
		t.Errorf("X-Tenant-ID = %q, want %q", got, defaultPlatformTenantID)
	}
}

func TestRegisterModule_ExplicitTenantWins(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Tenant-ID")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"module":"m"}`))
	}))
	defer srv.Close()

	c := NewClientWithHTTPClient(srv.URL, "svc", srv.Client(), zap.NewNop())
	c.logger = zap.NewNop()
	c.SetPlatformTenantID("11111111-1111-1111-1111-111111111111")
	_ = c.RegisterModule(context.Background(), "m", []PermissionDef{{Resource: "r", Actions: []string{"read"}}})
	if got != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("explicit tenant not used, got %q", got)
	}
}

func TestTenantID_EnvOverride(t *testing.T) {
	t.Setenv("PLATFORM_TENANT_ID", "22222222-2222-2222-2222-222222222222")
	c := &Client{}
	if id := c.tenantID(); id != "22222222-2222-2222-2222-222222222222" {
		t.Errorf("env override ignored, got %q", id)
	}
}
