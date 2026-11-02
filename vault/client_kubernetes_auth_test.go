// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
)

// newTestClient builds a Client wired to a test Vault server without going
// through NewClient (which would also try to authenticate immediately).
func newTestClient(t *testing.T, addr string, cfg Config) *Client {
	t.Helper()
	apiCfg := api.DefaultConfig()
	apiCfg.Address = addr
	apiClient, err := api.NewClient(apiCfg)
	if err != nil {
		t.Fatalf("api.NewClient: %v", err)
	}
	return &Client{client: apiClient, config: cfg, cache: make(map[string]*cachedSecret), stopCh: make(chan struct{})}
}

func writeTempToken(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write temp token: %v", err)
	}
	return path
}

// A successful Kubernetes auth login must set the client token from Vault's
// response and record a lease-based expiry -- the same contract AppRole and
// dev-token auth already provide, so callers (renewal loop, IsEnabled callers
// expecting a usable client) do not need to special-case the auth method.
func TestAuthenticateKubernetes_Success(t *testing.T) {
	var gotRole, gotJWT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/kubernetes/login" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotRole, _ = body["role"].(string)
		gotJWT, _ = body["jwt"].(string)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": map[string]interface{}{
				"client_token":   "s.k8s-issued-token",
				"lease_duration": 3600,
			},
		})
	}))
	defer srv.Close()

	tokenPath := writeTempToken(t, "fake-service-account-jwt")
	c := newTestClient(t, srv.URL, Config{
		Enabled:              true,
		KubernetesRole:       "domain-management-dkim-writer",
		KubernetesMountPath:  "kubernetes",
		KubernetesTokenPath:  tokenPath,
		TokenRenewalInterval: 30 * time.Minute,
	})

	if err := c.authenticate(); err != nil {
		t.Fatalf("authenticate() returned error: %v", err)
	}
	if c.client.Token() != "s.k8s-issued-token" {
		t.Errorf("client token = %q, want the token Vault returned", c.client.Token())
	}
	if gotRole != "domain-management-dkim-writer" {
		t.Errorf("role sent to Vault = %q", gotRole)
	}
	if gotJWT != "fake-service-account-jwt" {
		t.Errorf("jwt sent to Vault = %q, want contents of the token file", gotJWT)
	}
	c.tokenMu.RLock()
	expiry := c.tokenExpiry
	c.tokenMu.RUnlock()
	if time.Until(expiry) <= 0 || time.Until(expiry) > 2*time.Hour {
		t.Errorf("tokenExpiry not set from lease_duration: %v", expiry)
	}
}

// A publish that cannot even authenticate must surface as an error, not as a
// silently-nil client that later reports every write as a mysterious "no
// selectors" failure to whoever reads Vault instead.
func TestAuthenticateKubernetes_LoginRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{"permission denied"}})
	}))
	defer srv.Close()

	tokenPath := writeTempToken(t, "fake-service-account-jwt")
	c := newTestClient(t, srv.URL, Config{
		Enabled:             true,
		KubernetesRole:      "domain-management-dkim-writer",
		KubernetesMountPath: "kubernetes",
		KubernetesTokenPath: tokenPath,
	})

	err := c.authenticate()
	if err == nil {
		t.Fatal("expected an error for a rejected login, got nil")
	}
	if !strings.Contains(err.Error(), "kubernetes auth login failed") {
		t.Errorf("error does not identify Kubernetes auth as the failing step: %v", err)
	}
}

// If the projected ServiceAccount token is not mounted (e.g. a Deployment
// missing the volume this auth method depends on), that must fail loudly at
// authenticate() rather than attempt a login with an empty/garbage JWT.
func TestAuthenticateKubernetes_MissingTokenFile(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1:0", Config{
		Enabled:             true,
		KubernetesRole:      "domain-management-dkim-writer",
		KubernetesMountPath: "kubernetes",
		KubernetesTokenPath: "/nonexistent/path/token",
	})

	err := c.authenticate()
	if err == nil {
		t.Fatal("expected an error when the SA token file is missing")
	}
	if !strings.Contains(err.Error(), "service account token") {
		t.Errorf("error does not name the missing token file: %v", err)
	}
}

// Setting VAULT_K8S_ROLE must take the Kubernetes path even when legacy
// AppRole env vars are also present (e.g. left over from a prior deploy) --
// otherwise a config change intended to switch a service onto Kubernetes
// auth silently keeps using stale AppRole credentials instead.
func TestAuthenticate_KubernetesTakesPrecedenceOverAppRole(t *testing.T) {
	loginPath := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": map[string]interface{}{"client_token": "tok", "lease_duration": 60},
		})
	}))
	defer srv.Close()

	tokenPath := writeTempToken(t, "jwt")
	c := newTestClient(t, srv.URL, Config{
		Enabled:             true,
		RoleID:              "stale-role-id",
		SecretID:            "stale-secret-id",
		KubernetesRole:      "domain-management-dkim-writer",
		KubernetesMountPath: "kubernetes",
		KubernetesTokenPath: tokenPath,
	})

	if err := c.authenticate(); err != nil {
		t.Fatalf("authenticate() returned error: %v", err)
	}
	if loginPath != "/v1/auth/kubernetes/login" {
		t.Errorf("login hit %q, want the kubernetes auth path (AppRole config must be ignored)", loginPath)
	}
}

// CONTROL: without VAULT_K8S_ROLE, VAULT_TOKEN, or AppRole creds, authenticate
// must still refuse -- proving the new Kubernetes branch did not accidentally
// make the "nothing configured" case pass.
func TestAuthenticate_NoMethodConfiguredStillFails(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "")
	c := newTestClient(t, "http://127.0.0.1:0", Config{Enabled: true})
	if err := c.authenticate(); err == nil {
		t.Fatal("expected an error when no auth method is configured")
	}
}
