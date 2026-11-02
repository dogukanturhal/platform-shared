// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The one live KV v2 mount for application secrets on this cluster is
// "example" (see the ClusterSecretStore every non-Go consumer reads through).
// A default of "secret" -- Vault's own built-in mount, which holds none of
// this data -- silently nests every StandardMappings path one level too deep
// (e.g. secret/data/example/infrastructure/redis) and fails as a bare 403
// from that mount's policy, not as a recognizable wrong-URL error.
func TestDefaultConfig_MountPathMatchesLiveKVMount(t *testing.T) {
	got := DefaultConfig().MountPath
	if got != "example" {
		t.Errorf("DefaultConfig().MountPath = %q, want %q (the live application KV v2 mount)", got, "example")
	}
}

// GetSecret must address <mount>/data/<path> using the configured mount --
// not fold a path segment that happens to look like a mount name into the
// request. A control: a path that DOESN'T start with "example" proves the
// assertion is about the configured mount, not a hardcoded string match.
func TestGetSecret_UsesConfiguredMountNotPathPrefix(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"data":{"password":"irrelevant-in-this-test"}}}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, Config{Enabled: true, MountPath: "example"})
	if _, err := c.GetSecret(context.Background(), "infrastructure/redis"); err != nil {
		t.Fatalf("GetSecret: %v", err)
	}

	const want = "/v1/example/data/infrastructure/redis"
	if gotPath != want {
		t.Errorf("request path = %q, want %q", gotPath, want)
	}

	// Control: a differently-mounted client must produce a DIFFERENT URL.
	// If this ever matched the same path as above, the test above would be
	// vacuous (asserting a hardcoded string rather than the configured mount).
	c2 := newTestClient(t, srv.URL, Config{Enabled: true, MountPath: "other-mount"})
	if _, err := c2.GetSecret(context.Background(), "infrastructure/redis"); err != nil {
		t.Fatalf("GetSecret (control): %v", err)
	}
	const wantControl = "/v1/other-mount/data/infrastructure/redis"
	if gotPath != wantControl {
		t.Errorf("control request path = %q, want %q", gotPath, wantControl)
	}
}

// A 403 with no other context reads as "the whole secret system is denied."
// The error must name the mount and the logical path separately so a wrong
// mount default is diagnosable from the log line alone, without needing to
// reproduce the request by hand.
func TestGetSecret_ErrorNamesMountAndPathSeparately(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, Config{Enabled: true, MountPath: "secret"})
	_, err := c.GetSecret(context.Background(), "example/infrastructure/redis")
	if err == nil {
		t.Fatal("expected an error from a 403 response")
	}
	if !strings.Contains(err.Error(), `mount="secret"`) {
		t.Errorf("error does not name the mount: %v", err)
	}
	if !strings.Contains(err.Error(), `path="example/infrastructure/redis"`) {
		t.Errorf("error does not name the logical path: %v", err)
	}
}
