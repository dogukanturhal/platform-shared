// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var paymentContext = TokenContext{ContextVersion: "v1", Service: "payments", Provider: "stripe", Purpose: "customer-token", TenantID: "tenant-1"}

func testProtector(t *testing.T, handler http.HandlerFunc) TokenProtector {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	tokenPath := filepath.Join(t.TempDir(), "sa-token")
	if err := os.WriteFile(tokenPath, []byte("projected-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "vault-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(server.URL)
	p, err := NewTokenProtector(context.Background(), TokenProtectorConfig{Address: server.URL, AllowedHosts: []string{u.Host}, TLSCAFile: caPath, AuthMethod: "kubernetes", KubernetesRole: "payments", KubernetesTokenPath: tokenPath, TransitMount: "transit", EncryptionKey: "payment-token", HMACKey: "payment-token-hmac", RequestTimeout: time.Second, RenewalWindow: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func vaultReply(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}
func loginReply(w http.ResponseWriter) {
	vaultReply(w, map[string]any{"auth": map[string]any{"client_token": "vault-session", "lease_duration": 3600}})
}

func tlsConfig(t *testing.T, server *httptest.Server) TokenProtectorConfig {
	t.Helper()
	caPath := filepath.Join(t.TempDir(), "vault-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(server.URL)
	tokenPath := filepath.Join(t.TempDir(), "sa-token")
	if err := os.WriteFile(tokenPath, []byte("projected-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	return TokenProtectorConfig{Address: server.URL, AllowedHosts: []string{u.Host}, TLSCAFile: caPath, AuthMethod: "kubernetes", KubernetesRole: "payments", KubernetesTokenPath: tokenPath, TransitMount: "transit", EncryptionKey: "payment-token", HMACKey: "payment-token-hmac", RequestTimeout: time.Second, RenewalWindow: time.Minute}
}

func TestTokenProtectorKubernetesTransitContract(t *testing.T) {
	var contextSeen string
	p := testProtector(t, func(w http.ResponseWriter, r *http.Request) {
		var request map[string]string
		_ = json.NewDecoder(r.Body).Decode(&request)
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			if request["role"] != "payments" || request["jwt"] != "projected-jwt" {
				t.Error("Kubernetes login request was not exact")
			}
			loginReply(w)
		case "/v1/transit/encrypt/payment-token":
			contextSeen = request["context"]
			vaultReply(w, map[string]any{"data": map[string]any{"ciphertext": "vault:v2:encrypted"}})
		case "/v1/transit/decrypt/payment-token":
			if request["context"] != contextSeen {
				t.Error("decrypt context differs")
			}
			vaultReply(w, map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString([]byte("token-value"))}})
		case "/v1/transit/hmac/payment-token-hmac":
			vaultReply(w, map[string]any{"data": map[string]any{"hmac": "vault:v3:digest"}})
		case "/v1/transit/verify/payment-token-hmac":
			vaultReply(w, map[string]any{"data": map[string]any{"valid": true}})
		case "/v1/transit/rewrap/payment-token":
			if request["context"] != contextSeen {
				t.Error("rewrap context differs")
			}
			vaultReply(w, map[string]any{"data": map[string]any{"ciphertext": "vault:v4:rewrapped"}})
		case "/v1/transit/keys/payment-token":
			vaultReply(w, map[string]any{"data": map[string]any{"latest_version": 4, "min_decryption_version": 1, "min_encryption_version": 4}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	protected, err := p.Protect(context.Background(), []byte("token-value"), paymentContext)
	if err != nil || protected.KeyVersion != 2 {
		t.Fatalf("protect: %#v %v", protected, err)
	}
	if got, err := p.Unprotect(context.Background(), protected, paymentContext); err != nil || string(got) != "token-value" {
		t.Fatalf("unprotect: %q %v", got, err)
	}
	digest, err := p.Digest(context.Background(), []byte("token-value"), paymentContext)
	if err != nil || digest.KeyVersion != 3 {
		t.Fatalf("digest: %#v %v", digest, err)
	}
	if valid, err := p.VerifyDigest(context.Background(), []byte("token-value"), paymentContext, digest); err != nil || !valid {
		t.Fatalf("verify: %t %v", valid, err)
	}
	if rewrapped, err := p.Rewrap(context.Background(), protected, paymentContext); err != nil || rewrapped.KeyVersion != 4 {
		t.Fatalf("rewrap: %#v %v", rewrapped, err)
	}
	metadata, err := p.EncryptionKeyMetadata(context.Background())
	if err != nil || metadata.LatestVersion != 4 {
		t.Fatalf("metadata: %#v %v", metadata, err)
	}
	decoded, err := base64.StdEncoding.DecodeString(contextSeen)
	if err != nil || !strings.Contains(string(decoded), `"tenant_id":"tenant-1"`) {
		t.Fatal("context is not canonical base64 JSON")
	}
}

func TestTokenProtectorRenewalReauthenticationAndConcurrency(t *testing.T) {
	var logins, renewals, encrypts atomic.Int32
	p := testProtector(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			logins.Add(1)
			vaultReply(w, map[string]any{"auth": map[string]any{"client_token": "session", "lease_duration": 1}})
		case "/v1/auth/token/renew-self":
			renewals.Add(1)
			http.Error(w, "expired", http.StatusForbidden)
		case "/v1/transit/encrypt/payment-token":
			encrypts.Add(1)
			vaultReply(w, map[string]any{"data": map[string]any{"ciphertext": "vault:v1:encrypted"}})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	})
	time.Sleep(1100 * time.Millisecond)
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.Protect(context.Background(), []byte("x"), paymentContext); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if logins.Load() < 2 || renewals.Load() < 1 || encrypts.Load() != 12 {
		t.Fatalf("login=%d renewal=%d encrypt=%d", logins.Load(), renewals.Load(), encrypts.Load())
	}
}

func forceRenewal(t *testing.T, protector TokenProtector) *vaultTokenProtector {
	t.Helper()
	p := protector.(*vaultTokenProtector)
	p.mu.Lock()
	p.expires = time.Now().Add(time.Hour)
	p.refresh = time.Time{}
	p.mu.Unlock()
	return p
}

func TestTokenProtectorRenewsNestedAuthLeaseAndRotatesToken(t *testing.T) {
	var logins, renewals, encrypts atomic.Int32
	p := testProtector(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			logins.Add(1)
			vaultReply(w, map[string]any{"auth": map[string]any{"client_token": "initial-session", "lease_duration": 3600}})
		case "/v1/auth/token/renew-self":
			renewals.Add(1)
			if r.Header.Get("X-Vault-Token") != "initial-session" {
				t.Error("renewal did not use the original token")
			}
			vaultReply(w, map[string]any{"auth": map[string]any{"client_token": "rotated-session", "lease_duration": 4, "renewable": true}})
		case "/v1/transit/encrypt/payment-token":
			encrypts.Add(1)
			if r.Header.Get("X-Vault-Token") != "rotated-session" {
				t.Error("Transit request did not use the rotated token")
			}
			vaultReply(w, map[string]any{"data": map[string]any{"ciphertext": "vault:v1:encrypted"}})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	})
	concrete := forceRenewal(t, p)
	if _, err := p.Protect(context.Background(), []byte("x"), paymentContext); err != nil {
		t.Fatal(err)
	}
	concrete.mu.Lock()
	refresh, expires := concrete.refresh, concrete.expires
	concrete.mu.Unlock()
	now := time.Now()
	if logins.Load() != 1 || renewals.Load() != 1 || encrypts.Load() != 1 {
		t.Fatalf("login=%d renewal=%d encrypt=%d", logins.Load(), renewals.Load(), encrypts.Load())
	}
	if !refresh.After(now) || !expires.After(refresh) || expires.Sub(now) < 3*time.Second {
		t.Fatalf("renewed lease was not scheduled: refresh=%v expires=%v now=%v", refresh, expires, now)
	}
}

func TestTokenProtectorMalformedRenewalFallsBackToOneLogin(t *testing.T) {
	var logins, renewals atomic.Int32
	p := testProtector(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			if logins.Add(1) == 1 {
				vaultReply(w, map[string]any{"auth": map[string]any{"client_token": "initial-session", "lease_duration": 3600}})
				return
			}
			vaultReply(w, map[string]any{"auth": map[string]any{"client_token": "replacement-session", "lease_duration": 3600}})
		case "/v1/auth/token/renew-self":
			renewals.Add(1)
			vaultReply(w, map[string]any{"auth": map[string]any{"lease_duration": "invalid", "renewable": true}})
		case "/v1/transit/encrypt/payment-token":
			if r.Header.Get("X-Vault-Token") != "replacement-session" {
				t.Error("Transit request did not use fallback login token")
			}
			vaultReply(w, map[string]any{"data": map[string]any{"ciphertext": "vault:v1:encrypted"}})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	})
	forceRenewal(t, p)
	if _, err := p.Protect(context.Background(), []byte("x"), paymentContext); err != nil {
		t.Fatal(err)
	}
	if logins.Load() != 2 || renewals.Load() != 1 {
		t.Fatalf("login=%d renewal=%d", logins.Load(), renewals.Load())
	}
}

func TestTokenProtectorSingleFlightsConcurrentRenewal(t *testing.T) {
	var logins, renewals, encrypts atomic.Int32
	p := testProtector(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			logins.Add(1)
			vaultReply(w, map[string]any{"auth": map[string]any{"client_token": "session", "lease_duration": 3600}})
		case "/v1/auth/token/renew-self":
			renewals.Add(1)
			vaultReply(w, map[string]any{"auth": map[string]any{"lease_duration": 3600, "renewable": true}})
		case "/v1/transit/encrypt/payment-token":
			encrypts.Add(1)
			vaultReply(w, map[string]any{"data": map[string]any{"ciphertext": "vault:v1:encrypted"}})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	})
	forceRenewal(t, p)
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.Protect(context.Background(), []byte("x"), paymentContext); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if logins.Load() != 1 || renewals.Load() != 1 || encrypts.Load() != 12 {
		t.Fatalf("login=%d renewal=%d encrypt=%d", logins.Load(), renewals.Load(), encrypts.Load())
	}
}

func TestTokenProtectorRenewalCancellationAndOversizedResponsesAreRedacted(t *testing.T) {
	for name, handler := range map[string]func(t *testing.T){
		"canceled": func(t *testing.T) {
			renewStarted := make(chan struct{})
			releaseRenewal := make(chan struct{})
			defer close(releaseRenewal)
			p := testProtector(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/auth/kubernetes/login":
					loginReply(w)
				case "/v1/auth/token/renew-self":
					close(renewStarted)
					<-releaseRenewal
				default:
					t.Errorf("unexpected %s", r.URL.Path)
				}
			})
			forceRenewal(t, p)
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() { _, err := p.Protect(ctx, []byte("x"), paymentContext); result <- err }()
			select {
			case <-renewStarted:
				cancel()
			case <-time.After(time.Second):
				t.Fatal("renewal did not start")
			}
			select {
			case err := <-result:
				if err == nil || strings.Contains(err.Error(), "session") {
					t.Fatalf("canceled renewal leaked or succeeded: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("canceled renewal did not return")
			}
		},
		"oversized": func(t *testing.T) {
			const secret = "renewal-token-secret"
			var logins atomic.Int32
			p := testProtector(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/auth/kubernetes/login":
					if logins.Add(1) == 1 {
						vaultReply(w, map[string]any{"auth": map[string]any{"client_token": "session", "lease_duration": 3600}})
						return
					}
					http.Error(w, secret, http.StatusServiceUnavailable)
				case "/v1/auth/token/renew-self":
					_, _ = w.Write([]byte(strings.Repeat("x", maxVaultResponseBytes+1)))
				default:
					t.Errorf("unexpected %s", r.URL.Path)
				}
			})
			forceRenewal(t, p)
			_, err := p.Protect(context.Background(), []byte("x"), paymentContext)
			if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "session") {
				t.Fatalf("oversized renewal leaked or succeeded: %v", err)
			}
			if logins.Load() != 2 {
				t.Fatalf("expected one fallback login, got %d", logins.Load())
			}
		},
	} {
		t.Run(name, handler)
	}
}

func TestTokenProtectorReauthenticatesAfterTransitForbidden(t *testing.T) {
	var logins, encrypts atomic.Int32
	p := testProtector(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			logins.Add(1)
			vaultReply(w, map[string]any{"auth": map[string]any{"client_token": "fresh-session", "lease_duration": 3600}})
		case "/v1/transit/encrypt/payment-token":
			if encrypts.Add(1) == 1 {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			vaultReply(w, map[string]any{"data": map[string]any{"ciphertext": "vault:v1:encrypted"}})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	})
	if _, err := p.Protect(context.Background(), []byte("x"), paymentContext); err != nil {
		t.Fatal(err)
	}
	if logins.Load() != 2 || encrypts.Load() != 2 {
		t.Fatalf("login=%d encrypt=%d", logins.Load(), encrypts.Load())
	}
}

func TestTokenProtectorSingleFlightsConcurrentAuthFailure(t *testing.T) {
	var logins atomic.Int32
	p := testProtector(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			if logins.Add(1) == 1 {
				vaultReply(w, map[string]any{"auth": map[string]any{"client_token": "session", "lease_duration": 1}})
				return
			}
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		case "/v1/auth/token/renew-self":
			http.Error(w, "expired", http.StatusForbidden)
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	})
	time.Sleep(600 * time.Millisecond)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.Protect(context.Background(), []byte("x"), paymentContext); err == nil {
				t.Error("authentication failure was accepted")
			}
		}()
	}
	wg.Wait()
	if logins.Load() != 2 {
		t.Fatalf("expected one reauthentication attempt, got %d logins", logins.Load())
	}
}

func TestTokenProtectorFailClosedAndRedacts(t *testing.T) {
	secret := "plaintext-token"
	for name, handler := range map[string]http.HandlerFunc{
		"unavailable": func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "down", http.StatusServiceUnavailable) },
		"malformed": func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "login") {
				loginReply(w)
			} else {
				_, _ = w.Write([]byte("{"))
			}
		},
		"oversized": func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "login") {
				loginReply(w)
			} else {
				_, _ = w.Write([]byte(strings.Repeat("x", maxVaultResponseBytes+1)))
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			if name == "unavailable" {
				server := httptest.NewServer(handler)
				defer server.Close()
				tokenPath := filepath.Join(t.TempDir(), "sa-token")
				if err := os.WriteFile(tokenPath, []byte("projected-jwt"), 0o600); err != nil {
					t.Fatal(err)
				}
				_, err := NewTokenProtector(context.Background(), TokenProtectorConfig{Address: server.URL, AuthMethod: "kubernetes", KubernetesRole: "payments", KubernetesTokenPath: tokenPath, TransitMount: "transit", EncryptionKey: "payment-token", HMACKey: "payment-token-hmac", RequestTimeout: time.Second})
				if err == nil || strings.Contains(err.Error(), secret) {
					t.Fatal("authentication did not fail closed or leaked secret")
				}
				return
			}
			p := testProtector(t, handler)
			_, err := p.Protect(context.Background(), []byte(secret), paymentContext)
			if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "vault-session") {
				t.Fatalf("expected redacted failure, got %v", err)
			}
		})
	}
}

func TestTokenProtectorRejectsOversizedPlaintext(t *testing.T) {
	p := testProtector(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			loginReply(w)
		case "/v1/transit/decrypt/payment-token":
			vaultReply(w, map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", defaultMaxTokenBytes+1)))}})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	})
	_, err := p.Unprotect(context.Background(), ProtectedToken{Ciphertext: "vault:v1:encrypted", KeyVersion: 1}, paymentContext)
	if err == nil {
		t.Fatal("oversized plaintext was accepted")
	}
}

func TestTokenProtectorRejectsContextMismatchAndUnsafeConfiguration(t *testing.T) {
	p := testProtector(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "login") {
			loginReply(w)
			return
		}
		http.Error(w, "context mismatch", http.StatusBadRequest)
	})
	_, err := p.Unprotect(context.Background(), ProtectedToken{Ciphertext: "vault:v1:encrypted", KeyVersion: 1}, TokenContext{Service: "payments", Provider: "stripe", Purpose: "customer-token", TenantID: "other"})
	if err == nil {
		t.Fatal("context mismatch was accepted")
	}
	_, err = NewTokenProtector(context.Background(), TokenProtectorConfig{Address: "https://vault.example", AuthMethod: "approle", KubernetesRole: "bad/role", KubernetesTokenPath: "/token", TransitMount: "transit", EncryptionKey: "key", HMACKey: "hmac", RequestTimeout: time.Second})
	if err == nil {
		t.Fatal("unsafe auth configuration accepted")
	}
	if DigestEqual(TokenDigest{Value: "vault:v1:a", KeyVersion: 1}, TokenDigest{Value: "vault:v1:b", KeyVersion: 1}) {
		t.Fatal("different digests compare equal")
	}
}

func TestTokenProtectorEndpointAndInputHardening(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/kubernetes/login" {
			loginReply(w)
			return
		}
		vaultReply(w, map[string]any{"data": map[string]any{"ciphertext": "vault:v1:encrypted", "key_version": 2}})
	}))
	defer server.Close()
	cfg := tlsConfig(t, server)
	for _, address := range []string{"http://vault.example", "https://user@vault.example", "https://vault.example?x=y", "https://vault.example#fragment"} {
		bad := cfg
		bad.Address = address
		if _, err := NewTokenProtector(context.Background(), bad); err == nil {
			t.Fatalf("unsafe endpoint accepted: %s", address)
		}
	}
	bad := cfg
	bad.TransitMount = "transit/../../sys"
	if _, err := NewTokenProtector(context.Background(), bad); err == nil {
		t.Fatal("path injection accepted")
	}
	bad = cfg
	bad.TLSCAFile = filepath.Join(t.TempDir(), "missing")
	if _, err := NewTokenProtector(context.Background(), bad); err == nil {
		t.Fatal("missing CA bundle accepted")
	}
	p, err := NewTokenProtector(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Protect(context.Background(), []byte(strings.Repeat("x", defaultMaxTokenBytes+1)), paymentContext); err == nil {
		t.Fatal("oversized token accepted")
	}
	if _, err := p.Protect(context.Background(), []byte("x"), TokenContext{ContextVersion: "v1", Service: "Payments", Provider: "stripe", Purpose: "customer-token", TenantID: "tenant-1"}); err == nil {
		t.Fatal("non-canonical context accepted")
	}
	if _, err := p.Protect(context.Background(), []byte("x"), paymentContext); err == nil {
		t.Fatal("response version mismatch accepted")
	}
}

func TestTokenProtectorRejectsRedirects(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://attacker.invalid", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	cfg := tlsConfig(t, server)
	_, err := NewTokenProtector(context.Background(), cfg)
	if err == nil {
		t.Fatal("redirected Vault login was accepted")
	}
}
