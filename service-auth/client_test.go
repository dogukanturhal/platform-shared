// SPDX-License-Identifier: Apache-2.0

package serviceauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// generateTestKeyPair produces a 2048-bit RSA key pair for tests only.
// 2048 bits keeps the test suite fast; production keys should be 4096 bits.
func generateTestKeyPair(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generateTestKeyPair: rsa.GenerateKey: %v", err)
	}

	privDER := x509.MarshalPKCS1PrivateKey(privKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	})

	return privKey, privPEM
}

// newTestClient creates a ServiceClient backed by a freshly generated key pair
// and returns both the client and the private key so callers can derive the
// corresponding public key for middleware tests.
func newTestClient(t *testing.T, slug, kid string) (*ServiceClient, *rsa.PrivateKey) {
	t.Helper()
	privKey, privPEM := generateTestKeyPair(t)

	client, err := NewServiceClient(slug, privPEM, kid)
	if err != nil {
		t.Fatalf("NewServiceClient: %v", err)
	}

	return client, privKey
}

// ---------------------------------------------------------------------------
// TestNewServiceClient_ValidKey
// ---------------------------------------------------------------------------

func TestNewServiceClient_ValidKey(t *testing.T) {
	tests := []struct {
		name        string
		serviceSlug string
		keyID       string
		buildPEM    func(t *testing.T) []byte
		wantErr     bool
	}{
		{
			name:        "PKCS1 RSA private key",
			serviceSlug: "billing-service",
			keyID:       "billing-key-1",
			buildPEM: func(t *testing.T) []byte {
				t.Helper()
				_, pemBytes := generateTestKeyPair(t)
				return pemBytes
			},
			wantErr: false,
		},
		{
			name:        "PKCS8 RSA private key",
			serviceSlug: "tenant-management",
			keyID:       "tm-key-1",
			buildPEM: func(t *testing.T) []byte {
				t.Helper()
				privKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("rsa.GenerateKey: %v", err)
				}
				der, err := x509.MarshalPKCS8PrivateKey(privKey)
				if err != nil {
					t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
				}
				return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pemBytes := tt.buildPEM(t)
			client, err := NewServiceClient(tt.serviceSlug, pemBytes, tt.keyID)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if client == nil {
				t.Fatal("expected non-nil client")
			}
			if client.serviceSlug != tt.serviceSlug {
				t.Errorf("serviceSlug = %q; want %q", client.serviceSlug, tt.serviceSlug)
			}
			if client.keyID != tt.keyID {
				t.Errorf("keyID = %q; want %q", client.keyID, tt.keyID)
			}
			if client.audience != defaultAudience {
				t.Errorf("audience = %q; want %q", client.audience, defaultAudience)
			}
			if client.privateKey == nil {
				t.Error("privateKey must not be nil")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestNewServiceClient_InvalidKey
// ---------------------------------------------------------------------------

func TestNewServiceClient_InvalidKey(t *testing.T) {
	_, validPEM := generateTestKeyPair(t)

	tests := []struct {
		name        string
		serviceSlug string
		keyID       string
		pemBytes    []byte
		wantErrSub  string // substring that must appear in the error
	}{
		{
			name:        "empty serviceSlug",
			serviceSlug: "",
			keyID:       "k1",
			pemBytes:    validPEM,
			wantErrSub:  "serviceSlug",
		},
		{
			name:        "empty keyID",
			serviceSlug: "billing-service",
			keyID:       "",
			pemBytes:    validPEM,
			wantErrSub:  "keyID",
		},
		{
			name:        "nil PEM bytes",
			serviceSlug: "billing-service",
			keyID:       "k1",
			pemBytes:    nil,
			wantErrSub:  "privateKeyPEM",
		},
		{
			name:        "empty PEM bytes",
			serviceSlug: "billing-service",
			keyID:       "k1",
			pemBytes:    []byte{},
			wantErrSub:  "privateKeyPEM",
		},
		{
			name:        "garbage bytes — no PEM block",
			serviceSlug: "billing-service",
			keyID:       "k1",
			pemBytes:    []byte("this is definitely not a PEM key"),
			wantErrSub:  "no PEM block",
		},
		{
			name:        "wrong PEM type",
			serviceSlug: "billing-service",
			keyID:       "k1",
			pemBytes: pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: []byte("fake-cert-der"),
			}),
			wantErrSub: "unsupported PEM block type",
		},
		{
			name:        "truncated PKCS1 DER",
			serviceSlug: "billing-service",
			keyID:       "k1",
			pemBytes: pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: []byte("not-valid-der"),
			}),
			wantErrSub: "PKCS#1 parse error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewServiceClient(tt.serviceSlug, tt.pemBytes, tt.keyID)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if client != nil {
				t.Error("expected nil client on error")
			}
			if !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Errorf("error %q does not contain expected substring %q", err.Error(), tt.wantErrSub)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestGenerateToken_ValidJWT
// ---------------------------------------------------------------------------

func TestGenerateToken_ValidJWT(t *testing.T) {
	const slug = "subscription-management"
	const kid = "sm-key-2"

	client, privKey := newTestClient(t, slug, kid)
	pubKey := &privKey.PublicKey

	tokenStr, err := client.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("GenerateToken returned empty string")
	}

	// Parse and verify with the matching public key.
	claims := &ServiceClaims{}
	token, err := jwt.ParseWithClaims(
		tokenStr,
		claims,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				t.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return pubKey, nil
		},
		jwt.WithAudience(defaultAudience),
	)
	if err != nil {
		t.Fatalf("jwt.ParseWithClaims: %v", err)
	}
	if !token.Valid {
		t.Fatal("token.Valid is false")
	}

	// --- Verify individual claims ---

	if claims.Issuer != slug {
		t.Errorf("iss = %q; want %q", claims.Issuer, slug)
	}
	if claims.Subject != slug {
		t.Errorf("sub = %q; want %q", claims.Subject, slug)
	}
	if claims.ServiceSlug != slug {
		t.Errorf("service_slug = %q; want %q", claims.ServiceSlug, slug)
	}
	if claims.ID == "" {
		t.Error("jti must not be empty")
	}

	// Audience must contain exactly "falcon-id".
	if len(claims.Audience) != 1 || claims.Audience[0] != defaultAudience {
		t.Errorf("aud = %v; want [%q]", claims.Audience, defaultAudience)
	}

	// "kid" header must match what we provided.
	if gotKid, ok := token.Header["kid"].(string); !ok || gotKid != kid {
		t.Errorf("kid header = %v; want %q", token.Header["kid"], kid)
	}

	// Expiry must be approximately now + 5 minutes.
	now := time.Now().UTC()
	wantExp := now.Add(tokenTTL)
	gotExp := claims.ExpiresAt.Time

	delta := gotExp.Sub(wantExp)
	if delta < -2*time.Second || delta > 2*time.Second {
		t.Errorf("exp delta out of tolerance: got %v, want ~%v", gotExp, wantExp)
	}

	// IssuedAt must be close to now.
	gotIat := claims.IssuedAt.Time
	iatDelta := gotIat.Sub(now)
	if iatDelta < -2*time.Second || iatDelta > 2*time.Second {
		t.Errorf("iat delta out of tolerance: got %v, want ~now", gotIat)
	}
}

// TestGenerateToken_UniqueJTI ensures two consecutively generated tokens carry
// different jti values, preventing replay acceptance when jti is tracked.
func TestGenerateToken_UniqueJTI(t *testing.T) {
	client, _ := newTestClient(t, "quota-service", "qs-key-1")

	tok1, err := client.GenerateToken()
	if err != nil {
		t.Fatalf("first GenerateToken: %v", err)
	}
	tok2, err := client.GenerateToken()
	if err != nil {
		t.Fatalf("second GenerateToken: %v", err)
	}

	// Parse without verification (we just want the jti claims).
	parser := jwt.NewParser()
	c1 := &ServiceClaims{}
	c2 := &ServiceClaims{}

	if _, _, err := parser.ParseUnverified(tok1, c1); err != nil {
		t.Fatalf("ParseUnverified tok1: %v", err)
	}
	if _, _, err := parser.ParseUnverified(tok2, c2); err != nil {
		t.Fatalf("ParseUnverified tok2: %v", err)
	}
	if c1.ID == c2.ID {
		t.Errorf("expected unique jti values; both tokens have jti=%q", c1.ID)
	}
}

// ---------------------------------------------------------------------------
// TestSignRequest_AddsAuthHeader
// ---------------------------------------------------------------------------

func TestSignRequest_AddsAuthHeader(t *testing.T) {
	const slug = "workflow-engine"
	const kid = "we-key-3"

	client, privKey := newTestClient(t, slug, kid)
	pubKey := &privKey.PublicKey

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://falcon-id/api/v1/internal/health", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}

	if err := client.SignRequest(req); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		t.Fatal("Authorization header not set after SignRequest")
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		t.Errorf("Authorization header %q does not start with \"Bearer \"", authHeader)
	}

	// The token must be verifiable with the client's public key.
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	claims := &ServiceClaims{}
	token, err := jwt.ParseWithClaims(
		tokenStr,
		claims,
		func(_ *jwt.Token) (interface{}, error) { return pubKey, nil },
		jwt.WithAudience(defaultAudience),
	)
	if err != nil {
		t.Fatalf("jwt.ParseWithClaims after SignRequest: %v", err)
	}
	if !token.Valid {
		t.Error("token.Valid is false after SignRequest")
	}
	if claims.ServiceSlug != slug {
		t.Errorf("service_slug = %q; want %q", claims.ServiceSlug, slug)
	}
}

// TestSignRequest_NilRequest ensures SignRequest returns an error for nil input
// rather than panicking.
func TestSignRequest_NilRequest(t *testing.T) {
	client, _ := newTestClient(t, "billing-service", "b-key-1")

	err := client.SignRequest(nil)
	if err == nil {
		t.Fatal("expected error for nil request, got nil")
	}
}

// TestSignRequest_OverwritesExistingHeader verifies that a pre-existing
// Authorization header is replaced, not appended to.
func TestSignRequest_OverwritesExistingHeader(t *testing.T) {
	client, _ := newTestClient(t, "billing-service", "b-key-1")

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://falcon-id/api/v1/internal/users", nil)
	req.Header.Set("Authorization", "Bearer old-stale-token")

	if err := client.SignRequest(req); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader == "Bearer old-stale-token" {
		t.Error("SignRequest did not overwrite the existing Authorization header")
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		t.Errorf("Authorization header %q does not start with \"Bearer \"", authHeader)
	}
}
