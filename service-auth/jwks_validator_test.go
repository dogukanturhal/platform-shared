// SPDX-License-Identifier: Apache-2.0

package serviceauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// buildJWKSServer starts an httptest.Server that serves a JWKS document
// containing the supplied RSA public key. Returns the server and its URL.
// The caller must close the server.
func buildJWKSServer(t *testing.T, kid string, pubKey *rsa.PublicKey) *httptest.Server {
	t.Helper()

	nBytes := pubKey.N.Bytes()
	eInt := big.NewInt(int64(pubKey.E))
	eBytes := eInt.Bytes()

	jwksDoc := map[string]interface{}{
		"keys": []interface{}{
			map[string]interface{}{
				"kty": "RSA",
				"kid": kid,
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(nBytes),
				"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksDoc)
	}))

	t.Cleanup(srv.Close)
	return srv
}

// buildTestJWT generates a signed service JWT for use in validator tests.
func buildTestJWT(t *testing.T, privKey *rsa.PrivateKey, kid, slug, issuer string) string {
	t.Helper()

	privDER := x509.MarshalPKCS1PrivateKey(privKey)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER})

	client, err := NewServiceClient(slug, privPEM, kid)
	if err != nil {
		t.Fatalf("NewServiceClient: %v", err)
	}
	_ = issuer // issuer == slug by convention in ServiceClient

	tokenStr, err := client.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	return tokenStr
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestJWTValidator_ValidToken(t *testing.T) {
	const kid = "test-kid-1"
	const slug = "integration-bus"

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	srv := buildJWKSServer(t, kid, &privKey.PublicKey)
	tokenStr := buildTestJWT(t, privKey, kid, slug, slug)

	validator, err := NewJWTValidator(srv.URL, "")
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	claims, err := validator.ValidateToken(tokenStr)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	if claims.ServiceSlug != slug {
		t.Errorf("ServiceSlug = %q; want %q", claims.ServiceSlug, slug)
	}
	if claims.ServiceID != slug {
		t.Errorf("ServiceID = %q; want %q", claims.ServiceID, slug)
	}
	if claims.ExpiresAt.IsZero() {
		t.Error("ExpiresAt must not be zero")
	}
}

func TestJWTValidator_IssuerMismatch(t *testing.T) {
	const kid = "test-kid-2"
	const slug = "billing-service"

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	srv := buildJWKSServer(t, kid, &privKey.PublicKey)
	tokenStr := buildTestJWT(t, privKey, kid, slug, slug)

	// Validator expects a different issuer.
	validator, err := NewJWTValidator(srv.URL, "different-issuer")
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	_, err = validator.ValidateToken(tokenStr)
	if err == nil {
		t.Fatal("expected issuer mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "issuer mismatch") {
		t.Errorf("error %q does not mention issuer mismatch", err.Error())
	}
}

func TestJWTValidator_UnknownKID(t *testing.T) {
	const kid = "test-kid-3"
	const slug = "crm-service"

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	// JWKS server returns a DIFFERENT kid than the one in the token.
	srv := buildJWKSServer(t, "completely-different-kid", &privKey.PublicKey)
	tokenStr := buildTestJWT(t, privKey, kid, slug, slug)

	validator, err := NewJWTValidator(srv.URL, "")
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	_, err = validator.ValidateToken(tokenStr)
	if err == nil {
		t.Fatal("expected unknown kid error, got nil")
	}
}

func TestJWTValidator_EmptyToken(t *testing.T) {
	validator, err := NewJWTValidator("http://localhost/jwks.json", "")
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	_, err = validator.ValidateToken("")
	if err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
}

func TestJWTValidator_KeyCaching(t *testing.T) {
	const kid = "cache-test-kid"
	const slug = "quota-service"

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	fetchCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetchCount++
		nBytes := privKey.N.Bytes()
		eBytes := big.NewInt(int64(privKey.E)).Bytes()

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []interface{}{
				map[string]interface{}{
					"kty": "RSA",
					"kid": kid,
					"alg": "RS256",
					"n":   base64.RawURLEncoding.EncodeToString(nBytes),
					"e":   base64.RawURLEncoding.EncodeToString(eBytes),
				},
			},
		})
	}))
	t.Cleanup(srv.Close)

	validator, _ := NewJWTValidator(srv.URL, "")
	validator.WithCacheTTL(10 * time.Second) // long TTL so cache doesn't expire

	tokenStr := buildTestJWT(t, privKey, kid, slug, slug)

	for i := 0; i < 5; i++ {
		if _, err := validator.ValidateToken(tokenStr); err != nil {
			t.Fatalf("ValidateToken iteration %d: %v", i, err)
		}
	}

	// JWKS endpoint should only have been called once (initial fetch).
	if fetchCount != 1 {
		t.Errorf("JWKS endpoint fetched %d times; want 1 (subsequent calls should use cache)", fetchCount)
	}
}

func TestJWTValidator_NewJWTValidator_EmptyURL(t *testing.T) {
	_, err := NewJWTValidator("", "")
	if err == nil {
		t.Fatal("expected error for empty jwksURL, got nil")
	}
}

func TestExtractKIDFromToken(t *testing.T) {
	const kid = "extract-kid-test"
	const slug = "test-service"

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	privDER := x509.MarshalPKCS1PrivateKey(privKey)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER})

	client, _ := NewServiceClient(slug, privPEM, kid)
	tokenStr, _ := client.GenerateToken()

	gotKID, err := extractKIDFromToken(tokenStr)
	if err != nil {
		t.Fatalf("extractKIDFromToken: %v", err)
	}
	if gotKID != kid {
		t.Errorf("kid = %q; want %q", gotKID, kid)
	}
}

func TestExtractKIDFromToken_MalformedToken(t *testing.T) {
	_, err := extractKIDFromToken("not-a-jwt")
	if err == nil {
		t.Fatal("expected error for malformed token, got nil")
	}
}
