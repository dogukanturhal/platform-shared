// SPDX-License-Identifier: Apache-2.0

package serviceauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// testJWKSServer spins up an HTTP server that returns a JWKS document for the
// given key pair. Returns the server and the key ID used.
func testJWKSServer(t *testing.T, pubKey *rsa.PublicKey, kid string) *httptest.Server {
	t.Helper()

	jwksDoc := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": kid,
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
			},
		},
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksDoc)
	}))
}

// mintServiceToken creates a signed JWT mimicking Falcon-ID's client_credentials grant.
func mintServiceToken(t *testing.T, privKey *rsa.PrivateKey, kid, clientID, scope, issuer string) string {
	t.Helper()

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":       issuer,
		"iat":       now.Unix(),
		"exp":       now.Add(5 * time.Minute).Unix(),
		"client_id": clientID,
		"scope":     scope,
		"jti":       "test-jti-1234",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("mintServiceToken: %v", err)
	}
	return signed
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestRequireServiceAuth_ValidToken(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	kid := "test-key-1"
	jwksServer := testJWKSServer(t, &privKey.PublicKey, kid)
	defer jwksServer.Close()

	tokenStr := mintServiceToken(t, privKey, kid, "svc-crm", "example.crm.*", "falcon-id")

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequireServiceAuth(JWKSConfig{
		JWKSURL: jwksServer.URL,
		Issuer:  "falcon-id",
	}))
	r.GET("/test", func(c *gin.Context) {
		clientID, _ := GetClientID(c)
		scope, _ := GetScope(c)
		c.JSON(200, gin.H{"client_id": clientID, "scope": scope})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["client_id"] != "svc-crm" {
		t.Errorf("client_id = %q; want svc-crm", body["client_id"])
	}
	if body["scope"] != "example.crm.*" {
		t.Errorf("scope = %q; want example.crm.*", body["scope"])
	}
}

func TestRequireServiceAuth_MissingToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequireServiceAuth(JWKSConfig{
		JWKSURL: "http://localhost:9999/.well-known/jwks.json",
	}))
	r.GET("/test", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRequireServiceAuth_ExpiredToken(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	kid := "test-key-2"
	jwksServer := testJWKSServer(t, &privKey.PublicKey, kid)
	defer jwksServer.Close()

	// Create expired token
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":       "falcon-id",
		"iat":       now.Add(-10 * time.Minute).Unix(),
		"exp":       now.Add(-5 * time.Minute).Unix(),
		"client_id": "svc-crm",
		"scope":     "example.crm.*",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenStr, _ := token.SignedString(privKey)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequireServiceAuth(JWKSConfig{
		JWKSURL: jwksServer.URL,
		Issuer:  "falcon-id",
	}))
	r.GET("/test", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	r.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRequireServiceAuth_WrongIssuer(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	kid := "test-key-3"
	jwksServer := testJWKSServer(t, &privKey.PublicKey, kid)
	defer jwksServer.Close()

	tokenStr := mintServiceToken(t, privKey, kid, "svc-crm", "example.crm.*", "wrong-issuer")

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequireServiceAuth(JWKSConfig{
		JWKSURL: jwksServer.URL,
		Issuer:  "falcon-id",
	}))
	r.GET("/test", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	r.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRequireServiceAuth_OptionalMode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequireServiceAuth(JWKSConfig{
		JWKSURL:  "http://localhost:9999/.well-known/jwks.json",
		Optional: true,
	}))
	r.GET("/test", func(c *gin.Context) {
		_, ok := GetClientID(c)
		c.JSON(200, gin.H{"authenticated": ok})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200 in optional mode, got %d", w.Code)
	}
}

func TestHasScope_WildcardMatching(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name     string
		scope    string
		required string
		want     bool
	}{
		{"exact match", "example.crm.contact.created", "example.crm.contact.created", true},
		{"wildcard match", "example.crm.*", "example.crm.contact.created", true},
		{"wildcard no match", "example.sd.*", "example.crm.contact.created", false},
		{"multiple scopes", "example.crm.* example.events.publish", "example.events.publish", true},
		{"empty scope", "", "example.crm.contact.created", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set(ContextKeyScope, tt.scope)

			got := HasScope(c, tt.required)
			if got != tt.want {
				t.Errorf("HasScope(%q, %q) = %v; want %v", tt.scope, tt.required, got, tt.want)
			}
		})
	}
}

func TestRequireScope_Grants(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(ContextKeyScope, "platform:tenants:read service:register")
		c.Next()
	})
	r.GET("/tenants",
		RequireScope("platform:tenants:read"),
		func(c *gin.Context) { c.String(200, "ok") },
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/tenants", nil)
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200 with granted scope, got %d body=%q", w.Code, w.Body.String())
	}
}

func TestRequireScope_DeniesWith403(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(ContextKeyScope, "service:register")
		c.Next()
	})
	r.GET("/tenants",
		RequireScope("platform:tenants:read"),
		func(c *gin.Context) { c.String(200, "ok") },
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/tenants", nil)
	r.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403 insufficient_scope, got %d body=%q", w.Code, w.Body.String())
	}
	wwwAuth := w.Header().Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Fatalf("expected WWW-Authenticate header with insufficient_scope, got empty")
	}
}

func TestRequireScope_DeniesWhenNoScopeOnContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/tenants",
		RequireScope("platform:tenants:read"),
		func(c *gin.Context) { c.String(200, "ok") },
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/tenants", nil)
	r.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403 when scope context absent, got %d", w.Code)
	}
}

func TestRequireAnyScope_Grants(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(ContextKeyScope, "platform:plans:read")
		c.Next()
	})
	r.GET("/plans",
		RequireAnyScope("platform:tenants:read", "platform:plans:read"),
		func(c *gin.Context) { c.String(200, "ok") },
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/plans", nil)
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200 when one of the scopes is granted, got %d", w.Code)
	}
}

func TestRequireAnyScope_EmptyScopesYields500(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/x",
		RequireAnyScope(),
		func(c *gin.Context) { c.String(200, "ok") },
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	r.ServeHTTP(w, req)

	if w.Code != 500 {
		t.Fatalf("expected 500 when RequireAnyScope is misconfigured, got %d", w.Code)
	}
}
