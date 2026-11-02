// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const testSecret = "test-secret-key-for-jwt-signing-32chars" // gitleaks:allow

// createTestToken creates a test JWT token with the given parameters.
// aud matches what falcon-id actually stamps on every access token (see
// audience.go) so tests using this helper exercise the real shape of
// production traffic rather than an aud-less token no real client sends.
func createTestToken(secret string, tenantID, userID uuid.UUID, expiresAt time.Time) string {
	return createTestTokenWithAudience(secret, tenantID, userID, expiresAt, []string{LegacyServiceMeshAudience, PlatformAPIAudience})
}

// createTestTokenWithAudience is createTestToken with an explicit aud, for
// tests that need to exercise the audience check itself.
func createTestTokenWithAudience(secret string, tenantID, userID uuid.UUID, expiresAt time.Time, aud interface{}) string {
	claims := jwt.MapClaims{
		"iss":         "hexxlock-iam",
		"sub":         userID.String(),
		"tenant_id":   tenantID.String(),
		"user_id":     userID.String(),
		"username":    "testuser",
		"email":       "test@example.com",
		"roles":       []string{"admin"},
		"permissions": []string{"subscription:admin", "payment:read"},
		"session_id":  uuid.New().String(),
		"iat":         time.Now().Unix(),
		"exp":         expiresAt.Unix(),
		"nbf":         time.Now().Unix(),
	}
	if aud != nil {
		claims["aud"] = aud
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString
}

func TestValidateAccessToken_ValidToken(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	expiresAt := time.Now().Add(time.Hour)

	tokenString := createTestToken(testSecret, tenantID, userID, expiresAt)

	config := &Config{
		JWTSecret: testSecret,
		JWTIssuer: "hexxlock-iam",
	}
	validator := NewTokenValidator(config)

	claims, err := validator.ValidateAccessToken(tokenString)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if claims.TenantID != tenantID {
		t.Errorf("Expected tenant ID %s, got %s", tenantID, claims.TenantID)
	}

	if claims.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, claims.UserID)
	}

	if claims.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got %s", claims.Username)
	}

	if len(claims.Roles) != 1 || claims.Roles[0] != "admin" {
		t.Errorf("Expected roles ['admin'], got %v", claims.Roles)
	}
}

// TestValidateAccessToken_LogIssuerCheck_NeverAltersOutcome guards the
// property Config.LogIssuerCheck's doc comment promises: it is a pure
// observer. Toggling it on must not change accept/reject decisions in
// either direction -- a bug that let it do so would make an operator's
// diagnostic switch double as a silent behaviour change.
func TestValidateAccessToken_LogIssuerCheck_NeverAltersOutcome(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	expiresAt := time.Now().Add(time.Hour)

	cases := []struct {
		name               string
		tokenIssuer        string
		requireValidIssuer bool
		wantErr            bool
	}{
		{"gate on, issuer matches", "hexxlock-iam", true, false},
		{"gate on, issuer mismatched", "some-other-issuer", true, true},
		{"gate off (today's fleet default, c-048), issuer mismatched", "some-other-issuer", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{
				"iss": tc.tokenIssuer,
				"sub": userID.String(), "tenant_id": tenantID.String(), "user_id": userID.String(),
				"aud": []string{LegacyServiceMeshAudience, PlatformAPIAudience},
				"iat": time.Now().Unix(), "exp": expiresAt.Unix(), "nbf": time.Now().Unix(),
			}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := token.SignedString([]byte(testSecret))
			if err != nil {
				t.Fatalf("failed to sign test token: %v", err)
			}

			for _, logEnabled := range []bool{false, true} {
				config := &Config{
					JWTSecret:          testSecret,
					JWTIssuer:          "hexxlock-iam",
					RequireValidIssuer: tc.requireValidIssuer,
					LogIssuerCheck:     logEnabled,
				}
				_, err := NewTokenValidator(config).ValidateAccessToken(tokenString)
				gotErr := err != nil
				if gotErr != tc.wantErr {
					t.Errorf("LogIssuerCheck=%v: got err=%v (%v), want err=%v", logEnabled, gotErr, err, tc.wantErr)
				}
			}
		})
	}
}

func TestValidateAccessToken_ExpiredToken(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	expiresAt := time.Now().Add(-time.Hour) // Expired 1 hour ago

	tokenString := createTestToken(testSecret, tenantID, userID, expiresAt)

	config := &Config{
		JWTSecret: testSecret,
	}
	validator := NewTokenValidator(config)

	_, err := validator.ValidateAccessToken(tokenString)
	if err == nil {
		t.Fatal("Expected error for expired token, got nil")
	}
}

func TestValidateAccessToken_InvalidSignature(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	expiresAt := time.Now().Add(time.Hour)

	// Create token with different secret
	tokenString := createTestToken("different-secret-key-32characters", tenantID, userID, expiresAt)

	config := &Config{
		JWTSecret: testSecret, // Different from the one used to create token
	}
	validator := NewTokenValidator(config)

	_, err := validator.ValidateAccessToken(tokenString)
	if err == nil {
		t.Fatal("Expected error for invalid signature, got nil")
	}
}

func TestValidateAccessToken_EmptyToken(t *testing.T) {
	config := &Config{
		JWTSecret: testSecret,
	}
	validator := NewTokenValidator(config)

	_, err := validator.ValidateAccessToken("")
	if err == nil {
		t.Fatal("Expected error for empty token, got nil")
	}
}

func TestValidateAccessToken_MalformedToken(t *testing.T) {
	config := &Config{
		JWTSecret: testSecret,
	}
	validator := NewTokenValidator(config)

	_, err := validator.ValidateAccessToken("not-a-valid-jwt-token")
	if err == nil {
		t.Fatal("Expected error for malformed token, got nil")
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantToken  string
		wantErr    bool
	}{
		{ //nolint:gosec // test token, not a real credential
			name:       "Valid bearer token",
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
			wantToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test", // gitleaks:allow
			wantErr:    false,
		},
		{ //nolint:gosec // test token, not a real credential
			name:       "Valid bearer token lowercase",
			authHeader: "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
			wantToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test", // gitleaks:allow
			wantErr:    false,
		},
		{
			name:       "Empty header",
			authHeader: "",
			wantToken:  "",
			wantErr:    true,
		},
		{
			name:       "Missing bearer prefix",
			authHeader: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test", // gitleaks:allow
			wantToken:  "",
			wantErr:    true,
		},
		{
			name:       "Wrong prefix",
			authHeader: "Basic dXNlcjpwYXNz",
			wantToken:  "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := ExtractBearerToken(tt.authHeader)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractBearerToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if token != tt.wantToken {
				t.Errorf("ExtractBearerToken() = %v, want %v", token, tt.wantToken)
			}
		})
	}
}

func TestParseTokenUnverified(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	expiresAt := time.Now().Add(time.Hour)

	tokenString := createTestToken(testSecret, tenantID, userID, expiresAt)

	claims, err := ParseTokenUnverified(tokenString)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if claims.TenantID != tenantID {
		t.Errorf("Expected tenant ID %s, got %s", tenantID, claims.TenantID)
	}
}

// ---- RS256 / JWKS test helpers ----

// generateTestRSAKey produces a 2048-bit RSA key pair for testing.
func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return key
}

// jwksHandlerForKey returns an http.HandlerFunc that serves a minimal JWKS
// containing a single RSA public key identified by kid.
func jwksHandlerForKey(kid string, pub *rsa.PublicKey) http.HandlerFunc {
	nBytes := pub.N.Bytes()
	eVal := big.NewInt(int64(pub.E))
	eBytes := eVal.Bytes()

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": kid,
				"n":   base64.RawURLEncoding.EncodeToString(nBytes),
				"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}
}

// mintRS256Token creates a signed RS256 JWT with a kid header and standard
// claims matching the tenant/user convention used throughout the test suite.
func mintRS256Token(t *testing.T, key *rsa.PrivateKey, kid, issuer string, tenantID, userID uuid.UUID, expiresAt time.Time) string {
	t.Helper()
	jwtToken := jwt.New(jwt.SigningMethodRS256)
	jwtToken.Header["kid"] = kid
	jwtToken.Claims = jwt.MapClaims{
		"iss":         issuer,
		"sub":         userID.String(),
		"tenant_id":   tenantID.String(),
		"user_id":     userID.String(),
		"username":    "rs256user",
		"email":       "rs256@example.com",
		"roles":       []string{"viewer"},
		"permissions": []string{"read:all"},
		"session_id":  uuid.New().String(),
		"aud":         []string{LegacyServiceMeshAudience, PlatformAPIAudience},
		"iat":         time.Now().Unix(),
		"exp":         expiresAt.Unix(),
		"nbf":         time.Now().Unix(),
	}
	tokenString, err := jwtToken.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return tokenString
}

// ---- RS256 / JWKS tests ----

func TestValidateAccessToken_RS256_JWKS_Success(t *testing.T) {
	key := generateTestRSAKey(t)
	const kid = "test-kid-1"
	const issuer = "hexxlock-iam"

	srv := httptest.NewServer(jwksHandlerForKey(kid, &key.PublicKey))
	defer srv.Close()

	tenantID := uuid.New()
	userID := uuid.New()
	tokenString := mintRS256Token(t, key, kid, issuer, tenantID, userID, time.Now().Add(time.Hour))

	config := &Config{
		JWKSURL:   srv.URL + "/jwks.json",
		JWTIssuer: issuer,
	}
	validator := NewTokenValidator(config)

	claims, err := validator.ValidateAccessToken(tokenString)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if claims.TenantID != tenantID {
		t.Errorf("tenant ID: got %s, want %s", claims.TenantID, tenantID)
	}
	if claims.UserID != userID {
		t.Errorf("user ID: got %s, want %s", claims.UserID, userID)
	}
	if claims.Username != "rs256user" {
		t.Errorf("username: got %s, want rs256user", claims.Username)
	}
}

func TestValidateAccessToken_RS256_JWKS_KeyNotFound(t *testing.T) {
	key := generateTestRSAKey(t)
	const signingKID = "signing-kid"
	const jwksKID = "different-kid" // JWKS exposes a different kid

	srv := httptest.NewServer(jwksHandlerForKey(jwksKID, &key.PublicKey))
	defer srv.Close()

	tenantID := uuid.New()
	userID := uuid.New()
	// Token signed with signingKID, but JWKS only has jwksKID.
	tokenString := mintRS256Token(t, key, signingKID, "hexxlock-iam", tenantID, userID, time.Now().Add(time.Hour))

	config := &Config{
		JWKSURL:   srv.URL + "/jwks.json",
		JWTIssuer: "hexxlock-iam",
	}
	validator := NewTokenValidator(config)

	_, err := validator.ValidateAccessToken(tokenString)
	if err == nil {
		t.Fatal("expected error when kid not found in JWKS, got nil")
	}
}

func TestValidateAccessToken_RS256_NoJWKSURL(t *testing.T) {
	key := generateTestRSAKey(t)
	tenantID := uuid.New()
	userID := uuid.New()
	// JWKSURL is empty — RS256 token should be rejected.
	tokenString := mintRS256Token(t, key, "some-kid", "hexxlock-iam", tenantID, userID, time.Now().Add(time.Hour))

	config := &Config{
		JWTSecret: testSecret, // HS256 configured, but token is RS256
		JWTIssuer: "hexxlock-iam",
	}
	validator := NewTokenValidator(config)

	_, err := validator.ValidateAccessToken(tokenString)
	if err == nil {
		t.Fatal("expected error for RS256 token with no JWKSURL configured, got nil")
	}
}

func TestValidateAccessToken_AlgConfusion_HMACOnRSA(t *testing.T) {
	// An HS256 token should still verify via the HS256 branch even when JWKSURL
	// is configured, ensuring dev tokens keep working alongside RS256 production tokens.
	key := generateTestRSAKey(t)
	const kid = "rs256-kid"

	srv := httptest.NewServer(jwksHandlerForKey(kid, &key.PublicKey))
	defer srv.Close()

	tenantID := uuid.New()
	userID := uuid.New()
	// Mint an HS256 token (not RS256).
	tokenString := createTestToken(testSecret, tenantID, userID, time.Now().Add(time.Hour))

	config := &Config{
		JWTSecret: testSecret,
		JWKSURL:   srv.URL + "/jwks.json",
		JWTIssuer: "hexxlock-iam",
	}
	validator := NewTokenValidator(config)

	claims, err := validator.ValidateAccessToken(tokenString)
	if err != nil {
		t.Fatalf("expected HS256 token to verify when JWKSURL also set, got: %v", err)
	}
	if claims.TenantID != tenantID {
		t.Errorf("tenant ID: got %s, want %s", claims.TenantID, tenantID)
	}
}

// --- t-456: audience validation ---
//
// falcon-id stamps aud = [LegacyServiceMeshAudience, PlatformAPIAudience]
// (optionally prefixed with ClientID) on every access token it mints for
// platform/API use — see audience.go. These tests cover the fail-closed
// check ValidateAccessToken now performs against that, and the aud
// claim-parsing fix (array vs. the old string-only assertion).

func TestValidateAccessToken_MissingAudience_Rejected(t *testing.T) {
	tenantID, userID := uuid.New(), uuid.New()
	tokenString := createTestTokenWithAudience(testSecret, tenantID, userID, time.Now().Add(time.Hour), nil)

	validator := NewTokenValidator(&Config{JWTSecret: testSecret})
	if _, err := validator.ValidateAccessToken(tokenString); err == nil {
		t.Fatal("expected token with no aud claim to be rejected, got no error")
	}
}

func TestValidateAccessToken_WrongAudience_Rejected(t *testing.T) {
	tenantID, userID := uuid.New(), uuid.New()
	// Shape of a token exchanged for a specific tenant destination
	// (accounts/sso-redirect's RFC 8693 exchange audiences the token to
	// destinationOrigin) -- must not validate against a platform consumer.
	tokenString := createTestTokenWithAudience(testSecret, tenantID, userID, time.Now().Add(time.Hour),
		[]string{"https://tenant-b.example.net"})

	validator := NewTokenValidator(&Config{JWTSecret: testSecret})
	if _, err := validator.ValidateAccessToken(tokenString); err == nil {
		t.Fatal("expected token audienced to an unrelated destination to be rejected, got no error")
	}
}

func TestValidateAccessToken_LegacyAudienceOnly_Accepted(t *testing.T) {
	tenantID, userID := uuid.New(), uuid.New()
	tokenString := createTestTokenWithAudience(testSecret, tenantID, userID, time.Now().Add(time.Hour),
		[]string{LegacyServiceMeshAudience})

	validator := NewTokenValidator(&Config{JWTSecret: testSecret})
	if _, err := validator.ValidateAccessToken(tokenString); err != nil {
		t.Fatalf("expected token with legacy mesh audience to be accepted, got: %v", err)
	}
}

func TestValidateAccessToken_PlatformAudienceOnly_Accepted(t *testing.T) {
	tenantID, userID := uuid.New(), uuid.New()
	tokenString := createTestTokenWithAudience(testSecret, tenantID, userID, time.Now().Add(time.Hour),
		[]string{PlatformAPIAudience})

	validator := NewTokenValidator(&Config{JWTSecret: testSecret})
	if _, err := validator.ValidateAccessToken(tokenString); err != nil {
		t.Fatalf("expected token with platform API audience to be accepted, got: %v", err)
	}
}

func TestValidateAccessToken_ClientIDPrefixedAudience_Accepted(t *testing.T) {
	// Matches falcon-id token_service.go's opts.ClientID case: the client
	// ID is prepended, not substituted -- the platform values are still
	// present alongside it.
	tenantID, userID := uuid.New(), uuid.New()
	tokenString := createTestTokenWithAudience(testSecret, tenantID, userID, time.Now().Add(time.Hour),
		[]string{"platform-admin", LegacyServiceMeshAudience, PlatformAPIAudience})

	validator := NewTokenValidator(&Config{JWTSecret: testSecret})
	if _, err := validator.ValidateAccessToken(tokenString); err != nil {
		t.Fatalf("expected client_id-prefixed platform audience to be accepted, got: %v", err)
	}
}

func TestValidateAccessToken_SingleStringAudience_Accepted(t *testing.T) {
	// RFC 7519 §4.1.3 permits aud as a bare string; falcon-id doesn't emit
	// this today (always an array) but the parser must still handle it.
	tenantID, userID := uuid.New(), uuid.New()
	tokenString := createTestTokenWithAudience(testSecret, tenantID, userID, time.Now().Add(time.Hour),
		PlatformAPIAudience)

	validator := NewTokenValidator(&Config{JWTSecret: testSecret})
	if _, err := validator.ValidateAccessToken(tokenString); err != nil {
		t.Fatalf("expected single-string platform audience to be accepted, got: %v", err)
	}
}

func TestParseMapClaims_AudienceArray(t *testing.T) {
	// Closes the m-613 bug: mapClaims["aud"].(string) silently discarded
	// aud on every real falcon-id token, which always emits an array.
	mapClaims := jwt.MapClaims{
		"aud": []interface{}{LegacyServiceMeshAudience, PlatformAPIAudience},
	}
	claims, err := parseMapClaims(mapClaims)
	if err != nil {
		t.Fatalf("parseMapClaims: %v", err)
	}
	if len(claims.Audience) != 2 || claims.Audience[0] != LegacyServiceMeshAudience || claims.Audience[1] != PlatformAPIAudience {
		t.Errorf("claims.Audience: got %v, want [%s %s]", claims.Audience, LegacyServiceMeshAudience, PlatformAPIAudience)
	}
}

func TestLoadFromEnv_JWKSAutoDerive(t *testing.T) {
	// Ensure that when JWT_ISSUER starts with https:// and JWT_JWKS_URL is
	// absent, JWKSURL is auto-derived following the OIDC discovery convention.
	t.Setenv("JWT_ISSUER", "https://example.com/")
	_ = os.Unsetenv("JWT_JWKS_URL")

	cfg := LoadFromEnv()
	want := "https://example.com/.well-known/jwks.json"
	if cfg.JWKSURL != want {
		t.Errorf("JWKSURL auto-derive: got %q, want %q", cfg.JWKSURL, want)
	}
}
