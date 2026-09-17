// SPDX-License-Identifier: Apache-2.0

package serviceauth

// JWTValidator validates service JWTs by fetching public keys from a JWKS
// endpoint (RFC 7517) and caching them in memory.
//
// This allows microservices (integration-bus, master-data, etc.) to validate
// service tokens without holding static key material — they simply point at
// Falcon-ID's well-known JWKS URL and the validator handles key rotation.
//
// Concurrency: JWTValidator is safe for concurrent use. Key fetches are
// protected by a read-write mutex; cache misses trigger a single fetch under
// write lock (singleflight-style).
//
// Usage:
//
//	validator, err := serviceauth.NewJWTValidator(
//	    "http://iam:8005/.well-known/jwks.json",
//	    "https://falcon-id-issuer",
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	claims, err := validator.ValidateToken(tokenString)
//	if err != nil {
//	    // token invalid
//	}
//
//	// In Gin:
//	router.Use(serviceauth.ServiceAuthMiddlewareFromValidator(validator))

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// ServiceValidatedClaims contains the validated claims from a service JWT.
// Returned by JWTValidator.ValidateToken.
type ServiceValidatedClaims struct {
	// ServiceID is the "sub" claim (service slug by convention).
	ServiceID string
	// ServiceSlug is the "service_slug" custom claim; falls back to "iss".
	ServiceSlug string
	// TenantID is the optional "tenant_id" claim.
	TenantID string
	// Scopes is the space-separated "scope" claim split into a slice.
	Scopes []string
	// ClientID is the optional "client_id" claim.
	ClientID string
	// ExpiresAt is when the token expires.
	ExpiresAt time.Time
}

// JWTValidator fetches RSA public keys from a JWKS endpoint and validates
// incoming service JWTs against them.
type JWTValidator struct {
	jwksURL    string
	issuer     string
	httpClient *http.Client

	mu         sync.RWMutex
	cachedKeys map[string]*rsa.PublicKey // keyed by kid
	fetchedAt  time.Time
	cacheTTL   time.Duration
}

// NewJWTValidator creates a JWTValidator that fetches keys from jwksURL and
// (optionally) validates the "iss" claim against issuer. Pass an empty issuer
// to skip issuer validation.
func NewJWTValidator(jwksURL, issuer string) (*JWTValidator, error) {
	if jwksURL == "" {
		return nil, errors.New("serviceauth: jwksURL must not be empty")
	}
	return &JWTValidator{
		jwksURL:    jwksURL,
		issuer:     issuer,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cachedKeys: make(map[string]*rsa.PublicKey),
		cacheTTL:   5 * time.Minute,
	}, nil
}

// WithCacheTTL overrides the default 5-minute key cache TTL. Useful in tests.
func (v *JWTValidator) WithCacheTTL(d time.Duration) *JWTValidator {
	v.cacheTTL = d
	return v
}

// ValidateToken parses and validates a JWT string.
// It fetches/refreshes the JWKS key cache as needed, then verifies the token's
// signature, expiry, and (if configured) issuer.
func (v *JWTValidator) ValidateToken(tokenString string) (*ServiceValidatedClaims, error) {
	if tokenString == "" {
		return nil, errors.New("serviceauth: token string is empty")
	}

	// Parse without verification first to extract kid from the header.
	headerKid, err := extractKIDFromToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("serviceauth: cannot extract kid: %w", err)
	}

	pubKey, err := v.resolvePublicKey(headerKid)
	if err != nil {
		return nil, fmt.Errorf("serviceauth: cannot resolve public key for kid=%q: %w", headerKid, err)
	}

	// Full parse + verify with the resolved key via the package-level helper.
	// We pass a single-entry map so validateServiceToken can locate the key by kid.
	trustedKeys := map[string]*rsa.PublicKey{headerKid: pubKey}
	claims, err := validateServiceToken(tokenString, trustedKeys)
	if err != nil {
		return nil, fmt.Errorf("serviceauth: token validation failed: %w", err)
	}

	// Issuer check (optional).
	if v.issuer != "" && claims.Issuer != v.issuer {
		return nil, fmt.Errorf("serviceauth: issuer mismatch: got %q, want %q", claims.Issuer, v.issuer)
	}

	// Build the validated claims result.
	serviceSlug := claims.ServiceSlug
	if serviceSlug == "" {
		serviceSlug = claims.Issuer
	}

	var expiresAt time.Time
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time
	}

	return &ServiceValidatedClaims{
		ServiceID:   claims.Subject,
		ServiceSlug: serviceSlug,
		ExpiresAt:   expiresAt,
	}, nil
}

// resolvePublicKey returns a cached key or fetches the JWKS when the cache is
// stale or does not contain the requested kid.
func (v *JWTValidator) resolvePublicKey(kid string) (*rsa.PublicKey, error) {
	// Fast path: check the read-locked cache.
	v.mu.RLock()
	key, ok := v.cachedKeys[kid]
	cacheStale := time.Since(v.fetchedAt) > v.cacheTTL
	v.mu.RUnlock()

	if ok && !cacheStale {
		return key, nil
	}

	// Slow path: fetch and rebuild the cache under write lock.
	v.mu.Lock()
	defer v.mu.Unlock()

	// Double-check after acquiring write lock.
	if k, found := v.cachedKeys[kid]; found && time.Since(v.fetchedAt) <= v.cacheTTL {
		return k, nil
	}

	newKeys, err := v.fetchJWKS(context.Background())
	if err != nil {
		return nil, fmt.Errorf("JWKS fetch failed: %w", err)
	}
	v.cachedKeys = newKeys
	v.fetchedAt = time.Now()

	key, ok = newKeys[kid]
	if !ok {
		return nil, fmt.Errorf("kid %q not found in JWKS after refresh", kid)
	}
	return key, nil
}

// jwksResponse is the minimal structure we need from a JWKS document.
type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	N   string `json:"n"` // base64url-encoded modulus
	E   string `json:"e"` // base64url-encoded exponent
}

// fetchJWKS retrieves the JWKS from the configured URL and parses RSA public keys.
func (v *JWTValidator) fetchJWKS(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building JWKS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", v.jwksURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decoding JWKS response: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		pubKey, err := jwkToRSAPublicKey(k)
		if err != nil {
			// Skip malformed keys; don't fail the whole fetch.
			continue
		}
		keys[k.Kid] = pubKey
	}

	if len(keys) == 0 {
		return nil, errors.New("JWKS response contained no usable RSA keys")
	}

	return keys, nil
}

// jwkToRSAPublicKey converts a JWK RSA key to *rsa.PublicKey.
func jwkToRSAPublicKey(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decoding modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decoding exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	if !e.IsInt64() {
		return nil, errors.New("RSA exponent too large")
	}

	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// extractKIDFromToken parses the JWT header without verifying the signature and
// returns the "kid" value.
func extractKIDFromToken(tokenString string) (string, error) {
	// A JWT is three base64url-encoded segments separated by '.'.
	// We only need the first (header) segment.
	dotIdx := -1
	for i, ch := range tokenString {
		if ch == '.' {
			dotIdx = i
			break
		}
	}
	if dotIdx < 0 {
		return "", errors.New("malformed JWT: no period separator found")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(tokenString[:dotIdx])
	if err != nil {
		return "", fmt.Errorf("decoding JWT header: %w", err)
	}

	var header struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", fmt.Errorf("parsing JWT header JSON: %w", err)
	}

	if header.Kid == "" {
		return "", errors.New("JWT header missing \"kid\"")
	}

	return header.Kid, nil
}
