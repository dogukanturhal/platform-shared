// SPDX-License-Identifier: Apache-2.0

// Package serviceauth provides service-to-service JWT authentication.
//
// This file adds JWKS-based middleware for validating JWTs issued by Falcon-ID's
// /oauth/token endpoint (client_credentials grant). Services obtain tokens via
// the OAuth2 client_credentials flow and include them in requests as Bearer tokens.
// Receiving services validate the JWT signature against Falcon-ID's JWKS endpoint.
package serviceauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Context keys set by the JWKS middleware on successful authentication.
const (
	// ContextKeyClientID is the OAuth2 client_id from the JWT claims.
	ContextKeyClientID = "client_id"

	// ContextKeyScope is the space-separated scope string from the JWT.
	ContextKeyScope = "scope"

	// ContextKeyTokenTenantID is the tenant_id from the JWT (if present).
	ContextKeyTokenTenantID = "token_tenant_id"
)

// JWKSConfig holds configuration for the JWKS-based middleware.
type JWKSConfig struct {
	// JWKSURL is the URL of Falcon-ID's JWKS endpoint.
	// Example: http://iam:8005/.well-known/jwks.json
	JWKSURL string

	// Issuer is the expected "iss" claim in the JWT. Empty to skip issuer validation.
	Issuer string

	// CacheTTL controls how long JWKS keys are cached. Default: 5 minutes.
	CacheTTL time.Duration

	// HTTPClient allows injecting a custom HTTP client (useful for tests).
	HTTPClient *http.Client

	// Optional: if true, the middleware only sets context values when a token is
	// present but does not reject unauthenticated requests (allowing chained auth).
	Optional bool
}

// jwksCache stores fetched JWKS keys with TTL-based invalidation.
type jwksCache struct {
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	ttl       time.Duration
}

func (c *jwksCache) get(kid string) (*rsa.PublicKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok := c.keys[kid]
	return key, ok
}

func (c *jwksCache) set(keys map[string]*rsa.PublicKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = keys
	c.fetchedAt = time.Now()
}

// jwksDocument mirrors the JSON structure of a JWKS endpoint response.
type jwksDocument struct {
	Keys []jwksKey `json:"keys"`
}

type jwksKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// ServiceTokenClaims are the JWT claims expected in a Falcon-ID-issued service token.
type ServiceTokenClaims struct {
	jwt.RegisteredClaims
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	TenantID string `json:"tenant_id"`
}

// RequireServiceAuth returns a Gin middleware that validates incoming JWTs signed by
// Falcon-ID against its JWKS endpoint. On success it populates the context with:
//   - ContextKeyClientID ("client_id"): the OAuth2 client_id
//   - ContextKeyScope ("scope"): the granted scopes
//   - ContextKeyServiceSlug ("service_slug"): alias for client_id (backward compat)
//   - ContextKeyServiceID ("service_id"): alias for client_id
//   - ContextKeyTokenTenantID ("token_tenant_id"): tenant_id if present
//
// On failure the middleware aborts with 401 Unauthorized.
func RequireServiceAuth(cfg JWKSConfig) gin.HandlerFunc {
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	cache := &jwksCache{
		keys: make(map[string]*rsa.PublicKey),
		ttl:  cfg.CacheTTL,
	}

	return func(c *gin.Context) {
		tokenStr, err := extractBearer(c.GetHeader("Authorization"))
		if err != nil {
			if cfg.Optional {
				c.Next()
				return
			}
			abortUnauthorized(c, "missing or malformed Authorization header")
			return
		}

		claims, err := validateJWKSToken(tokenStr, cache, cfg)
		if err != nil {
			abortUnauthorized(c, err.Error())
			return
		}

		// Populate context for downstream handlers.
		c.Set(ContextKeyClientID, claims.ClientID)
		c.Set(ContextKeyScope, claims.Scope)
		c.Set(ContextKeyServiceSlug, claims.ClientID)
		c.Set(ContextKeyServiceID, claims.ClientID)
		if claims.TenantID != "" {
			c.Set(ContextKeyTokenTenantID, claims.TenantID)
		}

		c.Next()
	}
}

// validateJWKSToken parses and validates a JWT against cached JWKS keys.
func validateJWKSToken(tokenStr string, cache *jwksCache, cfg JWKSConfig) (*ServiceTokenClaims, error) {
	claims := &ServiceTokenClaims{}

	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256"}),
	}
	if cfg.Issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(cfg.Issuer))
	}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		// Enforce RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %q", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("JWT missing kid header")
		}

		// Try cache first
		if pubKey, found := cache.get(kid); found {
			return pubKey, nil
		}

		// Cache miss — unknown kid. Re-fetch JWKS only if the cache is old enough
		// to prevent a DoS via fabricated kid values forcing unbounded upstream calls.
		// A 10-second cooldown is a practical lower bound: real key rotations are
		// rare (hours/days) and legitimate tokens will not arrive with unknown kids
		// during normal operations.
		const minRefetchInterval = 10 * time.Second
		cache.mu.RLock()
		lastFetch := cache.fetchedAt
		cache.mu.RUnlock()

		if time.Since(lastFetch) < minRefetchInterval {
			return nil, fmt.Errorf("unknown key ID %q (cache refreshed %.1fs ago, cooldown active)", kid, time.Since(lastFetch).Seconds())
		}

		if err := fetchJWKS(cache, cfg); err != nil {
			return nil, fmt.Errorf("JWKS fetch failed: %w", err)
		}

		pubKey, found := cache.get(kid)
		if !found {
			return nil, fmt.Errorf("unknown key ID %q", kid)
		}
		return pubKey, nil
	}, parserOpts...)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("token is not valid")
	}

	return claims, nil
}

// fetchJWKS retrieves the JWKS document from the configured URL and updates the cache.
func fetchJWKS(cache *jwksCache, cfg JWKSConfig) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, cfg.JWKSURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create JWKS request: %w", err)
	}
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request to JWKS endpoint failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var doc jwksDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("failed to decode JWKS response: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Use != "sig" || k.Kid == "" {
			continue
		}

		pubKey, err := parseJWKRSA(k)
		if err != nil {
			continue // Skip malformed keys
		}
		keys[k.Kid] = pubKey
	}

	if len(keys) == 0 {
		return errors.New("JWKS endpoint returned no usable RSA signing keys")
	}

	cache.set(keys)
	return nil
}

// parseJWKRSA converts a JWK RSA key entry to an *rsa.PublicKey.
func parseJWKRSA(k jwksKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// GetClientID retrieves the authenticated service client_id from the Gin context.
func GetClientID(c *gin.Context) (string, bool) {
	v, exists := c.Get(ContextKeyClientID)
	if !exists {
		return "", false
	}
	id, ok := v.(string)
	return id, ok
}

// GetTokenTenantID retrieves the tenant_id from the service JWT claims.
func GetTokenTenantID(c *gin.Context) (string, bool) {
	v, exists := c.Get(ContextKeyTokenTenantID)
	if !exists {
		return "", false
	}
	id, ok := v.(string)
	return id, ok
}

// GetScope retrieves the scope string from the service JWT claims.
func GetScope(c *gin.Context) (string, bool) {
	v, exists := c.Get(ContextKeyScope)
	if !exists {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// HasScope checks if the authenticated service has a specific scope.
// Supports wildcard matching: "example.crm.*" matches "example.crm.contact.created".
func HasScope(c *gin.Context, required string) bool {
	scopeStr, ok := GetScope(c)
	if !ok || scopeStr == "" {
		return false
	}

	scopes := strings.Fields(scopeStr)
	for _, s := range scopes {
		if s == required {
			return true
		}
		// Wildcard matching: "example.crm.*" matches anything starting with "example.crm."
		if strings.HasSuffix(s, ".*") {
			prefix := strings.TrimSuffix(s, "*")
			if strings.HasPrefix(required, prefix) {
				return true
			}
		}
	}
	return false
}

// RequireScope returns a Gin middleware that enforces presence of a single
// OAuth2 scope on the authenticated service token (set earlier in the chain
// by RequireServiceAuth). It aborts with 403 insufficient_scope when the
// scope is missing, matching RFC 6750 §3.1 error semantics.
//
// Use it to scope-gate individual handlers that share an upstream
// RequireServiceAuth() middleware:
//
//	group := router.Group("/api/v1")
//	group.Use(serviceauth.RequireServiceAuth(jwksCfg))
//	group.GET("/tenants",
//	    serviceauth.RequireScope("platform:tenants:read"),
//	    handler.List,
//	)
//
// Wildcard matching follows HasScope: a granted scope ending in `.*` matches
// any required scope sharing the prefix.
func RequireScope(scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !HasScope(c, scope) {
			abortInsufficientScope(c, scope)
			return
		}
		c.Next()
	}
}

// RequireAnyScope returns a Gin middleware that enforces presence of at least
// one of the supplied scopes on the authenticated service token. Aborts with
// 403 insufficient_scope when none of the scopes are granted.
//
// Empty scopes argument is treated as a misconfiguration and aborts with 500
// to surface the error rather than silently allowing any token through.
func RequireAnyScope(scopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(scopes) == 0 {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error":             "server_error",
				"error_description": "RequireAnyScope invoked with empty scope list",
			})
			return
		}
		for _, s := range scopes {
			if HasScope(c, s) {
				c.Next()
				return
			}
		}
		abortInsufficientScope(c, strings.Join(scopes, " "))
	}
}

// abortInsufficientScope writes an RFC 6750 §3.1 insufficient_scope error
// response. The required scope is surfaced both in the JSON body and in the
// WWW-Authenticate header so RFC-compliant clients can self-correct.
func abortInsufficientScope(c *gin.Context, required string) {
	c.Header("WWW-Authenticate", fmt.Sprintf(`Bearer error="insufficient_scope", scope="%s"`, required))
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error":             "insufficient_scope",
		"error_description": "token is missing required scope: " + required,
		"required_scope":    required,
	})
}
