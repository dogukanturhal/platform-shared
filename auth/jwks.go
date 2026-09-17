// SPDX-License-Identifier: Apache-2.0

// TODO: factor into shared/jwksfetch package — the primitives here
// (extractKIDFromToken, fetchJWKS, jwkToRSAPublicKey) duplicate the
// unexported helpers in service-auth/jwks_validator.go. They are kept
// separate to avoid coupling the auth package to service-auth's internal
// surface; a future shared/jwksfetch package can remove the duplication.

package auth

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

const jwksCacheTTL = 5 * time.Minute

// jwksResolver caches RSA public keys fetched from a JWKS endpoint. It is
// safe for concurrent use; cache misses trigger a single fetch under write
// lock (singleflight-style double-check).
type jwksResolver struct {
	url        string
	httpClient *http.Client

	mu         sync.RWMutex
	cachedKeys map[string]*rsa.PublicKey
	fetchedAt  time.Time
	cacheTTL   time.Duration
}

func newJWKSResolver(url string) *jwksResolver {
	return &jwksResolver{
		url:        url,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cachedKeys: make(map[string]*rsa.PublicKey),
		cacheTTL:   jwksCacheTTL,
	}
}

// resolveKey returns the RSA public key for kid, fetching the JWKS when the
// cache is stale or does not contain the requested kid.
func (r *jwksResolver) resolveKey(kid string) (*rsa.PublicKey, error) {
	// Fast path: read-locked cache lookup.
	r.mu.RLock()
	key, ok := r.cachedKeys[kid]
	stale := time.Since(r.fetchedAt) > r.cacheTTL
	r.mu.RUnlock()

	if ok && !stale {
		return key, nil
	}

	// Slow path: fetch under write lock.
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock to avoid duplicate fetches.
	if k, found := r.cachedKeys[kid]; found && time.Since(r.fetchedAt) <= r.cacheTTL {
		return k, nil
	}

	newKeys, err := r.fetchJWKS(context.Background())
	if err != nil {
		return nil, fmt.Errorf("JWKS fetch failed: %w", err)
	}
	r.cachedKeys = newKeys
	r.fetchedAt = time.Now()

	key, ok = newKeys[kid]
	if !ok {
		return nil, fmt.Errorf("kid %q not found in JWKS after refresh", kid)
	}
	return key, nil
}

// jwksDocument is the minimal JWKS structure we need (RFC 7517).
type jwksDocument struct {
	Keys []jwksKey `json:"keys"`
}

type jwksKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	N   string `json:"n"` // base64url-encoded modulus
	E   string `json:"e"` // base64url-encoded exponent
}

// fetchJWKS retrieves the JWKS from the configured URL and parses RSA public keys.
func (r *jwksResolver) fetchJWKS(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return nil, fmt.Errorf("building JWKS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", r.url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned HTTP %d", resp.StatusCode)
	}

	var doc jwksDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding JWKS response: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		pubKey, err := parseRSAPublicKey(k)
		if err != nil {
			// Skip individual malformed keys; don't fail the whole fetch.
			continue
		}
		keys[k.Kid] = pubKey
	}

	if len(keys) == 0 {
		return nil, errors.New("JWKS response contained no usable RSA keys")
	}

	return keys, nil
}

// parseRSAPublicKey converts a JWKS RSA key object to *rsa.PublicKey.
func parseRSAPublicKey(k jwksKey) (*rsa.PublicKey, error) {
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

// (note: kid extraction is handled by the jwt library — ValidateAccessToken's
// keyFunc reads token.Header["kid"] directly, so we don't need a standalone
// header parser here.)

// jwksResolveKey is the TokenValidator method called from the keyFunc when an
// RS256 token is presented. It delegates to the embedded jwksResolver.
func (v *TokenValidator) jwksResolveKey(kid string) (*rsa.PublicKey, error) {
	if v.jwks == nil {
		return nil, errors.New("JWKS resolver not initialised")
	}
	return v.jwks.resolveKey(kid)
}
