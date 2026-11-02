// SPDX-License-Identifier: Apache-2.0

package operatorauth

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

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	jwksTTL             = 5 * time.Minute
	jwksRefetchCooldown = 10 * time.Second
	clockLeeway         = 30 * time.Second
	// grantType is falcon-id's gty marker on operator assertions; an access
	// token that merely lists the audience is not accepted.
	grantType = "operator_exchange"
)

// Claims are the operator assertion's claims.
type Claims struct {
	jwt.RegisteredClaims
	TenantID       string   `json:"tenant_id"`
	TID            string   `json:"tid"`
	UserID         string   `json:"user_id"`
	Email          string   `json:"email"`
	GrantType      string   `json:"gty"`
	PlatformRoles  []string `json:"platform_roles"`
	OpsPerms       []string `json:"ops_perms"`
	ElevationID    string   `json:"elev_id"`
	AuthTime       int64    `json:"auth_time"`
	AMR            []string `json:"amr"`
	ImpersonatorID *string  `json:"impersonator_id,omitempty"`
	// StandingPlatformAdmin is falcon-id's signed claim that the actor is the
	// standing (non-JIT) platform_admin. Missing => false => full friction.
	StandingPlatformAdmin bool `json:"standing_platform_admin"`
}

// Config configures a Verifier.
type Config struct {
	// JWKSURL is falcon-id's JWKS endpoint. Required.
	JWKSURL string
	// Issuer is falcon-id's issuer. Required.
	Issuer string
	// HTTPClient is optional (default: 10s timeout).
	HTTPClient *http.Client
}

// Verifier validates operator assertions (RS256, JWKS, issuer, audience,
// expiry) and exposes the middleware.
type Verifier struct {
	jwksURL string
	issuer  string
	client  *http.Client

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

// NewVerifier builds a Verifier. It fails on a missing JWKS URL or issuer so
// a mis-wired service cannot start with the operator surface unprotected.
func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.JWKSURL == "" || cfg.Issuer == "" {
		return nil, errors.New("operatorauth: JWKSURL and Issuer are required")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Verifier{
		jwksURL: cfg.JWKSURL,
		issuer:  cfg.Issuer,
		client:  client,
		keys:    map[string]*rsa.PublicKey{},
	}, nil
}

func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	k, ok := v.keys[kid]
	fresh := time.Since(v.fetchedAt) < jwksTTL
	last := v.fetchedAt
	v.mu.RUnlock()
	if ok && fresh {
		return k, nil
	}
	// Unknown kid / stale cache: refetch, but not more than once per cooldown
	// (a fabricated kid must not force unbounded upstream calls).
	if !ok && time.Since(last) < jwksRefetchCooldown {
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
	if err := v.fetch(ctx); err != nil {
		if ok {
			return k, nil // stale-but-known key beats failing closed on a JWKS blip
		}
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown key id %q", kid)
}

func (v *Verifier) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kty, Use, Kid, N, E string
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("jwks decode: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	if len(keys) == 0 {
		return errors.New("jwks: no usable RSA keys")
	}
	v.mu.Lock()
	v.keys, v.fetchedAt = keys, time.Now()
	v.mu.Unlock()
	return nil
}

// Verify validates an operator assertion and returns the actor. It checks
// signature, issuer, audience hexxlock-ops, expiry, the operator_exchange
// grant marker, the internal tenant (tid AND tenant_id, when both present
// they must agree) and refuses impersonation tokens.
func (v *Verifier) Verify(ctx context.Context, tokenString string) (*Actor, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		return v.key(ctx, kid)
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(Audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(clockLeeway),
	)
	if err != nil {
		return nil, err
	}
	if claims.GrantType != grantType {
		return nil, errors.New("not an operator assertion")
	}
	tenant := claims.TID
	if tenant == "" {
		tenant = claims.TenantID
	}
	if claims.TID != "" && claims.TenantID != "" && claims.TID != claims.TenantID {
		return nil, errors.New("tenant claims disagree")
	}
	if claims.ImpersonatorID != nil && *claims.ImpersonatorID != "" {
		return nil, errImpersonated
	}
	idStr := claims.UserID
	if idStr == "" {
		idStr = claims.Subject
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		return nil, errors.New("invalid subject")
	}
	a := &Actor{
		UserID:        id,
		Email:         claims.Email,
		TenantID:      tenant,
		PlatformRoles: claims.PlatformRoles,
		Perms:         claims.OpsPerms,
		ElevationID:   claims.ElevationID,
		AMR:           claims.AMR,
		TokenID:       claims.ID,

		StandingPlatformAdmin: claims.StandingPlatformAdmin,
	}
	if claims.AuthTime > 0 {
		a.AuthTime = time.Unix(claims.AuthTime, 0)
	}
	if claims.ExpiresAt != nil {
		a.ExpiresAt = claims.ExpiresAt.Time
	}
	return a, nil
}

var errImpersonated = errors.New("impersonated actor not allowed")
