// SPDX-License-Identifier: Apache-2.0

package serviceauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TokenClientConfig holds configuration for the OAuth2 client_credentials token client.
type TokenClientConfig struct {
	// TokenURL is the Falcon-ID token endpoint.
	// Example: http://iam:8005/oauth/token
	TokenURL string

	// ClientID is the service's OAuth2 client_id (e.g., "svc-crm").
	ClientID string

	// ClientSecret is the service's OAuth2 client_secret.
	ClientSecret string

	// Scope is the requested scope (optional).
	Scope string

	// HTTPClient allows injecting a custom HTTP client.
	HTTPClient *http.Client
}

// tokenResponse mirrors the OAuth2 token response body.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}

// TokenClient obtains and caches service-to-service JWTs from Falcon-ID.
// It is safe for concurrent use.
type TokenClient struct {
	cfg    TokenClientConfig
	mu     sync.RWMutex
	token  string
	expiry time.Time
}

// NewTokenClient creates a new TokenClient.
func NewTokenClient(cfg TokenClientConfig) (*TokenClient, error) {
	if cfg.TokenURL == "" {
		return nil, errors.New("serviceauth: TokenURL must not be empty")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("serviceauth: ClientID must not be empty")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("serviceauth: ClientSecret must not be empty")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &TokenClient{cfg: cfg}, nil
}

// GetToken returns a cached token if still valid, otherwise fetches a new one.
// Tokens are considered expired 60 seconds before their actual expiry to avoid
// race conditions where a token expires between retrieval and use.
func (tc *TokenClient) GetToken() (string, error) {
	tc.mu.RLock()
	if tc.token != "" && time.Now().Before(tc.expiry) {
		token := tc.token
		tc.mu.RUnlock()
		return token, nil
	}
	tc.mu.RUnlock()

	return tc.refreshToken()
}

// refreshToken fetches a new token from Falcon-ID's token endpoint.
func (tc *TokenClient) refreshToken() (string, error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Double-check after acquiring write lock (another goroutine may have refreshed).
	if tc.token != "" && time.Now().Before(tc.expiry) {
		return tc.token, nil
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {tc.cfg.ClientID},
		"client_secret": {tc.cfg.ClientSecret},
	}
	if tc.cfg.Scope != "" {
		form.Set("scope", tc.cfg.Scope)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, tc.cfg.TokenURL, strings.NewReader(form.Encode())) //nolint:gosec // URL is from configuration
	if err != nil {
		return "", fmt.Errorf("serviceauth: failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := tc.cfg.HTTPClient.Do(req) //nolint:gosec // request URL is from configuration
	if err != nil {
		return "", fmt.Errorf("serviceauth: token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("serviceauth: token endpoint returned status %d", resp.StatusCode)
	}

	var tokResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokResp); err != nil {
		return "", fmt.Errorf("serviceauth: failed to decode token response: %w", err)
	}

	if tokResp.AccessToken == "" {
		return "", errors.New("serviceauth: token endpoint returned empty access_token")
	}

	// Cache with 60-second safety margin before actual expiry.
	expiresIn := time.Duration(tokResp.ExpiresIn) * time.Second
	if expiresIn > 60*time.Second {
		expiresIn -= 60 * time.Second
	}
	tc.token = tokResp.AccessToken
	tc.expiry = time.Now().Add(expiresIn)

	return tc.token, nil
}

// RoundTripper returns an http.RoundTripper that automatically attaches a
// service JWT to outgoing requests. Use it to wrap http.Client transports.
//
// Example:
//
//	tokenClient, _ := serviceauth.NewTokenClient(cfg)
//	httpClient := &http.Client{Transport: tokenClient.RoundTripper(nil)}
func (tc *TokenClient) RoundTripper(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &serviceAuthTransport{
		base:        base,
		tokenClient: tc,
	}
}

// serviceAuthTransport is an http.RoundTripper that injects the Bearer token.
type serviceAuthTransport struct {
	base        http.RoundTripper
	tokenClient *TokenClient
}

func (t *serviceAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.tokenClient.GetToken()
	if err != nil {
		return nil, fmt.Errorf("serviceauth: RoundTrip: %w", err)
	}

	// Clone the request to avoid mutating the caller's request.
	r2 := req.Clone(req.Context())
	r2.Header.Set("Authorization", "Bearer "+token)

	return t.base.RoundTrip(r2)
}
