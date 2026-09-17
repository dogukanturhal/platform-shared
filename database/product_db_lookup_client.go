// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// TenantDatabaseInfo contains the database connection information returned by
// the Falcon-ID internal tenant-databases endpoint.
type TenantDatabaseInfo struct {
	Host             *string `json:"host"`
	DatabaseName     string  `json:"database_name"`
	Schema           string  `json:"schema"`
	Username         *string `json:"username"`
	IsolationMode    string  `json:"isolation_mode"`
	ConnectionString *string `json:"connection_string,omitempty"` // decrypted by Falcon-ID for silo mode
}

// TokenProvider generates short-lived JWT tokens for service-to-service auth.
// This interface matches the service-auth ServiceClient.GenerateToken() method.
type TokenProvider interface {
	GenerateToken() (string, error)
}

// ProductDBLookupClient is an HTTP client that queries Falcon-ID's internal
// endpoint for tenant database connection information.
//
// Supports two auth modes:
//   - Legacy: X-Internal-Key header (static API key)
//   - JWT: Authorization: Bearer <jwt> via TokenProvider (preferred)
//
// When both are set, JWT takes precedence.
type ProductDBLookupClient struct {
	baseURL       string
	apiKey        string        // legacy static key
	tokenProvider TokenProvider // JWT-based auth (preferred)
	httpClient    *http.Client
	log           *zap.Logger

	// Token cache: avoid minting a new JWT for every lookup.
	tokenMu     sync.Mutex
	cachedToken string
	tokenExpiry time.Time
}

// NewProductDBLookupClient creates a new lookup client with static API key auth.
// baseURL is the Falcon-ID internal service URL (e.g., "http://iam:8005").
// apiKey is the INTERNAL_API_KEY used for service-to-service auth.
func NewProductDBLookupClient(baseURL, apiKey string, log *zap.Logger) *ProductDBLookupClient {
	return &ProductDBLookupClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		log: log,
	}
}

// LookupClientOption configures a ProductDBLookupClient.
type LookupClientOption func(*ProductDBLookupClient)

// WithTokenProvider sets a JWT token provider for service auth.
// When set, the client uses Authorization: Bearer <jwt> instead of X-Internal-Key.
func WithTokenProvider(tp TokenProvider) LookupClientOption {
	return func(c *ProductDBLookupClient) {
		c.tokenProvider = tp
	}
}

// NewProductDBLookupClientWithOptions creates a lookup client with functional options.
func NewProductDBLookupClientWithOptions(baseURL string, log *zap.Logger, opts ...LookupClientOption) *ProductDBLookupClient {
	c := &ProductDBLookupClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		log: log,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// LookupTenantDatabase queries Falcon-ID for the database connection info
// for a specific tenant and database name.
func (c *ProductDBLookupClient) LookupTenantDatabase(ctx context.Context, tenantID, databaseName string) (*TenantDatabaseInfo, error) {
	url := fmt.Sprintf("%s/internal/v1/tenant-databases/%s/%s", c.baseURL, tenantID, databaseName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Set auth header: JWT preferred, fallback to static API key.
	if err := c.setAuthHeader(req); err != nil {
		return nil, fmt.Errorf("set auth header: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lookup request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("lookup returned %d: %s", resp.StatusCode, string(body))
	}

	var info TenantDatabaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &info, nil
}

// setAuthHeader sets the appropriate auth header on the request.
func (c *ProductDBLookupClient) setAuthHeader(req *http.Request) error {
	if c.tokenProvider == nil {
		if c.apiKey != "" {
			req.Header.Set("X-Internal-Key", c.apiKey)
			return nil
		}
		return fmt.Errorf("no auth method configured (set apiKey or tokenProvider)")
	}

	token, err := c.getOrRefreshToken()
	if err != nil {
		// If JWT fails but we have a static key, fall back.
		if c.apiKey == "" {
			return fmt.Errorf("generate service token: %w", err)
		}
		if c.log != nil {
			c.log.Warn("JWT token generation failed, falling back to API key", zap.Error(err))
		}
		req.Header.Set("X-Internal-Key", c.apiKey)
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// getOrRefreshToken returns a cached token or mints a new one.
// Tokens are cached for 4 minutes (service tokens have 5-min lifetime).
func (c *ProductDBLookupClient) getOrRefreshToken() (string, error) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	if c.cachedToken != "" && time.Now().Before(c.tokenExpiry) {
		return c.cachedToken, nil
	}

	token, err := c.tokenProvider.GenerateToken()
	if err != nil {
		return "", err
	}

	c.cachedToken = token
	c.tokenExpiry = time.Now().Add(4 * time.Minute)
	return token, nil
}
