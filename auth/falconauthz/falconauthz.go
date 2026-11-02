// SPDX-License-Identifier: Apache-2.0

// Package falconauthz implements auth.PermissionChecker on top of falcon-id's
// self-scoped POST /api/v1/authorize/batch. falcon-id access tokens carry roles
// but no `permissions` claim, so services resolve permissions by forwarding the
// caller's own bearer token to falcon-id's SpiceDB-backed engine.
package falconauthz

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dogukanturhal/platform-shared/auth"
)

const (
	// EnvResolverURL is the env var holding falcon-id's base URL.
	EnvResolverURL = "AUTHZ_RESOLVER_URL"

	batchPath       = "/api/v1/authorize/batch"
	defaultTimeout  = 2 * time.Second
	maxCacheTTL     = 30 * time.Second
	defaultCacheTTL = 30 * time.Second
	defaultMaxCache = 4096
	maxResponseSize = 1 << 20
)

// Config configures a Checker.
type Config struct {
	BaseURL    string        // falcon-id base URL, e.g. http://falcon-id.falcon-id.svc:8080
	HTTPClient *http.Client  // optional; defaults to a client with a 2s timeout
	CacheTTL   time.Duration // optional; capped at 30s
	MaxEntries int           // optional; cache bound
}

// Checker is an auth.PermissionChecker backed by falcon-id.
type Checker struct {
	url    string
	client *http.Client
	ttl    time.Duration
	max    int

	mu    sync.Mutex
	cache map[cacheKey]cacheEntry
}

type cacheKey struct {
	token [sha256.Size]byte
	perm  string
}

type cacheEntry struct {
	allowed bool
	expires time.Time
}

var _ auth.PermissionChecker = (*Checker)(nil)

// New returns a Checker, or an error if BaseURL is empty.
func New(cfg Config) (*Checker, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		return nil, errors.New("falconauthz: base URL is required")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	ttl := cfg.CacheTTL
	if ttl <= 0 || ttl > maxCacheTTL {
		ttl = defaultCacheTTL
	}
	max := cfg.MaxEntries
	if max <= 0 {
		max = defaultMaxCache
	}
	return &Checker{url: base + batchPath, client: client, ttl: ttl, max: max, cache: make(map[cacheKey]cacheEntry)}, nil
}

// NewFromEnv builds a Checker from AUTHZ_RESOLVER_URL. It returns (nil, nil)
// when the variable is unset so callers keep claim-only behaviour.
func NewFromEnv() (*Checker, error) {
	u := strings.TrimSpace(os.Getenv(EnvResolverURL))
	if u == "" {
		return nil, nil
	}
	return New(Config{BaseURL: u})
}

type batchRequest struct {
	UserID      string   `json:"userId"`
	TenantID    string   `json:"tenantId"`
	Permissions []string `json:"permissions"`
}

type batchResponse struct {
	Results map[string]bool `json:"results"`
}

// isResolvable reports whether p is a three-part module:resource:action name.
// Two-part names such as platform:admin are claim-only and never sent.
func isResolvable(p string) bool {
	parts := strings.Split(p, ":")
	if len(parts) != 3 {
		return false
	}
	for _, s := range parts {
		if s == "" {
			return false
		}
	}
	return true
}

// CheckPermissions implements auth.PermissionChecker.
func (c *Checker) CheckPermissions(ctx context.Context, q auth.PermissionQuery) (map[string]bool, error) {
	out := make(map[string]bool, len(q.Permissions))
	tok := sha256.Sum256([]byte(q.Bearer))
	now := time.Now()

	var missing []string
	seen := make(map[string]bool, len(q.Permissions))
	c.mu.Lock()
	for _, p := range q.Permissions {
		if !isResolvable(p) || seen[p] {
			continue
		}
		seen[p] = true
		if e, ok := c.cache[cacheKey{tok, p}]; ok && now.Before(e.expires) {
			out[p] = e.allowed
			continue
		}
		missing = append(missing, p)
	}
	c.mu.Unlock()

	if len(missing) == 0 {
		return out, nil
	}

	body, err := json.Marshal(batchRequest{UserID: q.UserID.String(), TenantID: q.TenantID.String(), Permissions: missing})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+q.Bearer)
	// falcon-id's tenant middleware rejects /api/v1 calls without it (the edge
	// gateway sets it for browser traffic); the tenant comes from the validated
	// JWT and falcon-id pins it to the session again.
	req.Header.Set("X-Tenant-ID", q.TenantID.String())

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("falconauthz: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseSize))
		return nil, fmt.Errorf("falconauthz: unexpected status %d", resp.StatusCode)
	}
	var parsed batchResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("falconauthz: decode response: %w", err)
	}

	exp := now.Add(c.ttl)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache)+len(missing) > c.max {
		c.evictLocked(now)
	}
	for _, p := range missing {
		allowed := parsed.Results[p]
		out[p] = allowed
		if len(c.cache) < c.max {
			c.cache[cacheKey{tok, p}] = cacheEntry{allowed: allowed, expires: exp}
		}
	}
	return out, nil
}

// evictLocked drops expired entries and, if still over the bound, everything.
func (c *Checker) evictLocked(now time.Time) {
	for k, e := range c.cache {
		if !now.Before(e.expires) {
			delete(c.cache, k)
		}
	}
	if len(c.cache) >= c.max {
		c.cache = make(map[cacheKey]cacheEntry)
	}
}
