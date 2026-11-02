// SPDX-License-Identifier: Apache-2.0

package quota

import (
	"net/http"
	"strings"
	"time"
)

// Client is the quota SDK v2: Reserve/Confirm/Release/Return with idempotency keys and
// source refs, absolute Recount, and the cached registry. It is separate from the legacy
// QuotaClient, which stays for existing importers.
type Client struct {
	baseURL    string
	httpClient *http.Client
	enabled    bool
	reg        *registryCache
}

// Option configures a Client.
type Option func(*Client)

// WithEnabled turns enforcement on or off; a disabled client returns no-op holds.
func WithEnabled(v bool) Option { return func(c *Client) { c.enabled = v } }

// WithRegistryTTL overrides DefaultRegistryTTL.
func WithRegistryTTL(d time.Duration) Option { return func(c *Client) { c.reg.ttl = d } }

// NewClient builds a v2 client. httpClient should be service-auth's NewIAMHTTPClient with
// scopes quota:usage:read quota:usage:update tenant:act-as.
func NewClient(baseURL string, httpClient *http.Client, opts ...Option) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	c := &Client{baseURL: strings.TrimRight(baseURL, "/"), httpClient: httpClient, enabled: true,
		reg: &registryCache{ttl: DefaultRegistryTTL}}
	for _, o := range opts {
		o(c)
	}
	return c
}
