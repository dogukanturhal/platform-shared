// SPDX-License-Identifier: Apache-2.0

// Package vault provides a centralized HashiCorp Vault client for secret management
// across multi-tenant services.
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
)

// Config holds the configuration for the Vault client.
type Config struct {
	// Enabled determines if Vault integration is active.
	// When false, the client falls back to environment variables.
	Enabled bool `mapstructure:"VAULT_ENABLED"`

	// Address is the URL of the Vault server.
	Address string `mapstructure:"VAULT_ADDR"`

	// RoleID for AppRole authentication.
	RoleID string `mapstructure:"VAULT_ROLE_ID"`

	// SecretID for AppRole authentication.
	SecretID string `mapstructure:"VAULT_SECRET_ID"`

	// KubernetesRole is the Vault Kubernetes auth role to log in as. Setting
	// this selects Kubernetes auth (the pod's projected ServiceAccount token
	// as the credential, verified by Vault via the Kubernetes TokenReview
	// API) over AppRole -- no role_id/secret_id pair to provision, deliver,
	// or rotate. This is the in-cluster idiomatic method: it is what every
	// non-Go Vault consumer on this cluster already uses (see
	// the GitOps repository platform/vault/k8s-auth-*-role.yaml and the
	// AuthBackendRole precedent for each service), and it requires no static
	// secret material at all.
	KubernetesRole string `mapstructure:"VAULT_K8S_ROLE"`

	// KubernetesMountPath is the mount path of the Kubernetes auth backend
	// (Vault default: "kubernetes").
	KubernetesMountPath string `mapstructure:"VAULT_K8S_MOUNT_PATH"`

	// KubernetesTokenPath is the filesystem path to the pod's ServiceAccount
	// JWT presented as the login credential. Defaults to the standard
	// projected/automounted path; override when the JWT is delivered via a
	// dedicated projected volume instead (recommended when
	// automountServiceAccountToken is false at the pod level for other
	// reasons, so only this narrowly-scoped token is exposed to the
	// container rather than the full default SA token).
	KubernetesTokenPath string `mapstructure:"VAULT_K8S_TOKEN_PATH"`

	// Namespace for Vault Enterprise namespaces.
	Namespace string `mapstructure:"VAULT_NAMESPACE"`

	// CacheTTL is the duration to cache secrets before refreshing.
	CacheTTL time.Duration `mapstructure:"VAULT_CACHE_TTL"`

	// TokenRenewalInterval is how often to attempt token renewal.
	TokenRenewalInterval time.Duration `mapstructure:"VAULT_TOKEN_RENEWAL_INTERVAL"`

	// MountPath is the mount path for the KV v2 secrets engine that GetSecret
	// / PutSecret address. It is a mount name, not a path prefix: every
	// StandardMappings VaultPath (see config_loader.go) is written relative
	// to this mount, e.g. "platform/jwt" under mount "example" reads as
	// example/data/platform/jwt. The one live KV v2 mount used for these
	// application secrets on this cluster is "example" (see the
	// ClusterSecretStore "vault-backend" in the GitOps repository, which every
	// non-Go consumer already reads through); "secret" is Vault's built-in
	// default mount and holds none of this data. Getting this wrong doesn't
	// 404 -- it silently nests the logical path one level too deep under
	// the wrong mount (e.g. secret/data/example/platform/jwt) and the
	// caller's own policy denies it there, surfacing as a bare 403 that
	// looks like a missing grant rather than a wrong URL.
	MountPath string `mapstructure:"VAULT_MOUNT_PATH"`

	// RetryMax is the maximum number of retries for Vault operations.
	RetryMax int `mapstructure:"VAULT_RETRY_MAX"`

	// RetryWaitMin is the minimum time to wait between retries.
	RetryWaitMin time.Duration `mapstructure:"VAULT_RETRY_WAIT_MIN"`

	// RetryWaitMax is the maximum time to wait between retries.
	RetryWaitMax time.Duration `mapstructure:"VAULT_RETRY_WAIT_MAX"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:              false,
		Address:              "http://vault:8200",
		CacheTTL:             5 * time.Minute,
		TokenRenewalInterval: 30 * time.Minute,
		MountPath:            "example",
		KubernetesMountPath:  "kubernetes",
		KubernetesTokenPath:  "/var/run/secrets/kubernetes.io/serviceaccount/token",
		RetryMax:             3,
		RetryWaitMin:         1 * time.Second,
		RetryWaitMax:         5 * time.Second,
	}
}

// cachedSecret holds a secret value with its expiration time.
type cachedSecret struct {
	value      map[string]interface{}
	expiration time.Time
}

// Client provides methods for interacting with HashiCorp Vault.
type Client struct {
	client *api.Client
	config Config

	// Cache for secrets
	cache   map[string]*cachedSecret
	cacheMu sync.RWMutex

	// Token management
	tokenExpiry time.Time
	tokenMu     sync.RWMutex

	// Lifecycle management
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewClient creates a new Vault client with the provided configuration.
// If Vault is disabled, it returns a client that falls back to environment variables.
func NewClient(cfg Config) (*Client, error) {
	c := &Client{
		config: cfg,
		cache:  make(map[string]*cachedSecret),
		stopCh: make(chan struct{}),
	}

	if !cfg.Enabled {
		return c, nil
	}

	// Create Vault API client configuration
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = cfg.Address
	vaultConfig.MaxRetries = cfg.RetryMax
	vaultConfig.MinRetryWait = cfg.RetryWaitMin
	vaultConfig.MaxRetryWait = cfg.RetryWaitMax

	var err error
	c.client, err = api.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Set namespace if provided (Vault Enterprise)
	if cfg.Namespace != "" {
		c.client.SetNamespace(cfg.Namespace)
	}

	// Authenticate with AppRole
	if err := c.authenticate(); err != nil {
		return nil, fmt.Errorf("failed to authenticate with Vault: %w", err)
	}

	// Start background token renewal
	c.wg.Add(1)
	go c.tokenRenewalLoop()

	return c, nil
}

// authenticate performs authentication with Vault.
// Supports direct token auth (dev mode via VAULT_TOKEN), Kubernetes auth
// (production, in-cluster; selected by setting VAULT_K8S_ROLE), and AppRole
// auth (selected by setting VAULT_ROLE_ID/VAULT_SECRET_ID). Kubernetes auth is
// checked before AppRole so a service that sets VAULT_K8S_ROLE never needs to
// also carry unused AppRole config.
func (c *Client) authenticate() error {
	// Dev mode: direct token auth via VAULT_TOKEN env var
	if token := os.Getenv("VAULT_TOKEN"); token != "" && (c.config.RoleID == "" || c.config.SecretID == "") && c.config.KubernetesRole == "" {
		c.client.SetToken(token)
		c.tokenMu.Lock()
		c.tokenExpiry = time.Now().Add(24 * time.Hour)
		c.tokenMu.Unlock()
		return nil
	}

	if c.config.KubernetesRole != "" {
		return c.authenticateKubernetes()
	}

	// Production mode: AppRole authentication
	if c.config.RoleID == "" || c.config.SecretID == "" {
		return fmt.Errorf("VAULT_ROLE_ID and VAULT_SECRET_ID required for AppRole auth " +
			"(or VAULT_K8S_ROLE for Kubernetes auth, or VAULT_TOKEN for dev)")
	}

	data := map[string]interface{}{
		"role_id":   c.config.RoleID,
		"secret_id": c.config.SecretID,
	}

	resp, err := c.client.Logical().Write("auth/approle/login", data)
	if err != nil {
		return fmt.Errorf("AppRole login failed: %w", err)
	}

	return c.setTokenFromAuth(resp)
}

// authenticateKubernetes logs in to Vault's Kubernetes auth method using the
// pod's projected ServiceAccount JWT as the credential. Vault verifies the JWT
// against the Kubernetes TokenReview API and, on success, issues a Vault token
// scoped to the policies bound to KubernetesRole (see the AuthBackendRole
// resource provisioned for the consuming service in the GitOps repository).
//
// No static secret is minted, stored, or rotated for this path: the
// credential is the SA token Kubernetes itself already manages.
func (c *Client) authenticateKubernetes() error {
	jwt, err := os.ReadFile(c.config.KubernetesTokenPath)
	if err != nil {
		return fmt.Errorf("read Kubernetes service account token at %q: %w", c.config.KubernetesTokenPath, err)
	}

	mount := c.config.KubernetesMountPath
	if mount == "" {
		mount = "kubernetes"
	}

	data := map[string]interface{}{
		"role": c.config.KubernetesRole,
		"jwt":  string(jwt),
	}

	resp, err := c.client.Logical().Write(fmt.Sprintf("auth/%s/login", mount), data)
	if err != nil {
		return fmt.Errorf("kubernetes auth login failed (role=%s, mount=%s): %w", c.config.KubernetesRole, mount, err)
	}

	return c.setTokenFromAuth(resp)
}

// setTokenFromAuth applies a successful login response's client token and
// lease duration, shared by every auth method's login call.
func (c *Client) setTokenFromAuth(resp *api.Secret) error {
	if resp == nil || resp.Auth == nil {
		return fmt.Errorf("empty auth response from Vault")
	}

	c.client.SetToken(resp.Auth.ClientToken)

	c.tokenMu.Lock()
	c.tokenExpiry = time.Now().Add(time.Duration(resp.Auth.LeaseDuration) * time.Second)
	c.tokenMu.Unlock()

	return nil
}

// tokenRenewalLoop periodically renews the Vault token.
func (c *Client) tokenRenewalLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.TokenRenewalInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.tokenMu.RLock()
			needsRenewal := time.Until(c.tokenExpiry) < c.config.TokenRenewalInterval*2
			c.tokenMu.RUnlock()

			if needsRenewal {
				if err := c.renewToken(); err != nil {
					// If renewal fails, try to re-authenticate
					if err := c.authenticate(); err != nil {
						fmt.Fprintf(os.Stderr, "WARNING: Vault token renewal and re-auth failed: %v\n", err)
					}
				}
			}
		}
	}
}

// renewToken attempts to renew the current Vault token.
func (c *Client) renewToken() error {
	secret, err := c.client.Auth().Token().RenewSelf(0)
	if err != nil {
		return fmt.Errorf("token renewal failed: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("empty renewal response from Vault")
	}

	c.tokenMu.Lock()
	c.tokenExpiry = time.Now().Add(time.Duration(secret.Auth.LeaseDuration) * time.Second)
	c.tokenMu.Unlock()

	return nil
}

// GetSecret retrieves a secret from Vault by path.
// path is relative to the configured KV v2 mount (c.config.MountPath, e.g.
// "example") -- it must NOT repeat the mount name. Example: path
// "platform/jwt" against mount "example" reads example/data/platform/jwt.
func (c *Client) GetSecret(ctx context.Context, path string) (map[string]interface{}, error) {
	if !c.config.Enabled {
		return nil, fmt.Errorf("vault is not enabled")
	}

	// Check cache first
	if cached := c.getFromCache(path); cached != nil {
		return cached, nil
	}

	// Read from Vault (KV v2)
	fullPath := fmt.Sprintf("%s/data/%s", c.config.MountPath, path)
	secret, err := c.client.Logical().ReadWithContext(ctx, fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret: mount=%q path=%q: %w", c.config.MountPath, path, err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("secret not found: mount=%q path=%q", c.config.MountPath, path)
	}

	// KV v2 wraps data in a "data" key
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected secret format: mount=%q path=%q", c.config.MountPath, path)
	}

	// Cache the secret
	c.setInCache(path, data)

	return data, nil
}

// PutSecret writes a secret to KV v2, creating a new version.
//
// Deliberately additive: this client has been read-only, and most callers
// should stay that way. Whether a service may actually write is decided by its
// VAULT POLICY, not by the presence of this method -- a service whose policy
// grants only "read" gets a 403 here regardless. Do not treat the existence of
// PutSecret as authorisation to widen a policy.
//
// The cache is invalidated for the path rather than updated, so the next read
// re-fetches from Vault. Updating it in place would let a write that Vault
// later rejected (policy, sealed, quota) leave this process serving a value
// that was never stored.
func (c *Client) PutSecret(ctx context.Context, path string, data map[string]interface{}) error {
	if !c.config.Enabled {
		return fmt.Errorf("vault is not enabled")
	}
	if len(data) == 0 {
		// An empty write creates a version with no keys, which reads back as a
		// present-but-empty secret -- indistinguishable from a corrupt entry
		// for any consumer. Refuse it rather than store it.
		return fmt.Errorf("refusing to write empty secret: mount=%q path=%q", c.config.MountPath, path)
	}

	// KV v2 requires the payload nested under "data" and writes to the /data/
	// prefix, mirroring GetSecret above.
	fullPath := fmt.Sprintf("%s/data/%s", c.config.MountPath, path)
	if _, err := c.client.Logical().WriteWithContext(ctx, fullPath, map[string]interface{}{
		"data": data,
	}); err != nil {
		// The mount and path are safe to log; the values are not, and are
		// never included.
		return fmt.Errorf("failed to write secret: mount=%q path=%q: %w", c.config.MountPath, path, err)
	}

	c.InvalidateCache(path)
	return nil
}

// PutSecretKV1 writes a secret to a KV **version 1** engine.
//
// Separate from PutSecret because the two engines differ in both the request
// path and the payload shape, and getting either wrong fails quietly:
//
//	v2:  PUT {mount}/data/{path}   body {"data": {...}}
//	v1:  PUT {mount}/{path}        body {...}
//
// A v2-shaped write into a v1 mount stores a literal "data" key wrapping the
// real content, which then reads back as a secret whose fields are all missing.
// Nothing errors; the consumer simply finds nothing.
//
// The mount is an explicit argument rather than the client's configured
// MountPath, because a v1 engine is necessarily a DIFFERENT mount from this
// client's default v2 one -- an engine's version is fixed at mount time.
//
// Whether the caller may write is decided by its Vault policy, not by this
// method existing.
func (c *Client) PutSecretKV1(ctx context.Context, mount, path string, data map[string]interface{}) error {
	if !c.config.Enabled {
		return fmt.Errorf("vault is not enabled")
	}
	if mount == "" || path == "" {
		return fmt.Errorf("vault: mount and path are both required for a KV v1 write")
	}
	if len(data) == 0 {
		// An empty write creates a present-but-empty secret, indistinguishable
		// from a corrupt entry for any consumer. Refuse rather than store it.
		return fmt.Errorf("refusing to write empty secret at %s/%s", mount, path)
	}

	// v1 takes the payload at the top level -- no "data" wrapper, no /data/
	// path segment.
	fullPath := fmt.Sprintf("%s/%s", strings.Trim(mount, "/"), strings.TrimPrefix(path, "/"))
	if _, err := c.client.Logical().WriteWithContext(ctx, fullPath, data); err != nil {
		// Path is safe to log; values never are.
		return fmt.Errorf("failed to write KV v1 secret at %s: %w", fullPath, err)
	}

	c.InvalidateCache(path)
	return nil
}

// GetSecretValue retrieves a specific value from a secret path.
func (c *Client) GetSecretValue(ctx context.Context, path, key string) (string, error) {
	data, err := c.GetSecret(ctx, path)
	if err != nil {
		return "", fmt.Errorf("GetSecretValue: GetSecret failed: %w", err)
	}

	value, ok := data[key]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret %s", key, path)
	}

	str, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("value at %s/%s is not a string", path, key)
	}

	return str, nil
}

// GetSecretJSON retrieves a secret and unmarshals it into the provided struct.
func (c *Client) GetSecretJSON(ctx context.Context, path string, v interface{}) error {
	data, err := c.GetSecret(ctx, path)
	if err != nil {
		return fmt.Errorf("GetSecretJSON: GetSecret failed: %w", err)
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal secret data: %w", err)
	}

	if err := json.Unmarshal(jsonData, v); err != nil {
		return fmt.Errorf("failed to unmarshal secret into struct: %w", err)
	}

	return nil
}

// GetOrEnv retrieves a secret value from Vault, falling back to an environment variable.
// This is the primary method for graceful fallback behavior.
func (c *Client) GetOrEnv(ctx context.Context, vaultPath, vaultKey, envVar string) string {
	if c.config.Enabled {
		value, err := c.GetSecretValue(ctx, vaultPath, vaultKey)
		if err == nil && value != "" {
			return value
		}
	}

	return os.Getenv(envVar)
}

// getFromCache retrieves a secret from the cache if it exists and hasn't expired.
func (c *Client) getFromCache(path string) map[string]interface{} {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()

	cached, ok := c.cache[path]
	if !ok {
		return nil
	}

	if time.Now().After(cached.expiration) {
		return nil
	}

	return cached.value
}

// setInCache stores a secret in the cache.
func (c *Client) setInCache(path string, value map[string]interface{}) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	c.cache[path] = &cachedSecret{
		value:      value,
		expiration: time.Now().Add(c.config.CacheTTL),
	}
}

// InvalidateCache removes a specific path from the cache.
func (c *Client) InvalidateCache(path string) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	delete(c.cache, path)
}

// InvalidateAllCache clears the entire cache.
func (c *Client) InvalidateAllCache() {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	c.cache = make(map[string]*cachedSecret)
}

// Close gracefully shuts down the client.
func (c *Client) Close() error {
	if c.stopCh != nil {
		close(c.stopCh)
	}
	c.wg.Wait()
	return nil
}

// IsEnabled returns whether Vault integration is enabled.
func (c *Client) IsEnabled() bool {
	return c.config.Enabled
}

// HealthCheck verifies connectivity to Vault.
func (c *Client) HealthCheck(ctx context.Context) error {
	if !c.config.Enabled {
		return nil
	}

	health, err := c.client.Sys().HealthWithContext(ctx)
	if err != nil {
		return fmt.Errorf("vault health check failed: %w", err)
	}

	if !health.Initialized {
		return fmt.Errorf("vault is not initialized")
	}

	if health.Sealed {
		return fmt.Errorf("vault is sealed")
	}

	return nil
}

// Status returns the current status of the Vault client.
type Status struct {
	Enabled     bool      `json:"enabled"`
	Connected   bool      `json:"connected"`
	TokenExpiry time.Time `json:"token_expiry,omitempty"`
}

// GetStatus returns the current status of the Vault client.
func (c *Client) GetStatus(ctx context.Context) Status {
	status := Status{
		Enabled: c.config.Enabled,
	}

	if !c.config.Enabled {
		return status
	}

	c.tokenMu.RLock()
	status.TokenExpiry = c.tokenExpiry
	c.tokenMu.RUnlock()

	if err := c.HealthCheck(ctx); err == nil {
		status.Connected = true
	}

	return status
}
