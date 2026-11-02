// SPDX-License-Identifier: Apache-2.0

// Package permissions provides a client for registering module permissions with Falcon-ID.
package permissions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// PermissionDef defines a single resource's permissions for registration.
type PermissionDef struct {
	Resource    string   `json:"resource"`
	Actions     []string `json:"actions"`
	DisplayName string   `json:"displayName,omitempty"`
	Description string   `json:"description,omitempty"`
}

// registerModuleRequest is the request body sent to Falcon-ID.
type registerModuleRequest struct {
	Module      string          `json:"module"`
	Permissions []PermissionDef `json:"permissions"`
}

// registerModuleResponse is the response body from Falcon-ID.
type registerModuleResponse struct {
	Module     string `json:"module"`
	Registered int    `json:"registered"`
	Updated    int    `json:"updated"`
}

// Client registers module permissions with Falcon-ID on service startup.
type Client struct {
	falconIDURL    string
	internalAPIKey string
	serviceName    string
	httpClient     *http.Client
	logger         *zap.Logger
	// requireStaticKey is true when the client was created via NewClient and
	// therefore depends on an explicit internalAPIKey for authentication. When
	// false (NewClientWithHTTPClient), the injected transport carries a Bearer
	// token and an empty key is valid.
	requireStaticKey bool
	// platformTenantID overrides the tenant sent on registration. Empty uses
	// PLATFORM_TENANT_ID, then the well-known exampletenant id.
	platformTenantID string
}

// defaultPlatformTenantID is exampletenant, the tenant that owns
// platform-level records. Overridable via PLATFORM_TENANT_ID so a differently
// seeded environment does not need a rebuild.
const defaultPlatformTenantID = "00000000-0000-0000-0000-000000000002"

// SetPlatformTenantID overrides the tenant used for permission registration.
func (c *Client) SetPlatformTenantID(id string) { c.platformTenantID = id }

func (c *Client) tenantID() string {
	if c.platformTenantID != "" {
		return c.platformTenantID
	}
	if v := os.Getenv("PLATFORM_TENANT_ID"); v != "" {
		return v
	}
	return defaultPlatformTenantID
}

// NewClient creates a new permission registration client. logger must not be
// nil — it is the only place a registration failure is ever reported (
// a package-global zap.L() default silently discarded every failure in
// services that never call zap.ReplaceGlobals).
//
// Deprecated: Use NewClientWithHTTPClient for OAuth2 service-auth support.
func NewClient(falconIDURL, internalAPIKey, serviceName string, logger *zap.Logger) *Client {
	return &Client{
		falconIDURL:      falconIDURL,
		internalAPIKey:   internalAPIKey,
		serviceName:      serviceName,
		requireStaticKey: true,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		logger: logger.Named("permissions"),
	}
}

// NewClientWithHTTPClient creates a permission registration client that uses the
// provided http.Client for all outbound requests. Pass an http.Client whose
// Transport injects a service JWT (e.g., via serviceauth.TokenClient.RoundTripper)
// to replace static INTERNAL_API_KEY authentication.
//
// When httpClient carries a Bearer token, the X-Internal-Key header is omitted;
// Falcon-ID accepts either mechanism for backward compatibility.
//
// logger must not be nil — see NewClient.
func NewClientWithHTTPClient(falconIDURL, serviceName string, httpClient *http.Client, logger *zap.Logger) *Client {
	return &Client{
		falconIDURL: falconIDURL,
		serviceName: serviceName,
		httpClient:  httpClient,
		logger:      logger.Named("permissions"),
	}
}

// RegisterModule sends POST /internal/v1/permissions/register with X-Internal-Key header.
// Idempotent — safe to call on every startup. Logs success/failure but does NOT fatal.
func (c *Client) RegisterModule(ctx context.Context, module string, permissions []PermissionDef) error {
	if c.falconIDURL == "" {
		c.logger.Warn("Skipping permission registration: missing Falcon-ID URL",
			zap.String("service", c.serviceName),
			zap.String("module", module),
		)
		return nil
	}

	if c.requireStaticKey && c.internalAPIKey == "" {
		c.logger.Warn("Skipping permission registration: missing internal API key",
			zap.String("service", c.serviceName),
			zap.String("module", module),
		)
		return nil
	}

	reqBody := registerModuleRequest{
		Module:      module,
		Permissions: permissions,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		c.logger.Error("Failed to marshal permission registration request",
			zap.String("service", c.serviceName),
			zap.String("module", module),
			zap.Error(err),
		)
		return fmt.Errorf("marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/internal/v1/permissions/register", c.falconIDURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		c.logger.Error("Failed to create permission registration request",
			zap.String("service", c.serviceName),
			zap.String("module", module),
			zap.Error(err),
		)
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.internalAPIKey != "" {
		req.Header.Set("X-Internal-Key", c.internalAPIKey)
	}
	req.Header.Set("X-Service-Name", c.serviceName)
	// Falcon-ID's ExtractTenant middleware sources the tenant from this header
	// alone and rejects the request without it, so permission registration has
	// been failing on every service at startup with:
	//   400 {"error":"Tenant context required","message":"X-Tenant-ID header is required..."}
	//
	// Registration is PLATFORM-level metadata -- a module declaring which
	// permissions it offers -- so there is no per-tenant value to send and the
	// platform tenant is the correct principal. The alternative, exempting the
	// route from tenant extraction in Falcon-ID, would widen an auth surface to
	// fix a caller that simply omitted a header; sending the header changes no
	// control.
	//
	// Non-blocking by design: registration already logs and continues on
	// failure, so a service still starts if this is wrong.
	req.Header.Set("X-Tenant-ID", c.tenantID())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// ERROR, not Warn: a service's module never lands in the IAM
		// catalog when this fires, silently leaving every permission that
		// module's own RequirePermission gates check for unreachable by
		// anyone. That is exactly how the /internal/v1/permissions/register
		// 404 went unnoticed for weeks -- non-blocking still means
		// "don't fail startup", it does not mean "don't page anyone".
		c.logger.Error("Permission registration request failed (non-blocking)",
			zap.String("service", c.serviceName),
			zap.String("module", module),
			zap.Error(err),
		)
		return fmt.Errorf("http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		// See the Error rationale above -- same silent-catalog-gap failure
		// mode, just surfaced via an HTTP error status instead of a
		// transport error.
		c.logger.Error("Permission registration returned error (non-blocking)",
			zap.String("service", c.serviceName),
			zap.String("module", module),
			zap.Int("status", resp.StatusCode),
			zap.String("body", string(respBody)),
		)
		return fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var result registerModuleResponse
	if err := json.Unmarshal(respBody, &result); err == nil {
		c.logger.Info("Permission registration successful",
			zap.String("service", c.serviceName),
			zap.String("module", result.Module),
			zap.Int("registered", result.Registered),
			zap.Int("updated", result.Updated),
		)
	} else {
		c.logger.Info("Permission registration completed",
			zap.String("service", c.serviceName),
			zap.String("module", module),
			zap.Int("status", resp.StatusCode),
		)
	}

	return nil
}

// PermissionManifest is the top-level structure of a permissions.yaml manifest file.
// Each service that uses declarative permission registration should ship a manifest at
// its service root so that cold-start registration is self-describing.
//
// Example manifest:
//
//	module: billing
//	permissions:
//	  - resource: invoices
//	    actions: [create, read, update, delete, export, approve]
//	    description: Invoice management
//	  - resource: payments
//	    actions: [create, read, update, delete, refund]
//	    description: Payment processing
type PermissionManifest struct {
	Module      string          `yaml:"module"`
	Permissions []PermissionDef `yaml:"permissions"`
}

// permissionDefYAML is a YAML-friendly shadow of PermissionDef used during
// manifest unmarshalling. PermissionDef uses JSON struct tags for the wire
// protocol; YAML deserialization uses lower-case field names by convention.
type permissionDefYAML struct {
	Resource    string   `yaml:"resource"`
	Actions     []string `yaml:"actions"`
	DisplayName string   `yaml:"displayName,omitempty"`
	Description string   `yaml:"description,omitempty"`
}

// LoadManifest reads and parses a YAML permission manifest from disk.
// It returns a validated PermissionManifest or an error if the file is
// missing, unreadable, or malformed.
func LoadManifest(path string) (*PermissionManifest, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from trusted service configuration
	if err != nil {
		return nil, fmt.Errorf("read manifest %q: %w", path, err)
	}
	return ParseManifest(data, path)
}

// ParseManifest parses a YAML permission manifest from memory, e.g. a file
// embedded with //go:embed so it ships inside the binary. name is only used in
// error messages.
func ParseManifest(data []byte, name string) (*PermissionManifest, error) {
	// Unmarshal into a shadow struct first so that we control field mapping
	// independently of the JSON wire tags on PermissionDef.
	var raw struct {
		Module      string              `yaml:"module"`
		Permissions []permissionDefYAML `yaml:"permissions"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse manifest %q: %w", name, err)
	}

	if raw.Module == "" {
		return nil, fmt.Errorf("manifest %q: module field is required", name)
	}

	perms := make([]PermissionDef, 0, len(raw.Permissions))
	for _, p := range raw.Permissions {
		if p.Resource == "" {
			return nil, fmt.Errorf("manifest %q: permission entry missing resource field", name)
		}
		perms = append(perms, PermissionDef(p))
	}

	return &PermissionManifest{
		Module:      raw.Module,
		Permissions: perms,
	}, nil
}

// RegisterFromManifest loads permissions from a YAML manifest file at manifestPath
// and registers them with Falcon-ID. The call is idempotent and safe to invoke on
// every startup. Returns nil when the manifest declares no permissions (empty
// permissions list is valid for services that defer registration).
//
// Manifest format:
//
//	module: billing
//	permissions:
//	  - resource: invoices
//	    actions: [create, read, update, delete, export, approve]
//	    description: Invoice management
func (c *Client) RegisterFromManifest(ctx context.Context, manifestPath string) error {
	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	return c.RegisterModule(ctx, manifest.Module, manifest.Permissions)
}

// RegisterFromManifestBytes is RegisterFromManifest for a manifest already in
// memory. Services embed permissions.yaml with //go:embed and pass the bytes, so
// registration does not depend on the file being present in the container image.
func (c *Client) RegisterFromManifestBytes(ctx context.Context, data []byte) error {
	manifest, err := ParseManifest(data, "embedded permissions manifest")
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	return c.RegisterModule(ctx, manifest.Module, manifest.Permissions)
}

// RegisterWithRetry attempts permission registration up to 5 times with
// exponential backoff (2 s → 4 s → 8 s → 16 s). It returns nil on the first
// successful call and wraps the last error with attempt count on exhaustion.
//
// Use this variant when the IAM service may not be reachable immediately at
// pod start (e.g., rolling deployments where Falcon-ID starts after dependents).
// For fire-and-forget goroutines, prefer RegisterModule which is already
// non-blocking and logs its own warnings.
func (c *Client) RegisterWithRetry(ctx context.Context, module string, perms []PermissionDef) error {
	backoff := 2 * time.Second
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		err := c.RegisterModule(ctx, module, perms)
		if err == nil {
			return nil
		}
		lastErr = err
		if attempt < 4 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("permission registration cancelled after %d attempts: %w", attempt+1, ctx.Err())
			case <-time.After(backoff):
			}
			backoff *= 2
		}
	}
	return fmt.Errorf("permission registration failed after 5 attempts: %w", lastErr)
}

// StandardCRUD returns the standard CRUD action set: create, read, update, delete, *
func StandardCRUD() []string {
	return []string{"create", "read", "update", "delete", "*"}
}
