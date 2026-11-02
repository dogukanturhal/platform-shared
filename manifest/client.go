// SPDX-License-Identifier: Apache-2.0

// Package manifest provides a lightweight client for service resource
// self-registration with Falcon-ID. Services call RegisterOnStartup from
// main() once the configuration is available; the call is non-blocking and
// never fatal — a registration failure only produces a warning log.
//
// Usage:
//
//	manifestClient := manifest.NewClient(cfg.IAMServiceURL, cfg.InternalAPIKey, "workflow-engine", logger)
//	go manifestClient.RegisterOnStartup([]manifest.Resource{
//	    manifest.Database("hexxlock_workflow", "Workflow Database", "workflow", 0),
//	    manifest.KafkaTopic("example.workflow.events", "Workflow Events Topic", 3, 168, 10),
//	})
package manifest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// ExampleSuiteProductID is the well-known UUID for the Example Suite product.
// Services that belong to ExampleSuite pass this as their product ID.
const ExampleSuiteProductID = "00000000-0000-0000-0000-000000000010"

// Resource describes a single infrastructure resource a service requires.
type Resource struct {
	Type        string                 `json:"resource_type"`
	Name        string                 `json:"resource_name"`
	DisplayName string                 `json:"display_name"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Priority    int                    `json:"priority"`
	IsRequired  bool                   `json:"is_required"`
}

// registerRequest is the wire format sent to Falcon-ID.
type registerRequest struct {
	ServiceSlug string     `json:"service_slug"`
	ProductID   string     `json:"product_id"`
	Resources   []Resource `json:"resources"`
}

// registerResponse is the wire format returned by Falcon-ID.
type registerResponse struct {
	ServiceSlug    string `json:"service_slug"`
	ProductID      string `json:"product_id"`
	Registered     int    `json:"registered"`
	Updated        int    `json:"updated"`
	TotalManifests int    `json:"total_manifests"`
}

// Client sends resource manifests to Falcon-ID on service startup.
type Client struct {
	falconIDURL    string
	internalAPIKey string
	serviceSlug    string
	productID      string
	httpClient     *http.Client
	log            *zap.Logger
}

// NewClient creates a manifest registration client. The client registers
// resources for the ExampleSuite product (ExampleSuiteProductID). To target a different
// product use NewClientWithProduct. logger must not be nil — it is the only
// place RegisterOnStartup ever reports anything: the method returns void, so
// a caller has no error to check (a package-global zap.L()
// default made that the only signal, and silently, in every service that
// never calls zap.ReplaceGlobals).
//
// Deprecated: Use NewClientWithHTTPClient for OAuth2 service-auth support.
func NewClient(falconIDURL, internalAPIKey, serviceSlug string, logger *zap.Logger) *Client {
	return NewClientWithProduct(falconIDURL, internalAPIKey, serviceSlug, ExampleSuiteProductID, logger)
}

// NewClientWithProduct creates a manifest registration client that targets an
// arbitrary product ID. Use this when registering resources for a product other
// than ExampleSuite.
//
// Deprecated: Use NewClientWithHTTPClientAndProduct for OAuth2 service-auth support.
func NewClientWithProduct(falconIDURL, internalAPIKey, serviceSlug, productID string, logger *zap.Logger) *Client {
	return &Client{
		falconIDURL:    falconIDURL,
		internalAPIKey: internalAPIKey,
		serviceSlug:    serviceSlug,
		productID:      productID,
		httpClient:     &http.Client{Timeout: 10 * time.Second},
		log:            logger.Named("manifest"),
	}
}

// NewClientWithHTTPClient creates a manifest registration client that uses the
// provided http.Client for all outbound requests. Pass an http.Client whose
// Transport injects a service JWT (e.g., via serviceauth.TokenClient.RoundTripper)
// to replace static INTERNAL_API_KEY authentication.
//
// logger must not be nil — see NewClient.
func NewClientWithHTTPClient(falconIDURL, serviceSlug string, httpClient *http.Client, logger *zap.Logger) *Client {
	return NewClientWithHTTPClientAndProduct(falconIDURL, serviceSlug, ExampleSuiteProductID, httpClient, logger)
}

// NewClientWithHTTPClientAndProduct creates a manifest registration client that
// targets an arbitrary product ID and uses the provided http.Client.
func NewClientWithHTTPClientAndProduct(falconIDURL, serviceSlug, productID string, httpClient *http.Client, logger *zap.Logger) *Client {
	return &Client{
		falconIDURL: falconIDURL,
		serviceSlug: serviceSlug,
		productID:   productID,
		httpClient:  httpClient,
		log:         logger.Named("manifest"),
	}
}

// RegisterOnStartup registers the provided resources with Falcon-ID.
// It retries up to 5 times with exponential back-off (2 s, 4 s, 8 s, 16 s).
// The call is intended to be launched in a goroutine from main(); it never
// calls log.Fatal or panics — failures are logged as warnings only.
func (c *Client) RegisterOnStartup(resources []Resource) {
	if c.falconIDURL == "" {
		c.log.Warn("Skipping resource manifest registration: missing Falcon-ID URL",
			zap.String("service", c.serviceSlug),
		)
		return
	}

	const maxAttempts = 5
	backoff := 2 * time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := c.register(resources)
		if err == nil {
			return
		}

		c.log.Warn("Resource manifest registration failed (will retry)",
			zap.String("service", c.serviceSlug),
			zap.Int("attempt", attempt),
			zap.Int("max_attempts", maxAttempts),
			zap.Duration("backoff", backoff),
			zap.Error(err),
		)

		if attempt < maxAttempts {
			time.Sleep(backoff)
			backoff *= 2
		}
	}

	c.log.Warn("Resource manifest registration gave up after all retries — service will continue without registered manifest",
		zap.String("service", c.serviceSlug),
	)
}

// register performs a single registration attempt.
func (c *Client) register(resources []Resource) error {
	payload := registerRequest{
		ServiceSlug: c.serviceSlug,
		ProductID:   c.productID,
		Resources:   resources,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal manifest request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/internal/resource-manifest/register", c.falconIDURL)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.internalAPIKey != "" {
		req.Header.Set("X-Internal-Key", c.internalAPIKey)
	}
	req.Header.Set("X-Service-Name", c.serviceSlug)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var result registerResponse
	if err := json.Unmarshal(respBody, &result); err == nil {
		c.log.Info("Resource manifest registered successfully",
			zap.String("service", c.serviceSlug),
			zap.String("product_id", c.productID),
			zap.Int("registered", result.Registered),
			zap.Int("updated", result.Updated),
			zap.Int("total_manifests", result.TotalManifests),
		)
	} else {
		c.log.Info("Resource manifest registration completed",
			zap.String("service", c.serviceSlug),
			zap.Int("status", resp.StatusCode),
		)
	}

	return nil
}

// ---- Convenience constructors for common resource types ----

// Database returns a Resource for a PostgreSQL database.
// migrationDir is stored in config for the provisioner; pass "" when not applicable.
func Database(name, displayName, migrationDir string, priority int) Resource {
	cfg := map[string]interface{}{
		"engine": "postgresql",
	}
	if migrationDir != "" {
		cfg["migration_dir"] = migrationDir
	}
	return Resource{
		Type:        "database",
		Name:        name,
		DisplayName: displayName,
		Config:      cfg,
		Priority:    priority,
		IsRequired:  true,
	}
}

// KafkaTopic returns a Resource for a Kafka topic.
// partitions and retentionHours are stored in config for the provisioner.
func KafkaTopic(name, displayName string, partitions, retentionHours, priority int) Resource {
	return Resource{
		Type:        "kafka_topic",
		Name:        name,
		DisplayName: displayName,
		Config: map[string]interface{}{
			"partitions":      partitions,
			"retention_hours": retentionHours,
		},
		Priority:   priority,
		IsRequired: false,
	}
}

// StorageBucket returns a Resource for a storage bucket.
// strategy is the isolation strategy: "pool", "bridge", or "silo".
func StorageBucket(name, displayName, strategy string, priority int) Resource {
	return Resource{
		Type:        "storage_bucket",
		Name:        name,
		DisplayName: displayName,
		Config: map[string]interface{}{
			"isolation_strategy": strategy,
		},
		Priority:   priority,
		IsRequired: false,
	}
}
