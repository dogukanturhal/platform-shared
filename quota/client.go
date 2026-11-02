// SPDX-License-Identifier: Apache-2.0

// Package quota provides quota management functionality for tracking and enforcing
// resource usage limits across tenants.
package quota

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// ResourceType defines the types of resources that can be quota-limited
type ResourceType string

// ResourceTypeUsers and its siblings are the supported quota resource types.
//
// Deprecated: the quota-service registry (GET /internal/v1/quota/registry, Client.Registry)
// is the source of truth for keys; pass registry keys as plain strings to the v2 Client.
// These constants stay for existing importers and are no longer extended.
const (
	ResourceTypeUsers            ResourceType = "users"
	ResourceTypeStorageBytes     ResourceType = "storage_bytes"
	ResourceTypeAPIRequestsDaily ResourceType = "api_requests_daily"
	ResourceTypeContacts         ResourceType = "contacts"
	ResourceTypeInvoices         ResourceType = "invoices"
	ResourceTypeProducts         ResourceType = "products"
	ResourceTypeEmployees        ResourceType = "employees"
	ResourceTypeEmailSendsDaily  ResourceType = "email_sends_daily"
	ResourceTypeEmailSendsMonth  ResourceType = "email_sends_monthly"
	ResourceTypeIntegrations     ResourceType = "integrations"
	ResourceTypeWebhooks         ResourceType = "webhooks"
	ResourceTypeDocuments        ResourceType = "documents"

	// Marketing-automation resources (marketing plan limits) — registered in
	// quota-service validators 2026-06-06 alongside the marketing
	// services' usage-reporting wiring.
	ResourceTypeWorkflows ResourceType = "workflows"
	ResourceTypeCampaigns ResourceType = "campaigns"
	ResourceTypeSegments  ResourceType = "segments"
	ResourceTypeTemplates ResourceType = "templates"
	ResourceTypeLeads     ResourceType = "leads"
)

// QuotaStatus represents the current status of a quota
type QuotaStatus string //nolint:revive // public API stability

// QuotaStatusOK and its siblings are the supported quota status values.
const (
	QuotaStatusOK        QuotaStatus = "ok"
	QuotaStatusWarning   QuotaStatus = "warning"
	QuotaStatusExceeded  QuotaStatus = "exceeded"
	QuotaStatusUnlimited QuotaStatus = "unlimited"
	QuotaStatusError     QuotaStatus = "error"
)

// QuotaCheckResult is the result of checking quota availability
type QuotaCheckResult struct { //nolint:revive // public API stability
	Allowed        bool        `json:"allowed"`
	CurrentUsage   int64       `json:"current_usage"`
	EffectiveLimit int64       `json:"effective_limit"`
	Remaining      int64       `json:"remaining"`
	Status         QuotaStatus `json:"status"`
	Message        string      `json:"message"`
}

// QuotaClient is a client for the quota service
type QuotaClient struct { //nolint:revive // public API stability
	baseURL    string
	httpClient *http.Client
	enabled    bool
}

// NewQuotaClient creates a new quota client
func NewQuotaClient(baseURL string, enabled bool) *QuotaClient {
	return &QuotaClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		enabled: enabled,
	}
}

// NewQuotaClientWithHTTPClient creates a quota client using the provided
// *http.Client. Use this with service-auth's NewIAMHTTPClient so every
// request carries an OAuth client_credentials Bearer — quota-service's
// /check, /increment and /decrement sit behind RequirePermission gates
// (quota:usage:read / quota:usage:update), and granted scopes surface as
// permissions for service tokens (platform-shared/auth jwt.go). A plain
// unauthenticated client 401/403s on every call.
func NewQuotaClientWithHTTPClient(baseURL string, enabled bool, httpClient *http.Client) *QuotaClient {
	if httpClient == nil {
		return NewQuotaClient(baseURL, enabled)
	}
	return &QuotaClient{
		baseURL:    baseURL,
		httpClient: httpClient,
		enabled:    enabled,
	}
}

// CheckQuota checks if a resource action is allowed
func (c *QuotaClient) CheckQuota(ctx context.Context, tenantID uuid.UUID, resourceType ResourceType, amount int64) (*QuotaCheckResult, error) {
	if !c.enabled {
		return &QuotaCheckResult{
			Allowed: true,
			Status:  QuotaStatusOK,
			Message: "Quota enforcement disabled",
		}, nil
	}

	if amount == 0 {
		amount = 1
	}

	reqBody := map[string]interface{}{
		"tenant_id":        tenantID.String(),
		"resource_type":    resourceType,
		"requested_amount": amount,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/v1/quota/check", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// If quota service is unavailable, allow the action (fail-open)
		return &QuotaCheckResult{
			Allowed: true,
			Status:  QuotaStatusError,
			Message: "Quota service unavailable",
		}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Auth/validation failures must not silently deny (a bare-decoded
		// error body leaves Allowed=false and the middleware 403s every
		// request). Treat as service-unavailable: fail-open like the
		// transport-error branch above.
		return &QuotaCheckResult{
			Allowed: true,
			Status:  QuotaStatusError,
			Message: fmt.Sprintf("Quota service returned status %d", resp.StatusCode),
		}, nil
	}

	// quota-service wraps payloads via platform-shared/response:
	// {"success":true,"data":{...}}. Unwrap the envelope; tolerate a bare
	// body for forwards/backwards compatibility.
	var envelope struct {
		Data *QuotaCheckResult `json:"data"`
	}
	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	if err := json.Unmarshal(raw, &envelope); err == nil && envelope.Data != nil {
		return envelope.Data, nil
	}
	var result QuotaCheckResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// IncrementUsage increments quota usage
func (c *QuotaClient) IncrementUsage(ctx context.Context, tenantID uuid.UUID, resourceType ResourceType, amount int64) (bool, error) {
	if !c.enabled {
		return true, nil
	}

	if amount == 0 {
		amount = 1
	}

	reqBody := map[string]interface{}{
		"tenant_id":     tenantID.String(),
		"resource_type": resourceType,
		"amount":        amount,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/v1/quota/increment", bytes.NewBuffer(jsonBody))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// If quota service is unavailable, allow the action
		return true, nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusForbidden {
		return false, nil
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("quota service returned status %d", resp.StatusCode)
	}

	return true, nil
}

// DecrementUsage decrements quota usage
func (c *QuotaClient) DecrementUsage(ctx context.Context, tenantID uuid.UUID, resourceType ResourceType, amount int64) error {
	if !c.enabled {
		return nil
	}

	if amount == 0 {
		amount = 1
	}

	reqBody := map[string]interface{}{
		"tenant_id":     tenantID.String(),
		"resource_type": resourceType,
		"amount":        amount,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/v1/quota/decrement", bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// If quota service is unavailable, ignore the error
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("quota service returned status %d", resp.StatusCode)
	}

	return nil
}

// Reservation mirrors quota-service's services.Reservation for the wire. A
// zero-value ID means the reservation is a no-op — either the client is
// disabled or quota-service was unreachable and the call failed open — so
// there is nothing for Confirm/Release to settle. Check NeedsSettlement
// before calling either.
type Reservation struct { //nolint:revive // public API stability
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Resource  string    `json:"resource"`
	Amount    int64     `json:"amount"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NeedsSettlement reports whether this reservation actually holds quota and
// therefore must be settled with Confirm or Release. It is false when the
// client is disabled or the reserve call failed open.
func (r *Reservation) NeedsSettlement() bool {
	return r != nil && r.ID != ""
}

// Reserve atomically holds amount of resourceType against tenantID's plan
// quota, ahead of work (an SMTP send, for example) whose success is not yet
// known. Unlike CheckQuota, a successful Reserve actually counts against the
// limit until the caller settles it with Confirm (the work succeeded) or
// Release (it didn't) — see quota-service's QuotaReservationService.
//
// Following CheckQuota's transport policy: a quota-service outage must not
// block sends outright, so a transport error here fails open (returns a
// no-op Reservation, nil error) rather than blocking the caller.
func (c *QuotaClient) Reserve(ctx context.Context, tenantID uuid.UUID, resourceType ResourceType, amount int64) (*Reservation, error) {
	if !c.enabled {
		return &Reservation{Status: "disabled"}, nil
	}

	if amount == 0 {
		amount = 1
	}

	reqBody := map[string]interface{}{
		"tenant_id":     tenantID.String(),
		"resource_type": resourceType,
		"amount":        amount,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/v1/quota/reserve", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &Reservation{Status: "error"}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusForbidden {
		return nil, &QuotaExceededError{
			ResourceType: resourceType,
			Message:      "quota exceeded",
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Same fail-open reasoning as CheckQuota: an auth/validation failure
		// must not silently block every send.
		return &Reservation{Status: "error"}, nil
	}

	var envelope struct {
		Data *Reservation `json:"data"`
	}
	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	if err := json.Unmarshal(raw, &envelope); err == nil && envelope.Data != nil {
		return envelope.Data, nil
	}
	var result Reservation
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// Confirm settles a reservation into actual usage in full. Call it once the
// reserved work has succeeded.
func (c *QuotaClient) Confirm(ctx context.Context, reservationID string) error {
	return c.ConfirmPartial(ctx, reservationID, -1)
}

// ConfirmPartial settles a reservation, recording only actualAmount as real
// usage and freeing the unused remainder of what was reserved. Pass -1 to
// confirm the full originally-reserved amount (equivalent to Confirm).
func (c *QuotaClient) ConfirmPartial(ctx context.Context, reservationID string, actualAmount int64) error {
	if !c.enabled || reservationID == "" {
		return nil
	}

	reqBody := map[string]interface{}{"actual_amount": actualAmount}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		c.baseURL+"/api/v1/quota/reservations/"+reservationID+"/confirm", bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// If quota service is unavailable, ignore the error — the
		// reservation's own grace-window TTL (redisKeyGraceMultiplier) or
		// SweepStale will reclaim it rather than double-charging the tenant.
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("quota service returned status %d", resp.StatusCode)
	}

	return nil
}

// Release frees a reservation without recording any usage against it — call
// this when the reserved work did not happen (the send failed before
// dispatch, for example).
func (c *QuotaClient) Release(ctx context.Context, reservationID string) error {
	if !c.enabled || reservationID == "" {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		c.baseURL+"/api/v1/quota/reservations/"+reservationID+"/release", http.NoBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// If quota service is unavailable, ignore the error — same
		// reasoning as ConfirmPartial: the reservation self-expires.
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("quota service returned status %d", resp.StatusCode)
	}

	return nil
}

// MustCheckQuota checks quota and returns an error if exceeded
func (c *QuotaClient) MustCheckQuota(ctx context.Context, tenantID uuid.UUID, resourceType ResourceType, amount int64) error {
	result, err := c.CheckQuota(ctx, tenantID, resourceType, amount)
	if err != nil {
		return fmt.Errorf("MustCheckQuota: CheckQuota failed: %w", err)
	}

	if !result.Allowed {
		return &QuotaExceededError{
			ResourceType: resourceType,
			CurrentUsage: result.CurrentUsage,
			Limit:        result.EffectiveLimit,
			Message:      result.Message,
		}
	}

	return nil
}

// QuotaExceededError is returned when quota is exceeded
type QuotaExceededError struct { //nolint:revive // public API stability
	ResourceType ResourceType
	CurrentUsage int64
	Limit        int64
	Message      string
	// Requested and Enforcement are filled from the 409 quota_exceeded problem (SDK v2).
	Requested   int64
	Enforcement string
}

func (e *QuotaExceededError) Error() string {
	return fmt.Sprintf("quota exceeded for %s: %s (current: %d, limit: %d)",
		e.ResourceType, e.Message, e.CurrentUsage, e.Limit)
}

// IsQuotaExceededError checks if an error is a QuotaExceededError
func IsQuotaExceededError(err error) bool {
	var qe *QuotaExceededError
	return errors.As(err, &qe)
}
