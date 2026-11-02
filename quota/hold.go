// SPDX-License-Identifier: Apache-2.0

package quota

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var failOpenTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "quota_fail_open_total",
	Help: "Quota calls allowed because quota-service was unavailable and the key's fail_mode is open.",
}, []string{"key"})

// ErrQuotaUnavailable is returned (wrapped in *UnavailableError) when quota-service
// cannot be reached and the key fails closed; callers answer 503.
var ErrQuotaUnavailable = errors.New("quota service unavailable")

// ErrIdempotencyConflict means an idempotency key was replayed with a different amount.
var ErrIdempotencyConflict = errors.New("idempotency key reused with a different amount")

// UnavailableError wraps the transport or 5xx cause of a fail-closed refusal.
type UnavailableError struct {
	Key   string
	Cause error
}

func (e *UnavailableError) Error() string {
	return fmt.Sprintf("quota unavailable for %s: %v", e.Key, e.Cause)
}

// Is makes errors.Is(err, ErrQuotaUnavailable) match.
func (e *UnavailableError) Is(target error) bool { return target == ErrQuotaUnavailable }

// Unwrap returns the underlying cause.
func (e *UnavailableError) Unwrap() error { return e.Cause }

// Hold is a reserved amount awaiting Confirm or Release. A no-op hold (client disabled, or
// failed open) settles to nothing.
type Hold struct {
	ID       string
	TenantID uuid.UUID
	Key      string
	Amount   int64
	// Replayed is true when an idempotent Reserve returned an existing reservation.
	Replayed bool

	c       *Client
	mu      sync.Mutex
	settled bool
}

// Noop reports whether the hold holds nothing server-side.
func (h *Hold) Noop() bool { return h == nil || h.ID == "" }

// Reserve holds amount of key for the tenant. idemKey is a stable id of the business
// operation: replaying it returns the same hold and never double-counts.
func (c *Client) Reserve(ctx context.Context, tenant uuid.UUID, key string, amount int64, idemKey string) (*Hold, error) {
	if idemKey == "" {
		return nil, errors.New("quota reserve: idempotency key required")
	}
	if amount < 0 {
		return nil, errors.New("quota reserve: amount must be positive")
	}
	if amount == 0 {
		amount = 1
	}
	noop := &Hold{TenantID: tenant, Key: key, Amount: amount, c: c}
	if !c.enabled {
		return noop, nil
	}
	resp, body, err := c.do(ctx, http.MethodPost, "/api/v1/quota/reserve", nil, map[string]any{
		"tenant_id": tenant, "resource_type": key, "amount": amount, "idempotency_key": idemKey,
	})
	if err != nil {
		return c.unavailable(ctx, noop, err)
	}
	switch {
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
		return c.unavailable(ctx, noop, fmt.Errorf("status %d", resp.StatusCode))
	case resp.StatusCode == http.StatusConflict || resp.StatusCode == http.StatusForbidden:
		if err := refusal(resp.StatusCode, body, key, amount); err != nil {
			return nil, err
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("quota reserve: status %d", resp.StatusCode)
	}
	var r struct {
		ID       string `json:"id"`
		Replayed bool   `json:"replayed"`
	}
	if err := unwrap(body, &r); err != nil || r.ID == "" {
		return nil, fmt.Errorf("quota reserve: bad response: %v", err)
	}
	return &Hold{ID: r.ID, TenantID: tenant, Key: key, Amount: amount, Replayed: r.Replayed, c: c}, nil
}

// unavailable applies the key's registry fail mode to a transport/5xx failure.
func (c *Client) unavailable(ctx context.Context, noop *Hold, cause error) (*Hold, error) {
	reg, _ := c.Registry(ctx)
	if reg.FailMode(noop.Key) == FailModeOpen {
		failOpenTotal.WithLabelValues(noop.Key).Inc()
		return noop, nil
	}
	return nil, &UnavailableError{Key: noop.Key, Cause: cause}
}

// refusal maps a 409 problem+json or the legacy 403 "Quota exceeded" to typed errors.
// It returns nil for a 403 that is not a quota refusal (an auth failure).
func refusal(status int, body []byte, key string, amount int64) error {
	var p struct {
		Code        string `json:"code"`
		Limit       int64  `json:"limit"`
		Usage       int64  `json:"usage"`
		Requested   int64  `json:"requested"`
		Enforcement string `json:"enforcement"`
		Error       *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &p)
	switch {
	case status == http.StatusConflict && p.Code == "idempotency_conflict":
		return fmt.Errorf("quota reserve %s: %w", key, ErrIdempotencyConflict)
	case status == http.StatusConflict && p.Code == "quota_exceeded":
		return &QuotaExceededError{ResourceType: ResourceType(key), CurrentUsage: p.Usage, Limit: p.Limit,
			Requested: p.Requested, Enforcement: p.Enforcement, Message: "quota exceeded"}
	case status == http.StatusForbidden && p.Error != nil && strings.Contains(strings.ToLower(p.Error.Message), "quota exceeded"):
		return &QuotaExceededError{ResourceType: ResourceType(key), Requested: amount, Message: "quota exceeded"}
	case status == http.StatusConflict:
		return fmt.Errorf("quota reserve %s: conflict %q", key, p.Code)
	}
	return nil
}

// Confirm settles the hold into usage, ledgered under sourceRef (the business document
// id). Idempotent: a repeat, or a no-op hold, returns nil.
func (h *Hold) Confirm(ctx context.Context, sourceRef string) error {
	return h.settle(ctx, "confirm", map[string]any{"actual_amount": -1, "source_ref": sourceRef})
}

// Release frees the hold without recording usage. Idempotent; an unsettled hold also
// expires server-side.
func (h *Hold) Release(ctx context.Context) error {
	return h.settle(ctx, "release", nil)
}

func (h *Hold) settle(ctx context.Context, verb string, body any) error {
	if h.Noop() || !h.c.enabled {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.settled {
		return nil
	}
	resp, _, err := h.c.do(ctx, http.MethodPost, "/api/v1/quota/reservations/"+h.ID+"/"+verb, nil, body)
	if err != nil {
		return fmt.Errorf("quota %s: %w", verb, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("quota %s: status %d", verb, resp.StatusCode)
	}
	h.settled = true
	return nil
}

// Return gives amount of a stock key back (delete/archive). Idempotent per sourceRef.
func (c *Client) Return(ctx context.Context, tenant uuid.UUID, key string, amount int64, sourceRef string) error {
	if !c.enabled {
		return nil
	}
	if sourceRef == "" {
		return errors.New("quota return: source ref required")
	}
	if amount <= 0 {
		amount = 1
	}
	resp, _, err := c.do(ctx, http.MethodPost, "/api/v1/quota/return", nil, map[string]any{
		"tenant_id": tenant, "resource_type": key, "amount": amount, "source_ref": sourceRef,
	})
	if err != nil {
		return fmt.Errorf("quota return: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("quota return: status %d", resp.StatusCode)
	}
	return nil
}

// RecountItem is one absolute count. PeriodStart applies to flow keys only.
type RecountItem struct {
	Key         string     `json:"resource_type"`
	Count       int64      `json:"count"`
	PeriodStart *time.Time `json:"period_start,omitempty"`
}

// RecountResult is the per-key outcome of Recount.
type RecountResult struct {
	Key      string `json:"resource_type"`
	Status   string `json:"status"` // ok | corrected | stale_period | unknown_resource | invalid | error
	Recorded int64  `json:"recorded"`
	Actual   int64  `json:"actual"`
	Drift    int64  `json:"drift"`
}

// Recount reports absolute counts for the tenant (POST /internal/v1/usage/recount, needs
// tenant:act-as + quota:usage:update).
func (c *Client) Recount(ctx context.Context, tenant uuid.UUID, items []RecountItem) ([]RecountResult, error) {
	if !c.enabled {
		return nil, nil
	}
	resp, body, err := c.do(ctx, http.MethodPost, "/internal/v1/usage/recount",
		map[string]string{"X-Tenant-ID": tenant.String()}, map[string]any{"tenant_id": tenant, "items": items})
	if err != nil {
		return nil, fmt.Errorf("quota recount: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("quota recount: status %d", resp.StatusCode)
	}
	var out struct {
		Results []RecountResult `json:"results"`
	}
	if err := unwrap(body, &out); err != nil {
		return nil, fmt.Errorf("quota recount: %w", err)
	}
	return out.Results, nil
}

func (c *Client) do(ctx context.Context, method, path string, headers map[string]string, body any) (*http.Response, []byte, error) {
	var rd io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rd)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, err
	}
	return resp, raw, nil
}

// unwrap decodes a response.Success envelope {"success":true,"data":{...}}, tolerating a bare body.
func unwrap(raw []byte, out any) error {
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err == nil && len(env.Data) > 0 {
		raw = env.Data
	}
	return json.Unmarshal(raw, out)
}
