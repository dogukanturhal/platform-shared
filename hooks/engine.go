// SPDX-License-Identifier: Apache-2.0

// Package hooks provides an auth event hooks engine that delivers webhook
// notifications to tenant-configured HTTP endpoints. It mirrors the behavior
// of products like Auth0 Actions or Okta Event Hooks: for synchronous triggers
// the engine POSTs a signed payload, waits for a response, and either allows
// or denies the action based on the response. For asynchronous triggers the
// engine fires and forgets.
package hooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Trigger types
// ---------------------------------------------------------------------------

// TriggerType identifies the point in an auth flow where a hook fires.
type TriggerType string

// TriggerPreLogin and its siblings are the supported hook trigger points.
const (
	TriggerPreLogin         TriggerType = "pre-login"
	TriggerPostLogin        TriggerType = "post-login"
	TriggerPreTokenIssue    TriggerType = "pre-token-issue"
	TriggerPreRegistration  TriggerType = "pre-registration"
	TriggerPostRegistration TriggerType = "post-registration"
	TriggerPasswordChange   TriggerType = "password-change"
	TriggerPreMFA           TriggerType = "pre-mfa"
	TriggerPostMFA          TriggerType = "post-mfa"
	TriggerUserDeleted      TriggerType = "user-deleted"
	TriggerSessionRevoked   TriggerType = "session-revoked"
)

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

// HookConfig defines a single webhook endpoint registered by a tenant.
type HookConfig struct {
	// ID uniquely identifies this hook within a tenant.
	ID string `json:"id"`

	// TenantID scopes this hook to a specific tenant.
	TenantID string `json:"tenant_id"`

	// Name is a human-readable label.
	Name string `json:"name"`

	// URL is the HTTPS endpoint that receives the webhook POST.
	URL string `json:"url"`

	// Trigger is the event that causes this hook to fire.
	Trigger TriggerType `json:"trigger"`

	// Secret is used to compute the HMAC-SHA256 signature sent in the
	// X-Hook-Signature request header. Can be empty (no signature).
	Secret string `json:"secret"`

	// Enabled controls whether the hook participates in execution.
	// Disabled hooks are silently skipped.
	Enabled bool `json:"enabled"`

	// Async controls delivery mode. When true the engine fires the request in
	// a background goroutine and does not wait for a response (fire-and-forget).
	// The hook cannot deny an action when Async is true.
	Async bool `json:"async"`

	// Priority determines the execution order among hooks for the same trigger.
	// Lower values run first. Hooks with equal priority run in registration order.
	Priority int `json:"priority"`

	// TimeoutMs is the maximum number of milliseconds the engine waits for a
	// synchronous hook to respond before treating the call as timed-out and
	// applying the fail-open policy (allow=true). Defaults to 3000 ms.
	TimeoutMs int `json:"timeout_ms"`
}

// HookPayload is the JSON body POSTed to a webhook endpoint.
type HookPayload struct {
	// Trigger identifies the event.
	Trigger TriggerType `json:"trigger"`

	// TenantID is the tenant that owns the hook.
	TenantID string `json:"tenant_id"`

	// Timestamp is when the event occurred (UTC).
	Timestamp time.Time `json:"timestamp"`

	// Data carries event-specific fields (user ID, IP address, MFA method, …).
	Data map[string]interface{} `json:"data"`

	// RequestID is a correlation ID for tracing the originating HTTP request.
	RequestID string `json:"request_id"`
}

// HookResponse is the JSON body the webhook endpoint returns for synchronous
// hooks. Async hooks' responses are discarded.
type HookResponse struct {
	// Allow controls whether the action should proceed. A false value causes
	// the engine to stop processing remaining hooks and deny the action.
	Allow bool `json:"allow"`

	// Enrich carries additional key/value pairs the engine merges into the
	// caller's enrichment map (e.g., extra JWT claims or profile attributes).
	Enrich map[string]interface{} `json:"enrich"`

	// Message is a human-readable explanation for denials.
	Message string `json:"message"`
}

// ---------------------------------------------------------------------------
// Internal circuit breaker
// ---------------------------------------------------------------------------

// circuitBreaker is a simple per-hook failure counter.
// After maxFailures consecutive failures the circuit opens and all calls
// return an error immediately until openUntil has elapsed.
type circuitBreaker struct {
	mu          sync.Mutex
	failures    int
	maxFailures int
	openUntil   time.Time
}

// Allow returns true if the circuit is closed (calls permitted).
func (cb *circuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.failures >= cb.maxFailures {
		if time.Now().Before(cb.openUntil) {
			return false
		}
		// Recovery: half-open — let a single probe through and reset counter.
		cb.failures = 0
	}
	return true
}

// RecordSuccess resets the failure counter.
func (cb *circuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
}

// RecordFailure increments the failure counter and, upon reaching the threshold,
// opens the circuit for 60 seconds.
func (cb *circuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	if cb.failures >= cb.maxFailures {
		cb.openUntil = time.Now().Add(60 * time.Second)
	}
}

// ---------------------------------------------------------------------------
// HookEngine
// ---------------------------------------------------------------------------

const (
	defaultTimeoutMs   = 3000
	circuitMaxFailures = 3
)

// HookEngine manages webhook hook registration and execution for all tenants.
// It is safe for concurrent use.
type HookEngine struct {
	client          *http.Client
	hooks           map[string][]HookConfig    // tenantID -> sorted hook list
	circuitBreakers map[string]*circuitBreaker // hookID -> circuit breaker
	mu              sync.RWMutex
	logger          *zap.Logger
}

// NewHookEngine creates a HookEngine backed by a default http.Client.
// Callers that need custom TLS or transport settings should use
// NewHookEngineWithClient.
func NewHookEngine(logger *zap.Logger) *HookEngine {
	return NewHookEngineWithClient(logger, &http.Client{})
}

// NewHookEngineWithClient creates a HookEngine using the provided http.Client.
// This is useful in tests where an httptest.Server transport is required.
func NewHookEngineWithClient(logger *zap.Logger, client *http.Client) *HookEngine {
	return &HookEngine{
		client:          client,
		hooks:           make(map[string][]HookConfig),
		circuitBreakers: make(map[string]*circuitBreaker),
		logger:          logger,
	}
}

// RegisterHooks replaces the hook list for tenantID with hooks, sorted by
// Priority ascending. Calling RegisterHooks with an empty slice is equivalent
// to calling RemoveHooks.
func (e *HookEngine) RegisterHooks(tenantID string, hooks []HookConfig) {
	sorted := make([]HookConfig, len(hooks))
	copy(sorted, hooks)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	e.mu.Lock()
	defer e.mu.Unlock()

	e.hooks[tenantID] = sorted

	// Ensure a circuit breaker exists for every registered hook.
	for _, h := range sorted {
		if _, ok := e.circuitBreakers[h.ID]; !ok {
			e.circuitBreakers[h.ID] = &circuitBreaker{maxFailures: circuitMaxFailures}
		}
	}
}

// RemoveHooks deletes all hooks registered for tenantID.
func (e *HookEngine) RemoveHooks(tenantID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.hooks, tenantID)
}

// Execute runs all enabled hooks for the given trigger and tenantID.
//
// Execution rules:
//   - Disabled hooks are skipped.
//   - Hooks whose circuit breaker is open are skipped (fail-open).
//   - Hooks are executed in ascending Priority order.
//   - Sync hooks: POST payload; if allow=false, stop and deny immediately.
//   - Sync hooks: timeout => fail-open (allow=true), circuit failure recorded.
//   - Async hooks: fired in a goroutine; result does not affect the response.
//   - Enrich data from all sync hooks is merged into the returned HookResponse.
//   - If no hooks match, returns &HookResponse{Allow: true}.
func (e *HookEngine) Execute(ctx context.Context, trigger TriggerType, tenantID string, data map[string]interface{}) (*HookResponse, error) {
	e.mu.RLock()
	hooks := e.hooks[tenantID]
	e.mu.RUnlock()

	merged := &HookResponse{
		Allow:  true,
		Enrich: make(map[string]interface{}),
	}

	payload := HookPayload{
		Trigger:   trigger,
		TenantID:  tenantID,
		Timestamp: time.Now().UTC(),
		Data:      data,
		RequestID: requestIDFromContext(ctx),
	}

	for _, hook := range hooks {
		if hook.Trigger != trigger {
			continue
		}
		if !hook.Enabled {
			continue
		}

		e.mu.RLock()
		cb := e.circuitBreakers[hook.ID]
		e.mu.RUnlock()

		if cb != nil && !cb.Allow() {
			e.logger.Warn("hooks: circuit breaker open, skipping hook",
				zap.String("hook_id", hook.ID),
				zap.String("hook_name", hook.Name),
			)
			continue
		}

		if hook.Async {
			go e.callHookAsync(hook, payload) //nolint:gosec // async hooks intentionally use a detached context
			continue
		}

		resp, err := e.callHookSync(ctx, hook, payload)
		if err != nil {
			// Fail-open: log and continue to next hook.
			e.logger.Warn("hooks: sync hook call failed, failing open",
				zap.String("hook_id", hook.ID),
				zap.Error(err),
			)
			if cb != nil {
				cb.RecordFailure()
			}
			continue
		}

		if cb != nil {
			cb.RecordSuccess()
		}

		// Merge enrichment data.
		for k, v := range resp.Enrich {
			merged.Enrich[k] = v
		}

		// A denial short-circuits remaining hooks.
		if !resp.Allow {
			merged.Allow = false
			merged.Message = resp.Message
			return merged, nil
		}
	}

	return merged, nil
}

// signPayload computes HMAC-SHA256 of payload using secret and returns the hex
// digest. Returns an empty string when secret is empty.
func (e *HookEngine) signPayload(payload []byte, secret string) string {
	if secret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// callHookSync sends the payload to hook.URL and waits up to hook.TimeoutMs
// for a response. It returns a fail-open HookResponse on timeout or transport
// error. A non-2xx HTTP status is treated as a failure (circuit breaker tick)
// and the engine fails open.
func (e *HookEngine) callHookSync(ctx context.Context, hook HookConfig, payload HookPayload) (*HookResponse, error) {
	timeoutMs := hook.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = defaultTimeoutMs
	}

	deadline := time.Duration(timeoutMs) * time.Millisecond
	callCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("hooks: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, hook.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("hooks: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if sig := e.signPayload(body, hook.Secret); sig != "" {
		req.Header.Set("X-Hook-Signature", sig)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		// Covers context deadline exceeded and transport errors.
		return nil, fmt.Errorf("hooks: http call to %q: %w", hook.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("hooks: hook %q returned status %d", hook.ID, resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("hooks: read response body: %w", err)
	}

	var hookResp HookResponse
	if err := json.Unmarshal(respBody, &hookResp); err != nil {
		return nil, fmt.Errorf("hooks: unmarshal response: %w", err)
	}

	return &hookResp, nil
}

// callHookAsync fires the hook in a background goroutine. Any error is logged
// but not propagated to the caller. It also maintains the circuit breaker.
func (e *HookEngine) callHookAsync(hook HookConfig, payload HookPayload) {
	body, err := json.Marshal(payload)
	if err != nil {
		e.logger.Error("hooks: async marshal payload", zap.String("hook_id", hook.ID), zap.Error(err))
		return
	}

	// Use a background context so cancellation of the original request does not
	// abort the async delivery.
	callCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, hook.URL, bytes.NewReader(body))
	if err != nil {
		e.logger.Error("hooks: async create request", zap.String("hook_id", hook.ID), zap.Error(err))
		return
	}
	req.Header.Set("Content-Type", "application/json")

	if sig := e.signPayload(body, hook.Secret); sig != "" {
		req.Header.Set("X-Hook-Signature", sig)
	}

	e.mu.RLock()
	cb := e.circuitBreakers[hook.ID]
	e.mu.RUnlock()

	resp, err := e.client.Do(req)
	if err != nil {
		e.logger.Warn("hooks: async hook call failed",
			zap.String("hook_id", hook.ID),
			zap.Error(err),
		)
		if cb != nil {
			cb.RecordFailure()
		}
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if cb != nil {
			cb.RecordSuccess()
		}
	} else {
		e.logger.Warn("hooks: async hook returned non-2xx",
			zap.String("hook_id", hook.ID),
			zap.Int("status", resp.StatusCode),
		)
		if cb != nil {
			cb.RecordFailure()
		}
	}
}

// requestIDFromContext extracts a request ID from the context if one was stored
// under the conventional key. Returns an empty string when not present.
func requestIDFromContext(ctx context.Context) string {
	if v := ctx.Value(requestIDKey{}); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// requestIDKey is the unexported context key used to store a request ID.
type requestIDKey struct{}

// ContextWithRequestID returns a child context that carries the supplied
// request ID, readable by requestIDFromContext.
func ContextWithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, requestID)
}
