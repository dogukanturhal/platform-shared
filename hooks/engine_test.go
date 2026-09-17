// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestEngine creates a HookEngine backed by the supplied http.Client and a
// no-op zap logger so tests do not produce log noise.
func newTestEngine(t *testing.T, client *http.Client) *HookEngine {
	t.Helper()
	logger := zap.NewNop()
	return NewHookEngineWithClient(logger, client)
}

// allowServer returns an httptest.Server that always responds with allow=true.
func allowServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(HookResponse{Allow: true})
	}))
}

// denyServer returns an httptest.Server that always responds with allow=false
// and the supplied message.
func denyServer(t *testing.T, message string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(HookResponse{Allow: false, Message: message})
	}))
}

// makeHook returns a default HookConfig pointing at url.
func makeHook(id string, url string, trigger TriggerType) HookConfig {
	tenantID := "tenant-1"
	return HookConfig{
		ID:        id,
		TenantID:  tenantID,
		Name:      id,
		URL:       url,
		Trigger:   trigger,
		Secret:    "test-secret",
		Enabled:   true,
		Async:     false,
		Priority:  0,
		TimeoutMs: 3000,
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestHookEngine_NoHooks_ReturnsAllow(t *testing.T) {
	e := newTestEngine(t, &http.Client{})

	resp, err := e.Execute(context.Background(), TriggerPreLogin, "tenant-1", nil)

	require.NoError(t, err)
	assert.True(t, resp.Allow, "no hooks registered must return allow=true")
}

func TestHookEngine_SyncHook_Allow(t *testing.T) {
	srv := allowServer(t)
	defer srv.Close()

	e := newTestEngine(t, srv.Client())
	hook := makeHook("h1", srv.URL, TriggerPreLogin)
	e.RegisterHooks("tenant-1", []HookConfig{hook})

	resp, err := e.Execute(context.Background(), TriggerPreLogin, "tenant-1", map[string]interface{}{"user_id": "u1"})

	require.NoError(t, err)
	assert.True(t, resp.Allow)
}

func TestHookEngine_SyncHook_Deny(t *testing.T) {
	srv := denyServer(t, "blocked by policy")
	defer srv.Close()

	e := newTestEngine(t, srv.Client())
	hook := makeHook("h1", srv.URL, TriggerPreLogin)
	e.RegisterHooks("tenant-1", []HookConfig{hook})

	resp, err := e.Execute(context.Background(), TriggerPreLogin, "tenant-1", nil)

	require.NoError(t, err)
	assert.False(t, resp.Allow)
	assert.Equal(t, "blocked by policy", resp.Message)
}

func TestHookEngine_AsyncHook_FireAndForget(t *testing.T) {
	// Channel receives the request body so the test can confirm delivery.
	received := make(chan []byte, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf [4096]byte
		n, _ := r.Body.Read(buf[:])
		received <- buf[:n]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := newTestEngine(t, srv.Client())
	hook := makeHook("h-async", srv.URL, TriggerPostLogin)
	hook.Async = true
	e.RegisterHooks("tenant-1", []HookConfig{hook})

	resp, err := e.Execute(context.Background(), TriggerPostLogin, "tenant-1", map[string]interface{}{"user_id": "u42"})

	require.NoError(t, err)
	assert.True(t, resp.Allow, "async hook must never deny")

	// Wait for the async goroutine to deliver the request.
	select {
	case body := <-received:
		var payload HookPayload
		require.NoError(t, json.Unmarshal(body, &payload))
		assert.Equal(t, TriggerPostLogin, payload.Trigger)
		assert.Equal(t, "tenant-1", payload.TenantID)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for async hook delivery")
	}
}

func TestHookEngine_Timeout_ReturnsAllow(t *testing.T) {
	// The handler blocks until Execute() times out and disconnects. We signal
	// the handler to unblock via a channel so the server can shut down promptly.
	unblock := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wait for either the client to disconnect or the test to signal us.
		select {
		case <-r.Context().Done():
		case <-unblock:
		}
		w.WriteHeader(http.StatusOK)
	}))
	// Close the server after the handler has been unblocked (see below).
	// We do NOT use defer here; we close it manually after signaling unblock.

	e := newTestEngine(t, srv.Client())
	hook := makeHook("h-timeout", srv.URL, TriggerPreLogin)
	hook.TimeoutMs = 100 // Very short timeout.
	e.RegisterHooks("tenant-1", []HookConfig{hook})

	start := time.Now()
	resp, err := e.Execute(context.Background(), TriggerPreLogin, "tenant-1", nil)

	// Unblock the handler so the server can close cleanly, then close it.
	close(unblock)
	srv.Close()

	require.NoError(t, err, "timeout must not surface as error to caller")
	assert.True(t, resp.Allow, "timeout must fail open (allow=true)")
	assert.Less(t, time.Since(start), 2*time.Second, "must return well before server timeout")
}

func TestHookEngine_HMACSignature_Correct(t *testing.T) {
	const secret = "super-secret"
	var capturedSig string
	var capturedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSig = r.Header.Get("X-Hook-Signature")
		var buf [4096]byte
		n, _ := r.Body.Read(buf[:])
		capturedBody = buf[:n]
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(HookResponse{Allow: true})
	}))
	defer srv.Close()

	e := newTestEngine(t, srv.Client())
	hook := makeHook("h-sig", srv.URL, TriggerPreLogin)
	hook.Secret = secret
	e.RegisterHooks("tenant-1", []HookConfig{hook})

	_, err := e.Execute(context.Background(), TriggerPreLogin, "tenant-1", nil)
	require.NoError(t, err)

	// Compute expected HMAC.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(capturedBody)
	expected := hex.EncodeToString(mac.Sum(nil))

	assert.Equal(t, expected, capturedSig, "X-Hook-Signature must be HMAC-SHA256 of the raw request body")
}

func TestHookEngine_CircuitBreaker_TripsOnFailures(t *testing.T) {
	// Return HTTP 500 three times — enough to open the circuit.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	e := newTestEngine(t, srv.Client())
	hook := makeHook("h-cb", srv.URL, TriggerPreLogin)
	hook.TimeoutMs = 500
	e.RegisterHooks("tenant-1", []HookConfig{hook})

	// Execute circuitMaxFailures times to open the circuit.
	for i := 0; i < circuitMaxFailures; i++ {
		resp, err := e.Execute(context.Background(), TriggerPreLogin, "tenant-1", nil)
		require.NoError(t, err)
		assert.True(t, resp.Allow, "failures must fail open")
	}

	// One more call — circuit is now open, server must NOT be contacted.
	callsBefore := calls.Load()
	resp, err := e.Execute(context.Background(), TriggerPreLogin, "tenant-1", nil)
	require.NoError(t, err)
	assert.True(t, resp.Allow)
	assert.Equal(t, callsBefore, calls.Load(), "open circuit must skip the HTTP call")
}

func TestHookEngine_CircuitBreaker_RecoverAfterTimeout(t *testing.T) {
	// First call fails, subsequent calls succeed. We manually manipulate the
	// circuit breaker to simulate the 60s window having elapsed.
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n <= int32(circuitMaxFailures) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(HookResponse{Allow: true})
	}))
	defer srv.Close()

	e := newTestEngine(t, srv.Client())
	hook := makeHook("h-recover", srv.URL, TriggerPreLogin)
	hook.TimeoutMs = 500
	e.RegisterHooks("tenant-1", []HookConfig{hook})

	// Trip the circuit.
	for i := 0; i < circuitMaxFailures; i++ {
		e.Execute(context.Background(), TriggerPreLogin, "tenant-1", nil) //nolint:errcheck,gosec // test helper
	}

	// Simulate the recovery window having elapsed by back-dating openUntil.
	e.mu.RLock()
	cb := e.circuitBreakers["h-recover"]
	e.mu.RUnlock()
	require.NotNil(t, cb)

	cb.mu.Lock()
	cb.openUntil = time.Now().Add(-1 * time.Second) // already in the past
	cb.mu.Unlock()

	// Next call should probe through (circuit half-open → success → closed).
	resp, err := e.Execute(context.Background(), TriggerPreLogin, "tenant-1", nil)
	require.NoError(t, err)
	assert.True(t, resp.Allow, "circuit must recover and allow the call")
}

func TestHookEngine_PriorityOrdering(t *testing.T) {
	// Record which hook IDs are called in order.
	var mu sync.Mutex
	var order []string

	makeOrderServer := func(id string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			order = append(order, id)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(HookResponse{Allow: true})
		}))
	}

	srvLow := makeOrderServer("low")
	defer srvLow.Close()
	srvMid := makeOrderServer("mid")
	defer srvMid.Close()
	srvHigh := makeOrderServer("high")
	defer srvHigh.Close()

	e := newTestEngine(t, http.DefaultClient)

	// Register in reverse priority order to ensure engine sorts them.
	hooks := []HookConfig{
		{ID: "h-high", TenantID: "t1", Name: "high", URL: srvHigh.URL, Trigger: TriggerPreLogin, Enabled: true, Priority: 30, TimeoutMs: 2000},
		{ID: "h-low", TenantID: "t1", Name: "low", URL: srvLow.URL, Trigger: TriggerPreLogin, Enabled: true, Priority: 10, TimeoutMs: 2000},
		{ID: "h-mid", TenantID: "t1", Name: "mid", URL: srvMid.URL, Trigger: TriggerPreLogin, Enabled: true, Priority: 20, TimeoutMs: 2000},
	}
	e.RegisterHooks("t1", hooks)

	_, err := e.Execute(context.Background(), TriggerPreLogin, "t1", nil)
	require.NoError(t, err)

	mu.Lock()
	got := make([]string, len(order))
	copy(got, order)
	mu.Unlock()

	assert.Equal(t, []string{"low", "mid", "high"}, got, "hooks must execute in ascending priority order")
}

func TestHookEngine_DisabledHook_Skipped(t *testing.T) {
	var called atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Store(true)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(HookResponse{Allow: true})
	}))
	defer srv.Close()

	e := newTestEngine(t, srv.Client())
	hook := makeHook("h-disabled", srv.URL, TriggerPreLogin)
	hook.Enabled = false
	e.RegisterHooks("tenant-1", []HookConfig{hook})

	resp, err := e.Execute(context.Background(), TriggerPreLogin, "tenant-1", nil)
	require.NoError(t, err)
	assert.True(t, resp.Allow)
	assert.False(t, called.Load(), "disabled hook must not make an HTTP call")
}

func TestHookEngine_EnrichMergesData(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(HookResponse{
			Allow:  true,
			Enrich: map[string]interface{}{"claim_a": "value_a"},
		})
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(HookResponse{
			Allow:  true,
			Enrich: map[string]interface{}{"claim_b": 42},
		})
	}))
	defer srv2.Close()

	e := newTestEngine(t, http.DefaultClient)
	e.RegisterHooks("tenant-1", []HookConfig{
		{ID: "h1", TenantID: "tenant-1", Name: "h1", URL: srv1.URL, Trigger: TriggerPreTokenIssue, Enabled: true, Priority: 1, TimeoutMs: 2000},
		{ID: "h2", TenantID: "tenant-1", Name: "h2", URL: srv2.URL, Trigger: TriggerPreTokenIssue, Enabled: true, Priority: 2, TimeoutMs: 2000},
	})

	resp, err := e.Execute(context.Background(), TriggerPreTokenIssue, "tenant-1", nil)
	require.NoError(t, err)
	assert.True(t, resp.Allow)
	assert.Equal(t, "value_a", resp.Enrich["claim_a"])
	assert.Equal(t, 42.0, resp.Enrich["claim_b"]) // JSON numbers unmarshal as float64
}

func TestHookEngine_MultipleSyncHooks_StopsOnDeny(t *testing.T) {
	// Hook 1 (priority 1): allow.
	// Hook 2 (priority 2): deny.
	// Hook 3 (priority 3): must NOT be called.
	var thirdCalled atomic.Bool

	srv1 := allowServer(t)
	defer srv1.Close()

	srv2 := denyServer(t, "access denied at hook 2")
	defer srv2.Close()

	srv3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		thirdCalled.Store(true)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(HookResponse{Allow: true})
	}))
	defer srv3.Close()

	e := newTestEngine(t, http.DefaultClient)
	e.RegisterHooks("tenant-1", []HookConfig{
		{ID: "h1", TenantID: "tenant-1", Name: "h1", URL: srv1.URL, Trigger: TriggerPreLogin, Enabled: true, Priority: 1, TimeoutMs: 2000},
		{ID: "h2", TenantID: "tenant-1", Name: "h2", URL: srv2.URL, Trigger: TriggerPreLogin, Enabled: true, Priority: 2, TimeoutMs: 2000},
		{ID: "h3", TenantID: "tenant-1", Name: "h3", URL: srv3.URL, Trigger: TriggerPreLogin, Enabled: true, Priority: 3, TimeoutMs: 2000},
	})

	resp, err := e.Execute(context.Background(), TriggerPreLogin, "tenant-1", nil)
	require.NoError(t, err)
	assert.False(t, resp.Allow, "deny from hook 2 must propagate")
	assert.Equal(t, "access denied at hook 2", resp.Message)
	assert.False(t, thirdCalled.Load(), "hook 3 must not be called after denial")
}

func TestHookEngine_RegisterAndRemoveHooks(t *testing.T) {
	srv := allowServer(t)
	defer srv.Close()

	e := newTestEngine(t, srv.Client())
	hook := makeHook("h1", srv.URL, TriggerPreLogin)
	e.RegisterHooks("tenant-1", []HookConfig{hook})

	// Confirm hook is registered.
	e.mu.RLock()
	registered := len(e.hooks["tenant-1"])
	e.mu.RUnlock()
	assert.Equal(t, 1, registered)

	e.RemoveHooks("tenant-1")

	// Confirm hooks are gone.
	e.mu.RLock()
	removed := len(e.hooks["tenant-1"])
	e.mu.RUnlock()
	assert.Equal(t, 0, removed)

	// Execute must return allow=true after removal.
	resp, err := e.Execute(context.Background(), TriggerPreLogin, "tenant-1", nil)
	require.NoError(t, err)
	assert.True(t, resp.Allow)
}

func TestHookEngine_TriggerFiltering(t *testing.T) {
	// Register a hook for PostLogin but execute PreLogin — hook must not fire.
	var called atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Store(true)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(HookResponse{Allow: false, Message: "wrong trigger"})
	}))
	defer srv.Close()

	e := newTestEngine(t, srv.Client())
	hook := makeHook("h-post", srv.URL, TriggerPostLogin) // PostLogin only.
	e.RegisterHooks("tenant-1", []HookConfig{hook})

	resp, err := e.Execute(context.Background(), TriggerPreLogin, "tenant-1", nil)
	require.NoError(t, err)
	assert.True(t, resp.Allow, "hook for different trigger must not affect response")
	assert.False(t, called.Load(), "hook must not be called for mismatched trigger")
}

func TestHookEngine_ContextWithRequestID(t *testing.T) {
	var capturedRequestID string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload HookPayload
		json.NewDecoder(r.Body).Decode(&payload) //nolint:errcheck,gosec // test helper
		capturedRequestID = payload.RequestID
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(HookResponse{Allow: true})
	}))
	defer srv.Close()

	e := newTestEngine(t, srv.Client())
	hook := makeHook("h-reqid", srv.URL, TriggerPreLogin)
	e.RegisterHooks("tenant-1", []HookConfig{hook})

	ctx := ContextWithRequestID(context.Background(), "req-abc-123")
	_, err := e.Execute(ctx, TriggerPreLogin, "tenant-1", nil)
	require.NoError(t, err)
	assert.Equal(t, "req-abc-123", capturedRequestID, "request ID must be propagated in payload")
}
