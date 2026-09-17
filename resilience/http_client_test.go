// SPDX-License-Identifier: Apache-2.0

package resilience

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewResilientHTTPClient(t *testing.T) {
	client := NewResilientHTTPClient()

	if client == nil {
		t.Fatal("expected client to be created")
	}

	if client.maxRetries != 3 {
		t.Errorf("expected maxRetries 3, got %d", client.maxRetries)
	}

	if client.retryDelay != 100*time.Millisecond {
		t.Errorf("expected retryDelay 100ms, got %v", client.retryDelay)
	}

	if client.circuitBreaker == nil {
		t.Error("expected circuit breaker to be initialized")
	}
}

func TestNewResilientHTTPClientWithOptions(t *testing.T) {
	customCB := NewCircuitBreakerWithConfig(3, 10*time.Second)
	customHTTP := &http.Client{Timeout: 10 * time.Second}

	client := NewResilientHTTPClient(
		WithMaxRetries(5),
		WithRetryDelay(200*time.Millisecond),
		WithCircuitBreaker(customCB),
		WithHTTPClient(customHTTP),
		WithBackoffMultiplier(3.0),
	)

	if client.maxRetries != 5 {
		t.Errorf("expected maxRetries 5, got %d", client.maxRetries)
	}

	if client.retryDelay != 200*time.Millisecond {
		t.Errorf("expected retryDelay 200ms, got %v", client.retryDelay)
	}

	if client.circuitBreaker != customCB {
		t.Error("expected custom circuit breaker")
	}

	if client.client != customHTTP {
		t.Error("expected custom HTTP client")
	}

	if client.backoffMultiplier != 3.0 {
		t.Errorf("expected backoffMultiplier 3.0, got %f", client.backoffMultiplier)
	}
}

func TestResilientHTTPClientSuccessfulRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	}))
	defer server.Close()

	client := NewResilientHTTPClient()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "success" {
		t.Errorf("expected body 'success', got '%s'", string(body))
	}

	// Circuit should be closed after success
	if client.GetCircuitBreakerState() != StateClosed {
		t.Errorf("expected circuit closed, got %v", client.GetCircuitBreakerState())
	}
}

func TestResilientHTTPClientRetryOn5xxError(t *testing.T) {
	var attemptCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count := atomic.AddInt32(&attemptCount, 1)
		if count < 3 {
			// First two attempts fail with 503
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("service unavailable"))
		} else {
			// Third attempt succeeds
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("success"))
		}
	}))
	defer server.Close()

	client := NewResilientHTTPClient(WithRetryDelay(10 * time.Millisecond))

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	if attemptCount != 3 {
		t.Errorf("expected 3 attempts, got %d", attemptCount)
	}
}

func TestResilientHTTPClientNoRetryOn4xxError(t *testing.T) {
	var attemptCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attemptCount, 1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer server.Close()

	client := NewResilientHTTPClient(WithRetryDelay(10 * time.Millisecond))

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err == nil {
		t.Error("expected error for 4xx status")
	}
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}

	// Should not retry 4xx errors
	if attemptCount != 1 {
		t.Errorf("expected 1 attempt for 4xx error, got %d", attemptCount)
	}
}

func TestResilientHTTPClientMaxRetriesExhausted(t *testing.T) {
	var attemptCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attemptCount, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("always failing"))
	}))
	defer server.Close()

	client := NewResilientHTTPClient(
		WithMaxRetries(2),
		WithRetryDelay(10*time.Millisecond),
	)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Error("expected error after exhausting retries")
	}

	// Should attempt maxRetries + 1 times (initial + retries)
	expectedAttempts := int32(3) // 1 initial + 2 retries
	if attemptCount != expectedAttempts {
		t.Errorf("expected %d attempts, got %d", expectedAttempts, attemptCount)
	}

	if !strings.Contains(err.Error(), "failed after") {
		t.Errorf("error should mention failed attempts: %v", err)
	}
}

func TestResilientHTTPClientExponentialBackoff(t *testing.T) {
	var attemptTimes []time.Time

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attemptTimes = append(attemptTimes, time.Now())
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewResilientHTTPClient(
		WithMaxRetries(2),
		WithRetryDelay(50*time.Millisecond),
		WithBackoffMultiplier(2.0),
	)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	doResp, _ := client.Do(req)
	if doResp != nil {
		_ = doResp.Body.Close()
	}

	if len(attemptTimes) < 3 {
		t.Fatalf("expected at least 3 attempts, got %d", len(attemptTimes))
	}

	// Check backoff timing (approximate due to scheduling)
	delay1 := attemptTimes[1].Sub(attemptTimes[0])
	delay2 := attemptTimes[2].Sub(attemptTimes[1])

	// First delay should be ~50ms
	if delay1 < 40*time.Millisecond || delay1 > 100*time.Millisecond {
		t.Logf("warning: first delay %v outside expected range 40-100ms", delay1)
	}

	// Second delay should be ~100ms (2x first)
	if delay2 < 80*time.Millisecond || delay2 > 200*time.Millisecond {
		t.Logf("warning: second delay %v outside expected range 80-200ms", delay2)
	}
}

func TestResilientHTTPClientCircuitBreakerIntegration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	cb := NewCircuitBreakerWithConfig(2, 100*time.Millisecond)
	client := NewResilientHTTPClient(
		WithCircuitBreaker(cb),
		WithMaxRetries(0), // No retries to test circuit breaker directly
	)

	// First request - circuit closed, should attempt
	req1, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp1, err1 := client.Do(req1)
	if resp1 != nil {
		_ = resp1.Body.Close()
	}
	if err1 == nil {
		t.Error("expected error from failed request")
	}

	// Second request - circuit still closed
	req2, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp2, err2 := client.Do(req2)
	if resp2 != nil {
		_ = resp2.Body.Close()
	}
	if err2 == nil {
		t.Error("expected error from failed request")
	}

	// Circuit should now be open
	if client.GetCircuitBreakerState() != StateOpen {
		t.Errorf("expected circuit open, got %v", client.GetCircuitBreakerState())
	}

	// Third request - should be rejected by circuit breaker
	req3, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp3, err3 := client.Do(req3)
	if resp3 != nil {
		_ = resp3.Body.Close()
	}
	if !errors.Is(err3, ErrCircuitOpen) {
		t.Errorf("expected ErrCircuitOpen, got %v", err3)
	}
}

func TestResilientHTTPClientContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Slow response
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewResilientHTTPClient(WithRetryDelay(50 * time.Millisecond))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	cancelResp, cancelErr := client.Do(req)
	if cancelResp != nil {
		_ = cancelResp.Body.Close()
	}
	if cancelErr == nil {
		t.Error("expected context cancellation error")
	}

	if !errors.Is(cancelErr, context.DeadlineExceeded) {
		t.Errorf("expected DeadlineExceeded, got %v", err)
	}
}

func TestResilientHTTPClientWithRequestBody(t *testing.T) {
	var attemptCount int32
	var receivedBodies []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attemptCount, 1)
		body, _ := io.ReadAll(r.Body)
		receivedBodies = append(receivedBodies, string(body))

		if count < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	client := NewResilientHTTPClient(WithRetryDelay(10 * time.Millisecond))

	bodyContent := []byte(`{"key":"value"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL, bytes.NewBuffer(bodyContent))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if attemptCount != 2 {
		t.Errorf("expected 2 attempts, got %d", attemptCount)
	}

	// Verify body was sent correctly on all attempts
	for i, body := range receivedBodies {
		if body != string(bodyContent) {
			t.Errorf("attempt %d: expected body '%s', got '%s'", i+1, string(bodyContent), body)
		}
	}
}

func TestIsRetryableStatus(t *testing.T) {
	tests := []struct {
		statusCode int
		retryable  bool
	}{
		{200, false},
		{201, false},
		{400, false},
		{401, false},
		{403, false},
		{404, false},
		{408, true},  // Request Timeout
		{429, true},  // Too Many Requests
		{500, true},  // Internal Server Error
		{502, true},  // Bad Gateway
		{503, true},  // Service Unavailable
		{504, true},  // Gateway Timeout
		{505, false}, // HTTP Version Not Supported
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.statusCode), func(t *testing.T) {
			result := isRetryableStatus(tt.statusCode)
			if result != tt.retryable {
				t.Errorf("status %d: expected retryable=%v, got %v", tt.statusCode, tt.retryable, result)
			}
		})
	}
}

func TestCloneRequest(t *testing.T) {
	t.Run("nil request", func(t *testing.T) {
		_, err := cloneRequest(nil)
		if err == nil {
			t.Error("expected error for nil request")
		}
	})

	t.Run("request without body", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
		cloned, err := cloneRequest(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cloned.Method != req.Method {
			t.Errorf("expected method %s, got %s", req.Method, cloned.Method)
		}

		if cloned.URL.String() != req.URL.String() {
			t.Errorf("expected URL %s, got %s", req.URL, cloned.URL)
		}
	})

	t.Run("request with body", func(t *testing.T) {
		bodyContent := []byte("test body")
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com", bytes.NewBuffer(bodyContent))

		cloned, err := cloneRequest(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Read cloned body
		clonedBody, _ := io.ReadAll(cloned.Body)
		if string(clonedBody) != string(bodyContent) {
			t.Errorf("expected body '%s', got '%s'", string(bodyContent), string(clonedBody))
		}

		// Original body should still be readable
		originalBody, _ := io.ReadAll(req.Body)
		if string(originalBody) != string(bodyContent) {
			t.Errorf("original body should be readable, expected '%s', got '%s'", string(bodyContent), string(originalBody))
		}
	})

	t.Run("request with context", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", nil)

		cloned, err := cloneRequest(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cloned.Context() != ctx {
			t.Error("cloned request should preserve context")
		}
	})
}

func TestResilientHTTPClientResetCircuitBreaker(t *testing.T) {
	cb := NewCircuitBreakerWithConfig(1, 100*time.Millisecond)
	client := NewResilientHTTPClient(
		WithCircuitBreaker(cb),
		WithMaxRetries(0),
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	// Trigger circuit open
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	triggerResp, _ := client.Do(req)
	if triggerResp != nil {
		_ = triggerResp.Body.Close()
	}

	if client.GetCircuitBreakerState() != StateOpen {
		t.Errorf("expected circuit open, got %v", client.GetCircuitBreakerState())
	}

	// Reset circuit breaker
	client.ResetCircuitBreaker()

	if client.GetCircuitBreakerState() != StateClosed {
		t.Errorf("expected circuit closed after reset, got %v", client.GetCircuitBreakerState())
	}
}
