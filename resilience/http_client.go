// SPDX-License-Identifier: Apache-2.0

package resilience

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"
)

// ResilientHTTPClient wraps an HTTP client with circuit breaker and retry logic
type ResilientHTTPClient struct {
	client            *http.Client
	circuitBreaker    *CircuitBreaker
	maxRetries        int
	retryDelay        time.Duration
	backoffMultiplier float64
}

// Option is a functional option for configuring ResilientHTTPClient
type Option func(*ResilientHTTPClient)

// WithMaxRetries sets the maximum number of retry attempts
func WithMaxRetries(n int) Option {
	return func(c *ResilientHTTPClient) {
		if n >= 0 {
			c.maxRetries = n
		}
	}
}

// WithRetryDelay sets the initial retry delay (exponential backoff)
func WithRetryDelay(d time.Duration) Option {
	return func(c *ResilientHTTPClient) {
		if d > 0 {
			c.retryDelay = d
		}
	}
}

// WithCircuitBreaker sets a custom circuit breaker
func WithCircuitBreaker(cb *CircuitBreaker) Option {
	return func(c *ResilientHTTPClient) {
		if cb != nil {
			c.circuitBreaker = cb
		}
	}
}

// WithHTTPClient sets a custom underlying HTTP client
func WithHTTPClient(client *http.Client) Option {
	return func(c *ResilientHTTPClient) {
		if client != nil {
			c.client = client
		}
	}
}

// WithBackoffMultiplier sets the exponential backoff multiplier
func WithBackoffMultiplier(multiplier float64) Option {
	return func(c *ResilientHTTPClient) {
		if multiplier > 0 {
			c.backoffMultiplier = multiplier
		}
	}
}

// NewResilientHTTPClient creates a new resilient HTTP client with default settings
func NewResilientHTTPClient(opts ...Option) *ResilientHTTPClient {
	client := &ResilientHTTPClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		circuitBreaker:    NewCircuitBreaker(),
		maxRetries:        3,
		retryDelay:        100 * time.Millisecond,
		backoffMultiplier: 2.0,
	}

	// Apply options
	for _, opt := range opts {
		opt(client)
	}

	return client
}

// Do executes an HTTP request with retry logic and circuit breaker protection
func (c *ResilientHTTPClient) Do(req *http.Request) (*http.Response, error) {
	// Check circuit breaker before attempting request
	if !c.circuitBreaker.Allow() {
		return nil, ErrCircuitOpen
	}

	var lastErr error
	currentDelay := c.retryDelay

	// Attempt request with retries
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		// Clone request for retry (body needs to be re-readable)
		clonedReq, err := cloneRequest(req)
		if err != nil {
			return nil, fmt.Errorf("failed to clone request: %w", err)
		}

		// Execute request
		resp, err := c.executeRequest(clonedReq)

		// Success case (2xx status codes)
		if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			c.circuitBreaker.RecordSuccess()
			return resp, nil
		}

		// Record failure
		c.circuitBreaker.RecordFailure()

		// Determine if we should retry
		if err != nil {
			lastErr = err
		} else if resp != nil {
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
			// Close response body before retry
			if resp.Body != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}

		// Don't retry 4xx errors (client errors) - return immediately
		if resp != nil && resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return resp, lastErr
		}

		// Check if we've exhausted retries
		if attempt >= c.maxRetries {
			break
		}

		// Wait before retry with exponential backoff + jitter (full jitter strategy)
		// Prevents thundering herd when multiple clients retry simultaneously
		jitter := time.Duration(rand.Int63n(int64(currentDelay))) //nolint:gosec // jitter doesn't require cryptographic randomness
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(jitter):
			currentDelay = time.Duration(float64(currentDelay) * c.backoffMultiplier)
		}
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", c.maxRetries+1, lastErr)
}

// executeRequest performs the actual HTTP request
func (c *ResilientHTTPClient) executeRequest(req *http.Request) (*http.Response, error) {
	return c.client.Do(req) //nolint:gosec // request URL is caller-provided and validated upstream
}

// isRetryableStatus checks if an HTTP status code should trigger a retry
func isRetryableStatus(statusCode int) bool {
	// Retry on 5xx server errors and specific 4xx errors
	switch statusCode {
	case http.StatusRequestTimeout, // 408
		http.StatusTooManyRequests,     // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout:      // 504
		return true
	default:
		return false
	}
}

// cloneRequest creates a copy of the HTTP request with a re-readable body
func cloneRequest(req *http.Request) (*http.Request, error) {
	if req == nil {
		return nil, errors.New("request is nil")
	}

	// Create new request with same context
	ctx := req.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Clone basic request
	cloned := req.Clone(ctx)

	// Handle request body for retries
	if req.Body != nil {
		// Read body content
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}

		// Reset original request body
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// Set cloned request body
		cloned.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		cloned.ContentLength = int64(len(bodyBytes))
	}

	return cloned, nil
}

// GetCircuitBreakerState returns the current circuit breaker state
func (c *ResilientHTTPClient) GetCircuitBreakerState() State {
	return c.circuitBreaker.GetState()
}

// ResetCircuitBreaker resets the circuit breaker to closed state
func (c *ResilientHTTPClient) ResetCircuitBreaker() {
	c.circuitBreaker.Reset()
}
