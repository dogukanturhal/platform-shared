// SPDX-License-Identifier: Apache-2.0

// Package httpclient provides a resilient HTTP client with circuit breaker
// and retry patterns for service-to-service communication.
package httpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// CircuitState represents the current state of the circuit breaker
type CircuitState int

const (
	// StateClosed - circuit is closed, requests flow normally
	StateClosed CircuitState = iota
	// StateOpen - circuit is open, requests are rejected
	StateOpen
	// StateHalfOpen - circuit is testing if the service has recovered
	StateHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreakerConfig holds configuration for the circuit breaker
type CircuitBreakerConfig struct {
	// MaxFailures is the number of failures before opening the circuit
	MaxFailures int
	// Timeout is how long to wait before trying again (half-open state)
	Timeout time.Duration
	// HalfOpenMaxRequests is the max requests allowed in half-open state
	HalfOpenMaxRequests int
}

// DefaultCircuitBreakerConfig returns sensible defaults
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		MaxFailures:         5,
		Timeout:             30 * time.Second,
		HalfOpenMaxRequests: 3,
	}
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	config     CircuitBreakerConfig
	state      CircuitState
	failures   int
	successes  int
	lastFailed time.Time
	mu         sync.RWMutex
	logger     *zap.Logger
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config CircuitBreakerConfig, logger *zap.Logger) *CircuitBreaker {
	return &CircuitBreaker{
		config: config,
		state:  StateClosed,
		logger: logger,
	}
}

// Allow checks if a request is allowed through
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		// Check if timeout has passed
		if time.Since(cb.lastFailed) > cb.config.Timeout {
			cb.state = StateHalfOpen
			cb.successes = 0
			cb.logger.Info("circuit breaker transitioning to half-open")
			return true
		}
		return false
	case StateHalfOpen:
		return cb.successes < cb.config.HalfOpenMaxRequests
	default:
		return false
	}
}

// RecordSuccess records a successful request
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateHalfOpen:
		cb.successes++
		if cb.successes >= cb.config.HalfOpenMaxRequests {
			cb.state = StateClosed
			cb.failures = 0
			cb.logger.Info("circuit breaker closed after successful recovery")
		}
	case StateClosed:
		cb.failures = 0
	}
}

// RecordFailure records a failed request
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		cb.failures++
		if cb.failures >= cb.config.MaxFailures {
			cb.state = StateOpen
			cb.lastFailed = time.Now()
			cb.logger.Warn("circuit breaker opened due to failures",
				zap.Int("failures", cb.failures))
		}
	case StateHalfOpen:
		cb.state = StateOpen
		cb.lastFailed = time.Now()
		cb.logger.Warn("circuit breaker reopened after half-open failure")
	}
}

// State returns the current circuit state
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// RetryConfig holds configuration for retry behavior
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts
	MaxRetries int
	// InitialBackoff is the initial backoff duration
	InitialBackoff time.Duration
	// MaxBackoff is the maximum backoff duration
	MaxBackoff time.Duration
	// BackoffMultiplier is the multiplier for exponential backoff
	BackoffMultiplier float64
	// RetryableStatusCodes are HTTP status codes that should be retried
	RetryableStatusCodes []int
}

// DefaultRetryConfig returns sensible defaults
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:           3,
		InitialBackoff:       100 * time.Millisecond,
		MaxBackoff:           5 * time.Second,
		BackoffMultiplier:    2.0,
		RetryableStatusCodes: []int{408, 429, 500, 502, 503, 504},
	}
}

// Config holds the full client configuration
type Config struct {
	// BaseURL is the base URL for all requests
	BaseURL string
	// Timeout is the request timeout
	Timeout time.Duration
	// CircuitBreaker config
	CircuitBreaker CircuitBreakerConfig
	// Retry config
	Retry RetryConfig
	// Headers to include in all requests
	DefaultHeaders map[string]string
}

// DefaultConfig returns sensible default configuration
func DefaultConfig(baseURL string) *Config {
	return &Config{
		BaseURL:        baseURL,
		Timeout:        30 * time.Second,
		CircuitBreaker: DefaultCircuitBreakerConfig(),
		Retry:          DefaultRetryConfig(),
		DefaultHeaders: make(map[string]string),
	}
}

// Client is a resilient HTTP client with circuit breaker and retry
type Client struct {
	config         *Config
	httpClient     *http.Client
	circuitBreaker *CircuitBreaker
	logger         *zap.Logger
}

// NewClient creates a new resilient HTTP client
func NewClient(config *Config, logger *zap.Logger) *Client {
	return &Client{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		circuitBreaker: NewCircuitBreaker(config.CircuitBreaker, logger),
		logger:         logger,
	}
}

// ErrCircuitOpen is returned when the circuit breaker is open
var ErrCircuitOpen = fmt.Errorf("circuit breaker is open")

// Request performs an HTTP request with circuit breaker and retry
func (c *Client) Request(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	// Check circuit breaker
	if !c.circuitBreaker.Allow() {
		c.logger.Warn("request rejected by circuit breaker",
			zap.String("method", method),
			zap.String("path", path))
		return ErrCircuitOpen
	}

	// Prepare request body
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	url := c.config.BaseURL + path

	// Execute with retry
	var lastErr error
	backoff := c.config.Retry.InitialBackoff

	for attempt := 0; attempt <= c.config.Retry.MaxRetries; attempt++ {
		if attempt > 0 {
			c.logger.Debug("retrying request",
				zap.Int("attempt", attempt),
				zap.Duration("backoff", backoff))

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}

			// Increase backoff for next attempt
			backoff = time.Duration(float64(backoff) * c.config.Retry.BackoffMultiplier)
			if backoff > c.config.Retry.MaxBackoff {
				backoff = c.config.Retry.MaxBackoff
			}

			// Reset body reader for retry
			if body != nil {
				jsonBody, _ := json.Marshal(body)
				reqBody = bytes.NewBuffer(jsonBody)
			}
		}

		req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		// Set headers
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		for k, v := range c.config.DefaultHeaders {
			req.Header.Set(k, v)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			c.circuitBreaker.RecordFailure()
			continue
		}
		defer func() { _ = resp.Body.Close() }()

		// Check if status code is retryable
		if c.isRetryable(resp.StatusCode) {
			lastErr = fmt.Errorf("received retryable status code: %d", resp.StatusCode)
			c.circuitBreaker.RecordFailure()
			continue
		}

		// Check for success
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			c.circuitBreaker.RecordSuccess()

			if result != nil {
				if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
					return fmt.Errorf("failed to decode response: %w", err)
				}
			}
			return nil
		}

		// Non-retryable error
		c.circuitBreaker.RecordFailure()
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return fmt.Errorf("request failed after %d attempts: %w", c.config.Retry.MaxRetries+1, lastErr)
}

func (c *Client) isRetryable(statusCode int) bool {
	for _, code := range c.config.Retry.RetryableStatusCodes {
		if statusCode == code {
			return true
		}
	}
	return false
}

// Get performs a GET request
func (c *Client) Get(ctx context.Context, path string, result interface{}) error {
	return c.Request(ctx, http.MethodGet, path, nil, result)
}

// Post performs a POST request
func (c *Client) Post(ctx context.Context, path string, body interface{}, result interface{}) error {
	return c.Request(ctx, http.MethodPost, path, body, result)
}

// Put performs a PUT request
func (c *Client) Put(ctx context.Context, path string, body interface{}, result interface{}) error {
	return c.Request(ctx, http.MethodPut, path, body, result)
}

// Delete performs a DELETE request
func (c *Client) Delete(ctx context.Context, path string, result interface{}) error {
	return c.Request(ctx, http.MethodDelete, path, nil, result)
}

// Patch performs a PATCH request
func (c *Client) Patch(ctx context.Context, path string, body interface{}, result interface{}) error {
	return c.Request(ctx, http.MethodPatch, path, body, result)
}

// WithHeader creates a new client with an additional default header
func (c *Client) WithHeader(key, value string) *Client {
	newConfig := *c.config
	newConfig.DefaultHeaders = make(map[string]string)
	for k, v := range c.config.DefaultHeaders {
		newConfig.DefaultHeaders[k] = v
	}
	newConfig.DefaultHeaders[key] = value

	return &Client{
		config:         &newConfig,
		httpClient:     c.httpClient,
		circuitBreaker: c.circuitBreaker,
		logger:         c.logger,
	}
}

// WithAuthToken creates a new client with a Bearer token
func (c *Client) WithAuthToken(token string) *Client {
	return c.WithHeader("Authorization", "Bearer "+token)
}

// CircuitState returns the current circuit breaker state
func (c *Client) CircuitState() CircuitState {
	return c.circuitBreaker.State()
}
