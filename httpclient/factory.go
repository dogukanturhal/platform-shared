// SPDX-License-Identifier: Apache-2.0

// Package httpclient provides a resilient HTTP client factory with circuit breaker,
// retry patterns, and configurable timeouts for service-to-service communication.
package httpclient

import (
	"net/http"
	"time"

	"go.uber.org/zap"
)

// Common timeout constants for different service communication patterns.
const (
	// DatabaseTimeout is the timeout for operations that interact with databases
	// through other services.
	DatabaseTimeout = 5 * time.Second

	// InternalServiceTimeout is the timeout for internal service-to-service calls.
	InternalServiceTimeout = 10 * time.Second

	// ExternalAPITimeout is the timeout for calls to external third-party APIs.
	ExternalAPITimeout = 15 * time.Second

	// FileUploadTimeout is the timeout for file upload operations that may
	// transfer larger payloads.
	FileUploadTimeout = 60 * time.Second
)

// ClientOption is a functional option for configuring a ServiceClient.
type ClientOption func(*serviceClientConfig)

// serviceClientConfig holds the configuration built by functional options.
type serviceClientConfig struct {
	timeout        time.Duration
	maxRetries     *int
	circuitBreaker *CircuitBreakerConfig
	defaultHeaders map[string]string
}

// WithTimeout sets the HTTP request timeout for the client.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *serviceClientConfig) {
		c.timeout = timeout
	}
}

// WithMaxRetries sets the maximum number of retry attempts.
func WithMaxRetries(retries int) ClientOption {
	return func(c *serviceClientConfig) {
		c.maxRetries = &retries
	}
}

// WithCircuitBreaker configures the circuit breaker with custom settings.
func WithCircuitBreaker(maxFailures int, timeout time.Duration) ClientOption {
	return func(c *serviceClientConfig) {
		c.circuitBreaker = &CircuitBreakerConfig{
			MaxFailures:         maxFailures,
			Timeout:             timeout,
			HalfOpenMaxRequests: 3,
		}
	}
}

// WithDefaultHeader adds a default header to all requests made by the client.
func WithDefaultHeader(key, value string) ClientOption {
	return func(c *serviceClientConfig) {
		if c.defaultHeaders == nil {
			c.defaultHeaders = make(map[string]string)
		}
		c.defaultHeaders[key] = value
	}
}

// ServiceClient wraps the resilient Client and provides service-specific
// context such as the originating service name. It exposes both the high-level
// resilient API (Get, Post, Put, Delete, Patch) and a raw *http.Client for
// services that need to build custom requests.
type ServiceClient struct {
	// Client is the underlying resilient HTTP client with circuit breaker and retry.
	*Client

	// ServiceName identifies the calling service for logging and tracing.
	ServiceName string

	// HTTPClient exposes a raw *http.Client configured with the same timeout
	// as the resilient client. Use this when you need to build custom HTTP
	// requests with service-specific headers or non-JSON bodies.
	HTTPClient *http.Client
}

// NewServiceClient creates a new ServiceClient for the given service. It builds
// on top of the existing resilient Client, applying the provided functional options.
//
// If no timeout is specified, InternalServiceTimeout (10s) is used as the default.
//
// Example:
//
//	client := httpclient.NewServiceClient(
//	    "billing",
//	    "http://payment-gateway:8080",
//	    logger,
//	    httpclient.WithTimeout(httpclient.ExternalAPITimeout),
//	    httpclient.WithMaxRetries(5),
//	)
func NewServiceClient(serviceName, baseURL string, logger *zap.Logger, opts ...ClientOption) *ServiceClient {
	cfg := &serviceClientConfig{
		timeout: InternalServiceTimeout,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	// Build the underlying Config from defaults, then apply overrides.
	config := DefaultConfig(baseURL)
	config.Timeout = cfg.timeout

	if cfg.maxRetries != nil {
		config.Retry.MaxRetries = *cfg.maxRetries
	}

	if cfg.circuitBreaker != nil {
		config.CircuitBreaker = *cfg.circuitBreaker
	}

	// Merge default headers.
	if cfg.defaultHeaders != nil {
		for k, v := range cfg.defaultHeaders {
			config.DefaultHeaders[k] = v
		}
	}

	// Always include the service name header so downstream services can
	// identify the caller.
	config.DefaultHeaders["X-Service-Name"] = serviceName

	namedLogger := logger.With(zap.String("service_client", serviceName))

	resilientClient := NewClient(config, namedLogger)

	return &ServiceClient{
		Client:      resilientClient,
		ServiceName: serviceName,
		HTTPClient: &http.Client{
			Timeout: cfg.timeout,
		},
	}
}
