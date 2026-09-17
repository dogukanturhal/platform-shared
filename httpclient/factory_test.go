// SPDX-License-Identifier: Apache-2.0

package httpclient

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestNewServiceClient_Defaults(t *testing.T) {
	logger, _ := zap.NewProduction()
	sc := NewServiceClient("test-service", "http://localhost:8080", logger)

	if sc == nil {
		t.Fatal("expected non-nil ServiceClient")
	}
	if sc.ServiceName != "test-service" {
		t.Errorf("expected ServiceName 'test-service', got %q", sc.ServiceName)
	}
	if sc.Client == nil {
		t.Fatal("expected non-nil embedded Client")
	}
	if sc.HTTPClient == nil {
		t.Fatal("expected non-nil HTTPClient")
	}
	if sc.HTTPClient.Timeout != InternalServiceTimeout {
		t.Errorf("expected default timeout %v, got %v", InternalServiceTimeout, sc.HTTPClient.Timeout)
	}
}

func TestNewServiceClient_WithTimeout(t *testing.T) {
	logger, _ := zap.NewProduction()
	sc := NewServiceClient(
		"test-service",
		"http://localhost:8080",
		logger,
		WithTimeout(ExternalAPITimeout),
	)

	if sc.HTTPClient.Timeout != ExternalAPITimeout {
		t.Errorf("expected timeout %v, got %v", ExternalAPITimeout, sc.HTTPClient.Timeout)
	}
}

func TestNewServiceClient_WithMaxRetries(t *testing.T) {
	logger, _ := zap.NewProduction()
	sc := NewServiceClient(
		"test-service",
		"http://localhost:8080",
		logger,
		WithMaxRetries(5),
	)

	if sc.config.Retry.MaxRetries != 5 {
		t.Errorf("expected MaxRetries 5, got %d", sc.config.Retry.MaxRetries)
	}
}

func TestNewServiceClient_WithCircuitBreaker(t *testing.T) {
	logger, _ := zap.NewProduction()
	sc := NewServiceClient(
		"test-service",
		"http://localhost:8080",
		logger,
		WithCircuitBreaker(10, 60*time.Second),
	)

	if sc.config.CircuitBreaker.MaxFailures != 10 {
		t.Errorf("expected MaxFailures 10, got %d", sc.config.CircuitBreaker.MaxFailures)
	}
	if sc.config.CircuitBreaker.Timeout != 60*time.Second {
		t.Errorf("expected circuit breaker timeout 60s, got %v", sc.config.CircuitBreaker.Timeout)
	}
}

func TestNewServiceClient_WithDefaultHeader(t *testing.T) {
	logger, _ := zap.NewProduction()
	sc := NewServiceClient(
		"test-service",
		"http://localhost:8080",
		logger,
		WithDefaultHeader("X-Custom-Header", "custom-value"),
	)

	headerVal, ok := sc.config.DefaultHeaders["X-Custom-Header"]
	if !ok {
		t.Fatal("expected X-Custom-Header to be set")
	}
	if headerVal != "custom-value" {
		t.Errorf("expected header value 'custom-value', got %q", headerVal)
	}
}

func TestNewServiceClient_ServiceNameHeader(t *testing.T) {
	logger, _ := zap.NewProduction()
	sc := NewServiceClient(
		"billing-service",
		"http://localhost:8080",
		logger,
	)

	headerVal, ok := sc.config.DefaultHeaders["X-Service-Name"]
	if !ok {
		t.Fatal("expected X-Service-Name header to be set automatically")
	}
	if headerVal != "billing-service" {
		t.Errorf("expected header value 'billing-service', got %q", headerVal)
	}
}

func TestNewServiceClient_MultipleOptions(t *testing.T) {
	logger, _ := zap.NewProduction()
	sc := NewServiceClient(
		"payment-gateway",
		"http://payment:8080",
		logger,
		WithTimeout(FileUploadTimeout),
		WithMaxRetries(5),
		WithCircuitBreaker(3, 15*time.Second),
		WithDefaultHeader("X-API-Key", "secret"),
	)

	if sc.HTTPClient.Timeout != FileUploadTimeout {
		t.Errorf("expected timeout %v, got %v", FileUploadTimeout, sc.HTTPClient.Timeout)
	}
	if sc.config.Retry.MaxRetries != 5 {
		t.Errorf("expected MaxRetries 5, got %d", sc.config.Retry.MaxRetries)
	}
	if sc.config.CircuitBreaker.MaxFailures != 3 {
		t.Errorf("expected MaxFailures 3, got %d", sc.config.CircuitBreaker.MaxFailures)
	}
	if sc.config.DefaultHeaders["X-API-Key"] != "secret" {
		t.Errorf("expected X-API-Key header 'secret', got %q", sc.config.DefaultHeaders["X-API-Key"])
	}
}

func TestTimeoutConstants(t *testing.T) {
	if DatabaseTimeout != 5*time.Second {
		t.Errorf("expected DatabaseTimeout 5s, got %v", DatabaseTimeout)
	}
	if InternalServiceTimeout != 10*time.Second {
		t.Errorf("expected InternalServiceTimeout 10s, got %v", InternalServiceTimeout)
	}
	if ExternalAPITimeout != 15*time.Second {
		t.Errorf("expected ExternalAPITimeout 15s, got %v", ExternalAPITimeout)
	}
	if FileUploadTimeout != 60*time.Second {
		t.Errorf("expected FileUploadTimeout 60s, got %v", FileUploadTimeout)
	}
}
