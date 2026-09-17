# Resilience Package Usage Guide

## Integration with ExampleSuite Platform Services

### Quick Start for Service Developers

#### 1. Import the Package

```go
import (
    "github.com/hexxlock/platform-services/shared/resilience"
)
```

#### 2. Create a Resilient HTTP Client

```go
// In your service initialization
func NewServiceClient() *ServiceClient {
    return &ServiceClient{
        client: resilience.NewResilientHTTPClient(
            resilience.WithMaxRetries(3),
            resilience.WithRetryDelay(100*time.Millisecond),
        ),
    }
}
```

#### 3. Make Inter-Service Calls

```go
func (s *ServiceClient) CallIAMService(ctx context.Context) error {
    req, err := http.NewRequestWithContext(
        ctx,
        http.MethodGet,
        "http://iam-service:8001/api/v1/users",
        nil,
    )
    if err != nil {
        return err
    }

    // Add tenant context and auth
    req.Header.Set("X-Tenant-ID", getTenantIDFromContext(ctx))
    req.Header.Set("Authorization", getJWTFromContext(ctx))

    resp, err := s.client.Do(req)
    if err != nil {
        return fmt.Errorf("IAM service call failed: %w", err)
    }
    defer resp.Body.Close()

    // Process response...
    return nil
}
```

## Real-World Examples

### Example 1: Tenant Management → IAM Service

```go
// platform-services/tenant-management/internal/clients/iam_client.go
package clients

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"

    "github.com/hexxlock/platform-services/shared/resilience"
)

type IAMClient struct {
    baseURL string
    client  *resilience.ResilientHTTPClient
}

func NewIAMClient(baseURL string) *IAMClient {
    cb := resilience.NewCircuitBreakerWithConfig(5, 30*time.Second)

    return &IAMClient{
        baseURL: baseURL,
        client: resilience.NewResilientHTTPClient(
            resilience.WithMaxRetries(3),
            resilience.WithRetryDelay(100*time.Millisecond),
            resilience.WithCircuitBreaker(cb),
        ),
    }
}

func (c *IAMClient) CreateUser(ctx context.Context, userReq CreateUserRequest) (*User, error) {
    body, _ := json.Marshal(userReq)
    url := fmt.Sprintf("%s/api/v1/users", c.baseURL)

    req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
    if err != nil {
        return nil, err
    }

    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Tenant-ID", getTenantID(ctx))

    resp, err := c.client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("create user failed: %w", err)
    }
    defer resp.Body.Close()

    var user User
    if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
        return nil, err
    }

    return &user, nil
}
```

### Example 2: Billing Service → Payment Gateway

```go
// platform-services/billing/internal/clients/payment_client.go
package clients

import (
    "context"
    "fmt"
    "net/http"

    "github.com/hexxlock/platform-services/shared/resilience"
)

type PaymentClient struct {
    client *resilience.ResilientHTTPClient
}

func NewPaymentClient() *PaymentClient {
    // Payment operations need aggressive retries
    return &PaymentClient{
        client: resilience.NewResilientHTTPClient(
            resilience.WithMaxRetries(5),
            resilience.WithRetryDelay(200*time.Millisecond),
            resilience.WithBackoffMultiplier(2.0),
        ),
    }
}

func (c *PaymentClient) ProcessPayment(ctx context.Context, payment PaymentRequest) error {
    req, _ := http.NewRequestWithContext(
        ctx,
        http.MethodPost,
        "http://payment-gateway:8006/api/v1/process",
        toJSON(payment),
    )

    resp, err := c.client.Do(req)
    if err != nil {
        // Handle circuit open scenario
        if errors.Is(err, resilience.ErrCircuitOpen) {
            return fmt.Errorf("payment gateway unavailable: %w", err)
        }
        return fmt.Errorf("payment processing failed: %w", err)
    }
    defer resp.Body.Close()

    return nil
}
```

### Example 3: Business Module → Platform Service

```go
// business-modules/crm/src/Infrastructure/Clients/TenantServiceClient.cs equivalent in Go
package clients

import (
    "context"
    "time"

    "github.com/hexxlock/platform-services/shared/resilience"
)

type TenantServiceClient struct {
    client *resilience.ResilientHTTPClient
}

func NewTenantServiceClient() *TenantServiceClient {
    return &TenantServiceClient{
        client: resilience.NewResilientHTTPClient(),
    }
}

func (c *TenantServiceClient) GetTenantSettings(ctx context.Context, tenantID string) (*TenantSettings, error) {
    url := fmt.Sprintf("http://tenant-management:8002/api/v1/tenants/%s/settings", tenantID)

    req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    req.Header.Set("X-Tenant-ID", tenantID)

    resp, err := c.client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var settings TenantSettings
    json.NewDecoder(resp.Body).Decode(&settings)
    return &settings, nil
}
```

## Configuration by Service Type

### Critical Services (IAM, Tenant Management)
```go
resilience.NewResilientHTTPClient(
    resilience.WithMaxRetries(5),
    resilience.WithRetryDelay(100*time.Millisecond),
    resilience.WithCircuitBreaker(
        resilience.NewCircuitBreakerWithConfig(10, 60*time.Second),
    ),
)
```

### Standard Services (Billing, Subscription, Workflow)
```go
resilience.NewResilientHTTPClient(
    resilience.WithMaxRetries(3),
    resilience.WithRetryDelay(100*time.Millisecond),
)
```

### Background Tasks (Document Processor, Marketing Automation)
```go
resilience.NewResilientHTTPClient(
    resilience.WithMaxRetries(10),
    resilience.WithRetryDelay(500*time.Millisecond),
    resilience.WithBackoffMultiplier(1.5),
)
```

## Monitoring and Observability

### Log Circuit Breaker State Changes

```go
type MonitoredClient struct {
    client *resilience.ResilientHTTPClient
    logger *zap.Logger
}

func (c *MonitoredClient) Do(req *http.Request) (*http.Response, error) {
    stateBefore := c.client.GetCircuitBreakerState()

    resp, err := c.client.Do(req)

    stateAfter := c.client.GetCircuitBreakerState()
    if stateBefore != stateAfter {
        c.logger.Warn("circuit breaker state changed",
            zap.String("from", stateBefore.String()),
            zap.String("to", stateAfter.String()),
            zap.String("service", req.URL.Host),
        )
    }

    return resp, err
}
```

### Metrics Collection

```go
import "go.opentelemetry.io/otel/metric"

type MetricsClient struct {
    client       *resilience.ResilientHTTPClient
    requestCount metric.Int64Counter
    errorCount   metric.Int64Counter
}

func (c *MetricsClient) Do(req *http.Request) (*http.Response, error) {
    c.requestCount.Add(req.Context(), 1)

    resp, err := c.client.Do(req)
    if err != nil {
        c.errorCount.Add(req.Context(), 1)
    }

    return resp, err
}
```

## Testing with Resilience

### Unit Testing

```go
func TestServiceClient(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
    }))
    defer server.Close()

    client := NewServiceClient(server.URL)

    ctx := context.Background()
    err := client.DoSomething(ctx)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
}
```

### Integration Testing with Retries

```go
func TestServiceClientWithRetries(t *testing.T) {
    var attempts int32

    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        count := atomic.AddInt32(&attempts, 1)
        if count < 3 {
            w.WriteHeader(http.StatusServiceUnavailable)
            return
        }
        w.WriteHeader(http.StatusOK)
    }))
    defer server.Close()

    client := NewServiceClient(server.URL)

    err := client.DoSomething(context.Background())
    if err != nil {
        t.Fatalf("expected success after retries: %v", err)
    }

    if attempts != 3 {
        t.Errorf("expected 3 attempts, got %d", attempts)
    }
}
```

## Migration from Existing Code

### Before (without resilience)
```go
func (c *Client) GetUser(ctx context.Context, id string) (*User, error) {
    req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/users/"+id, nil)
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var user User
    json.NewDecoder(resp.Body).Decode(&user)
    return &user, nil
}
```

### After (with resilience)
```go
func (c *Client) GetUser(ctx context.Context, id string) (*User, error) {
    req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/users/"+id, nil)

    // Use resilient client instead of standard http.Client
    resp, err := c.resilientClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var user User
    json.NewDecoder(resp.Body).Decode(&user)
    return &user, nil
}
```

## Common Patterns

### Pattern 1: Service Client Wrapper

```go
type ServiceClient struct {
    baseURL        string
    resilientHTTP  *resilience.ResilientHTTPClient
    tenantID       string
    authToken      string
}

func (c *ServiceClient) doRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
    url := c.baseURL + path
    req, err := http.NewRequestWithContext(ctx, method, url, body)
    if err != nil {
        return nil, err
    }

    // Add common headers
    req.Header.Set("X-Tenant-ID", c.tenantID)
    req.Header.Set("Authorization", "Bearer "+c.authToken)
    req.Header.Set("Content-Type", "application/json")

    return c.resilientHTTP.Do(req)
}
```

### Pattern 2: Fallback Strategy

```go
func (c *Client) GetData(ctx context.Context) (*Data, error) {
    resp, err := c.resilientClient.Do(req)

    // Check if circuit is open
    if errors.Is(err, resilience.ErrCircuitOpen) {
        // Fallback to cache
        return c.getFromCache(ctx)
    }

    if err != nil {
        return nil, err
    }

    // Process response...
}
```

### Pattern 3: Service-Specific Client Factory

```go
func NewPlatformServiceClients(config *Config) *PlatformClients {
    return &PlatformClients{
        IAM:    newIAMClient(config.IAMBaseURL),
        Tenant: newTenantClient(config.TenantBaseURL),
        Billing: newBillingClient(config.BillingBaseURL),
    }
}

func newIAMClient(baseURL string) *resilience.ResilientHTTPClient {
    cb := resilience.NewCircuitBreakerWithConfig(5, 30*time.Second)
    return resilience.NewResilientHTTPClient(
        resilience.WithMaxRetries(3),
        resilience.WithCircuitBreaker(cb),
    )
}
```

## Troubleshooting

### Issue: Circuit keeps opening
**Solution**: Increase failure threshold or check service health

### Issue: Too many retries on 4xx errors
**Solution**: 4xx errors are NOT retried automatically - check your error handling

### Issue: Request body not being sent on retry
**Solution**: Package handles body cloning automatically - ensure body is seekable

### Issue: Context deadline exceeded
**Solution**: Increase context timeout to account for retries and backoff

## Best Practices Summary

1. Create resilient client once during service initialization
2. Use context with timeout for all requests
3. Add tenant ID and auth headers to all requests
4. Monitor circuit breaker state changes
5. Implement fallback strategies for critical operations
6. Log failures for observability
7. Tune retry parameters based on service SLA
8. Test with both success and failure scenarios

## Next Steps

1. Replace existing http.Client usage with resilience.ResilientHTTPClient
2. Add circuit breaker monitoring to dashboards
3. Configure alerts for circuit state changes
4. Review and tune retry parameters per service
5. Add integration tests with retry scenarios
