# Resilience Package

Circuit breaker and retry library for resilient inter-service HTTP communication.

## Features

- **Circuit Breaker**: Three-state (Closed, Open, HalfOpen) circuit breaker pattern
- **Automatic Retry**: Exponential backoff retry for transient failures
- **Smart Retry Logic**: Only retries 5xx errors and network failures, not 4xx client errors
- **Context Support**: Full context propagation for cancellation and timeouts
- **Zero Dependencies**: Uses only Go standard library
- **Thread-Safe**: Safe for concurrent use across goroutines
- **Highly Tested**: 95.5% test coverage

## Quick Start

### Basic Usage

```go
import "github.com/dogukanturhal/platform-shared/resilience"

// Create a resilient HTTP client
client := resilience.NewResilientHTTPClient()

// Make a request
req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/data", nil)
resp, err := client.Do(req)
if err != nil {
    log.Printf("Request failed: %v", err)
    return
}
defer resp.Body.Close()
```

### Custom Configuration

```go
// Create custom circuit breaker
cb := resilience.NewCircuitBreakerWithConfig(3, 10*time.Second)

// Create client with custom settings
client := resilience.NewResilientHTTPClient(
    resilience.WithMaxRetries(5),
    resilience.WithRetryDelay(200*time.Millisecond),
    resilience.WithBackoffMultiplier(2.0),
    resilience.WithCircuitBreaker(cb),
)

ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
resp, err := client.Do(req)
```

## Circuit Breaker

### States

1. **Closed** (Normal): All requests pass through
2. **Open** (Failing): Requests immediately fail without attempting
3. **HalfOpen** (Testing): Limited requests to test recovery

### State Transitions

```
Closed --[failures >= threshold]--> Open
Open --[recovery timeout elapsed]--> HalfOpen
HalfOpen --[success]--> Closed
HalfOpen --[failure]--> Open
```

### Standalone Circuit Breaker

```go
cb := resilience.NewCircuitBreakerWithConfig(5, 30*time.Second)

if cb.Allow() {
    err := makeServiceCall()
    if err != nil {
        cb.RecordFailure()
    } else {
        cb.RecordSuccess()
    }
}

// Check state
state := cb.GetState() // StateClosed, StateOpen, or StateHalfOpen
```

## Retry Behavior

### Retryable Status Codes

- 408 Request Timeout
- 429 Too Many Requests
- 500 Internal Server Error
- 502 Bad Gateway
- 503 Service Unavailable
- 504 Gateway Timeout

### Non-Retryable (4xx Client Errors)

- 400 Bad Request
- 401 Unauthorized
- 403 Forbidden
- 404 Not Found
- etc.

### Exponential Backoff

Default configuration:
- Initial delay: 100ms
- Multiplier: 2.0
- Max retries: 3

Example delays: 100ms → 200ms → 400ms

## Configuration Options

### ResilientHTTPClient Options

```go
// Maximum retry attempts (default: 3)
resilience.WithMaxRetries(5)

// Initial retry delay (default: 100ms)
resilience.WithRetryDelay(200*time.Millisecond)

// Backoff multiplier (default: 2.0)
resilience.WithBackoffMultiplier(3.0)

// Custom circuit breaker
resilience.WithCircuitBreaker(cb)

// Custom HTTP client
resilience.WithHTTPClient(&http.Client{Timeout: 10*time.Second})
```

### Circuit Breaker Configuration

```go
// Default: 5 failures, 30s timeout
cb := resilience.NewCircuitBreaker()

// Custom configuration
cb := resilience.NewCircuitBreakerWithConfig(
    3,              // failure threshold
    10*time.Second, // recovery timeout
)
```

## Error Handling

### Circuit Open Error

```go
resp, err := client.Do(req)
if errors.Is(err, resilience.ErrCircuitOpen) {
    log.Println("Circuit breaker is open, service unavailable")
    return
}
```

### HTTP Errors

```go
resp, err := client.Do(req)
if err != nil {
    log.Printf("Request failed: %v", err)
    return
}

if resp.StatusCode >= 400 {
    // Handle error response
}
```

## Best Practices

1. **Reuse Clients**: Create once, use for multiple requests
2. **Set Timeouts**: Always use context with timeout
3. **Monitor Circuit State**: Log circuit breaker state changes
4. **Tune Parameters**: Adjust thresholds based on service characteristics
5. **Handle Circuit Open**: Implement fallback behavior for circuit open scenarios

## Example: Service-to-Service Call

```go
type ServiceClient struct {
    client *resilience.ResilientHTTPClient
}

func NewServiceClient(baseURL string) *ServiceClient {
    cb := resilience.NewCircuitBreakerWithConfig(5, 30*time.Second)

    return &ServiceClient{
        client: resilience.NewResilientHTTPClient(
            resilience.WithMaxRetries(3),
            resilience.WithRetryDelay(100*time.Millisecond),
            resilience.WithCircuitBreaker(cb),
        ),
    }
}

func (s *ServiceClient) GetUser(ctx context.Context, userID string) (*User, error) {
    url := fmt.Sprintf("https://iam-service/users/%s", userID)

    req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if err != nil {
        return nil, err
    }

    req.Header.Set("X-Tenant-ID", getTenantID(ctx))
    req.Header.Set("Authorization", getBearerToken(ctx))

    resp, err := s.client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to get user: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
    }

    var user User
    if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }

    return &user, nil
}
```

## Testing

Run tests with coverage:

```bash
go test ./resilience/... -v -cover
```

Current coverage: **95.5%**

## Thread Safety

All components are thread-safe and can be safely used across multiple goroutines:

- Circuit breaker uses `sync.RWMutex` for state management
- HTTP client is safe for concurrent use
- Request cloning ensures body re-readability on retries

## Performance Considerations

- Circuit breaker adds minimal overhead (~100ns per call)
- Retry backoff uses `time.After` (non-blocking)
- Request body is cloned for retries (memory overhead for large payloads)
- Use connection pooling via custom `http.Client` for high-throughput scenarios

## Integration

This package is designed for inter-service communication:

- **IAM Service**: Authentication and authorization calls
- **Tenant Management**: Tenant provisioning and metadata
- **Billing Service**: Payment and subscription operations
- **Business Modules**: CRM, HR, Inventory, etc.

### Multi-Tenancy Support

```go
req.Header.Set("X-Tenant-ID", tenantID)
req.Header.Set("Authorization", "Bearer "+jwtToken)
```

### Observability

Integrate with OpenTelemetry for distributed tracing:

```go
import "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

client := resilience.NewResilientHTTPClient(
    resilience.WithHTTPClient(&http.Client{
        Transport: otelhttp.NewTransport(http.DefaultTransport),
        Timeout:   30 * time.Second,
    }),
)
```

## License

Part of multi-tenant services.
