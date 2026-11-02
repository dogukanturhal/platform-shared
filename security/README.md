# Security Package

Shared security utilities for multi-tenant services.

## URL Validator (SSRF Protection)

### Overview

The URL validator provides comprehensive protection against Server-Side Request Forgery (SSRF) attacks by validating user-supplied URLs before they are used in server-side HTTP requests.

### Features

- ✅ HTTPS scheme enforcement
- ✅ Private IP range blocking (IPv4 and IPv6)
- ✅ Localhost detection and blocking
- ✅ DNS resolution and validation
- ✅ Optional domain allowlist
- ✅ Comprehensive error messages
- ✅ Zero dependencies (uses Go standard library)

### Quick Start

#### Basic Usage (Default Configuration)

```go
import "github.com/dogukanturhal/platform-shared/security"

// Validate a user-supplied URL
func handleCallback(c *gin.Context) {
    callbackURL := c.Query("callback_url")

    // Validate with default settings (HTTPS only, block private IPs)
    if err := security.ValidateURL(callbackURL); err != nil {
        c.JSON(400, gin.H{"error": "Invalid callback URL"})
        return
    }

    // Safe to use callbackURL
    resp, err := http.Get(callbackURL)
    // ...
}
```

#### With Domain Allowlist

```go
import "github.com/dogukanturhal/platform-shared/security"

// Only allow specific domains
allowedDomains := []string{"example.org", "example.com"}

if err := security.ValidateURLWithAllowlist(redirectURL, allowedDomains); err != nil {
    return fmt.Errorf("invalid redirect URL: %w", err)
}
```

#### Advanced Configuration

```go
import "github.com/dogukanturhal/platform-shared/security"

// Create custom validator
config := security.URLValidatorConfig{
    RequireHTTPS:    true,
    BlockPrivateIPs: true,
    AllowedDomains:  []string{"example.org", "partner.com"},
}

validator := security.NewURLValidator(config)

// Use in handler
type MyHandler struct {
    urlValidator *security.URLValidator
}

func (h *MyHandler) ProcessWebhook(c *gin.Context) {
    webhookURL := c.PostForm("url")

    if err := h.urlValidator.Validate(webhookURL); err != nil {
        logger.Warn("Invalid webhook URL",
            zap.String("url", webhookURL),
            zap.Error(err),
        )
        c.JSON(400, gin.H{"error": "Invalid webhook URL"})
        return
    }

    // Safe to use webhookURL
}
```

### Configuration Options

```go
type URLValidatorConfig struct {
    // AllowedDomains is an optional allowlist of domains
    // If empty, all non-private domains are allowed
    // Supports subdomains (e.g., "example.com" allows "app.example.com")
    AllowedDomains []string

    // RequireHTTPS enforces HTTPS-only URLs (default: true)
    RequireHTTPS bool

    // BlockPrivateIPs blocks URLs that resolve to private IP ranges (default: true)
    BlockPrivateIPs bool
}
```

### Blocked IP Ranges

#### IPv4
- `10.0.0.0/8` - Private networks
- `172.16.0.0/12` - Private networks
- `192.168.0.0/16` - Private networks
- `127.0.0.0/8` - Loopback
- `169.254.0.0/16` - Link-local (AWS metadata)
- `0.0.0.0/8` - Current network
- `224.0.0.0/4` - Multicast
- `240.0.0.0/4` - Reserved

#### IPv6
- `::1/128` - Loopback
- `fe80::/10` - Link-local
- `fc00::/7` - Unique local addresses
- `ff00::/8` - Multicast

### Error Types

```go
var (
    ErrInvalidURL          = errors.New("invalid URL format")
    ErrInsecureScheme      = errors.New("only HTTPS URLs are allowed")
    ErrPrivateIP           = errors.New("URL resolves to a private IP address")
    ErrLocalhostNotAllowed = errors.New("localhost URLs are not allowed")
    ErrDomainNotAllowed    = errors.New("URL domain is not in the allowlist")
)
```

### Usage Examples

#### Example 1: OAuth Redirect URL Validation

```go
func (h *OAuthHandler) Authorize(c *gin.Context) {
    redirectURI := c.Query("redirect_uri")

    // Validate redirect_uri to prevent open redirect + SSRF
    if err := h.urlValidator.Validate(redirectURI); err != nil {
        c.JSON(400, gin.H{"error": "Invalid redirect_uri"})
        return
    }

    // Generate authorization code and redirect
    // ...
}
```

#### Example 2: Webhook URL Registration

```go
func (h *WebhookHandler) Register(c *gin.Context) {
    var req struct {
        URL    string   `json:"url" binding:"required"`
        Events []string `json:"events" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    // Validate webhook URL
    if err := h.urlValidator.Validate(req.URL); err != nil {
        c.JSON(400, gin.H{
            "error": "Invalid webhook URL: must be HTTPS and publicly accessible",
        })
        return
    }

    // Store webhook
    // ...
}
```

#### Example 3: Integration with Config

```go
// config/config.go
type Config struct {
    // ...
    AllowedCallbackDomains []string
}

func Load() (*Config, error) {
    // Parse from environment variable (comma-separated)
    domainsStr := viper.GetString("ALLOWED_CALLBACK_DOMAINS")
    var allowedDomains []string
    if domainsStr != "" {
        for _, domain := range strings.Split(domainsStr, ",") {
            allowedDomains = append(allowedDomains, strings.TrimSpace(domain))
        }
    }

    return &Config{
        AllowedCallbackDomains: allowedDomains,
    }, nil
}

// main.go
func main() {
    cfg := config.Load()

    // Create validator from config
    validatorConfig := security.DefaultURLValidatorConfig()
    validatorConfig.AllowedDomains = cfg.AllowedCallbackDomains

    validator := security.NewURLValidator(validatorConfig)

    // Pass to handlers
    handler := handlers.NewMyHandler(validator, logger)
}
```

### Testing

The URL validator includes comprehensive tests covering all attack vectors:

```bash
cd platform-services/shared
go test ./security -v
```

### Performance

- **DNS Resolution**: ~1-2ms per unique hostname
- **IP Validation**: <0.1ms per URL
- **Caching**: Consider implementing DNS caching for high-traffic scenarios

### Security Best Practices

1. **Always validate user-supplied URLs** before making server-side requests
2. **Use domain allowlists** when possible for strictest security
3. **Log rejected URLs** for security monitoring
4. **Monitor for patterns** of SSRF attempts
5. **Keep allowlists minimal** - only add domains you control or trust
6. **Use HTTPS enforcement** in production (RequireHTTPS: true)

### Common Pitfalls

❌ **Don't**:
```go
// BAD: No validation
callbackURL := c.Query("callback")
http.Get(callbackURL)  // SSRF vulnerability!
```

❌ **Don't**:
```go
// BAD: Only checking scheme
if !strings.HasPrefix(url, "https://") {
    return errors.New("must be HTTPS")
}
// Still vulnerable to https://169.254.169.254
```

✅ **Do**:
```go
// GOOD: Complete validation
if err := security.ValidateURL(callbackURL); err != nil {
    return err
}
http.Get(callbackURL)  // Safe!
```

### Integration Checklist

When integrating URL validator into a service:

- [ ] Identify all user-supplied URLs in your service
- [ ] Add URL validation before any server-side HTTP requests
- [ ] Configure domain allowlist if applicable
- [ ] Add logging for rejected URLs
- [ ] Write integration tests
- [ ] Update API documentation with validation requirements
- [ ] Add security notes to endpoint documentation

### Related Security Features

- **Redirect Validator**: See `redirect_validator.go` for client-side redirect validation
- **JWT Validation**: See `platform-services/shared/auth/` for token validation
- **Rate Limiting**: See `platform-services/shared/middleware/rate_limiter.go`

### Support

For questions or security concerns:
- Create an issue in the repository
- Contact the security team
- Review OWASP SSRF Prevention guidelines

## Other Security Utilities

(Additional security utilities documentation here)

---

**Last Updated**: 2026-02-11
**Security contact**: see SECURITY.md in the repository root
