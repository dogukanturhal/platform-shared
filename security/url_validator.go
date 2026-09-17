// SPDX-License-Identifier: Apache-2.0

package security

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	// ErrInvalidURL indicates the URL is malformed
	ErrInvalidURL = errors.New("invalid URL format")
	// ErrInsecureScheme indicates the URL does not use HTTPS
	ErrInsecureScheme = errors.New("only HTTPS URLs are allowed")
	// ErrPrivateIP indicates the URL resolves to a private IP address
	ErrPrivateIP = errors.New("URL resolves to a private IP address")
	// ErrLocalhostNotAllowed indicates the URL points to localhost
	ErrLocalhostNotAllowed = errors.New("localhost URLs are not allowed")
	// ErrDomainNotAllowed indicates the URL domain is not in the allowlist
	ErrDomainNotAllowed = errors.New("URL domain is not in the allowlist")
)

// URLValidatorConfig holds configuration for URL validation
type URLValidatorConfig struct {
	// AllowedDomains is an optional allowlist of domains. If empty, all non-private domains are allowed.
	AllowedDomains []string
	// RequireHTTPS enforces HTTPS-only URLs (default: true)
	RequireHTTPS bool
	// BlockPrivateIPs blocks URLs that resolve to private IP ranges (default: true)
	BlockPrivateIPs bool
}

// DefaultURLValidatorConfig returns a secure default configuration
func DefaultURLValidatorConfig() URLValidatorConfig {
	return URLValidatorConfig{
		RequireHTTPS:    true,
		BlockPrivateIPs: true,
		AllowedDomains:  []string{},
	}
}

// URLValidator provides SSRF protection for user-supplied URLs
type URLValidator struct {
	config URLValidatorConfig
}

// NewURLValidator creates a new URL validator with the given configuration
func NewURLValidator(config URLValidatorConfig) *URLValidator {
	return &URLValidator{config: config}
}

// NewDefaultURLValidator creates a new URL validator with secure defaults
func NewDefaultURLValidator() *URLValidator {
	return NewURLValidator(DefaultURLValidatorConfig())
}

// Validate validates a user-supplied URL against SSRF attacks
func (v *URLValidator) Validate(rawURL string) error {
	if rawURL == "" {
		return ErrInvalidURL
	}

	// Parse the URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidURL, err)
	}

	// Validate scheme
	if v.config.RequireHTTPS && parsedURL.Scheme != "https" {
		return ErrInsecureScheme
	}

	// Extract hostname
	hostname := parsedURL.Hostname()
	if hostname == "" {
		return ErrInvalidURL
	}

	// Block localhost variations
	if v.isLocalhost(hostname) {
		return ErrLocalhostNotAllowed
	}

	// Check domain allowlist if configured
	if len(v.config.AllowedDomains) > 0 {
		if !v.isDomainAllowed(hostname) {
			return ErrDomainNotAllowed
		}
	}

	// Resolve hostname to IP and check for private ranges
	if v.config.BlockPrivateIPs {
		if err := v.validateIPAddress(hostname); err != nil {
			return fmt.Errorf("Validate: %w", err)
		}
	}

	return nil
}

// isLocalhost checks if the hostname is localhost or a localhost variation
func (v *URLValidator) isLocalhost(hostname string) bool {
	hostname = strings.ToLower(hostname)

	localhostVariations := []string{
		"localhost",
		"localhost.localdomain",
		"127.0.0.1",
		"::1",
		"0.0.0.0",
		"::",
	}

	for _, variation := range localhostVariations {
		if hostname == variation {
			return true
		}
	}

	return false
}

// isDomainAllowed checks if the hostname matches the allowlist
func (v *URLValidator) isDomainAllowed(hostname string) bool {
	hostname = strings.ToLower(hostname)

	for _, allowed := range v.config.AllowedDomains {
		allowed = strings.ToLower(allowed)

		// Exact match
		if hostname == allowed {
			return true
		}

		// Subdomain match (e.g., "example.com" allows "app.example.com")
		if strings.HasSuffix(hostname, "."+allowed) {
			return true
		}
	}

	return false
}

// validateIPAddress resolves the hostname and validates IP addresses
func (v *URLValidator) validateIPAddress(hostname string) error {
	// Resolve hostname to IP addresses
	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), hostname)
	if err != nil {
		return fmt.Errorf("failed to resolve hostname: %w", err)
	}

	if len(addrs) == 0 {
		return fmt.Errorf("hostname did not resolve to any IP addresses")
	}

	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ips = append(ips, addr.IP)
	}

	// Check each resolved IP
	for _, ip := range ips {
		if v.isPrivateIP(ip) {
			return fmt.Errorf("%w: %s", ErrPrivateIP, ip.String())
		}
	}

	return nil
}

// isPrivateIP checks if an IP address is in a private range
func (v *URLValidator) isPrivateIP(ip net.IP) bool {
	// Check for IPv4 private ranges
	if ip4 := ip.To4(); ip4 != nil {
		return v.isPrivateIPv4(ip4)
	}

	// Check for IPv6 private ranges
	if ip16 := ip.To16(); ip16 != nil {
		return v.isPrivateIPv6(ip16)
	}

	return false
}

// isPrivateIPv4 checks if an IPv4 address is in a private range
func (v *URLValidator) isPrivateIPv4(ip net.IP) bool {
	// Private IPv4 ranges:
	// 10.0.0.0/8
	// 172.16.0.0/12
	// 192.168.0.0/16
	// 127.0.0.0/8 (loopback)
	// 169.254.0.0/16 (link-local)
	// 0.0.0.0/8 (current network)
	// 224.0.0.0/4 (multicast)
	// 240.0.0.0/4 (reserved)

	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"0.0.0.0/8",
		"224.0.0.0/4",
		"240.0.0.0/4",
	}

	for _, cidr := range privateRanges {
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

// isPrivateIPv6 checks if an IPv6 address is in a private range
func (v *URLValidator) isPrivateIPv6(ip net.IP) bool {
	// Private IPv6 ranges:
	// ::1/128 (loopback)
	// fe80::/10 (link-local)
	// fc00::/7 (unique local)
	// ff00::/8 (multicast)

	privateRanges := []string{
		"::1/128",
		"fe80::/10",
		"fc00::/7",
		"ff00::/8",
	}

	for _, cidr := range privateRanges {
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

// ValidateURL is a convenience function for validating a URL with default configuration
func ValidateURL(rawURL string) error {
	validator := NewDefaultURLValidator()
	return validator.Validate(rawURL)
}

// ValidateURLWithAllowlist validates a URL against a domain allowlist
func ValidateURLWithAllowlist(rawURL string, allowedDomains []string) error {
	config := DefaultURLValidatorConfig()
	config.AllowedDomains = allowedDomains
	validator := NewURLValidator(config)
	return validator.Validate(rawURL)
}
