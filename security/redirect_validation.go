// SPDX-License-Identifier: Apache-2.0

// Package security provides URL and redirect validation utilities for platform services.
package security

import (
	"net/url"
	"strings"
)

// RedirectValidationConfig holds configuration for redirect URL validation
type RedirectValidationConfig struct {
	// AllowedOrigins is a list of trusted origin URLs (e.g., ["https://app.example.app"])
	AllowedOrigins []string
	// BaseDomain allows any subdomain of this domain (e.g., "example.app")
	BaseDomain string
	// DefaultPath is the fallback path if validation fails
	DefaultPath string
	// AllowRelativePaths determines if relative paths (starting with /) are allowed
	AllowRelativePaths bool
}

// ValidateRedirectURL validates a redirect URL to prevent open redirect attacks.
//
// Security rules:
// - Rejects javascript:, data:, file:, and vbscript: URLs
// - Rejects protocol-relative URLs (//example.com)
// - Only allows relative paths (starting with /) or URLs from allowed origins
// - Validates against allowlist of trusted domains
//
// Parameters:
//   - redirectURL: The URL to validate
//   - config: Validation configuration
//
// Returns:
//   - The validated redirect URL or the default path
func ValidateRedirectURL(redirectURL string, config RedirectValidationConfig) string {
	// Set defaults
	if config.DefaultPath == "" {
		config.DefaultPath = "/"
	}

	// If no redirect URL provided, use default
	trimmedURL := strings.TrimSpace(redirectURL)
	if trimmedURL == "" {
		return config.DefaultPath
	}

	// Convert to lowercase for protocol checks
	lowerURL := strings.ToLower(trimmedURL)

	// Block dangerous protocols
	dangerousProtocols := []string{
		"javascript:",
		"data:",
		"vbscript:",
		"file:",
		"about:",
	}
	for _, protocol := range dangerousProtocols {
		if strings.HasPrefix(lowerURL, protocol) {
			return config.DefaultPath
		}
	}

	// Block protocol-relative URLs (//example.com)
	if strings.HasPrefix(trimmedURL, "//") {
		return config.DefaultPath
	}

	// Allow relative paths (starting with /)
	if strings.HasPrefix(trimmedURL, "/") && !strings.HasPrefix(trimmedURL, "//") {
		if config.AllowRelativePaths {
			// Validate that it's a proper path (no backslashes for path traversal)
			if strings.Contains(trimmedURL, "\\") {
				return config.DefaultPath
			}
			return trimmedURL
		}
		return config.DefaultPath
	}

	// If it's an absolute URL, validate the origin
	parsedURL, err := url.Parse(trimmedURL)
	if err != nil {
		// Invalid URL format - return default
		return config.DefaultPath
	}

	// Only allow http and https protocols
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return config.DefaultPath
	}

	// Build origin from URL (scheme + host)
	urlOrigin := parsedURL.Scheme + "://" + parsedURL.Host

	// Check if URL matches an allowed origin
	for _, allowed := range config.AllowedOrigins {
		if urlOrigin == allowed {
			return trimmedURL
		}
	}

	// Check subdomain matching if BaseDomain is provided
	if config.BaseDomain != "" {
		hostname := strings.ToLower(parsedURL.Hostname())
		normalizedBaseDomain := strings.ToLower(config.BaseDomain)

		// Check if hostname is the base domain or a subdomain of it
		if hostname == normalizedBaseDomain || strings.HasSuffix(hostname, "."+normalizedBaseDomain) {
			return trimmedURL
		}
	}

	// URL doesn't match any allowed origin
	return config.DefaultPath
}

// CreateRedirectValidator creates a redirect URL validator with preset configuration.
// Useful for consistent validation across an application.
func CreateRedirectValidator(config RedirectValidationConfig) func(string) string {
	return func(url string) string {
		return ValidateRedirectURL(url, config)
	}
}
