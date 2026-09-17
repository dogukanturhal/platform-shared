// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"github.com/gin-gonic/gin"
)

// SecurityHeadersConfig contains configuration for security headers middleware
type SecurityHeadersConfig struct {
	// ContentSecurityPolicy sets the Content-Security-Policy header
	// Default: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'"
	ContentSecurityPolicy string

	// StrictTransportSecurity sets the Strict-Transport-Security header
	// Default: "max-age=31536000; includeSubDomains" (1 year)
	StrictTransportSecurity string

	// XContentTypeOptions sets the X-Content-Type-Options header
	// Default: "nosniff"
	XContentTypeOptions string

	// XFrameOptions sets the X-Frame-Options header
	// Default: "DENY"
	XFrameOptions string

	// XSSProtection sets the X-XSS-Protection header
	// Default: "1; mode=block"
	XSSProtection string

	// ReferrerPolicy sets the Referrer-Policy header
	// Default: "strict-origin-when-cross-origin"
	ReferrerPolicy string

	// PermissionsPolicy sets the Permissions-Policy header
	// Default: "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
	PermissionsPolicy string

	// CacheControl sets the Cache-Control header for API responses
	// Default: "no-store, no-cache, must-revalidate, private"
	CacheControl string

	// IsDevelopment disables HSTS and relaxes CSP in development
	IsDevelopment bool

	// CSPReportOnly uses Content-Security-Policy-Report-Only instead of enforcing
	// Recommended: Enable this first in production to detect issues before enforcing
	CSPReportOnly bool
}

// DefaultSecurityHeadersConfig returns production-ready security headers configuration
// NOTE: CSPReportOnly is true by default - set to false after validating no issues in production
func DefaultSecurityHeadersConfig() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		ContentSecurityPolicy:   "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
		StrictTransportSecurity: "max-age=31536000; includeSubDomains; preload",
		XContentTypeOptions:     "nosniff",
		XFrameOptions:           "DENY",
		XSSProtection:           "1; mode=block",
		ReferrerPolicy:          "strict-origin-when-cross-origin",
		PermissionsPolicy:       "geolocation=(), microphone=(), camera=(), payment=(), usb=(), accelerometer=(), gyroscope=(), magnetometer=()",
		CacheControl:            "no-store, no-cache, must-revalidate, private",
		IsDevelopment:           false,
		CSPReportOnly:           true, // Start in report-only mode for safety
	}
}

// DevelopmentSecurityHeadersConfig returns relaxed security headers for development
func DevelopmentSecurityHeadersConfig() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		ContentSecurityPolicy:   "default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: https: http:; connect-src 'self' ws: wss: http: https:",
		StrictTransportSecurity: "", // Disabled in development
		XContentTypeOptions:     "nosniff",
		XFrameOptions:           "SAMEORIGIN",
		XSSProtection:           "1; mode=block",
		ReferrerPolicy:          "strict-origin-when-cross-origin",
		PermissionsPolicy:       "",
		CacheControl:            "no-store",
		IsDevelopment:           true,
	}
}

// SecurityHeaders returns a middleware that sets security-related HTTP headers
func SecurityHeaders(config ...SecurityHeadersConfig) gin.HandlerFunc {
	cfg := DefaultSecurityHeadersConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	return func(c *gin.Context) {
		// X-Content-Type-Options - Prevents MIME type sniffing
		if cfg.XContentTypeOptions != "" {
			c.Header("X-Content-Type-Options", cfg.XContentTypeOptions)
		}

		// X-Frame-Options - Prevents clickjacking
		if cfg.XFrameOptions != "" {
			c.Header("X-Frame-Options", cfg.XFrameOptions)
		}

		// X-XSS-Protection - Legacy XSS protection for older browsers
		if cfg.XSSProtection != "" {
			c.Header("X-XSS-Protection", cfg.XSSProtection)
		}

		// Referrer-Policy - Controls referrer information
		if cfg.ReferrerPolicy != "" {
			c.Header("Referrer-Policy", cfg.ReferrerPolicy)
		}

		// Content-Security-Policy - Mitigates XSS and data injection
		// Use CSPReportOnly=true first in production to detect issues before enforcing
		if cfg.ContentSecurityPolicy != "" {
			if cfg.CSPReportOnly && !cfg.IsDevelopment {
				c.Header("Content-Security-Policy-Report-Only", cfg.ContentSecurityPolicy)
			} else {
				c.Header("Content-Security-Policy", cfg.ContentSecurityPolicy)
			}
		}

		// Strict-Transport-Security - Forces HTTPS (skip in development)
		if cfg.StrictTransportSecurity != "" && !cfg.IsDevelopment {
			c.Header("Strict-Transport-Security", cfg.StrictTransportSecurity)
		}

		// Permissions-Policy - Restricts browser features
		if cfg.PermissionsPolicy != "" {
			c.Header("Permissions-Policy", cfg.PermissionsPolicy)
		}

		// Cache-Control for API responses
		if cfg.CacheControl != "" {
			c.Header("Cache-Control", cfg.CacheControl)
			c.Header("Pragma", "no-cache")
		}

		// Additional security headers
		c.Header("X-Permitted-Cross-Domain-Policies", "none")
		c.Header("X-Download-Options", "noopen")

		c.Next()
	}
}

// APISecurityHeaders returns security headers optimized for JSON API responses
func APISecurityHeaders(isDevelopment bool) gin.HandlerFunc {
	if isDevelopment {
		return SecurityHeaders(DevelopmentSecurityHeadersConfig())
	}
	return SecurityHeaders(DefaultSecurityHeadersConfig())
}
