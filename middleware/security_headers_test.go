// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestSecurityHeaders(t *testing.T) {
	production := http.Header{}
	for name, value := range map[string]string{
		"X-Content-Type-Options":              "nosniff",
		"X-Frame-Options":                     "DENY",
		"X-XSS-Protection":                    "1; mode=block",
		"Referrer-Policy":                     "strict-origin-when-cross-origin",
		"Permissions-Policy":                  "geolocation=(), microphone=(), camera=(), payment=(), usb=(), accelerometer=(), gyroscope=(), magnetometer=()",
		"Strict-Transport-Security":           "max-age=31536000; includeSubDomains; preload",
		"Content-Security-Policy-Report-Only": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
		"Cache-Control":                       "no-store, no-cache, must-revalidate, private",
		"Pragma":                              "no-cache",
		"X-Permitted-Cross-Domain-Policies":   "none",
		"X-Download-Options":                  "noopen",
	} {
		production.Set(name, value)
	}
	development := production.Clone()
	development.Del("Strict-Transport-Security")
	development.Del("Permissions-Policy")
	development.Del("Content-Security-Policy-Report-Only")
	development.Set("X-Frame-Options", "SAMEORIGIN")
	development.Set("Cache-Control", "no-store")
	development.Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: https: http:; connect-src 'self' ws: wss: http: https:")
	enforcing := production.Clone()
	enforcing.Set("Content-Security-Policy", enforcing.Get("Content-Security-Policy-Report-Only"))
	enforcing.Del("Content-Security-Policy-Report-Only")
	enforcingConfig := DefaultSecurityHeadersConfig()
	enforcingConfig.CSPReportOnly = false
	developmentOverride := DevelopmentSecurityHeadersConfig()
	developmentOverride.CSPReportOnly = true
	developmentOverride.StrictTransportSecurity = "max-age=123"
	empty := http.Header{}
	empty.Set("X-Permitted-Cross-Domain-Policies", "none")
	empty.Set("X-Download-Options", "noopen")

	tests := []struct {
		name    string
		handler gin.HandlerFunc
		want    http.Header
	}{
		{"implicit defaults", SecurityHeaders(), production},
		{"explicit defaults", SecurityHeaders(DefaultSecurityHeadersConfig()), production},
		{"enforcing CSP", SecurityHeaders(enforcingConfig), enforcing},
		{"development", SecurityHeaders(DevelopmentSecurityHeadersConfig()), development},
		{"development overrides HSTS and report-only", SecurityHeaders(developmentOverride), development},
		{"empty configuration omits optional headers", SecurityHeaders(SecurityHeadersConfig{}), empty},
		{"API production", APISecurityHeaders(false), production},
		{"API development", APISecurityHeaders(true), development},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			called := false
			router.Use(func(c *gin.Context) {
				tt.handler(c)
				// Gin also advances the chain after middleware returns. Check here to
				// ensure SecurityHeaders itself called c.Next().
				assert.True(t, called, "downstream handler must run before middleware returns")
			})
			router.GET("/test", func(c *gin.Context) {
				called = true
				c.Status(http.StatusNoContent)
			})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/test", nil))
			assert.True(t, called, "downstream handler must run")
			assert.Equal(t, http.StatusNoContent, response.Code)
			assert.Equal(t, tt.want, response.Header())
		})
	}
}
