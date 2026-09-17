// SPDX-License-Identifier: Apache-2.0

package security

import (
	"testing"
)

func TestValidateRedirectURL(t *testing.T) {
	tests := []struct {
		name        string
		redirectURL string
		config      RedirectValidationConfig
		expected    string
	}{
		// Dangerous protocols
		{
			name:        "block javascript: URL",
			redirectURL: "javascript:alert(1)",
			config:      RedirectValidationConfig{DefaultPath: "/"},
			expected:    "/",
		},
		{
			name:        "block javascript: URL (case insensitive)",
			redirectURL: "JavaScript:alert(1)",
			config:      RedirectValidationConfig{DefaultPath: "/"},
			expected:    "/",
		},
		{
			name:        "block data: URL",
			redirectURL: "data:text/html,<script>alert(1)</script>",
			config:      RedirectValidationConfig{DefaultPath: "/"},
			expected:    "/",
		},
		{
			name:        "block vbscript: URL",
			redirectURL: "vbscript:msgbox(1)",
			config:      RedirectValidationConfig{DefaultPath: "/"},
			expected:    "/",
		},
		{
			name:        "block file: URL",
			redirectURL: "file:///etc/passwd",
			config:      RedirectValidationConfig{DefaultPath: "/"},
			expected:    "/",
		},
		{
			name:        "block about: URL",
			redirectURL: "about:blank",
			config:      RedirectValidationConfig{DefaultPath: "/"},
			expected:    "/",
		},

		// Protocol-relative URLs
		{
			name:        "block protocol-relative URL",
			redirectURL: "//evil.com",
			config:      RedirectValidationConfig{DefaultPath: "/"},
			expected:    "/",
		},
		{
			name:        "block protocol-relative URL with path",
			redirectURL: "//evil.com/phishing",
			config:      RedirectValidationConfig{DefaultPath: "/"},
			expected:    "/",
		},

		// Relative paths
		{
			name:        "allow relative path",
			redirectURL: "/dashboard",
			config:      RedirectValidationConfig{AllowRelativePaths: true, DefaultPath: "/"},
			expected:    "/dashboard",
		},
		{
			name:        "allow relative path with segments",
			redirectURL: "/users/profile",
			config:      RedirectValidationConfig{AllowRelativePaths: true, DefaultPath: "/"},
			expected:    "/users/profile",
		},
		{
			name:        "block path with backslash",
			redirectURL: "/path\\traversal",
			config:      RedirectValidationConfig{AllowRelativePaths: true, DefaultPath: "/"},
			expected:    "/",
		},
		{
			name:        "disallow relative paths when configured",
			redirectURL: "/dashboard",
			config:      RedirectValidationConfig{AllowRelativePaths: false, DefaultPath: "/"},
			expected:    "/",
		},

		// Absolute URLs with allowed origins
		{
			name:        "allow URL from allowed origin",
			redirectURL: "https://app.example.app/dashboard",
			config: RedirectValidationConfig{
				AllowedOrigins: []string{"https://app.example.app"},
				DefaultPath:    "/",
			},
			expected: "https://app.example.app/dashboard",
		},
		{
			name:        "reject URL from non-allowed origin",
			redirectURL: "https://evil.com",
			config: RedirectValidationConfig{
				AllowedOrigins: []string{"https://app.example.app"},
				DefaultPath:    "/",
			},
			expected: "/",
		},
		{
			name:        "handle port numbers correctly",
			redirectURL: "http://localhost:3000/dashboard",
			config: RedirectValidationConfig{
				AllowedOrigins: []string{"http://localhost:3000"},
				DefaultPath:    "/",
			},
			expected: "http://localhost:3000/dashboard",
		},
		{
			name:        "reject different port",
			redirectURL: "http://localhost:3001/dashboard",
			config: RedirectValidationConfig{
				AllowedOrigins: []string{"http://localhost:3000"},
				DefaultPath:    "/",
			},
			expected: "/",
		},

		// Subdomain matching
		{
			name:        "allow subdomain of base domain",
			redirectURL: "https://app.example.app/dashboard",
			config: RedirectValidationConfig{
				BaseDomain:  "example.app",
				DefaultPath: "/",
			},
			expected: "https://app.example.app/dashboard",
		},
		{
			name:        "allow base domain itself",
			redirectURL: "https://example.app",
			config: RedirectValidationConfig{
				BaseDomain:  "example.app",
				DefaultPath: "/",
			},
			expected: "https://example.app",
		},
		{
			name:        "reject non-subdomain",
			redirectURL: "https://evilexample.app",
			config: RedirectValidationConfig{
				BaseDomain:  "example.app",
				DefaultPath: "/",
			},
			expected: "/",
		},
		{
			name:        "reject domain with base domain as suffix",
			redirectURL: "https://example.app.evil.com",
			config: RedirectValidationConfig{
				BaseDomain:  "example.app",
				DefaultPath: "/",
			},
			expected: "/",
		},
		{
			name:        "handle case-insensitive domains",
			redirectURL: "https://APP.EXAMPLESUITE.APP/dashboard",
			config: RedirectValidationConfig{
				BaseDomain:  "ExampleSuite.app",
				DefaultPath: "/",
			},
			expected: "https://APP.EXAMPLESUITE.APP/dashboard",
		},

		// Default path
		{
			name:        "use custom default path",
			redirectURL: "javascript:alert(1)",
			config:      RedirectValidationConfig{DefaultPath: "/dashboard"},
			expected:    "/dashboard",
		},
		{
			name:        "use custom default path for empty string",
			redirectURL: "",
			config:      RedirectValidationConfig{DefaultPath: "/home"},
			expected:    "/home",
		},

		// Edge cases
		{
			name:        "handle empty string",
			redirectURL: "",
			config:      RedirectValidationConfig{DefaultPath: "/"},
			expected:    "/",
		},
		{
			name:        "handle whitespace",
			redirectURL: "   ",
			config:      RedirectValidationConfig{DefaultPath: "/"},
			expected:    "/",
		},
		{
			name:        "handle malformed URL",
			redirectURL: "not a url",
			config:      RedirectValidationConfig{AllowRelativePaths: false, DefaultPath: "/"},
			expected:    "/",
		},
		{
			name:        "allow query parameters",
			redirectURL: "/dashboard?tab=settings",
			config:      RedirectValidationConfig{AllowRelativePaths: true, DefaultPath: "/"},
			expected:    "/dashboard?tab=settings",
		},
		{
			name:        "allow fragments",
			redirectURL: "/dashboard#profile",
			config:      RedirectValidationConfig{AllowRelativePaths: true, DefaultPath: "/"},
			expected:    "/dashboard#profile",
		},
		{
			name:        "reject ftp protocol",
			redirectURL: "ftp://example.com/file",
			config:      RedirectValidationConfig{DefaultPath: "/"},
			expected:    "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateRedirectURL(tt.redirectURL, tt.config)
			if result != tt.expected {
				t.Errorf("ValidateRedirectURL(%q, %+v) = %q, want %q",
					tt.redirectURL, tt.config, result, tt.expected)
			}
		})
	}
}

func TestCreateRedirectValidator(t *testing.T) {
	validator := CreateRedirectValidator(RedirectValidationConfig{
		BaseDomain:         "example.app",
		DefaultPath:        "/dashboard",
		AllowRelativePaths: true,
	})

	tests := []struct {
		input    string
		expected string
	}{
		{"https://app.example.app/users", "https://app.example.app/users"},
		{"https://evil.com", "/dashboard"},
		{"/relative", "/relative"},
		{"javascript:alert(1)", "/dashboard"},
	}

	for _, tt := range tests {
		result := validator(tt.input)
		if result != tt.expected {
			t.Errorf("validator(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}
