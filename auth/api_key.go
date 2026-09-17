// SPDX-License-Identifier: Apache-2.0

// Package auth provides authentication utilities including JWT validation,
// API key management, and middleware for Gin-based HTTP services.
package auth

import (
	"crypto/subtle"
)

// APIKeyValidator provides API key validation functionality
type APIKeyValidator struct {
	config *Config
}

// NewAPIKeyValidator creates a new APIKeyValidator
func NewAPIKeyValidator(config *Config) *APIKeyValidator {
	return &APIKeyValidator{
		config: config,
	}
}

// ValidateInternalAPIKey validates an API key against the configured internal key.
// Uses constant-time comparison to prevent timing attacks.
//
// Deprecated: Use ValidateServiceAPIKey for scoped key validation instead.
func (v *APIKeyValidator) ValidateInternalAPIKey(apiKey string) bool {
	if v.config.InternalAPIKey == "" || apiKey == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(apiKey), []byte(v.config.InternalAPIKey)) == 1
}

// ValidateServiceAPIKey validates an API key against the configured scoped service keys.
// Returns the matched ServiceAPIKey and true if found, or zero-value and false if not.
// Uses constant-time comparison against all configured keys to prevent timing attacks.
func (v *APIKeyValidator) ValidateServiceAPIKey(apiKey string) (ServiceAPIKey, bool) {
	if apiKey == "" || len(v.config.ServiceAPIKeys) == 0 {
		return ServiceAPIKey{}, false
	}

	apiKeyBytes := []byte(apiKey)
	var matched ServiceAPIKey
	found := false

	for _, sak := range v.config.ServiceAPIKeys {
		if subtle.ConstantTimeCompare(apiKeyBytes, []byte(sak.Key)) == 1 {
			matched = ServiceAPIKey{
				Key:         sak.Key,
				ServiceName: sak.ServiceName,
				Permissions: sak.Permissions,
			}
			found = true
		}
	}

	return matched, found
}

// ValidateAnyAPIKey validates the provided key against both scoped service keys
// and the legacy internal key. Returns the service name, permissions, and whether
// the key matched. Scoped keys take precedence over the legacy key.
func (v *APIKeyValidator) ValidateAnyAPIKey(apiKey string) (serviceName string, permissions []string, ok bool) {
	if apiKey == "" {
		return "", nil, false
	}

	// Try scoped keys first
	if sak, found := v.ValidateServiceAPIKey(apiKey); found {
		return sak.ServiceName, sak.Permissions, true
	}

	// Fall back to legacy key
	if v.ValidateInternalAPIKey(apiKey) {
		return "legacy-internal", []string{"internal:service:read", "internal:service:write"}, true
	}

	return "", nil, false
}

// IsInternalAPIKey checks if a string looks like an internal API key
// This is used to determine the authentication method
func IsInternalAPIKey(key string) bool {
	// Internal API keys typically don't have a specific prefix
	// They are simple random strings
	return len(key) >= 32 && len(key) <= 128
}

// IsHexxlockAPIKey checks if a string looks like a HexxLock API key
// HexxLock API keys have the format: hxk_<base64_encoded_data>
func IsHexxlockAPIKey(key string) bool {
	return len(key) > 4 && key[:4] == "hxk_"
}

// IsServiceAccountToken checks if a string looks like a service account token
// Service account tokens have the format: hxs_<base64_encoded_data>
func IsServiceAccountToken(key string) bool {
	return len(key) > 4 && key[:4] == "hxs_"
}
