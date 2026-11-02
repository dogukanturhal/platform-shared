// SPDX-License-Identifier: Apache-2.0

// Package errors provides standardized error types and codes for multi-tenant services.
package errors

import "net/http"

// Auth-specific error codes for consistent error handling across all services
// These error codes align with the frontend AuthErrorCodes in @hexxlock/shared-utils
const (
	// Token validation errors (401)
	ErrCodeAuthInvalidToken ErrorCode = "AUTH_INVALID_TOKEN" //nolint:gosec // error code, not a credential
	ErrCodeAuthTokenExpired ErrorCode = "AUTH_TOKEN_EXPIRED" //nolint:gosec // error code, not a credential
	ErrCodeAuthMissingToken ErrorCode = "AUTH_MISSING_TOKEN" //nolint:gosec // error code, not a credential

	// Permission errors (403)
	ErrCodeAuthPermissionDenied ErrorCode = "AUTH_PERMISSION_DENIED"
	ErrCodeAuthTenantMismatch   ErrorCode = "AUTH_TENANT_MISMATCH"

	// Rate limiting (429)
	ErrCodeAuthRateLimited ErrorCode = "AUTH_RATE_LIMITED"

	// Realm errors (404/403)
	ErrCodeAuthRealmNotFound ErrorCode = "AUTH_REALM_NOT_FOUND"
	ErrCodeAuthRealmInactive ErrorCode = "AUTH_REALM_INACTIVE"
)

// Auth error constructors

// InvalidToken creates an AUTH_INVALID_TOKEN error (401)
// Use when the provided token is malformed, has invalid signature, or is otherwise invalid
func InvalidToken(message string) *APIError {
	if message == "" {
		message = "Invalid authentication token"
	}
	return NewAPIError(ErrCodeAuthInvalidToken, http.StatusUnauthorized, message)
}

// TokenExpired creates an AUTH_TOKEN_EXPIRED error (401)
// Use when the token has passed its expiration time
func TokenExpired(message string) *APIError {
	if message == "" {
		message = "Authentication token has expired"
	}
	return NewAPIError(ErrCodeAuthTokenExpired, http.StatusUnauthorized, message)
}

// MissingToken creates an AUTH_MISSING_TOKEN error (401)
// Use when no authentication token was provided in the request
func MissingToken(message string) *APIError {
	if message == "" {
		message = "Authentication token is required"
	}
	return NewAPIError(ErrCodeAuthMissingToken, http.StatusUnauthorized, message)
}

// PermissionDenied creates an AUTH_PERMISSION_DENIED error (403)
// Use when the user lacks the required permission for the operation
func PermissionDenied(message string) *APIError {
	if message == "" {
		message = "You do not have permission to perform this action"
	}
	return NewAPIError(ErrCodeAuthPermissionDenied, http.StatusForbidden, message)
}

// TenantMismatch creates an AUTH_TENANT_MISMATCH error (403)
// Use when the user attempts to access resources from a different tenant
func TenantMismatch(message string) *APIError {
	if message == "" {
		message = "Access denied: tenant mismatch"
	}
	return NewAPIError(ErrCodeAuthTenantMismatch, http.StatusForbidden, message)
}

// AuthRateLimited creates an AUTH_RATE_LIMITED error (429)
// Use when authentication attempts have exceeded the rate limit
func AuthRateLimited(message string) *APIError {
	if message == "" {
		message = "Too many authentication attempts. Please try again later"
	}
	return NewAPIError(ErrCodeAuthRateLimited, http.StatusTooManyRequests, message)
}

// RealmNotFound creates an AUTH_REALM_NOT_FOUND error (404)
// Use when the specified realm does not exist
func RealmNotFound(message string) *APIError {
	if message == "" {
		message = "Realm not found"
	}
	return NewAPIError(ErrCodeAuthRealmNotFound, http.StatusNotFound, message)
}

// RealmInactive creates an AUTH_REALM_INACTIVE error (403)
// Use when the realm exists but is not in an active state
func RealmInactive(message string) *APIError {
	if message == "" {
		message = "Realm is not active"
	}
	return NewAPIError(ErrCodeAuthRealmInactive, http.StatusForbidden, message)
}
