// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"github.com/dogukanturhal/platform-shared/errors"
)

// Auth-specific error codes
const (
	ErrCodeTokenExpired      errors.ErrorCode = "TOKEN_EXPIRED"
	ErrCodeTokenInvalid      errors.ErrorCode = "TOKEN_INVALID"
	ErrCodeTokenMalformed    errors.ErrorCode = "TOKEN_MALFORMED" //nolint:gosec // error code, not a credential
	ErrCodeTokenRevoked      errors.ErrorCode = "TOKEN_REVOKED"
	ErrCodeMissingToken      errors.ErrorCode = "MISSING_TOKEN"
	ErrCodeInvalidAPIKey     errors.ErrorCode = "INVALID_API_KEY" //nolint:gosec // error code, not a credential
	ErrCodeMissingTenant     errors.ErrorCode = "MISSING_TENANT"
	ErrCodePermissionDenied  errors.ErrorCode = "PERMISSION_DENIED"
	ErrCodeInsufficientRoles errors.ErrorCode = "INSUFFICIENT_ROLES"
	ErrCodeInvalidSignature  errors.ErrorCode = "INVALID_SIGNATURE"
)

// Auth-specific error constructors

// ErrTokenExpired creates an error for expired tokens
func ErrTokenExpired() *errors.APIError {
	return errors.NewAPIError(ErrCodeTokenExpired, 401, "Token has expired")
}

// ErrTokenInvalid creates an error for invalid tokens
func ErrTokenInvalid(reason string) *errors.APIError {
	msg := "Invalid token"
	if reason != "" {
		msg = reason
	}
	return errors.NewAPIError(ErrCodeTokenInvalid, 401, msg)
}

// ErrTokenMalformed creates an error for malformed tokens
func ErrTokenMalformed() *errors.APIError {
	return errors.NewAPIError(ErrCodeTokenMalformed, 401, "Token is malformed")
}

// ErrTokenRevoked creates an error for revoked tokens
func ErrTokenRevoked() *errors.APIError {
	return errors.NewAPIError(ErrCodeTokenRevoked, 401, "Token has been revoked")
}

// ErrMissingToken creates an error for missing authorization header
func ErrMissingToken() *errors.APIError {
	return errors.NewAPIError(ErrCodeMissingToken, 401, "Authorization header required")
}

// ErrInvalidAPIKey creates an error for invalid API keys
func ErrInvalidAPIKey() *errors.APIError {
	return errors.NewAPIError(ErrCodeInvalidAPIKey, 401, "Invalid API key")
}

// ErrMissingTenant creates an error for missing tenant context
func ErrMissingTenant() *errors.APIError {
	return errors.NewAPIError(ErrCodeMissingTenant, 400, "Tenant context required")
}

// ErrPermissionDenied creates an error for permission denied
func ErrPermissionDenied(permission string) *errors.APIError {
	msg := "Permission denied"
	if permission != "" {
		msg = "Permission denied: " + permission + " required"
	}
	return errors.NewAPIError(ErrCodePermissionDenied, 403, msg)
}

// ErrInsufficientRoles creates an error for insufficient roles
func ErrInsufficientRoles(role string) *errors.APIError {
	msg := "Insufficient roles"
	if role != "" {
		msg = "Role required: " + role
	}
	return errors.NewAPIError(ErrCodeInsufficientRoles, 403, msg)
}

// ErrInvalidSignature creates an error for invalid token signature
func ErrInvalidSignature() *errors.APIError {
	return errors.NewAPIError(ErrCodeInvalidSignature, 401, "Invalid token signature")
}
