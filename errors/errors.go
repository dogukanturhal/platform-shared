// SPDX-License-Identifier: Apache-2.0

package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// ErrorCode represents a standardized error code
type ErrorCode string

// Error codes for client errors (4xx) and server errors (5xx).
const (
	// ErrCodeBadRequest is the error code for 400 Bad Request errors.
	ErrCodeBadRequest          ErrorCode = "BAD_REQUEST"
	ErrCodeValidation          ErrorCode = "VALIDATION_ERROR"
	ErrCodeUnauthorized        ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden           ErrorCode = "FORBIDDEN"
	ErrCodeNotFound            ErrorCode = "NOT_FOUND"
	ErrCodeConflict            ErrorCode = "CONFLICT"
	ErrCodeTooManyRequests     ErrorCode = "TOO_MANY_REQUESTS"
	ErrCodeUnprocessableEntity ErrorCode = "UNPROCESSABLE_ENTITY"

	// ErrCodeInternalServer is the error code for 500 Internal Server Error.
	ErrCodeInternalServer     ErrorCode = "INTERNAL_SERVER_ERROR"
	ErrCodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	ErrCodeBadGateway         ErrorCode = "BAD_GATEWAY"
	ErrCodeGatewayTimeout     ErrorCode = "GATEWAY_TIMEOUT"
)

// APIError represents a standardized API error
type APIError struct {
	Code       ErrorCode              `json:"code"`
	Message    string                 `json:"message"`
	Details    map[string]interface{} `json:"details,omitempty"`
	StatusCode int                    `json:"-"`
	Err        error                  `json:"-"`
}

// Error implements the error interface
func (e *APIError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s - %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error
func (e *APIError) Unwrap() error {
	return e.Err
}

// WithDetails adds details to the error
func (e *APIError) WithDetails(details map[string]interface{}) *APIError {
	e.Details = details
	return e
}

// WithError wraps an underlying error
func (e *APIError) WithError(err error) *APIError {
	e.Err = err
	return e
}

// NewAPIError creates a new API error
func NewAPIError(code ErrorCode, statusCode int, message string) *APIError {
	return &APIError{
		Code:       code,
		StatusCode: statusCode,
		Message:    message,
	}
}

// Common error constructors

// BadRequest creates a 400 Bad Request error
func BadRequest(message string) *APIError {
	return NewAPIError(ErrCodeBadRequest, http.StatusBadRequest, message)
}

// ValidationError creates a 400 validation error with field details
func ValidationError(message string, fields map[string]string) *APIError {
	details := make(map[string]interface{})
	for k, v := range fields {
		details[k] = v
	}
	return NewAPIError(ErrCodeValidation, http.StatusBadRequest, message).WithDetails(details)
}

// Unauthorized creates a 401 Unauthorized error
func Unauthorized(message string) *APIError {
	if message == "" {
		message = "Authentication required"
	}
	return NewAPIError(ErrCodeUnauthorized, http.StatusUnauthorized, message)
}

// Forbidden creates a 403 Forbidden error
func Forbidden(message string) *APIError {
	if message == "" {
		message = "Access denied"
	}
	return NewAPIError(ErrCodeForbidden, http.StatusForbidden, message)
}

// NotFound creates a 404 Not Found error
func NotFound(resource string) *APIError {
	message := "Resource not found"
	if resource != "" {
		message = fmt.Sprintf("%s not found", resource)
	}
	return NewAPIError(ErrCodeNotFound, http.StatusNotFound, message)
}

// Conflict creates a 409 Conflict error
func Conflict(message string) *APIError {
	return NewAPIError(ErrCodeConflict, http.StatusConflict, message)
}

// TooManyRequests creates a 429 Too Many Requests error
func TooManyRequests(message string) *APIError {
	if message == "" {
		message = "Too many requests. Please try again later"
	}
	return NewAPIError(ErrCodeTooManyRequests, http.StatusTooManyRequests, message)
}

// UnprocessableEntity creates a 422 Unprocessable Entity error
func UnprocessableEntity(message string) *APIError {
	return NewAPIError(ErrCodeUnprocessableEntity, http.StatusUnprocessableEntity, message)
}

// InternalServerError creates a 500 Internal Server Error
func InternalServerError(message string) *APIError {
	if message == "" {
		message = "An unexpected error occurred"
	}
	return NewAPIError(ErrCodeInternalServer, http.StatusInternalServerError, message)
}

// ServiceUnavailable creates a 503 Service Unavailable error
func ServiceUnavailable(message string) *APIError {
	if message == "" {
		message = "Service temporarily unavailable"
	}
	return NewAPIError(ErrCodeServiceUnavailable, http.StatusServiceUnavailable, message)
}

// BadGateway creates a 502 Bad Gateway error
func BadGateway(message string) *APIError {
	if message == "" {
		message = "Bad gateway"
	}
	return NewAPIError(ErrCodeBadGateway, http.StatusBadGateway, message)
}

// GatewayTimeout creates a 504 Gateway Timeout error
func GatewayTimeout(message string) *APIError {
	if message == "" {
		message = "Gateway timeout"
	}
	return NewAPIError(ErrCodeGatewayTimeout, http.StatusGatewayTimeout, message)
}

// IsAPIError checks if an error is an APIError
func IsAPIError(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr)
}

// GetAPIError extracts APIError from an error, returns nil if not an APIError
func GetAPIError(err error) *APIError {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return nil
}
