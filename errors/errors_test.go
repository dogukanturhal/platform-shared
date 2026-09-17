// SPDX-License-Identifier: Apache-2.0

package errors

import (
	"errors"
	"net/http"
	"testing"
)

func TestAPIError_Error(t *testing.T) {
	tests := []struct {
		name     string
		apiErr   *APIError
		expected string
	}{
		{
			name: "error without underlying error",
			apiErr: &APIError{
				Code:    ErrCodeBadRequest,
				Message: "Invalid input",
			},
			expected: "BAD_REQUEST: Invalid input",
		},
		{
			name: "error with underlying error",
			apiErr: &APIError{
				Code:    ErrCodeInternalServer,
				Message: "Database error",
				Err:     errors.New("connection timeout"),
			},
			expected: "INTERNAL_SERVER_ERROR: Database error - connection timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.apiErr.Error()
			if got != tt.expected {
				t.Errorf("Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAPIError_Unwrap(t *testing.T) {
	underlyingErr := errors.New("underlying error")
	apiErr := &APIError{
		Code:    ErrCodeInternalServer,
		Message: "Wrapper error",
		Err:     underlyingErr,
	}

	unwrapped := apiErr.Unwrap()
	if unwrapped != underlyingErr { //nolint:errorlint // testing exact Unwrap() identity
		t.Errorf("Unwrap() = %v, want %v", unwrapped, underlyingErr)
	}

	// Test nil case
	apiErr2 := &APIError{
		Code:    ErrCodeBadRequest,
		Message: "No underlying error",
	}
	if unwrapped := apiErr2.Unwrap(); unwrapped != nil {
		t.Errorf("Unwrap() = %v, want nil", unwrapped)
	}
}

func TestAPIError_WithDetails(t *testing.T) {
	apiErr := &APIError{
		Code:    ErrCodeValidation,
		Message: "Validation failed",
	}

	details := map[string]interface{}{
		"field1": "error message 1",
		"field2": "error message 2",
	}

	result := apiErr.WithDetails(details)

	if result.Details == nil {
		t.Fatal("WithDetails() returned nil details")
	}

	if len(result.Details) != 2 {
		t.Errorf("WithDetails() got %d details, want 2", len(result.Details))
	}

	if result.Details["field1"] != "error message 1" {
		t.Errorf("WithDetails() field1 = %v, want 'error message 1'", result.Details["field1"])
	}
}

func TestAPIError_WithError(t *testing.T) {
	apiErr := &APIError{
		Code:    ErrCodeInternalServer,
		Message: "Server error",
	}

	underlyingErr := errors.New("database connection failed")
	result := apiErr.WithError(underlyingErr)

	if result.Err != underlyingErr { //nolint:errorlint // testing exact WithError() identity
		t.Errorf("WithError() = %v, want %v", result.Err, underlyingErr)
	}
}

func TestNewAPIError(t *testing.T) {
	code := ErrCodeNotFound
	statusCode := http.StatusNotFound
	message := "Resource not found"

	apiErr := NewAPIError(code, statusCode, message)

	if apiErr.Code != code {
		t.Errorf("NewAPIError() Code = %v, want %v", apiErr.Code, code)
	}
	if apiErr.StatusCode != statusCode {
		t.Errorf("NewAPIError() StatusCode = %v, want %v", apiErr.StatusCode, statusCode)
	}
	if apiErr.Message != message {
		t.Errorf("NewAPIError() Message = %v, want %v", apiErr.Message, message)
	}
}

func TestBadRequest(t *testing.T) {
	message := "Invalid request parameters"
	apiErr := BadRequest(message)

	if apiErr.Code != ErrCodeBadRequest {
		t.Errorf("BadRequest() Code = %v, want %v", apiErr.Code, ErrCodeBadRequest)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("BadRequest() StatusCode = %v, want %v", apiErr.StatusCode, http.StatusBadRequest)
	}
	if apiErr.Message != message {
		t.Errorf("BadRequest() Message = %v, want %v", apiErr.Message, message)
	}
}

func TestValidationError(t *testing.T) {
	message := "Validation failed"
	fields := map[string]string{
		"email": "invalid email format",
		"name":  "name is required",
	}

	apiErr := ValidationError(message, fields)

	if apiErr.Code != ErrCodeValidation {
		t.Errorf("ValidationError() Code = %v, want %v", apiErr.Code, ErrCodeValidation)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("ValidationError() StatusCode = %v, want %v", apiErr.StatusCode, http.StatusBadRequest)
	}
	if apiErr.Message != message {
		t.Errorf("ValidationError() Message = %v, want %v", apiErr.Message, message)
	}
	if len(apiErr.Details) != 2 {
		t.Errorf("ValidationError() got %d details, want 2", len(apiErr.Details))
	}
}

func TestUnauthorized(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		expectedMessage string
	}{
		{
			name:            "with custom message",
			message:         "Invalid token",
			expectedMessage: "Invalid token",
		},
		{
			name:            "with empty message",
			message:         "",
			expectedMessage: "Authentication required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiErr := Unauthorized(tt.message)

			if apiErr.Code != ErrCodeUnauthorized {
				t.Errorf("Unauthorized() Code = %v, want %v", apiErr.Code, ErrCodeUnauthorized)
			}
			if apiErr.StatusCode != http.StatusUnauthorized {
				t.Errorf("Unauthorized() StatusCode = %v, want %v", apiErr.StatusCode, http.StatusUnauthorized)
			}
			if apiErr.Message != tt.expectedMessage {
				t.Errorf("Unauthorized() Message = %v, want %v", apiErr.Message, tt.expectedMessage)
			}
		})
	}
}

func TestForbidden(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		expectedMessage string
	}{
		{
			name:            "with custom message",
			message:         "Insufficient permissions",
			expectedMessage: "Insufficient permissions",
		},
		{
			name:            "with empty message",
			message:         "",
			expectedMessage: "Access denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiErr := Forbidden(tt.message)

			if apiErr.Code != ErrCodeForbidden {
				t.Errorf("Forbidden() Code = %v, want %v", apiErr.Code, ErrCodeForbidden)
			}
			if apiErr.StatusCode != http.StatusForbidden {
				t.Errorf("Forbidden() StatusCode = %v, want %v", apiErr.StatusCode, http.StatusForbidden)
			}
			if apiErr.Message != tt.expectedMessage {
				t.Errorf("Forbidden() Message = %v, want %v", apiErr.Message, tt.expectedMessage)
			}
		})
	}
}

func TestNotFound(t *testing.T) {
	tests := []struct {
		name            string
		resource        string
		expectedMessage string
	}{
		{
			name:            "with resource name",
			resource:        "User",
			expectedMessage: "User not found",
		},
		{
			name:            "without resource name",
			resource:        "",
			expectedMessage: "Resource not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiErr := NotFound(tt.resource)

			if apiErr.Code != ErrCodeNotFound {
				t.Errorf("NotFound() Code = %v, want %v", apiErr.Code, ErrCodeNotFound)
			}
			if apiErr.StatusCode != http.StatusNotFound {
				t.Errorf("NotFound() StatusCode = %v, want %v", apiErr.StatusCode, http.StatusNotFound)
			}
			if apiErr.Message != tt.expectedMessage {
				t.Errorf("NotFound() Message = %v, want %v", apiErr.Message, tt.expectedMessage)
			}
		})
	}
}

func TestConflict(t *testing.T) {
	message := "Resource already exists"
	apiErr := Conflict(message)

	if apiErr.Code != ErrCodeConflict {
		t.Errorf("Conflict() Code = %v, want %v", apiErr.Code, ErrCodeConflict)
	}
	if apiErr.StatusCode != http.StatusConflict {
		t.Errorf("Conflict() StatusCode = %v, want %v", apiErr.StatusCode, http.StatusConflict)
	}
	if apiErr.Message != message {
		t.Errorf("Conflict() Message = %v, want %v", apiErr.Message, message)
	}
}

func TestTooManyRequests(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		expectedMessage string
	}{
		{
			name:            "with custom message",
			message:         "Rate limit: 100 requests per minute",
			expectedMessage: "Rate limit: 100 requests per minute",
		},
		{
			name:            "with empty message",
			message:         "",
			expectedMessage: "Too many requests. Please try again later",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiErr := TooManyRequests(tt.message)

			if apiErr.Code != ErrCodeTooManyRequests {
				t.Errorf("TooManyRequests() Code = %v, want %v", apiErr.Code, ErrCodeTooManyRequests)
			}
			if apiErr.StatusCode != http.StatusTooManyRequests {
				t.Errorf("TooManyRequests() StatusCode = %v, want %v", apiErr.StatusCode, http.StatusTooManyRequests)
			}
			if apiErr.Message != tt.expectedMessage {
				t.Errorf("TooManyRequests() Message = %v, want %v", apiErr.Message, tt.expectedMessage)
			}
		})
	}
}

func TestUnprocessableEntity(t *testing.T) {
	message := "Cannot process entity"
	apiErr := UnprocessableEntity(message)

	if apiErr.Code != ErrCodeUnprocessableEntity {
		t.Errorf("UnprocessableEntity() Code = %v, want %v", apiErr.Code, ErrCodeUnprocessableEntity)
	}
	if apiErr.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("UnprocessableEntity() StatusCode = %v, want %v", apiErr.StatusCode, http.StatusUnprocessableEntity)
	}
	if apiErr.Message != message {
		t.Errorf("UnprocessableEntity() Message = %v, want %v", apiErr.Message, message)
	}
}

func TestInternalServerError(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		expectedMessage string
	}{
		{
			name:            "with custom message",
			message:         "Database connection failed",
			expectedMessage: "Database connection failed",
		},
		{
			name:            "with empty message",
			message:         "",
			expectedMessage: "An unexpected error occurred",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiErr := InternalServerError(tt.message)

			if apiErr.Code != ErrCodeInternalServer {
				t.Errorf("InternalServerError() Code = %v, want %v", apiErr.Code, ErrCodeInternalServer)
			}
			if apiErr.StatusCode != http.StatusInternalServerError {
				t.Errorf("InternalServerError() StatusCode = %v, want %v", apiErr.StatusCode, http.StatusInternalServerError)
			}
			if apiErr.Message != tt.expectedMessage {
				t.Errorf("InternalServerError() Message = %v, want %v", apiErr.Message, tt.expectedMessage)
			}
		})
	}
}

func TestServiceUnavailable(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		expectedMessage string
	}{
		{
			name:            "with custom message",
			message:         "Maintenance in progress",
			expectedMessage: "Maintenance in progress",
		},
		{
			name:            "with empty message",
			message:         "",
			expectedMessage: "Service temporarily unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiErr := ServiceUnavailable(tt.message)

			if apiErr.Code != ErrCodeServiceUnavailable {
				t.Errorf("ServiceUnavailable() Code = %v, want %v", apiErr.Code, ErrCodeServiceUnavailable)
			}
			if apiErr.StatusCode != http.StatusServiceUnavailable {
				t.Errorf("ServiceUnavailable() StatusCode = %v, want %v", apiErr.StatusCode, http.StatusServiceUnavailable)
			}
			if apiErr.Message != tt.expectedMessage {
				t.Errorf("ServiceUnavailable() Message = %v, want %v", apiErr.Message, tt.expectedMessage)
			}
		})
	}
}

func TestBadGateway(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		expectedMessage string
	}{
		{
			name:            "with custom message",
			message:         "Upstream service failed",
			expectedMessage: "Upstream service failed",
		},
		{
			name:            "with empty message",
			message:         "",
			expectedMessage: "Bad gateway",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiErr := BadGateway(tt.message)

			if apiErr.Code != ErrCodeBadGateway {
				t.Errorf("BadGateway() Code = %v, want %v", apiErr.Code, ErrCodeBadGateway)
			}
			if apiErr.StatusCode != http.StatusBadGateway {
				t.Errorf("BadGateway() StatusCode = %v, want %v", apiErr.StatusCode, http.StatusBadGateway)
			}
			if apiErr.Message != tt.expectedMessage {
				t.Errorf("BadGateway() Message = %v, want %v", apiErr.Message, tt.expectedMessage)
			}
		})
	}
}

func TestGatewayTimeout(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		expectedMessage string
	}{
		{
			name:            "with custom message",
			message:         "Request timeout after 30s",
			expectedMessage: "Request timeout after 30s",
		},
		{
			name:            "with empty message",
			message:         "",
			expectedMessage: "Gateway timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiErr := GatewayTimeout(tt.message)

			if apiErr.Code != ErrCodeGatewayTimeout {
				t.Errorf("GatewayTimeout() Code = %v, want %v", apiErr.Code, ErrCodeGatewayTimeout)
			}
			if apiErr.StatusCode != http.StatusGatewayTimeout {
				t.Errorf("GatewayTimeout() StatusCode = %v, want %v", apiErr.StatusCode, http.StatusGatewayTimeout)
			}
			if apiErr.Message != tt.expectedMessage {
				t.Errorf("GatewayTimeout() Message = %v, want %v", apiErr.Message, tt.expectedMessage)
			}
		})
	}
}

func TestIsAPIError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "is API error",
			err:      &APIError{Code: ErrCodeBadRequest, Message: "test"},
			expected: true,
		},
		{
			name:     "is not API error",
			err:      errors.New("regular error"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAPIError(tt.err)
			if result != tt.expected {
				t.Errorf("IsAPIError() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetAPIError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected *APIError
	}{
		{
			name: "get API error",
			err: &APIError{
				Code:       ErrCodeBadRequest,
				Message:    "test error",
				StatusCode: http.StatusBadRequest,
			},
			expected: &APIError{
				Code:       ErrCodeBadRequest,
				Message:    "test error",
				StatusCode: http.StatusBadRequest,
			},
		},
		{
			name:     "get non-API error",
			err:      errors.New("regular error"),
			expected: nil,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetAPIError(tt.err)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("GetAPIError() = %v, want nil", result)
				}
				return
			}
			if result == nil {
				t.Fatalf("GetAPIError() = nil, want non-nil")
			}
			if result.Code != tt.expected.Code {
				t.Errorf("GetAPIError() Code = %v, want %v", result.Code, tt.expected.Code)
			}
			if result.Message != tt.expected.Message {
				t.Errorf("GetAPIError() Message = %v, want %v", result.Message, tt.expected.Message)
			}
		})
	}
}
