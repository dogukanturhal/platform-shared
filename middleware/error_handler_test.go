// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	sharedErrors "github.com/dogukanturhal/platform-shared/errors"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestErrorHandler(t *testing.T) {
	tests := []struct {
		name               string
		setupHandler       func(*gin.Context)
		expectedStatusCode int
	}{
		{
			name: "no errors",
			setupHandler: func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			},
			expectedStatusCode: http.StatusOK,
		},
		{
			name: "API error",
			setupHandler: func(c *gin.Context) {
				_ = c.Error(sharedErrors.BadRequest("Invalid input"))
			},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name: "regular error converted to internal server error",
			setupHandler: func(c *gin.Context) {
				_ = c.Error(errors.New("some error"))
			},
			expectedStatusCode: http.StatusInternalServerError,
		},
		{
			name: "multiple errors - last one wins",
			setupHandler: func(c *gin.Context) {
				_ = c.Error(errors.New("first error"))
				_ = c.Error(sharedErrors.NotFound("User"))
			},
			expectedStatusCode: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, r := gin.CreateTestContext(w)

			r.Use(ErrorHandler())
			r.GET("/test", tt.setupHandler)

			c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
			r.ServeHTTP(w, c.Request)

			if w.Code != tt.expectedStatusCode {
				t.Errorf("ErrorHandler() status = %v, want %v", w.Code, tt.expectedStatusCode)
			}
		})
	}
}

func TestErrorHandlerWithConfig(t *testing.T) {
	var logCalled bool
	mockLogger := slog.New(slog.NewTextHandler(io.Discard, nil))

	config := ErrorHandlerConfig{
		Logger:         mockLogger,
		ShowStackTrace: true,
	}

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	r.Use(ErrorHandler(config))
	r.GET("/test", func(c *gin.Context) {
		logCalled = true
		_ = c.Error(sharedErrors.BadRequest("test error"))
	})

	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	r.ServeHTTP(w, c.Request)

	if w.Code != http.StatusBadRequest {
		t.Errorf("ErrorHandler() status = %v, want %v", w.Code, http.StatusBadRequest)
	}

	if !logCalled {
		t.Error("ErrorHandler() should have called the handler")
	}
}

func TestRecovery(t *testing.T) {
	tests := []struct {
		name         string
		setupHandler func(*gin.Context)
		shouldPanic  bool
		expectedCode int
	}{
		{
			name: "no panic",
			setupHandler: func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			},
			shouldPanic:  false,
			expectedCode: http.StatusOK,
		},
		{
			name: "panic with string",
			setupHandler: func(_ *gin.Context) {
				panic("something went wrong")
			},
			shouldPanic:  true,
			expectedCode: http.StatusInternalServerError,
		},
		{
			name: "panic with error",
			setupHandler: func(_ *gin.Context) {
				panic(errors.New("critical error"))
			},
			shouldPanic:  true,
			expectedCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, r := gin.CreateTestContext(w)

			r.Use(Recovery())
			r.GET("/test", tt.setupHandler)

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedCode {
				t.Errorf("Recovery() status = %v, want %v", w.Code, tt.expectedCode)
			}

			// Note: When using ServeHTTP, gin creates an internal context for the request.
			// The panic is recovered and the response is properly set, which we verify above.
			// If the panic wasn't recovered, this test would crash.
		})
	}
}

func TestRecoveryWithOnPanicCallback(t *testing.T) {
	var onPanicCalled bool
	var capturedPanic interface{}

	config := ErrorHandlerConfig{
		Logger:         slog.Default(),
		ShowStackTrace: true,
		OnPanic: func(_ *gin.Context, recovered interface{}, _ []byte) {
			onPanicCalled = true
			capturedPanic = recovered
		},
	}

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	r.Use(Recovery(config))
	r.GET("/test", func(_ *gin.Context) {
		panic("test panic")
	})

	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	r.ServeHTTP(w, c.Request)

	if !onPanicCalled {
		t.Error("Recovery() should have called OnPanic callback")
	}

	if capturedPanic != "test panic" {
		t.Errorf("Recovery() captured panic = %v, want 'test panic'", capturedPanic)
	}

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Recovery() status = %v, want %v", w.Code, http.StatusInternalServerError)
	}
}

func TestGlobalErrorHandler(t *testing.T) {
	tests := []struct {
		name               string
		setupHandler       func(*gin.Context)
		expectedStatusCode int
	}{
		{
			name: "handles panic",
			setupHandler: func(_ *gin.Context) {
				panic("critical error")
			},
			expectedStatusCode: http.StatusInternalServerError,
		},
		{
			name: "handles API error",
			setupHandler: func(c *gin.Context) {
				_ = c.Error(sharedErrors.Unauthorized("Invalid token"))
			},
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name: "successful request",
			setupHandler: func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			},
			expectedStatusCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, r := gin.CreateTestContext(w)

			r.Use(GlobalErrorHandler())
			r.GET("/test", tt.setupHandler)

			c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
			r.ServeHTTP(w, c.Request)

			if w.Code != tt.expectedStatusCode {
				t.Errorf("GlobalErrorHandler() status = %v, want %v", w.Code, tt.expectedStatusCode)
			}
		})
	}
}

func TestRequestErrorLogger(t *testing.T) {
	mockLogger := slog.Default()

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	r.Use(RequestErrorLogger(mockLogger))
	r.GET("/test", func(c *gin.Context) {
		_ = c.Error(sharedErrors.BadRequest("test error"))
		c.JSON(http.StatusBadRequest, gin.H{"error": "test"})
	})

	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	c.Set("request_id", "test-request-id")
	r.ServeHTTP(w, c.Request)

	if w.Code != http.StatusBadRequest {
		t.Errorf("RequestErrorLogger() status = %v, want %v", w.Code, http.StatusBadRequest)
	}
}

func TestHandleServiceError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedStatus int
		expectedCode   sharedErrors.ErrorCode
	}{
		{
			name:           "nil error",
			err:            nil,
			expectedStatus: 0,
			expectedCode:   "",
		},
		{
			name:           "already API error",
			err:            sharedErrors.BadRequest("test"),
			expectedStatus: http.StatusBadRequest,
			expectedCode:   sharedErrors.ErrCodeBadRequest,
		},
		{
			name:           "not found pattern",
			err:            errors.New("record not found"),
			expectedStatus: http.StatusNotFound,
			expectedCode:   sharedErrors.ErrCodeNotFound,
		},
		{
			name:           "not found pattern - no rows",
			err:            errors.New("no rows in result set"),
			expectedStatus: http.StatusNotFound,
			expectedCode:   sharedErrors.ErrCodeNotFound,
		},
		{
			name:           "duplicate pattern",
			err:            errors.New("duplicate key value violates unique constraint"),
			expectedStatus: http.StatusConflict,
			expectedCode:   sharedErrors.ErrCodeConflict,
		},
		{
			name:           "already exists pattern",
			err:            errors.New("user already exists"),
			expectedStatus: http.StatusConflict,
			expectedCode:   sharedErrors.ErrCodeConflict,
		},
		{
			name:           "unauthorized pattern",
			err:            errors.New("invalid token provided"),
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   sharedErrors.ErrCodeUnauthorized,
		},
		{
			name:           "forbidden pattern",
			err:            errors.New("permission denied"),
			expectedStatus: http.StatusForbidden,
			expectedCode:   sharedErrors.ErrCodeForbidden,
		},
		{
			name:           "validation pattern",
			err:            errors.New("validation error: field is required"),
			expectedStatus: http.StatusBadRequest,
			expectedCode:   sharedErrors.ErrCodeBadRequest,
		},
		{
			name:           "generic error",
			err:            errors.New("unknown error"),
			expectedStatus: http.StatusInternalServerError,
			expectedCode:   sharedErrors.ErrCodeInternalServer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HandleServiceError(tt.err)

			if tt.err == nil {
				if result != nil {
					t.Errorf("HandleServiceError() = %v, want nil", result)
				}
				return
			}

			apiErr := sharedErrors.GetAPIError(result)
			if apiErr == nil {
				t.Fatal("HandleServiceError() should return an APIError")
			}

			if apiErr.StatusCode != tt.expectedStatus {
				t.Errorf("HandleServiceError() StatusCode = %v, want %v", apiErr.StatusCode, tt.expectedStatus)
			}

			if apiErr.Code != tt.expectedCode {
				t.Errorf("HandleServiceError() Code = %v, want %v", apiErr.Code, tt.expectedCode)
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		substrs  []string
		expected bool
	}{
		{
			name:     "contains single substring",
			s:        "This is a test string",
			substrs:  []string{"test"},
			expected: true,
		},
		{
			name:     "contains one of multiple substrings",
			s:        "Record not found in database",
			substrs:  []string{"not found", "missing"},
			expected: true,
		},
		{
			name:     "case insensitive match",
			s:        "UPPERCASE STRING",
			substrs:  []string{"uppercase"},
			expected: true,
		},
		{
			name:     "does not contain any substring",
			s:        "This is a test",
			substrs:  []string{"missing", "absent"},
			expected: false,
		},
		{
			name:     "empty substring list",
			s:        "test string",
			substrs:  []string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(tt.s, tt.substrs...)
			if result != tt.expected {
				t.Errorf("contains() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestToLower(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "all uppercase",
			input:    "HELLO",
			expected: "hello",
		},
		{
			name:     "mixed case",
			input:    "Hello World",
			expected: "hello world",
		},
		{
			name:     "all lowercase",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "with numbers and symbols",
			input:    "Test123!@#",
			expected: "test123!@#",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toLower(tt.input)
			if result != tt.expected {
				t.Errorf("toLower() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIndexOf(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		substr   string
		expected int
	}{
		{
			name:     "substring at beginning",
			s:        "hello world",
			substr:   "hello",
			expected: 0,
		},
		{
			name:     "substring in middle",
			s:        "hello world",
			substr:   "world",
			expected: 6,
		},
		{
			name:     "substring not found",
			s:        "hello world",
			substr:   "missing",
			expected: -1,
		},
		{
			name:     "empty substring",
			s:        "hello",
			substr:   "",
			expected: 0,
		},
		{
			name:     "substring longer than string",
			s:        "hi",
			substr:   "hello",
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := indexOf(tt.s, tt.substr)
			if result != tt.expected {
				t.Errorf("indexOf() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDefaultErrorHandlerConfig(t *testing.T) {
	config := DefaultErrorHandlerConfig()

	if config.Logger == nil {
		t.Error("DefaultErrorHandlerConfig() Logger should not be nil")
	}

	if config.ShowStackTrace {
		t.Error("DefaultErrorHandlerConfig() ShowStackTrace should be false")
	}

	if config.OnPanic != nil {
		t.Error("DefaultErrorHandlerConfig() OnPanic should be nil")
	}
}
