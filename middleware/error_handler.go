// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"

	"github.com/dogukanturhal/platform-shared/errors"
	"github.com/dogukanturhal/platform-shared/response"
)

// ErrorHandlerConfig contains configuration for the error handler middleware
type ErrorHandlerConfig struct {
	// Logger for logging errors
	Logger *slog.Logger
	// ShowStackTrace enables stack trace in development
	ShowStackTrace bool
	// OnPanic is called when a panic occurs
	OnPanic func(c *gin.Context, recovered interface{}, stack []byte)
}

// DefaultErrorHandlerConfig returns default configuration
func DefaultErrorHandlerConfig() ErrorHandlerConfig {
	return ErrorHandlerConfig{
		Logger:         slog.Default(),
		ShowStackTrace: false,
		OnPanic:        nil,
	}
}

// ErrorHandler returns a middleware that handles errors
func ErrorHandler(config ...ErrorHandlerConfig) gin.HandlerFunc {
	cfg := DefaultErrorHandlerConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	return func(c *gin.Context) {
		c.Next()

		// Check if there were any errors
		if len(c.Errors) > 0 {
			err := c.Errors.Last().Err

			// Log the error
			if cfg.Logger != nil {
				cfg.Logger.Error("Request error",
					"method", c.Request.Method,
					"path", c.Request.URL.Path,
					"error", err.Error(),
					"request_id", c.GetString("request_id"),
				)
			}

			// Handle APIError
			if apiErr := errors.GetAPIError(err); apiErr != nil {
				response.Error(c, apiErr)
				return
			}

			// Default to internal server error
			response.InternalServerError(c, "An unexpected error occurred")
		}
	}
}

// Recovery returns a middleware that recovers from panics
func Recovery(config ...ErrorHandlerConfig) gin.HandlerFunc {
	cfg := DefaultErrorHandlerConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	return func(c *gin.Context) {
		defer func() {
			if recovered := recover(); recovered != nil {
				stack := debug.Stack()

				// Log the panic
				if cfg.Logger != nil {
					cfg.Logger.Error("Panic recovered",
						"method", c.Request.Method,
						"path", c.Request.URL.Path,
						"panic", recovered,
						"stack", string(stack),
						"request_id", c.GetString("request_id"),
					)
				}

				// Call custom panic handler if provided
				if cfg.OnPanic != nil {
					cfg.OnPanic(c, recovered, stack)
				}

				// Return 500 error
				c.AbortWithStatusJSON(http.StatusInternalServerError, response.Response{
					Success: false,
					Error: &response.ErrorBody{
						Code:    errors.ErrCodeInternalServer,
						Message: "An unexpected error occurred",
					},
				})
			}
		}()

		c.Next()
	}
}

// GlobalErrorHandler combines error handling and recovery
func GlobalErrorHandler(config ...ErrorHandlerConfig) gin.HandlerFunc {
	cfg := DefaultErrorHandlerConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	recoveryHandler := Recovery(cfg)
	errorHandler := ErrorHandler(cfg)

	return func(c *gin.Context) {
		// Apply recovery first
		recoveryHandler(c)
		// Then error handler
		errorHandler(c)
	}
}

// RequestErrorLogger creates a middleware that logs all errors
func RequestErrorLogger(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Log errors at the end of request
		for _, err := range c.Errors {
			level := slog.LevelError
			statusCode := c.Writer.Status()

			if statusCode >= 400 && statusCode < 500 {
				level = slog.LevelWarn
			}

			logger.Log(c.Request.Context(), level, "Request completed with error",
				"method", c.Request.Method,
				"path", c.Request.URL.Path,
				"status", statusCode,
				"error", err.Error(),
				"request_id", c.GetString("request_id"),
				"client_ip", c.ClientIP(),
			)
		}
	}
}

// HandleServiceError is a helper to handle errors from services
// It converts common errors to appropriate API errors
func HandleServiceError(err error) error {
	if err == nil {
		return nil
	}

	// If already an API error, return it directly (no wrapping, preserve type)
	if errors.IsAPIError(err) {
		return err
	}

	// Convert common error patterns
	errMsg := err.Error()

	// Check for common patterns
	switch {
	case contains(errMsg, "not found", "no rows", "record not found"):
		return errors.NotFound("").WithError(err)
	case contains(errMsg, "duplicate", "already exists", "unique constraint"):
		return errors.Conflict(errMsg).WithError(err)
	case contains(errMsg, "unauthorized", "invalid token", "expired"):
		return errors.Unauthorized("").WithError(err)
	case contains(errMsg, "forbidden", "permission denied", "access denied"):
		return errors.Forbidden("").WithError(err)
	case contains(errMsg, "validation", "invalid", "required"):
		return errors.BadRequest(errMsg).WithError(err)
	default:
		return errors.InternalServerError("").WithError(err)
	}
}

// contains checks if s contains any of the substrings (case-insensitive)
func contains(s string, substrs ...string) bool {
	sLower := toLower(s)
	for _, substr := range substrs {
		if indexOf(sLower, toLower(substr)) >= 0 {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
