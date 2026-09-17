// SPDX-License-Identifier: Apache-2.0

// Package response provides standardized HTTP response helpers for Gin-based services.
package response

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/dogukanturhal/platform-shared/errors"
)

// Response represents a standard API response
type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *ErrorBody  `json:"error,omitempty"`
	Meta    *Meta       `json:"meta,omitempty"`
}

// ErrorBody represents the error portion of a response
type ErrorBody struct {
	Code    errors.ErrorCode       `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// Meta represents pagination and other metadata
type Meta struct {
	Page       int   `json:"page,omitempty"`
	PageSize   int   `json:"pageSize,omitempty"`
	TotalItems int64 `json:"totalItems,omitempty"`
	TotalPages int   `json:"totalPages,omitempty"`
	HasNext    bool  `json:"hasNext,omitempty"`
	HasPrev    bool  `json:"hasPrev,omitempty"`
}

// PaginatedData represents paginated response data
type PaginatedData struct {
	Items interface{} `json:"items"`
	Meta  Meta        `json:"meta"`
}

// Success sends a successful response with data
func Success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, Response{
		Success: true,
		Data:    data,
	})
}

// SuccessWithStatus sends a successful response with custom status code
func SuccessWithStatus(c *gin.Context, statusCode int, data interface{}) {
	c.JSON(statusCode, Response{
		Success: true,
		Data:    data,
	})
}

// Created sends a 201 Created response
func Created(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, Response{
		Success: true,
		Data:    data,
	})
}

// NoContent sends a 204 No Content response
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// Paginated sends a paginated response
func Paginated(c *gin.Context, items interface{}, page, pageSize int, totalItems int64) {
	totalPages := int(totalItems) / pageSize
	if int(totalItems)%pageSize > 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, Response{
		Success: true,
		Data:    items,
		Meta: &Meta{
			Page:       page,
			PageSize:   pageSize,
			TotalItems: totalItems,
			TotalPages: totalPages,
			HasNext:    page < totalPages,
			HasPrev:    page > 1,
		},
	})
}

// Error sends an error response from an APIError
func Error(c *gin.Context, err *errors.APIError) {
	c.JSON(err.StatusCode, Response{
		Success: false,
		Error: &ErrorBody{
			Code:    err.Code,
			Message: err.Message,
			Details: err.Details,
		},
	})
}

// ErrorWithStatus sends an error response with custom status
func ErrorWithStatus(c *gin.Context, statusCode int, code errors.ErrorCode, message string) {
	c.JSON(statusCode, Response{
		Success: false,
		Error: &ErrorBody{
			Code:    code,
			Message: message,
		},
	})
}

// BadRequest sends a 400 Bad Request response
func BadRequest(c *gin.Context, message string) {
	Error(c, errors.BadRequest(message))
}

// ValidationFailed sends a 400 validation error response
func ValidationFailed(c *gin.Context, message string, fields map[string]string) {
	Error(c, errors.ValidationError(message, fields))
}

// Unauthorized sends a 401 Unauthorized response
func Unauthorized(c *gin.Context, message string) {
	Error(c, errors.Unauthorized(message))
}

// Forbidden sends a 403 Forbidden response
func Forbidden(c *gin.Context, message string) {
	Error(c, errors.Forbidden(message))
}

// NotFound sends a 404 Not Found response
func NotFound(c *gin.Context, resource string) {
	Error(c, errors.NotFound(resource))
}

// Conflict sends a 409 Conflict response
func Conflict(c *gin.Context, message string) {
	Error(c, errors.Conflict(message))
}

// InternalServerError sends a 500 Internal Server Error response
func InternalServerError(c *gin.Context, message string) {
	Error(c, errors.InternalServerError(message))
}

// ServiceUnavailable sends a 503 Service Unavailable response
func ServiceUnavailable(c *gin.Context, message string) {
	Error(c, errors.ServiceUnavailable(message))
}

// HandleError automatically handles any error and sends appropriate response
func HandleError(c *gin.Context, err error) {
	if apiErr := errors.GetAPIError(err); apiErr != nil {
		Error(c, apiErr)
		return
	}
	// Default to internal server error for unknown errors
	InternalServerError(c, "An unexpected error occurred")
}

// AbortWithError aborts the request with an error
func AbortWithError(c *gin.Context, err *errors.APIError) {
	c.AbortWithStatusJSON(err.StatusCode, Response{
		Success: false,
		Error: &ErrorBody{
			Code:    err.Code,
			Message: err.Message,
			Details: err.Details,
		},
	})
}
