// SPDX-License-Identifier: Apache-2.0

package response

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	sharedErrors "github.com/dogukanturhal/platform-shared/errors"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestSuccess(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	data := map[string]string{"message": "success"}
	Success(c, data)

	if w.Code != http.StatusOK {
		t.Errorf("Success() status = %v, want %v", w.Code, http.StatusOK)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if !resp.Success {
		t.Error("Success() Success field should be true")
	}

	if resp.Data == nil {
		t.Fatal("Success() Data should not be nil")
	}
}

func TestSuccessWithStatus(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		data       interface{}
	}{
		{
			name:       "202 Accepted",
			statusCode: http.StatusAccepted,
			data:       map[string]string{"status": "processing"},
		},
		{
			name:       "201 Created",
			statusCode: http.StatusCreated,
			data:       map[string]int{"id": 123},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			SuccessWithStatus(c, tt.statusCode, tt.data)

			if w.Code != tt.statusCode {
				t.Errorf("SuccessWithStatus() status = %v, want %v", w.Code, tt.statusCode)
			}

			var resp Response
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			if !resp.Success {
				t.Error("SuccessWithStatus() Success field should be true")
			}
		})
	}
}

func TestCreated(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	data := map[string]interface{}{"id": "123", "name": "test"}
	Created(c, data)

	if w.Code != http.StatusCreated {
		t.Errorf("Created() status = %v, want %v", w.Code, http.StatusCreated)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if !resp.Success {
		t.Error("Created() Success field should be true")
	}
}

func TestNoContent(t *testing.T) {
	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	r.GET("/test", func(c *gin.Context) {
		NoContent(c)
	})

	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	r.ServeHTTP(w, c.Request)

	if w.Code != http.StatusNoContent {
		t.Errorf("NoContent() status = %v, want %v", w.Code, http.StatusNoContent)
	}

	if w.Body.Len() != 0 {
		t.Errorf("NoContent() body length = %v, want 0", w.Body.Len())
	}
}

func TestPaginated(t *testing.T) {
	tests := []struct {
		name            string
		items           interface{}
		page            int
		pageSize        int
		totalItems      int64
		expectedPages   int
		expectedHasNext bool
		expectedHasPrev bool
	}{
		{
			name:            "first page with more pages",
			items:           []int{1, 2, 3, 4, 5},
			page:            1,
			pageSize:        5,
			totalItems:      25,
			expectedPages:   5,
			expectedHasNext: true,
			expectedHasPrev: false,
		},
		{
			name:            "middle page",
			items:           []int{6, 7, 8, 9, 10},
			page:            2,
			pageSize:        5,
			totalItems:      25,
			expectedPages:   5,
			expectedHasNext: true,
			expectedHasPrev: true,
		},
		{
			name:            "last page",
			items:           []int{21, 22, 23, 24, 25},
			page:            5,
			pageSize:        5,
			totalItems:      25,
			expectedPages:   5,
			expectedHasNext: false,
			expectedHasPrev: true,
		},
		{
			name:            "partial last page",
			items:           []int{21, 22, 23},
			page:            5,
			pageSize:        5,
			totalItems:      23,
			expectedPages:   5,
			expectedHasNext: false,
			expectedHasPrev: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			Paginated(c, tt.items, tt.page, tt.pageSize, tt.totalItems)

			if w.Code != http.StatusOK {
				t.Errorf("Paginated() status = %v, want %v", w.Code, http.StatusOK)
			}

			var resp Response
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			if !resp.Success {
				t.Error("Paginated() Success field should be true")
			}

			if resp.Meta == nil {
				t.Fatal("Paginated() Meta should not be nil")
			}

			if resp.Meta.Page != tt.page {
				t.Errorf("Paginated() Meta.Page = %v, want %v", resp.Meta.Page, tt.page)
			}

			if resp.Meta.PageSize != tt.pageSize {
				t.Errorf("Paginated() Meta.PageSize = %v, want %v", resp.Meta.PageSize, tt.pageSize)
			}

			if resp.Meta.TotalItems != tt.totalItems {
				t.Errorf("Paginated() Meta.TotalItems = %v, want %v", resp.Meta.TotalItems, tt.totalItems)
			}

			if resp.Meta.TotalPages != tt.expectedPages {
				t.Errorf("Paginated() Meta.TotalPages = %v, want %v", resp.Meta.TotalPages, tt.expectedPages)
			}

			if resp.Meta.HasNext != tt.expectedHasNext {
				t.Errorf("Paginated() Meta.HasNext = %v, want %v", resp.Meta.HasNext, tt.expectedHasNext)
			}

			if resp.Meta.HasPrev != tt.expectedHasPrev {
				t.Errorf("Paginated() Meta.HasPrev = %v, want %v", resp.Meta.HasPrev, tt.expectedHasPrev)
			}
		})
	}
}

func TestError(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	apiErr := sharedErrors.BadRequest("Invalid input")
	Error(c, apiErr)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Error() status = %v, want %v", w.Code, http.StatusBadRequest)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp.Success {
		t.Error("Error() Success field should be false")
	}

	if resp.Error == nil {
		t.Fatal("Error() Error field should not be nil")
	}

	if resp.Error.Code != sharedErrors.ErrCodeBadRequest {
		t.Errorf("Error() Error.Code = %v, want %v", resp.Error.Code, sharedErrors.ErrCodeBadRequest)
	}

	if resp.Error.Message != "Invalid input" {
		t.Errorf("Error() Error.Message = %v, want 'Invalid input'", resp.Error.Message)
	}
}

func TestErrorWithStatus(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	ErrorWithStatus(c, http.StatusTeapot, sharedErrors.ErrCodeBadRequest, "I'm a teapot")

	if w.Code != http.StatusTeapot {
		t.Errorf("ErrorWithStatus() status = %v, want %v", w.Code, http.StatusTeapot)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp.Success {
		t.Error("ErrorWithStatus() Success field should be false")
	}
}

func TestBadRequest(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	message := "Missing required field"
	BadRequest(c, message)

	if w.Code != http.StatusBadRequest {
		t.Errorf("BadRequest() status = %v, want %v", w.Code, http.StatusBadRequest)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp.Error.Message != message {
		t.Errorf("BadRequest() Error.Message = %v, want %v", resp.Error.Message, message)
	}
}

func TestValidationFailed(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	message := "Validation failed"
	fields := map[string]string{
		"email": "invalid email format",
		"age":   "must be at least 18",
	}

	ValidationFailed(c, message, fields)

	if w.Code != http.StatusBadRequest {
		t.Errorf("ValidationFailed() status = %v, want %v", w.Code, http.StatusBadRequest)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp.Error.Code != sharedErrors.ErrCodeValidation {
		t.Errorf("ValidationFailed() Error.Code = %v, want %v", resp.Error.Code, sharedErrors.ErrCodeValidation)
	}

	if len(resp.Error.Details) != 2 {
		t.Errorf("ValidationFailed() got %d details, want 2", len(resp.Error.Details))
	}
}

func TestUnauthorized(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	message := "Token expired"
	Unauthorized(c, message)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Unauthorized() status = %v, want %v", w.Code, http.StatusUnauthorized)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp.Error.Code != sharedErrors.ErrCodeUnauthorized {
		t.Errorf("Unauthorized() Error.Code = %v, want %v", resp.Error.Code, sharedErrors.ErrCodeUnauthorized)
	}
}

func TestForbidden(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	message := "Insufficient permissions"
	Forbidden(c, message)

	if w.Code != http.StatusForbidden {
		t.Errorf("Forbidden() status = %v, want %v", w.Code, http.StatusForbidden)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp.Error.Code != sharedErrors.ErrCodeForbidden {
		t.Errorf("Forbidden() Error.Code = %v, want %v", resp.Error.Code, sharedErrors.ErrCodeForbidden)
	}
}

func TestNotFound(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	resource := "User"
	NotFound(c, resource)

	if w.Code != http.StatusNotFound {
		t.Errorf("NotFound() status = %v, want %v", w.Code, http.StatusNotFound)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp.Error.Code != sharedErrors.ErrCodeNotFound {
		t.Errorf("NotFound() Error.Code = %v, want %v", resp.Error.Code, sharedErrors.ErrCodeNotFound)
	}
}

func TestConflict(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	message := "User already exists"
	Conflict(c, message)

	if w.Code != http.StatusConflict {
		t.Errorf("Conflict() status = %v, want %v", w.Code, http.StatusConflict)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp.Error.Code != sharedErrors.ErrCodeConflict {
		t.Errorf("Conflict() Error.Code = %v, want %v", resp.Error.Code, sharedErrors.ErrCodeConflict)
	}
}

func TestInternalServerError(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	message := "Database error"
	InternalServerError(c, message)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("InternalServerError() status = %v, want %v", w.Code, http.StatusInternalServerError)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp.Error.Code != sharedErrors.ErrCodeInternalServer {
		t.Errorf("InternalServerError() Error.Code = %v, want %v", resp.Error.Code, sharedErrors.ErrCodeInternalServer)
	}
}

func TestServiceUnavailable(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	message := "Service maintenance"
	ServiceUnavailable(c, message)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("ServiceUnavailable() status = %v, want %v", w.Code, http.StatusServiceUnavailable)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp.Error.Code != sharedErrors.ErrCodeServiceUnavailable {
		t.Errorf("ServiceUnavailable() Error.Code = %v, want %v", resp.Error.Code, sharedErrors.ErrCodeServiceUnavailable)
	}
}

func TestHandleError(t *testing.T) {
	tests := []struct {
		name               string
		err                error
		expectedStatusCode int
		expectedCode       sharedErrors.ErrorCode
	}{
		{
			name:               "API error",
			err:                sharedErrors.NotFound("User"),
			expectedStatusCode: http.StatusNotFound,
			expectedCode:       sharedErrors.ErrCodeNotFound,
		},
		{
			name:               "regular error",
			err:                errors.New("some error"),
			expectedStatusCode: http.StatusInternalServerError,
			expectedCode:       sharedErrors.ErrCodeInternalServer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			HandleError(c, tt.err)

			if w.Code != tt.expectedStatusCode {
				t.Errorf("HandleError() status = %v, want %v", w.Code, tt.expectedStatusCode)
			}

			var resp Response
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			if resp.Error.Code != tt.expectedCode {
				t.Errorf("HandleError() Error.Code = %v, want %v", resp.Error.Code, tt.expectedCode)
			}
		})
	}
}

func TestAbortWithError(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	apiErr := sharedErrors.Forbidden("Access denied")
	AbortWithError(c, apiErr)

	if w.Code != http.StatusForbidden {
		t.Errorf("AbortWithError() status = %v, want %v", w.Code, http.StatusForbidden)
	}

	if !c.IsAborted() {
		t.Error("AbortWithError() should abort the context")
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp.Success {
		t.Error("AbortWithError() Success field should be false")
	}
}
