// SPDX-License-Identifier: Apache-2.0

package storagesdk

import "fmt"

// StorageError is a structured error returned by the SDK when the storage-api
// responds with a non-2xx HTTP status. Callers can type-assert to inspect the
// status code or compare against the sentinel variables below.
type StorageError struct {
	// StatusCode is the HTTP status code returned by the storage-api.
	StatusCode int

	// Message is a human-readable description of the error.
	Message string
}

// Error implements the error interface.
func (e *StorageError) Error() string {
	return fmt.Sprintf("storagesdk: HTTP %d: %s", e.StatusCode, e.Message)
}

// Sentinel errors for well-known failure conditions. Callers can use
// errors.Is by comparing the StatusCode field, or match directly:
//
//	var se *storagesdk.StorageError
//	if errors.As(err, &se) && se.StatusCode == 507 { ... }
var (
	// ErrQuotaExceeded is returned when the tenant's storage quota has been reached.
	ErrQuotaExceeded = &StorageError{StatusCode: 507, Message: "storage quota exceeded"}

	// ErrNotFound is returned when the requested object or bucket does not exist.
	ErrNotFound = &StorageError{StatusCode: 404, Message: "object not found"}

	// ErrUnauthorized is returned when the service JWT is missing or invalid.
	ErrUnauthorized = &StorageError{StatusCode: 401, Message: "unauthorized"}

	// ErrForbidden is returned when the caller attempts cross-tenant access.
	ErrForbidden = &StorageError{StatusCode: 403, Message: "forbidden - cross-tenant access denied"}
)

// storageErrorFromStatus maps a well-known HTTP status code to the matching
// sentinel error, or constructs a new StorageError for unknown codes.
func storageErrorFromStatus(statusCode int, message string) *StorageError {
	switch statusCode {
	case 401:
		return ErrUnauthorized
	case 403:
		return ErrForbidden
	case 404:
		return ErrNotFound
	case 507:
		return ErrQuotaExceeded
	default:
		msg := message
		if msg == "" {
			msg = fmt.Sprintf("unexpected status %d", statusCode)
		}
		return &StorageError{StatusCode: statusCode, Message: msg}
	}
}
