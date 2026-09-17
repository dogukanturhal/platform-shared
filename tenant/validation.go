// SPDX-License-Identifier: Apache-2.0

package tenant

import (
	"errors"
	"log"

	"github.com/google/uuid"
)

// ErrMissingTenantID is returned when a required tenant ID is absent from the context.
var (
	ErrMissingTenantID = errors.New("tenant ID is required")
	ErrInvalidTenantID = errors.New("tenant ID is invalid")
)

// ValidateTenantID validates that a tenant ID string is present and a valid UUID.
func ValidateTenantID(tenantID string) (uuid.UUID, error) {
	if tenantID == "" {
		return uuid.Nil, ErrMissingTenantID
	}
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return uuid.Nil, ErrInvalidTenantID
	}
	if tenantUUID == uuid.Nil {
		return uuid.Nil, ErrMissingTenantID
	}
	return tenantUUID, nil
}

// ValidateTenantUUID validates a UUID directly.
func ValidateTenantUUID(tenantID uuid.UUID) error {
	if tenantID == uuid.Nil {
		return ErrMissingTenantID
	}
	return nil
}

// MustValidateTenantID validates tenant ID or uses log.Fatal if invalid.
// Use only in init/main setup code where failure should terminate the process.
func MustValidateTenantID(tenantID string) uuid.UUID {
	tenantUUID, err := ValidateTenantID(tenantID)
	if err != nil {
		// Use log.Fatal instead of panic for initialization errors
		log.Fatalf("invalid tenant ID: %v", err)
	}
	return tenantUUID
}
