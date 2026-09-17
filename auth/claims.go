// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"time"

	"github.com/google/uuid"
)

// Claims represents JWT token claims
// This structure mirrors the IAM service's Claims for compatibility
type Claims struct {
	Issuer                 string     `json:"iss"`
	Subject                string     `json:"sub"`
	Audience               []string   `json:"aud,omitempty"`
	TenantID               uuid.UUID  `json:"tenant_id"`
	UserID                 uuid.UUID  `json:"user_id"`
	Username               string     `json:"username"`
	Email                  string     `json:"email"`
	Roles                  []string   `json:"roles"`
	Permissions            []string   `json:"permissions"`
	SessionID              uuid.UUID  `json:"session_id"`
	IssuedAt               int64      `json:"iat"`
	ExpiresAt              int64      `json:"exp"`
	NotBefore              int64      `json:"nbf"`
	ImpersonatorID         *uuid.UUID `json:"impersonator_id,omitempty"`
	ImpersonationSessionID *uuid.UUID `json:"impersonation_session_id,omitempty"`
	// Service account fields (for client_credentials tokens)
	ServiceAccountID *uuid.UUID `json:"service_account_id,omitempty"`
	ClientID         string     `json:"client_id,omitempty"`
	TokenType        string     `json:"type,omitempty"` // "user" or "service_account"
	Scopes           []string   `json:"scopes,omitempty"`
}

// IsImpersonated returns true if this token represents an impersonated session
func (c *Claims) IsImpersonated() bool {
	return c.ImpersonatorID != nil
}

// IsServiceAccount returns true if this token is for a service account
func (c *Claims) IsServiceAccount() bool {
	return c.ServiceAccountID != nil || c.TokenType == "service_account"
}

// IsExpired returns true if the token has expired
func (c *Claims) IsExpired() bool {
	if c.ExpiresAt == 0 {
		return false
	}
	return c.ExpiresAt < time.Now().Unix()
}

// IsNotYetValid returns true if the token's not-before time is in the future
func (c *Claims) IsNotYetValid() bool {
	if c.NotBefore == 0 {
		return false
	}
	return c.NotBefore > time.Now().Unix()
}
