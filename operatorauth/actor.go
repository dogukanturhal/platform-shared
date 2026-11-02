// SPDX-License-Identifier: Apache-2.0

package operatorauth

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	// Audience is the aud of operator assertions.
	Audience = "hexxlock-ops"
	// HeaderActorAssertion carries the assertion (raw or "Bearer <jwt>").
	HeaderActorAssertion = "X-Actor-Assertion"
	// InternalTenantID is the Hexxlock platform tenant; only its members are
	// operators.
	InternalTenantID = "00000000-0000-0000-0000-000000000002"

	// CtxKeyActor is the gin context key holding the verified *Actor.
	CtxKeyActor = "operatorauth.actor"
	// CtxKeyActorUserID / CtxKeyActorLabel mirror the keys the services'
	// previous ActorVerifier middleware set, so handlers written against
	// those keep working during the migration.
	CtxKeyActorUserID = "operator_actor_user_id"
	CtxKeyActorLabel  = "operator_actor_label"
)

// Actor is the verified human operator behind a service call. Handlers take
// the audit actor from here and never from a request body.
type Actor struct {
	UserID        uuid.UUID
	Email         string
	TenantID      string
	PlatformRoles []string
	Perms         []string
	ElevationID   string
	// AuthTime is zero when the assertion carried no auth_time (step-up then
	// always fails).
	AuthTime time.Time
	AMR      []string
	TokenID  string
	// ExpiresAt is the assertion's own expiry.
	ExpiresAt time.Time
	// StandingPlatformAdmin mirrors the signed standing_platform_admin claim.
	// Use IsStandingPlatformAdmin, which also checks tenant and role.
	StandingPlatformAdmin bool
}

// Label is the human-readable audit label: "operator:<id> <email>".
func (a *Actor) Label() string {
	label := "operator:" + a.UserID.String()
	if a.Email != "" {
		label += " <" + a.Email + ">"
	}
	return label
}

// HasPerm reports whether the assertion carries exactly perm.
func (a *Actor) HasPerm(perm string) bool {
	for _, p := range a.Perms {
		if p == perm {
			return true
		}
	}
	return false
}

// strongAMR are the authentication-method references that count as a second
// factor for step-up (RFC 8176 values plus falcon-id's own).
var strongAMR = map[string]bool{
	"webauthn": true, "otp": true, "totp": true, "mfa": true,
	"hwk": true, "swk": true, "fido": true, "passkey": true,
}

// HasMFA reports whether the amr list contains a strong second factor.
func (a *Actor) HasMFA() bool {
	for _, m := range a.AMR {
		if strongAMR[strings.ToLower(m)] {
			return true
		}
	}
	return false
}

// IsStandingPlatformAdmin reports whether the actor is the standing
// platform_admin (signed claim, internal tenant, platform_admin role). Such an
// actor skips reason / confirmation / four-eyes friction; JIT-elevated admins
// and everyone else do not.
func (a *Actor) IsStandingPlatformAdmin() bool {
	if a == nil || !a.StandingPlatformAdmin || a.TenantID != InternalTenantID {
		return false
	}
	for _, r := range a.PlatformRoles {
		if r == "platform_admin" {
			return true
		}
	}
	return false
}

// IsStandingPlatformAdmin reports whether the verified operator in c is the
// standing platform_admin (false when c carries no operator).
func IsStandingPlatformAdmin(c *gin.Context) bool {
	return ActorFrom(c).IsStandingPlatformAdmin()
}

// ActorFrom returns the verified operator set by RequireOperator, or nil.
func ActorFrom(c *gin.Context) *Actor {
	v, ok := c.Get(CtxKeyActor)
	if !ok {
		return nil
	}
	a, _ := v.(*Actor)
	return a
}

// ActorIdentity returns the verified operator's id and audit label
// (uuid.Nil, "" when absent). Same shape as the services' legacy
// OperatorActor(c) helpers.
func ActorIdentity(c *gin.Context) (uuid.UUID, string) {
	a := ActorFrom(c)
	if a == nil {
		return uuid.Nil, ""
	}
	return a.UserID, a.Label()
}
