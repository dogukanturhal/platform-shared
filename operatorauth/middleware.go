// SPDX-License-Identifier: Apache-2.0

package operatorauth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

func assertionFromRequest(c *gin.Context) string {
	header := strings.TrimSpace(c.GetHeader(HeaderActorAssertion))
	if parts := strings.SplitN(header, " ", 2); len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		return strings.TrimSpace(parts[1])
	}
	return header
}

// RequireOperator authenticates the human operator behind a service call and
// requires perm (an ops:<domain>:<verb> permission) in the assertion's
// ops_perms. Mount AFTER the service's own ServiceAuth + RequireScope.
//
//   - missing, malformed, expired or badly signed assertion -> 401
//   - subject outside the Hexxlock internal tenant          -> 403
//   - impersonation token                                   -> 403
//   - no platform role, or perm not granted                 -> 403
//
// On success the verified *Actor is in the gin context (ActorFrom) and the
// legacy operator_actor_* keys are set. Handlers must take the audit actor
// from there, never from the request body.
func (v *Verifier) RequireOperator(perm string) gin.HandlerFunc {
	if perm == "" {
		// A route registered without a permission must not become open.
		panic("operatorauth: RequireOperator needs a permission")
	}
	return func(c *gin.Context) {
		token := assertionFromRequest(c)
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "actor_assertion_required"})
			return
		}
		actor, err := v.Verify(c.Request.Context(), token)
		if err != nil {
			if errors.Is(err, errImpersonated) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "impersonated_actor_not_allowed"})
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "actor_assertion_invalid"})
			return
		}
		if actor.TenantID != InternalTenantID {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "operator_requires_internal_tenant"})
			return
		}
		if len(actor.PlatformRoles) == 0 || !actor.HasPerm(perm) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "operator_permission_denied", "required": perm})
			return
		}
		c.Set(CtxKeyActor, actor)
		c.Set(CtxKeyActorUserID, actor.UserID)
		c.Set(CtxKeyActorLabel, actor.Label())
		c.Next()
	}
}

// RequireStepUp (T2) demands fresh multi-factor authentication: the
// assertion's auth_time must be within maxAge and its amr must include a
// strong second factor. On failure it answers 401
// insufficient_user_authentication (RFC 9470) so the console opens its
// WebAuthn/TOTP sheet and retries once. Mount after RequireOperator.
func RequireStepUp(maxAge time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		actor := ActorFrom(c)
		if actor == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "actor_assertion_required"})
			return
		}
		fresh := !actor.AuthTime.IsZero() && time.Since(actor.AuthTime) <= maxAge
		if !fresh || !actor.HasMFA() {
			sec := int(maxAge / time.Second)
			c.Header("WWW-Authenticate", fmt.Sprintf(`Bearer error="insufficient_user_authentication", max_age=%d`, sec))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "insufficient_user_authentication",
				"error_description": "recent multi-factor authentication is required",
				"max_age":           sec,
			})
			return
		}
		c.Next()
	}
}

// ApprovalChecker verifies a four-eyes approval for an action and consumes
// it atomically. The falcon-id approvals endpoint (a later phase) provides the
// implementation; until one is installed RequireApproval refuses everything.
type ApprovalChecker interface {
	// Consume returns nil only when c carries a valid, unused approval for
	// action bound to this request, and marks it used.
	Consume(c *gin.Context, action string) error
}

var approvalChecker atomic.Pointer[approvalHolder]

type approvalHolder struct{ ApprovalChecker }

// SetApprovalChecker installs the approval verifier. Not called anywhere in
// P0: RequireApproval fails closed.
func SetApprovalChecker(ac ApprovalChecker) {
	if ac == nil {
		approvalChecker.Store(nil)
		return
	}
	approvalChecker.Store(&approvalHolder{ac})
}

const (
	// CtxKeyApprovalMode is the gin context key RequireApproval sets.
	CtxKeyApprovalMode = "operatorauth.approval_mode"
	// ApprovalModeFourEyes: a second operator's approval was consumed.
	ApprovalModeFourEyes = "four_eyes"
	// ApprovalModePlatformAdminBypass: the standing platform_admin acted directly.
	ApprovalModePlatformAdminBypass = "platform_admin_bypass"
)

// ApprovalModeFrom returns how RequireApproval cleared c ("" when it did not
// run or did not pass).
func ApprovalModeFrom(c *gin.Context) string {
	return c.GetString(CtxKeyApprovalMode)
}

// RequireApproval (T3) demands a four-eyes approval for action. FAILS CLOSED:
// with no ApprovalChecker installed (the P0 state) every request is refused
// with 403 approval_required, so a destructive route wired to it cannot be
// reached by accident. The standing platform_admin bypasses the approval (after
// the checker-installed check) and is recorded as ApprovalModePlatformAdminBypass.
func RequireApproval(action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := approvalChecker.Load()
		if h == nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":  "approval_required",
				"action": action,
				"detail": "four-eyes approval is not available",
			})
			return
		}
		if IsStandingPlatformAdmin(c) {
			// Standing platform_admin acts directly; the audit event records
			// the bypass via ApprovalMode. Mirrors the success path so inline
			// callers can check c.IsAborted().
			c.Set(CtxKeyApprovalMode, ApprovalModePlatformAdminBypass)
			c.Next()
			return
		}
		if err := h.Consume(c, action); err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "approval_required", "action": action})
			return
		}
		c.Set(CtxKeyApprovalMode, ApprovalModeFourEyes)
		c.Next()
	}
}
