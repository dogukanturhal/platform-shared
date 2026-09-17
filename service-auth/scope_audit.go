// SPDX-License-Identifier: Apache-2.0

// This file adds observe-only counterparts to
// RequireScope / RequireAnyScope (see jwks_middleware.go), so that scope
// enforcement can be rolled out to a route group without a first request
// ever being rejected sight-unseen.
//
// # Background
//
// RequireServiceAuth validates JWT signature/issuer/audience only; scope is
// enforced solely where a handler chains RequireScope/RequireAnyScope. An
// audit found eight internal route groups across four repos chain neither,
// and every sampled caller of them has zero registered scopes for the
// endpoint it actually calls -- switching on enforcement directly would
// immediately 403 real production traffic (billing -> quota-service,
// business -> notification-service, business -> domain-management, ...).
//
// RequireScopeAudit / RequireAnyScopeAudit exist to close that visibility
// gap: they evaluate the identical HasScope predicate RequireScope and
// RequireAnyScope use, but always call c.Next(), and emit one structured
// WARN log line when the request would have been denied. That log line is
// the input to the next steps of this rollout: grant the missing scope,
// re-run the audit, and only then wire the group to the enforcing
// middleware.
//
// # Shape: a separate function pair, not a Mode field on RequireScope
//
// RequireScope and RequireAnyScope are already relied on in production --
// tenant-management's /api/v1/internal/* routes chain
// RequireScope("platform:tenants:read") / ("platform:tenants:write") /
// ("platform:plans:read") today (platform-core
// services/tenant-management/cmd/init.go). Threading a Mode field through
// those functions would mean editing the functions every other service's
// enforcement already depends on, for the sake of code paths (audit-only
// route groups) that do not exist yet. A bug introduced there risks
// call sites that are correctly enforcing today, not just the new
// observe-only ones.
//
// Keeping RequireScopeAudit/RequireAnyScopeAudit in this new file, built
// only on the already-exported HasScope/GetClientID/GetScope helpers, means
// jwks_middleware.go is not touched by this change at all -- zero blast
// radius on existing behavior, by construction rather than by test
// coverage alone.
//
// The trade-off: flipping a route group from audit to enforce later is a
// one-line code edit (swap the function name at the call site) rather than
// a config value flip. That is deliberate here, not a gap to fix in a later
// step: the audit that motivated this work found every sampled caller
// currently has zero registered scope for the routes it calls, so "flip to
// enforce" must never happen silently or by an operator toggling a flag --
// it should be a reviewed diff per route group, made only once that group's
// audit log has gone quiet.
//
// # Config surface for the later wiring step
//
// ScopeMode and ParseScopeMode below are not consumed by anything in this
// MR (RequireScope/RequireScopeAudit are still selected by which function
// name a call site uses). They exist so that the later step which wires
// this into the eight route groups can make the audit/enforce choice for a
// given group driven by a per-service env var read once at startup --
// giving a rollback under incident conditions ("go back to audit-only") a
// pod restart with a changed env var, not a rebuild -- without requiring
// any further change to this package.

package serviceauth

import (
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ScopeAuditEvent is the stable, grep-able / alert-able event name emitted
// whenever RequireScopeAudit or RequireAnyScopeAudit observes a request
// that would have been denied by the equivalent enforcing middleware. Treat
// this string as an API: do not rename it without updating any log-based
// alert built on it.
const ScopeAuditEvent = "scope_audit_would_deny"

// ScopeMode selects observe-only versus enforcing behavior for a route
// group. Nothing in this MR reads a ScopeMode value -- see the package doc
// comment above for why the choice today is still "which function did the
// call site invoke". ScopeMode is added now so the later wiring step has a
// shared vocabulary to parse an env var into, instead of each of the four
// call-site repos inventing its own.
type ScopeMode string

const (
	// ScopeModeAudit evaluates the scope predicate and logs a would-be
	// denial, but never rejects the request. This MR's default and only
	// behavior.
	ScopeModeAudit ScopeMode = "audit"

	// ScopeModeEnforce rejects a request missing the required scope with
	// 403 insufficient_scope, matching RequireScope / RequireAnyScope.
	ScopeModeEnforce ScopeMode = "enforce"
)

// ParseScopeMode parses a mode value, such as an env var, into a ScopeMode.
// Unrecognized or empty input maps to ScopeModeAudit: a missing or
// misconfigured env var must never silently turn on enforcement.
func ParseScopeMode(s string) ScopeMode {
	if strings.EqualFold(strings.TrimSpace(s), string(ScopeModeEnforce)) {
		return ScopeModeEnforce
	}
	return ScopeModeAudit
}

// RequireScopeAudit is the observe-only counterpart to RequireScope: it
// evaluates the identical HasScope predicate but always calls c.Next(),
// regardless of the outcome. It never aborts, changes the response status
// or headers, or mutates the Gin context.
//
// On a would-be denial it emits one WARN log line via logger carrying:
// the caller's client_id, the HTTP method and route, the scope that was
// required, and the scope(s) actually present on the token -- everything
// needed to grant the missing scope without a second investigation.
//
// logger may be nil only by caller mistake; RequireScopeAudit treats a nil
// logger as "do not log" rather than panicking, because this middleware is
// meant to sit on every internal request and must never itself become a
// source of errors. Pass zap.NewNop() in tests that do not care about log
// output.
//
// A token with a missing, empty, or malformed scope claim is exactly the
// population this middleware exists to measure: HasScope already reports
// "no" (not an error) for all of those, so RequireScopeAudit logs a
// would-be denial and continues -- it never panics or 500s.
func RequireScopeAudit(scope string, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !HasScope(c, scope) {
			logScopeAuditDenial(c, logger, []string{scope})
		}
		c.Next()
	}
}

// RequireAnyScopeAudit is the observe-only counterpart to RequireAnyScope:
// it evaluates the identical any-of predicate but always calls c.Next().
// See RequireScopeAudit for the logging contract and nil-logger behavior.
func RequireAnyScopeAudit(scopes []string, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, s := range scopes {
			if HasScope(c, s) {
				c.Next()
				return
			}
		}
		logScopeAuditDenial(c, logger, scopes)
		c.Next()
	}
}

// logScopeAuditDenial emits the WARN log line for a would-be scope denial.
// It logs only the client_id and scope claim values already extracted onto
// the Gin context by RequireServiceAuth -- never the raw bearer token or
// any client secret.
func logScopeAuditDenial(c *gin.Context, logger *zap.Logger, required []string) {
	if logger == nil {
		return
	}

	clientID, _ := GetClientID(c)
	grantedScope, _ := GetScope(c)

	path := c.FullPath()
	if path == "" {
		path = c.Request.URL.Path
	}

	logger.Warn(ScopeAuditEvent,
		zap.String("event", ScopeAuditEvent),
		zap.String("client_id", clientID),
		zap.String("method", c.Request.Method),
		zap.String("path", path),
		zap.Strings("required_scope", required),
		zap.String("granted_scope", grantedScope),
	)
}
