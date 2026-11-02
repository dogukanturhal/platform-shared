// SPDX-License-Identifier: Apache-2.0

// Package operatorauth is the shared operator-plane authorisation for the
// HexxLock platform-admin console.
//
// Every service that exposes operator (staff) routes verifies the acting human
// from the X-Actor-Assertion header with this package instead of carrying its
// own copy of an ActorVerifier. The assertion is the short-lived
// (5 min) token falcon-id mints through its operator token exchange:
//
//	aud            hexxlock-ops
//	sub, user_id   the operator
//	tid            the internal tenant (receivers re-check it)
//	platform_roles iam_platform_roles in force (standing viewer + active JIT)
//	ops_perms      ops:<domain>:<verb> permissions computed by falcon-id from
//	               SpiceDB hxl_platform - the ONLY authorisation input here
//	elev_id        the active elevation backing the elevated roles
//	auth_time, amr step-up evidence
//
// The operator's normal access token is deliberately NOT accepted: its roles
// claim carries standing tenant roles (platform_admin / iam_admin), which is
// the bypass this package exists to close. There is no role-name check
// anywhere in this package; falcon-id decides, services only compare the
// permission string.
//
// Middleware (mount after the service's own ServiceAuth + scope check):
//
//	v.RequireOperator("ops:tenants:read")   verifies the assertion + permission
//	RequireStepUp(5 * time.Minute)          T2: fresh MFA (auth_time + amr)
//	RequireApproval("tenant.purge.apply")   T3: four-eyes; fails closed
//	DirectReason(ReasonInBody)              reason auto-fill for the standing admin
//
// Standing platform_admin: falcon-id may sign standing_platform_admin=true for
// the standing (non-JIT) platform_admin. That actor (Actor.IsStandingPlatformAdmin)
// is never asked for reason codes, reason text or a second approver: DirectReason
// fills reason_code "platform_admin" + canonical text, and RequireApproval is
// bypassed (audit approval_mode "platform_admin_bypass"). Step-up is unchanged,
// "platform_admin" is rejected as a reason code from everyone else, and a
// missing claim means full friction.
//
// Audit: handlers build an AuditEvent (NewAuditEvent) and Emit it through an
// OutboxEmitter in the same transaction as the change; AuditHandler publishes
// the outbox rows to Kafka topic platform.ops-audit.v1, which falcon-id
// consumes into its INSERT-only platform_admin_audit_log.
package operatorauth
