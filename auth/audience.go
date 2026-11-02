// SPDX-License-Identifier: Apache-2.0

package auth

// Audience values that falcon-id stamps into the `aud` claim of every
// access token it mints for platform/API use. Mirrors
// falcon-id/internal/services/audience.go — see that file for the
// migration rationale: PlatformAPIAudience is the RFC 8707 canonical
// value, LegacyServiceMeshAudience is kept until every receiver has moved
// off it. falcon-id/internal/services/token_service.go stamps BOTH into
// `aud` on every mint (login, refresh, impersonation, v2/SpiceDB claims,
// and client_credentials service tokens) — it does not mint a distinct
// audience per consuming service, so this is one check shared by every
// platform-shared consumer, not a per-service value.
const (
	PlatformAPIAudience       = "https://api.example.com"
	LegacyServiceMeshAudience = "hexxlock-services"
)

// hasPlatformAudience reports whether aud contains at least one of the
// values falcon-id stamps on platform-bound tokens.
//
// This is deliberately unconditional — not gated behind a Config field —
// unlike RequireValidIssuer. That flag defaults on but silently does
// nothing without a matching JWTIssuer, and every one of the fleet's ten
// consumers currently has it in exactly that state (see the warning in
// jwt.go). An auth boundary doesn't get an opt-out that history has
// already shown goes unset.
func hasPlatformAudience(aud []string) bool {
	for _, a := range aud {
		if a == PlatformAPIAudience || a == LegacyServiceMeshAudience {
			return true
		}
	}
	return false
}
