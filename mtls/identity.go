// SPDX-License-Identifier: Apache-2.0

package mtls

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Gin context keys set by IdentityBindingMiddleware.
// Downstream handlers can read these with c.GetString / c.GetBool.
const (
	// ContextKeyMTLSIdentity holds the Common Name from the peer certificate.
	ContextKeyMTLSIdentity = "mtls_identity"

	// ContextKeyMTLSSpiffeID holds the SPIFFE URI SAN from the peer certificate,
	// if one is present.
	ContextKeyMTLSSpiffeID = "mtls_spiffe_id"

	// ContextKeyMTLSVerified is true when a valid client certificate was
	// presented and its chain verified against the configured CA pool.
	ContextKeyMTLSVerified = "mtls_verified"
)

// IdentityBindingMiddleware returns a Gin middleware that:
//  1. Extracts the client certificate identity (CN + SPIFFE URI SAN) and
//     stores it in the Gin context.
//  2. In ModeStrict, rejects requests that arrive without a client cert.
//  3. When both a JWT client_id and an mTLS identity are present, verifies
//     that they refer to the same service. A mismatch is treated as a
//     SECURITY INCIDENT: the event is logged at ERROR level with full context
//     and the request is aborted with 403.
//
// The middleware is intentionally lenient when the JWT client_id is absent —
// not every request carries a service JWT (e.g., health probes, user-facing
// APIs forwarded through the gateway). The mTLS certificate alone provides
// the transport-layer identity.
//
// log must be non-nil. Pass zap.NewNop() in tests that do not care about log
// output.
func IdentityBindingMiddleware(mode Mode, log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// No TLS at all — disabled mode or plain HTTP health probe.
		if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 {
			if mode == ModeStrict {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error":   "client_certificate_required",
					"message": "mTLS strict mode: client certificate is required",
				})
				return
			}
			// Permissive or disabled — allow through without mTLS identity.
			c.Next()
			return
		}

		// Extract identity from the first (leaf) client certificate.
		clientCert := c.Request.TLS.PeerCertificates[0]
		mtlsIdentity := clientCert.Subject.CommonName

		// Extract SPIFFE URI SAN if present.
		spiffeID := ""
		for _, uri := range clientCert.URIs {
			if strings.HasPrefix(uri.String(), "spiffe://") {
				spiffeID = uri.String()
				break
			}
		}

		c.Set(ContextKeyMTLSIdentity, mtlsIdentity)
		c.Set(ContextKeyMTLSSpiffeID, spiffeID)
		c.Set(ContextKeyMTLSVerified, true)

		// Identity binding: when a JWT client_id is present verify it matches
		// the mTLS certificate identity.
		if jwtClientIDRaw, exists := c.Get("client_id"); exists {
			jwtClientID, ok := jwtClientIDRaw.(string)
			if ok && jwtClientID != "" {
				if !identitiesMatch(mtlsIdentity, jwtClientID) {
					// SECURITY INCIDENT — log full context at ERROR level.
					log.Error("SECURITY: transport/application identity mismatch",
						zap.String("mtls_identity", mtlsIdentity),
						zap.String("mtls_spiffe_id", spiffeID),
						zap.String("jwt_client_id", jwtClientID),
						zap.String("remote_addr", c.ClientIP()),
						zap.String("request_path", c.Request.URL.Path),
						zap.String("request_method", c.Request.Method),
					)
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
						"error":   "identity_mismatch",
						"message": "Transport and application identities do not match",
					})
					return
				}
			}
		}

		c.Next()
	}
}

// GetMTLSIdentity retrieves the mTLS Common Name from the Gin context.
// Returns ("", false) if IdentityBindingMiddleware has not run or the request
// carried no client certificate.
func GetMTLSIdentity(c *gin.Context) (string, bool) {
	v, exists := c.Get(ContextKeyMTLSIdentity)
	if !exists {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// GetMTLSSpiffeID retrieves the SPIFFE URI SAN from the Gin context.
// Returns ("", false) when absent.
func GetMTLSSpiffeID(c *gin.Context) (string, bool) {
	v, exists := c.Get(ContextKeyMTLSSpiffeID)
	if !exists {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// IsMTLSVerified reports whether the current request was authenticated with a
// valid client certificate.
func IsMTLSVerified(c *gin.Context) bool {
	v, exists := c.Get(ContextKeyMTLSVerified)
	if !exists {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

// identitiesMatch normalises both the mTLS Common Name and JWT client_id to a
// bare service name and returns true when they refer to the same service.
//
// Normalisation rules:
//   - mTLS CN:     strip ".example.local" suffix (e.g., "crm.example.local" → "crm")
//   - JWT client:  strip "svc-" prefix          (e.g., "svc-crm" → "crm")
//
// This accommodates the naming conventions already in use across the platform
// without requiring a strict 1:1 string match.
func identitiesMatch(mtlsCN, jwtClientID string) bool {
	mtlsSvc := strings.TrimSuffix(mtlsCN, ".example.local")
	jwtSvc := strings.TrimPrefix(jwtClientID, "svc-")
	return mtlsSvc == jwtSvc
}

// RequireMTLS returns a Gin middleware that rejects requests that did not
// present a valid client certificate, regardless of the global mTLS mode.
// Use this on sensitive internal routes that must always require mTLS even
// when the server runs in permissive mode.
func RequireMTLS() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !IsMTLSVerified(c) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "client_certificate_required",
				"message": "This endpoint requires a valid mTLS client certificate",
			})
			return
		}
		c.Next()
	}
}

// AllowedIdentities returns a Gin middleware that restricts access to a named
// set of mTLS service identities. It must be chained after
// IdentityBindingMiddleware.
//
// allowed is a set of bare service names (e.g., "crm", "billing"). Matching
// uses the same normalisation as identitiesMatch.
//
// Example:
//
//	internal.Use(mtls.AllowedIdentities("crm", "billing", "integration-bus"))
func AllowedIdentities(allowed ...string) gin.HandlerFunc {
	allowSet := make(map[string]struct{}, len(allowed))
	for _, svc := range allowed {
		allowSet[strings.TrimPrefix(svc, "svc-")] = struct{}{}
	}

	return func(c *gin.Context) {
		identity, ok := GetMTLSIdentity(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "identity_required",
				"message": "mTLS identity is required for this endpoint",
			})
			return
		}

		bare := strings.TrimSuffix(identity, ".example.local")
		if _, permitted := allowSet[bare]; !permitted {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "identity_not_permitted",
				"message": fmt.Sprintf("Service %q is not permitted to call this endpoint", identity),
			})
			return
		}

		c.Next()
	}
}
