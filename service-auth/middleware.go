// SPDX-License-Identifier: Apache-2.0

// Package serviceauth — see client.go for package-level documentation.
package serviceauth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Context keys written by NewServiceAuthMiddleware.
// Downstream handlers retrieve service identity with:
//
//	slug, _ := c.Get(ContextKeyServiceSlug)
//	id,   _ := c.Get(ContextKeyServiceID)
const (
	// ContextKeyServiceSlug is the Gin context key for the authenticated service slug.
	ContextKeyServiceSlug = "service_slug"

	// ContextKeyServiceID is the Gin context key for the authenticated service ID
	// (the JWT "sub" claim, which equals the service slug by convention).
	ContextKeyServiceID = "service_id"
)

// NewServiceAuthMiddleware returns a Gin middleware that validates incoming
// service JWTs and populates the request context with the caller's identity.
//
// trustedKeys is a map from key-ID (kid) to RSA public key. A request is
// accepted when its JWT header contains a kid present in this map AND the
// signature is valid for the corresponding key.
//
// On success the middleware sets two context values:
//   - ContextKeyServiceSlug ("service_slug"): the "iss" / "service_slug" claim
//   - ContextKeyServiceID   ("service_id"):   the "sub" claim
//
// On failure the middleware aborts the request with 401 Unauthorized.
//
// Example:
//
//	pubKeys := map[string]*rsa.PublicKey{
//	    "billing-key-1": &billingPrivKey.PublicKey,
//	}
//	router.Use(serviceauth.NewServiceAuthMiddleware(pubKeys))
func NewServiceAuthMiddleware(trustedKeys map[string]*rsa.PublicKey) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr, err := extractBearer(c.GetHeader("Authorization"))
		if err != nil {
			abortUnauthorized(c, "missing or malformed Authorization header")
			return
		}

		claims, err := validateServiceToken(tokenStr, trustedKeys)
		if err != nil {
			abortUnauthorized(c, err.Error())
			return
		}

		// Populate context so downstream handlers can identify the caller.
		c.Set(ContextKeyServiceSlug, claims.ServiceSlug)
		c.Set(ContextKeyServiceID, claims.Subject)

		c.Next()
	}
}

// GetServiceSlug retrieves the authenticated service slug from the Gin context.
// Returns ("", false) if the middleware has not run or authentication failed.
func GetServiceSlug(c *gin.Context) (string, bool) {
	v, exists := c.Get(ContextKeyServiceSlug)
	if !exists {
		return "", false
	}
	slug, ok := v.(string)
	return slug, ok
}

// GetServiceID retrieves the authenticated service ID from the Gin context.
// Returns ("", false) if the middleware has not run or authentication failed.
func GetServiceID(c *gin.Context) (string, bool) {
	v, exists := c.Get(ContextKeyServiceID)
	if !exists {
		return "", false
	}
	id, ok := v.(string)
	return id, ok
}

// validateServiceToken parses and validates a JWT string against the provided
// set of trusted public keys. It enforces:
//   - RS256 signing algorithm (rejects any other algorithm)
//   - "kid" header present and mapped to a trusted public key
//   - Token not expired, not used before its "nbf" time
//   - Audience contains "falcon-id"
//   - "service_slug" claim is non-empty
func validateServiceToken(tokenStr string, trustedKeys map[string]*rsa.PublicKey) (*ServiceClaims, error) {
	claims := &ServiceClaims{}

	token, err := jwt.ParseWithClaims(
		tokenStr,
		claims,
		func(token *jwt.Token) (interface{}, error) {
			// Reject non-RSA algorithms to prevent algorithm confusion attacks.
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf(
					"serviceauth: unexpected signing method %q; only RS256 is accepted",
					token.Header["alg"],
				)
			}

			// Resolve the public key by key ID.
			kid, ok := token.Header["kid"].(string)
			if !ok || kid == "" {
				return nil, errors.New("serviceauth: JWT header missing \"kid\"")
			}

			pubKey, found := trustedKeys[kid]
			if !found {
				return nil, fmt.Errorf("serviceauth: unknown key ID %q", kid)
			}

			return pubKey, nil
		},
		jwt.WithAudience(defaultAudience),
		jwt.WithValidMethods([]string{signingAlgorithm}),
	)
	if err != nil {
		return nil, fmt.Errorf("serviceauth: token validation failed: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("serviceauth: token is not valid")
	}

	if claims.ServiceSlug == "" {
		return nil, errors.New("serviceauth: \"service_slug\" claim is empty")
	}

	return claims, nil
}

// extractBearer parses a raw Authorization header value and returns the bearer
// token. Returns an error if the header is empty or does not use the Bearer scheme.
func extractBearer(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.New("authorization header is absent")
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		// Accept case-insensitive "bearer" as well
		if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			return "", fmt.Errorf("authorization header does not use Bearer scheme: %q", authHeader)
		}
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", errors.New("bearer token is empty")
	}

	return parts[1], nil
}

// abortUnauthorized terminates the request with a structured 401 response.
func abortUnauthorized(c *gin.Context, message string) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"success": false,
		"error": gin.H{
			"code":    "SERVICE_AUTH_UNAUTHORIZED",
			"message": message,
		},
	})
}

// ServiceAuthMiddlewareFromValidator returns a Gin middleware that validates
// incoming service JWTs via a JWTValidator backed by a JWKS endpoint.
//
// This is the preferred way to protect routes in microservices that do not hold
// static public-key material — they delegate key resolution to Falcon-ID's JWKS
// endpoint automatically, including handling key rotation.
//
// On success it sets the same context keys as NewServiceAuthMiddleware:
//   - ContextKeyServiceSlug ("service_slug")
//   - ContextKeyServiceID   ("service_id")
//
// Example (in integration-bus or master-data cmd/main.go):
//
//	validator, _ := serviceauth.NewJWTValidator(
//	    cfg.FalconIDJWKSURL,  // "http://iam:8005/.well-known/jwks.json"
//	    cfg.FalconIDIssuer,   // optional; "" to skip
//	)
//	apiGroup.Use(serviceauth.ServiceAuthMiddlewareFromValidator(validator))
func ServiceAuthMiddlewareFromValidator(v *JWTValidator) gin.HandlerFunc { //nolint:revive // public API stability
	return func(c *gin.Context) {
		tokenStr, err := extractBearer(c.GetHeader("Authorization"))
		if err != nil {
			abortUnauthorized(c, "missing or malformed Authorization header")
			return
		}

		claims, err := v.ValidateToken(tokenStr)
		if err != nil {
			abortUnauthorized(c, err.Error())
			return
		}

		c.Set(ContextKeyServiceSlug, claims.ServiceSlug)
		c.Set(ContextKeyServiceID, claims.ServiceID)

		c.Next()
	}
}
