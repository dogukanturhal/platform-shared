// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	sharedLogger "github.com/dogukanturhal/platform-shared/logger"
)

// TokenValidator provides JWT token validation functionality
type TokenValidator struct {
	config *Config
	jwks   *jwksResolver // non-nil only when config.JWKSURL is set
}

// NewTokenValidator creates a new TokenValidator with the given configuration.
// When config.JWKSURL is non-empty, an RS256/JWKS resolver is initialised so
// that tokens signed with RSA keys can be verified in addition to HS256 tokens.
func NewTokenValidator(config *Config) *TokenValidator {
	v := &TokenValidator{config: config}
	if config.JWKSURL == "" {
		// Fall back to the deployed env var name.
		//
		// WHY THIS IS HERE AND NOT IN LoadFromEnv: every prod service sets
		// FALCON_ID_JWKS_URL (all ten, verified against running pods
		// 2026-08-28) and NONE sets JWT_JWKS_URL, which LoadFromEnv reads.
		// Nothing in this package read FALCON_ID_JWKS_URL at all, so
		// cfg.JWKSURL was empty everywhere and jwt.go rejected every RS256
		// token from falcon-id with "RS256 token received but JWT_JWKS_URL
		// not configured". It went unnoticed because real traffic arrives on
		// the API-key and BFF-proxy-header legs, never on the user-JWT leg.
		//
		// Fixing LoadFromEnv would NOT have fixed it: 8 of the 9 services
		// build an auth.Config{} struct literal and never call LoadFromEnv,
		// so that fix would itself have gone unread — reproducing the exact
		// bug it was meant to close. NewTokenValidator is the one path every
		// service passes through (NewMiddleware constructs through it), which
		// is why the fallback belongs here.
		//
		// Reading env in a constructor is not this package's usual style, and
		// it is deliberate: an explicit config.JWKSURL always wins, so callers
		// that do set it are unaffected, and no caller has to change.
		if fallback := os.Getenv("FALCON_ID_JWKS_URL"); fallback != "" {
			config.JWKSURL = fallback
		}
	}
	if config.JWKSURL != "" {
		v.jwks = newJWKSResolver(config.JWKSURL)
	}
	warnIfIssuerValidationUnenforceable(config)
	return v
}

// issuerValidationWarnOnce keeps the warning below to one line per process.
// The condition it reports is a static misconfiguration, so it is equally
// true on every request; logging it per validation would be pure noise.
var issuerValidationWarnOnce sync.Once

// warnIfIssuerValidationUnenforceable reports the one issuer configuration
// that silently does nothing: RequireValidIssuer set, JWTIssuer empty.
//
// ValidateAccessToken guards the comparison with
// `if v.config.RequireValidIssuer && v.config.JWTIssuer != ""`, so an empty
// JWTIssuer skips the check entirely. That is the correct guard — comparing
// against "" would reject every token — but it means a service can ask for
// issuer validation, be given nothing to validate against, and pass every
// token from any issuer while its config reads as if the check were on.
// Nothing in the process says otherwise, which is what makes it worth a log
// line rather than a comment.
//
// This deliberately does NOT change behaviour. Defaulting RequireValidIssuer
// to true is a separate, per-service change that has to follow a reconciled
// issuer value, not precede it: every prod consumer currently expects the
// literal "falcon-id" while falcon-id mints an https URL, so flipping the
// default first would reject every token fleet-wide rather than surface a
// misconfiguration.
//
// The logger is built inside the Once rather than in a package-level init()
// so that the well-configured case — the overwhelming majority — pays
// nothing. auth.middleware's legacyKeyWarningLogger uses the init() form for
// historical reasons; this is not that pattern and should not be merged into
// it, since the two warnings have independent lifetimes.
func warnIfIssuerValidationUnenforceable(config *Config) {
	if config == nil || !config.RequireValidIssuer || config.JWTIssuer != "" {
		return
	}
	issuerValidationWarnOnce.Do(func() {
		logger, err := sharedLogger.NewLogger("info", "production")
		if err != nil {
			logger = zap.NewNop()
		}
		service := os.Getenv("SERVICE_NAME")
		if service == "" {
			service = "unknown"
		}
		logger.Warn("[SECURITY] issuer validation requested but no issuer configured; every issuer will be accepted",
			zap.String("service", service),
			zap.String("remediation", "set JWT_ISSUER to the issuer falcon-id actually stamps, or set RequireValidIssuer=false to make the opt-out explicit"))
	})
}

// issuerCheckLoggerOnce builds the logger used by logIssuerCheck exactly
// once, not once-per-line like issuerValidationWarnOnce above: unlike that
// warning, this call site is meant to fire on every evaluation while it is
// enabled, so there is a real logger to build lazily, not a line to suppress
// after the first hit.
var (
	issuerCheckLoggerOnce sync.Once
	issuerCheckLogger     *zap.Logger
)

// logIssuerCheck reports one issuer-check evaluation. Called unconditionally
// by ValidateAccessToken whenever Config.LogIssuerCheck is set and an issuer
// is configured to compare against — on both outcomes (match and mismatch),
// and regardless of whether RequireValidIssuer is currently true, which is
// the whole point: see Config.LogIssuerCheck's doc comment for why a
// reject-only signal cannot answer whether the check is engaging (t-445,
// c-306).
func logIssuerCheck(required, matched bool, gotIssuer, wantIssuer string) {
	issuerCheckLoggerOnce.Do(func() {
		logger, err := sharedLogger.NewLogger("info", "production")
		if err != nil {
			logger = zap.NewNop()
		}
		issuerCheckLogger = logger
	})
	service := os.Getenv("SERVICE_NAME")
	if service == "" {
		service = "unknown"
	}
	issuerCheckLogger.Info("[SECURITY] issuer check evaluated",
		zap.String("service", service),
		zap.Bool("require_valid_issuer", required),
		zap.Bool("issuer_matched", matched),
		zap.String("got_issuer", gotIssuer),
		zap.String("want_issuer", wantIssuer))
}

// ValidateAccessToken validates a JWT access token and returns the claims
func (v *TokenValidator) ValidateAccessToken(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, ErrMissingToken()
	}

	// Parse and validate the token. Both RS256 (JWKS) and HS256 (shared
	// secret) paths are supported; the appropriate branch is selected based on
	// the algorithm declared in the token header.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA:
			if v.config.JWKSURL == "" {
				return nil, fmt.Errorf("RS256 token received but JWT_JWKS_URL not configured")
			}
			kid, _ := token.Header["kid"].(string)
			if kid == "" {
				return nil, fmt.Errorf("RS256 token missing kid header")
			}
			return v.jwksResolveKey(kid)
		case *jwt.SigningMethodHMAC:
			if v.config.JWTSecret == "" {
				return nil, fmt.Errorf("HS256 token received but JWT_SECRET not configured")
			}
			return []byte(v.config.JWTSecret), nil
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	})
	if err != nil {
		// Check for specific error types
		if strings.Contains(err.Error(), "token is expired") {
			return nil, ErrTokenExpired()
		}
		if strings.Contains(err.Error(), "signature is invalid") {
			return nil, ErrInvalidSignature()
		}
		return nil, ErrTokenInvalid(err.Error())
	}

	if !token.Valid {
		return nil, ErrTokenInvalid("token is not valid")
	}

	// Extract claims
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrTokenInvalid("failed to parse claims")
	}

	// Parse claims into our Claims struct
	claims, err := parseMapClaims(mapClaims)
	if err != nil {
		return nil, fmt.Errorf("ValidateAccessToken: s failed: %w", err)
	}

	// Diagnostic: report what the issuer check saw, unconditionally, before
	// the enforcement gate below runs and regardless of whether
	// RequireValidIssuer is even true. See Config.LogIssuerCheck and t-445.
	if v.config.LogIssuerCheck && v.config.JWTIssuer != "" {
		logIssuerCheck(v.config.RequireValidIssuer, claims.Issuer == v.config.JWTIssuer, claims.Issuer, v.config.JWTIssuer)
	}

	// Validate issuer if required
	if v.config.RequireValidIssuer && v.config.JWTIssuer != "" {
		if claims.Issuer != v.config.JWTIssuer {
			return nil, ErrTokenInvalid("invalid token issuer")
		}
	}

	// Validate audience — see audience.go. Every access token falcon-id
	// mints for platform use carries one of these; a token minted for
	// anything else (a device-attestation witness JWS, a tenant-scoped
	// token-exchange grant audienced to some other origin, or any other
	// falcon-id-signed JWT) does not, and must not validate here now that
	// the RS256 leg activates for services that bump to pick it up.
	if !hasPlatformAudience(claims.Audience) {
		return nil, ErrTokenInvalid("invalid token audience")
	}

	// Validate expiration
	now := time.Now().Unix()
	if claims.ExpiresAt > 0 && claims.ExpiresAt < now {
		return nil, ErrTokenExpired()
	}

	// Validate not-before
	if claims.NotBefore > 0 && claims.NotBefore > now {
		return nil, ErrTokenInvalid("token not yet valid")
	}

	return claims, nil
}

// ParseTokenUnverified parses a token without verifying the signature
// Use this only when you need to extract claims without validation (e.g., for logging)
func ParseTokenUnverified(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, ErrMissingToken()
	}

	// Parse without verification
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, ErrTokenMalformed()
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrTokenInvalid("failed to parse claims")
	}

	return parseMapClaims(mapClaims)
}

// parseMapClaims converts jwt.MapClaims to our Claims struct.
// Supports both tenant user tokens and platform admin tokens.
func parseMapClaims(mapClaims jwt.MapClaims) (*Claims, error) {
	claims := &Claims{}

	// Detect platform admin token (scope == "platform").
	isPlatformAdmin := false
	if scope, ok := mapClaims["scope"].(string); ok && scope == "platform" {
		isPlatformAdmin = true
		claims.TokenType = "platform_admin"
	}

	parseStringClaims(mapClaims, claims)

	if err := parseUUIDClaims(mapClaims, claims, isPlatformAdmin); err != nil {
		return nil, err
	}

	parseNumericClaims(mapClaims, claims)
	parseArrayClaims(mapClaims, claims, isPlatformAdmin)

	return claims, nil
}

// parseStringClaims extracts simple string fields from mapClaims into claims.
func parseStringClaims(mapClaims jwt.MapClaims, claims *Claims) {
	if iss, ok := mapClaims["iss"].(string); ok {
		claims.Issuer = iss
	}
	if sub, ok := mapClaims["sub"].(string); ok {
		claims.Subject = sub
	}
	claims.Audience = audienceValues(mapClaims)
	if username, ok := mapClaims["username"].(string); ok {
		claims.Username = username
	}
	if email, ok := mapClaims["email"].(string); ok {
		claims.Email = email
	}
	if clientID, ok := mapClaims["client_id"].(string); ok {
		claims.ClientID = clientID
	}
	if tokenType, ok := mapClaims["type"].(string); ok {
		claims.TokenType = tokenType
	}
}

// parseUUIDClaims extracts UUID fields from mapClaims into claims.
func parseUUIDClaims(mapClaims jwt.MapClaims, claims *Claims, isPlatformAdmin bool) error {
	tenantIDStr := firstString(mapClaims, "tenant_id", "tid")
	if tenantIDStr != "" {
		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			return ErrTokenInvalid("invalid tenant_id in token")
		}
		claims.TenantID = tenantID
	}

	if err := parseUserID(mapClaims, claims, isPlatformAdmin); err != nil {
		return err
	}

	sessionIDStr := firstString(mapClaims, "session_id", "sid")
	if sessionIDStr != "" {
		sessionID, err := uuid.Parse(sessionIDStr)
		if err != nil {
			return ErrTokenInvalid("invalid session_id in token")
		}
		claims.SessionID = sessionID
	}

	parseOptionalUUIDs(mapClaims, claims)
	return nil
}

// parseUserID resolves user_id vs admin_id depending on token type.
func parseUserID(mapClaims jwt.MapClaims, claims *Claims, isPlatformAdmin bool) error {
	if isPlatformAdmin {
		if adminIDStr, ok := mapClaims["admin_id"].(string); ok && adminIDStr != "" {
			adminID, err := uuid.Parse(adminIDStr)
			if err != nil {
				return ErrTokenInvalid("invalid admin_id in token")
			}
			claims.UserID = adminID
		}
		return nil
	}

	// Service tokens minted via OAuth2 client_credentials (RFC 6749 §4.4)
	// have no end-user identity. Falcon-ID's token endpoint sets
	// `sub == client_id` (a string slug like "svc-billing") because the
	// client itself is the principal. Previously parseUserID blindly
	// fed "sub" through uuid.Parse, which rejected every service token
	// with "invalid user_id" — surfacing as 401 on every S2S call once
	// services started minting JWTs via serviceauth.
	//
	// Recognise service tokens by (a) presence of `client_id` claim AND
	// (b) `sub == client_id`. For these, UserID stays zero (no real
	// user) and TokenType is tagged "service" so downstream
	// authorization can branch on it. Tenant_id, audience, scopes, etc.
	// are still parsed normally; tenant isolation continues to apply.
	if clientID, _ := mapClaims["client_id"].(string); clientID != "" {
		if sub, _ := mapClaims["sub"].(string); sub == clientID {
			claims.TokenType = "service"
			// RFC 6749 §4.4 semantics: for machine principals the GRANTED
			// scopes ARE the authorization. Falcon-ID filters the requested
			// set against the client's registration before minting
			// (ClientCredentialsGrant), so every entry in `scope` was
			// explicitly granted to this service in the IdP. Surface them
			// as Permissions so RequirePermission gates admit S2S callers —
			// client_credentials tokens carry no `permissions` claim, so
			// pure-JWT services 403'd on every gated route (example-business
			// → quota-service /increment hit this live 2026-06-06). OIDC
			// identity scopes (openid, profile, …) ride along harmlessly:
			// they can never match a resource:action gate.
			if scope, ok := mapClaims["scope"].(string); ok && scope != "" {
				claims.Permissions = append(claims.Permissions, strings.Fields(scope)...)
			}
			return nil
		}
	}

	userIDStr := firstString(mapClaims, "user_id", "sub")
	if userIDStr != "" {
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			return ErrTokenInvalid("invalid user_id in token")
		}
		claims.UserID = userID
	}
	return nil
}

// parseOptionalUUIDs extracts service-account and impersonation IDs (best-effort).
func parseOptionalUUIDs(mapClaims jwt.MapClaims, claims *Claims) {
	if saIDStr, ok := mapClaims["service_account_id"].(string); ok && saIDStr != "" {
		if saID, err := uuid.Parse(saIDStr); err == nil {
			claims.ServiceAccountID = &saID
		}
	}
	if impIDStr, ok := mapClaims["impersonator_id"].(string); ok && impIDStr != "" {
		if impID, err := uuid.Parse(impIDStr); err == nil {
			claims.ImpersonatorID = &impID
		}
	}
	if impSessionIDStr, ok := mapClaims["impersonation_session_id"].(string); ok && impSessionIDStr != "" {
		if impSessionID, err := uuid.Parse(impSessionIDStr); err == nil {
			claims.ImpersonationSessionID = &impSessionID
		}
	}
}

// parseNumericClaims extracts iat/exp/nbf timestamps.
func parseNumericClaims(mapClaims jwt.MapClaims, claims *Claims) {
	if iat, ok := mapClaims["iat"].(float64); ok {
		claims.IssuedAt = int64(iat)
	}
	if exp, ok := mapClaims["exp"].(float64); ok {
		claims.ExpiresAt = int64(exp)
	}
	if nbf, ok := mapClaims["nbf"].(float64); ok {
		claims.NotBefore = int64(nbf)
	}
}

// parseArrayClaims extracts roles, permissions, and scopes arrays.
func parseArrayClaims(mapClaims jwt.MapClaims, claims *Claims, isPlatformAdmin bool) {
	if roles, ok := mapClaims["roles"].([]interface{}); ok {
		claims.Roles = extractStrings(roles)
	}

	if isPlatformAdmin {
		if role, ok := mapClaims["role"].(string); ok && role != "" {
			claims.Roles = []string{role, "platform_admin"}
			if role == "super_admin" {
				claims.Roles = append(claims.Roles, "admin", "super_admin")
			}
		}
	}

	if permissions, ok := mapClaims["permissions"].([]interface{}); ok {
		claims.Permissions = extractStrings(permissions)
	}
	if scopes, ok := mapClaims["scopes"].([]interface{}); ok {
		claims.Scopes = extractStrings(scopes)
	}
}

// audienceValues normalises the JWT `aud` claim into a []string. RFC 7519
// §4.1.3 permits either a single string or an array of strings; falcon-id
// emits an array on every access token this validator sees (see
// audience.go), so the previous bare `.(string)` type assertion here
// silently discarded aud on every real token instead of populating it.
func audienceValues(mapClaims jwt.MapClaims) []string {
	switch v := mapClaims["aud"].(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []interface{}:
		return extractStrings(v)
	default:
		return nil
	}
}

// extractStrings converts a []interface{} to []string, keeping only string elements.
func extractStrings(items []interface{}) []string {
	result := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// firstString returns the first non-empty string value found for the given keys
// in a JWT claims map. Used to support both verbose (v0) and abbreviated (v1/v2) claim names.
func firstString(m jwt.MapClaims, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// ExtractBearerToken extracts the token from an Authorization header
func ExtractBearerToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", ErrMissingToken()
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 {
		return "", ErrTokenMalformed()
	}

	if strings.ToLower(parts[0]) != "bearer" {
		return "", ErrTokenMalformed()
	}

	return parts[1], nil
}
