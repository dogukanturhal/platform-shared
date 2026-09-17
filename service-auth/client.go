// SPDX-License-Identifier: Apache-2.0

// Package serviceauth provides service-to-service JWT authentication.
// Services use this to sign outgoing requests with their service JWT.
//
// # Overview
//
// Instead of sharing static API keys between microservices, each service
// holds an RSA private key and mints short-lived (5-minute) JWTs that it
// attaches to every outgoing inter-service HTTP request. Receiving services
// validate the JWT against the corresponding public key.
//
// # Usage
//
//	client, err := serviceauth.NewServiceClient("billing-service", privateKeyPEM, "key-id-1")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	req, _ := http.NewRequest(http.MethodGet, "http://falcon-id/internal/users", nil)
//	if err := client.SignRequest(req); err != nil {
//	    log.Fatal(err)
//	}
//	resp, err := http.DefaultClient.Do(req)
package serviceauth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	// defaultAudience is the expected audience for all service JWTs issued by this library.
	defaultAudience = "falcon-id"

	// tokenTTL is the lifetime of a generated service JWT.
	// Keeping it short (5 minutes) limits the blast radius of key compromise.
	tokenTTL = 5 * time.Minute

	// signingAlgorithm is the algorithm used to sign service JWTs.
	signingAlgorithm = "RS256"
)

// ServiceClient signs outgoing HTTP requests with a short-lived service JWT.
//
// A single ServiceClient instance is safe for concurrent use by multiple
// goroutines. Construct it once at application startup and reuse it.
type ServiceClient struct {
	serviceSlug string
	privateKey  *rsa.PrivateKey
	keyID       string
	audience    string
}

// ServiceClaims are the JWT claims embedded in a service token.
// They extend the standard registered claims with a service-specific
// slug that the receiver can use for authorization decisions.
type ServiceClaims struct {
	jwt.RegisteredClaims

	// ServiceSlug identifies the calling service (e.g., "billing-service").
	ServiceSlug string `json:"service_slug"`
}

// NewServiceClient parses the given RSA private key PEM block and returns a
// ServiceClient ready to sign requests on behalf of serviceSlug.
//
// Parameters:
//   - serviceSlug: human-readable service identifier included as the JWT "iss"
//     claim (e.g., "billing-service", "tenant-management").
//   - privateKeyPEM: PEM-encoded PKCS#8 or PKCS#1 RSA private key.
//   - keyID: opaque key identifier placed in the JWT "kid" header so receivers
//     can select the matching public key for verification.
//
// Returns an error if privateKeyPEM cannot be decoded or does not contain an
// RSA private key.
func NewServiceClient(serviceSlug string, privateKeyPEM []byte, keyID string) (*ServiceClient, error) {
	if serviceSlug == "" {
		return nil, errors.New("serviceauth: serviceSlug must not be empty")
	}
	if keyID == "" {
		return nil, errors.New("serviceauth: keyID must not be empty")
	}
	if len(privateKeyPEM) == 0 {
		return nil, errors.New("serviceauth: privateKeyPEM must not be empty")
	}

	privateKey, err := parseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("serviceauth: failed to parse private key: %w", err)
	}

	return &ServiceClient{
		serviceSlug: serviceSlug,
		privateKey:  privateKey,
		keyID:       keyID,
		audience:    defaultAudience,
	}, nil
}

// SignRequest adds an "Authorization: Bearer <jwt>" header to req.
// The JWT is freshly minted on every call so that each request carries a
// non-reusable token within its own narrow validity window.
//
// Returns an error only if token generation fails (e.g., random number
// generation is unavailable), which is extremely rare in practice.
func (c *ServiceClient) SignRequest(req *http.Request) error {
	if req == nil {
		return errors.New("serviceauth: request must not be nil")
	}

	token, err := c.GenerateToken()
	if err != nil {
		return fmt.Errorf("serviceauth: SignRequest: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// GenerateToken mints a signed RS256 JWT for the service.
//
// The returned token string contains the following claims:
//   - iss: the service slug (e.g., "billing-service")
//   - sub: the service slug (same value; identifies the principal)
//   - aud: "falcon-id"
//   - exp: now + 5 minutes
//   - iat: now
//   - jti: a random UUID, ensuring every token is unique
//   - service_slug: the service slug (redundant with iss, kept for readability)
//
// Callers should treat the returned string as an opaque bearer credential.
func (c *ServiceClient) GenerateToken() (string, error) {
	now := time.Now().UTC()

	jti, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("serviceauth: GenerateToken: could not generate jti: %w", err)
	}

	claims := ServiceClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    c.serviceSlug,
			Subject:   c.serviceSlug,
			Audience:  jwt.ClaimStrings{c.audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti.String(),
		},
		ServiceSlug: c.serviceSlug,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = c.keyID

	signed, err := token.SignedString(c.privateKey)
	if err != nil {
		return "", fmt.Errorf("serviceauth: GenerateToken: signing failed: %w", err)
	}

	return signed, nil
}

// parseRSAPrivateKey attempts to decode and parse a PEM-encoded RSA private key.
// It supports both PKCS#1 ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE KEY") formats.
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found in provided key material")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		// PKCS#1
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PKCS#1 parse error: %w", err)
		}
		return key, nil

	case "PRIVATE KEY":
		// PKCS#8 — may wrap RSA, EC, or Ed25519; we only accept RSA here
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PKCS#8 parse error: %w", err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not RSA (got %T)", key)
		}
		return rsaKey, nil

	default:
		return nil, fmt.Errorf("unsupported PEM block type %q; expected \"RSA PRIVATE KEY\" or \"PRIVATE KEY\"", block.Type)
	}
}
