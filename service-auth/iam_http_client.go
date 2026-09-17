// SPDX-License-Identifier: Apache-2.0

package serviceauth

import (
	"errors"
	"net/http"
	"time"
)

// ErrMissingCredentials is returned by NewIAMHTTPClient when clientID or
// clientSecret is empty. Callers are expected to warn-and-fall-back rather
// than fatal — production pods will fail registration calls until a secret
// lands in their env, but the service itself can still start.
var ErrMissingCredentials = errors.New("serviceauth: SERVICE_CLIENT_ID or SERVICE_CLIENT_SECRET is empty")

// IAMHTTPClientConfig holds configuration for the canonical IAM HTTP client.
type IAMHTTPClientConfig struct {
	// IAMURL is the base URL of Falcon-ID (e.g. http://hexxlock-iam:8005).
	IAMURL string

	// ClientID is the service's OAuth2 client_id, typically "svc-<slug>".
	ClientID string

	// ClientSecret is the OAuth2 client_secret (supplied from Vault via
	// ExternalSecret).
	ClientSecret string

	// Scope is the OAuth2 scope string. Defaults to "service:register"
	// when empty, which is sufficient for permission + manifest registration.
	Scope string

	// Timeout is the per-request timeout on the returned *http.Client.
	// Defaults to 10 s when zero.
	Timeout time.Duration
}

// NewIAMHTTPClient builds a ready-to-use *http.Client that injects an OAuth2
// client_credentials bearer token on every request to Falcon-ID.
//
// It returns (client, nil) when credentials are present and the token client
// initialises. It returns (unauthenticated-client, ErrMissingCredentials) when
// ClientID or ClientSecret is empty — this is the correct behaviour for pods
// that boot before their ExternalSecret has landed; the caller should log a
// warning, not fatal, so the rest of the service can still start.
//
// It returns (nil, err) for any other failure (e.g. a malformed TokenURL).
//
// Typical call site:
//
//	iamHTTP, err := serviceauth.NewIAMHTTPClient(serviceauth.IAMHTTPClientConfig{
//	    IAMURL:       cfg.IAMServiceURL,
//	    ClientID:     cfg.ServiceClientID,
//	    ClientSecret: cfg.ServiceClientSecret,
//	})
//	if errors.Is(err, serviceauth.ErrMissingCredentials) {
//	    logger.Warn("SERVICE_CLIENT_ID/SECRET not set — permission registration unauthenticated")
//	} else if err != nil {
//	    logger.Fatal("IAM HTTP client init failed", zap.Error(err))
//	}
//	permClient := permissions.NewClientWithHTTPClient(cfg.IAMServiceURL, "svc-name", iamHTTP, logger)
func NewIAMHTTPClient(cfg IAMHTTPClientConfig) (*http.Client, error) {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return &http.Client{Timeout: timeout}, ErrMissingCredentials
	}

	scope := cfg.Scope
	if scope == "" {
		scope = "service:register"
	}

	tokenClient, err := NewTokenClient(TokenClientConfig{
		TokenURL:     cfg.IAMURL + "/oauth/token",
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scope:        scope,
	})
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: tokenClient.RoundTripper(nil),
	}, nil
}
