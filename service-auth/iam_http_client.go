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

// ScopeRegistrationOnly is the scope a service needs for permission and
// manifest registration alone. Pass it to IAMHTTPClientConfig.Scope ONLY
// for a client that makes no other authenticated call — it is deliberately
// NOT a default, because a token silently narrowed to it 403s every other
// outbound call. See IAMHTTPClientConfig.Scope.
const ScopeRegistrationOnly = "service:register"

// IAMHTTPClientConfig holds configuration for the canonical IAM HTTP client.
type IAMHTTPClientConfig struct {
	// IAMURL is the base URL of Falcon-ID (e.g. http://iam.example.internal:8005).
	IAMURL string

	// ClientID is the service's OAuth2 client_id, typically "svc-<slug>".
	ClientID string

	// ClientSecret is the OAuth2 client_secret (supplied from Vault via
	// ExternalSecret).
	ClientSecret string

	// Scope is the OAuth2 scope string: a space-separated subset of what
	// this client is registered for, requested at token time.
	//
	// LEAVE IT EMPTY unless you deliberately want LESS than your client
	// was granted. Empty omits the `scope` parameter, and Falcon-ID then
	// issues the client's full registered set — making the client's
	// ServiceClientClaim manifest the single authorization boundary,
	// reviewed in one place instead of silently re-narrowed here.
	//
	// This field used to default to ScopeRegistrationOnly when empty, and
	// that default caused a production outage (2026-09-20). An OAuth2
	// client_credentials token can only ever be a SUBSET of what was
	// requested, so a service that left this blank received a token
	// carrying service:register and nothing else — no matter what its
	// manifest granted. subscription-management's every outbound call
	// beyond registration then 403'd insufficient_scope, silently and
	// permanently: tenant plan writes left billing and quota entitlements
	// stale for ten days while a tenant paid for a different plan, and
	// subscription cancellation was wholly non-functional for customers.
	// Nothing failed at boot, no test covered it, and the only trace was
	// one log line nobody read.
	//
	// Set it explicitly ONLY to narrow below the grant, and keep the value
	// in sync with the service's ServiceClientClaim.
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
//	    // Scope omitted on purpose: take the full registered grant.
//	    // Set it only to request LESS — see IAMHTTPClientConfig.Scope.
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

	// cfg.Scope passes through untouched: empty means "omit the scope
	// parameter", which yields the client's full registered set. See
	// IAMHTTPClientConfig.Scope for why defaulting to a narrow scope here
	// was a silent-underprivilege footgun rather than a safe default.
	tokenClient, err := NewTokenClient(TokenClientConfig{
		TokenURL:     cfg.IAMURL + "/oauth/token",
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scope:        cfg.Scope,
	})
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: tokenClient.RoundTripper(nil),
	}, nil
}
