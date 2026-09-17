// SPDX-License-Identifier: Apache-2.0

// Package mtls provides mutual TLS configuration for ExampleSuite platform services.
//
// It supports three modes of operation:
//
//   - disabled: plain HTTP, no TLS (local development)
//   - permissive: TLS enabled; client certificates accepted but not required
//   - strict: TLS enabled; client certificates required and verified (production)
//
// Usage — server side:
//
//	cfg := mtls.ConfigFromEnv()
//	tlsConfig, err := mtls.NewServerTLSConfig(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	srv := &http.Server{
//	    Addr:      ":8443",
//	    Handler:   router,
//	    TLSConfig: tlsConfig,
//	}
//
// Usage — client side:
//
//	cfg := mtls.ConfigFromEnv()
//	transport, err := mtls.NewClientTransport(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	client := &http.Client{Transport: transport}
package mtls

import "os"

// Mode controls the mTLS enforcement level for a service endpoint.
type Mode string

const (
	// ModeDisabled means no TLS at all. Use only for local development.
	ModeDisabled Mode = "disabled"

	// ModePermissive accepts both TLS connections with a client certificate
	// and plain TLS connections without one. This is the recommended default
	// for initial rollout.
	ModePermissive Mode = "permissive"

	// ModeStrict requires every inbound connection to present a valid client
	// certificate signed by the configured CA. Use this for production.
	ModeStrict Mode = "strict"
)

// Config holds all mTLS configuration for a service instance.
// Load it at startup with ConfigFromEnv and pass it to NewServerTLSConfig
// or NewClientTransport.
type Config struct {
	// Mode controls TLS enforcement. Defaults to "disabled".
	Mode Mode

	// CertFile is the path to the PEM-encoded service certificate (leaf cert).
	// When Vault PKI integration is used this is the file written by
	// VaultPKICertProvider after the first IssueCertificate call.
	CertFile string

	// KeyFile is the path to the PEM-encoded private key that corresponds to CertFile.
	KeyFile string

	// CAFile is the path to the PEM-encoded CA certificate bundle used to
	// verify peer certificates (both client and server).
	CAFile string

	// ServiceName is the logical name of this service, e.g. "crm" or
	// "integration-bus". Used in log messages and as the default Common Name
	// when requesting certificates from Vault PKI.
	ServiceName string

	// SpiffeID is the SPIFFE identifier for this service workload.
	// Format: spiffe://example.local/ns/{namespace}/sa/{service}
	// When non-empty it is validated against the URI SAN in peer certificates
	// by IdentityBindingMiddleware.
	SpiffeID string
}

// ConfigFromEnv builds a Config by reading environment variables.
// Every field has a sensible default so services can adopt mTLS incrementally.
//
// Environment variables:
//
//	MTLS_MODE        — "disabled" | "permissive" | "strict" (default: "disabled")
//	MTLS_CERT_FILE   — path to service certificate (default: "/vault/tls/tls.crt")
//	MTLS_KEY_FILE    — path to private key         (default: "/vault/tls/tls.key")
//	MTLS_CA_FILE     — path to CA bundle           (default: "/vault/tls/ca.crt")
//	SERVICE_NAME     — service slug                (default: "unknown")
//	MTLS_SPIFFE_ID   — SPIFFE URI                  (default: "")
func ConfigFromEnv() Config {
	return Config{
		Mode:        Mode(getEnv("MTLS_MODE", string(ModeDisabled))),
		CertFile:    getEnv("MTLS_CERT_FILE", "/vault/tls/tls.crt"),
		KeyFile:     getEnv("MTLS_KEY_FILE", "/vault/tls/tls.key"),
		CAFile:      getEnv("MTLS_CA_FILE", "/vault/tls/ca.crt"),
		ServiceName: getEnv("SERVICE_NAME", "unknown"),
		SpiffeID:    getEnv("MTLS_SPIFFE_ID", ""),
	}
}

// getEnv reads an environment variable and returns fallback when it is unset or empty.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
