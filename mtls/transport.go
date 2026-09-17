// SPDX-License-Identifier: Apache-2.0

package mtls

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// NewClientTransport returns an http.RoundTripper that presents the service's
// mTLS client certificate on every outgoing request.
//
// When cfg.Mode is ModeDisabled it returns http.DefaultTransport unchanged so
// existing code in development environments requires no modification.
//
// When cfg.Mode is ModePermissive or ModeStrict the returned transport:
//   - presents the service certificate from CertFile/KeyFile (auto-reloaded)
//   - verifies the server's certificate against CAFile
//   - enforces TLS 1.3 as the minimum version
//   - uses sensible connection pool limits
//
// The CertLoader inside the transport reloads certificates every 30 seconds,
// so Vault PKI renewals are picked up without restarting the service.
//
// Example:
//
//	cfg := mtls.ConfigFromEnv()
//	transport, err := mtls.NewClientTransport(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	client := &http.Client{Transport: transport}
func NewClientTransport(cfg Config) (http.RoundTripper, error) {
	if cfg.Mode == ModeDisabled {
		return http.DefaultTransport, nil
	}

	certLoader, err := NewCertLoader(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: NewClientTransport: %w", err)
	}

	caPool, err := loadCACertPool(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: NewClientTransport: %w", err)
	}

	return &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:           tls.VersionTLS13,
			GetClientCertificate: certLoader.GetClientCertificate,
			RootCAs:              caPool,
		},
		// Connection pool tuning — matches the integration-bus service defaults.
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}, nil
}

// NewClientTransportWithLoader is like NewClientTransport but accepts a
// pre-constructed CertLoader. Use this when multiple clients should share the
// same loader (and therefore the same background reload goroutine).
func NewClientTransportWithLoader(loader *CertLoader, caFile string) (http.RoundTripper, error) {
	if loader == nil {
		return nil, fmt.Errorf("mtls: NewClientTransportWithLoader: loader must not be nil")
	}

	caPool, err := loadCACertPool(caFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: NewClientTransportWithLoader: %w", err)
	}

	return &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:           tls.VersionTLS13,
			GetClientCertificate: loader.GetClientCertificate,
			RootCAs:              caPool,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}, nil
}
