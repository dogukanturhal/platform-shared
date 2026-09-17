// SPDX-License-Identifier: Apache-2.0

package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// NewServerTLSConfig builds a *tls.Config suitable for a Gin/HTTP server.
//
// When cfg.Mode is ModeDisabled it returns (nil, nil) — the caller should then
// start a plain http.Server without TLS.
//
// When cfg.Mode is ModePermissive the server advertises TLS and validates any
// client certificate that is presented, but does not require one. This allows a
// gradual rollout where some callers have not yet obtained mTLS credentials.
//
// When cfg.Mode is ModeStrict the server requires every client to present a
// certificate signed by the configured CA. Connections without a client cert
// are rejected at the TLS handshake layer before any HTTP handler runs.
//
// The returned config uses TLS 1.3 as the minimum version and loads the
// service certificate via a CertLoader so certificates are reloaded from disk
// without a service restart (Vault PKI auto-renewal support).
func NewServerTLSConfig(cfg Config) (*tls.Config, error) {
	if cfg.Mode == ModeDisabled {
		return nil, nil
	}

	certLoader, err := NewCertLoader(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: NewServerTLSConfig: %w", err)
	}

	caPool, err := loadCACertPool(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: NewServerTLSConfig: %w", err)
	}

	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: certLoader.GetCertificate,
		ClientCAs:      caPool,
	}

	switch cfg.Mode {
	case ModeStrict:
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	default: // ModePermissive
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
	}

	return tlsCfg, nil
}

// ListenAndServeTLS starts an HTTP server with the mTLS configuration derived
// from cfg. It is a convenience wrapper that replaces the common startup
// boilerplate in service main() functions.
//
// When cfg.Mode is ModeDisabled the server starts without TLS using plain
// http.ListenAndServe, which is safe for local development behind a reverse
// proxy or service mesh sidecar.
//
// The function blocks until the server returns an error. Callers should run it
// in a goroutine and handle graceful shutdown via http.Server.Shutdown.
//
// Example:
//
//	srv := &http.Server{Addr: ":8443", Handler: router}
//	tlsConfig, err := mtls.NewServerTLSConfig(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if tlsConfig != nil {
//	    srv.TLSConfig = tlsConfig
//	    if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
//	        log.Fatal(err)
//	    }
//	} else {
//	    if err := srv.ListenAndServe(); err != http.ErrServerClosed {
//	        log.Fatal(err)
//	    }
//	}
func ListenAndServeTLS(addr string, handler http.Handler, cfg Config) error {
	tlsCfg, err := NewServerTLSConfig(cfg)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 30 * time.Second,
	}

	if tlsCfg == nil {
		// ModeDisabled — plain HTTP.
		return srv.ListenAndServe()
	}

	// Certs are loaded by GetCertificate; empty strings are intentional.
	return srv.ListenAndServeTLS("", "")
}

// loadCACertPool reads the PEM-encoded CA bundle at path and returns a
// *x509.CertPool containing all certificates found in the file.
// Returns an error if the file cannot be read or contains no valid certificates.
func loadCACertPool(path string) (*x509.CertPool, error) {
	pemData, err := os.ReadFile(path) //nolint:gosec // path is from trusted configuration
	if err != nil {
		return nil, fmt.Errorf("loadCACertPool: ReadFile(%s): %w", path, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("loadCACertPool: no valid certificates found in %s", path)
	}

	return pool, nil
}
