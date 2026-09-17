// SPDX-License-Identifier: Apache-2.0

package mtls

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"
)

const (
	// certReloadInterval is how often the background poller checks for
	// certificate file changes. Keeping this short ensures that a Vault PKI
	// renewal (which rewrites the files on disk) is picked up quickly without
	// service restart.
	certReloadInterval = 30 * time.Second
)

// CertLoader holds a TLS certificate pair in memory and reloads it from disk
// whenever the underlying files change. It is safe for concurrent use.
//
// The loader integrates directly with crypto/tls via its GetCertificate and
// GetClientCertificate callbacks, so no explicit locking is needed by callers.
type CertLoader struct {
	certFile string
	keyFile  string

	mu      sync.RWMutex
	cert    *tls.Certificate
	lastMod time.Time // most recent mtime of certFile at last load

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewCertLoader loads the certificate pair located at certFile/keyFile and
// starts a background goroutine that polls for file changes every 30 seconds.
// Call Stop to release the background goroutine when the service shuts down.
//
// Returns an error if the initial certificate load fails; this is treated as
// a hard failure so services start with a valid certificate or not at all.
func NewCertLoader(certFile, keyFile string) (*CertLoader, error) {
	cl := &CertLoader{
		certFile: certFile,
		keyFile:  keyFile,
		stopCh:   make(chan struct{}),
	}

	if err := cl.load(); err != nil {
		return nil, fmt.Errorf("mtls: initial certificate load failed: %w", err)
	}

	cl.wg.Add(1)
	go cl.reloadLoop()

	return cl, nil
}

// GetCertificate satisfies tls.Config.GetCertificate. It is called by the TLS
// stack on every server-side handshake to fetch the current certificate.
func (cl *CertLoader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cl.mu.RLock()
	defer cl.mu.RUnlock()
	return cl.cert, nil
}

// GetClientCertificate satisfies tls.Config.GetClientCertificate. It is called
// by the TLS stack on every client-side handshake to fetch the certificate that
// should be presented to the server.
func (cl *CertLoader) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cl.mu.RLock()
	defer cl.mu.RUnlock()
	return cl.cert, nil
}

// Stop terminates the background reload goroutine. Callers should invoke this
// during graceful shutdown to avoid goroutine leaks.
func (cl *CertLoader) Stop() {
	close(cl.stopCh)
	cl.wg.Wait()
}

// ForceReload immediately checks the certificate files for changes and reloads
// them if the mtime has advanced. This is primarily useful in tests to avoid
// waiting for the 30-second polling interval.
func (cl *CertLoader) ForceReload() {
	cl.checkAndReload()
}

// load reads the certificate pair from disk and replaces the in-memory cert
// atomically. It records the mtime of certFile so the poller can skip
// unnecessary reloads.
func (cl *CertLoader) load() error {
	cert, err := tls.LoadX509KeyPair(cl.certFile, cl.keyFile)
	if err != nil {
		return fmt.Errorf("LoadX509KeyPair(%s, %s): %w", cl.certFile, cl.keyFile, err)
	}

	info, err := os.Stat(cl.certFile)
	if err != nil {
		return fmt.Errorf("stat(%s): %w", cl.certFile, err)
	}

	cl.mu.Lock()
	cl.cert = &cert
	cl.lastMod = info.ModTime()
	cl.mu.Unlock()

	return nil
}

// reloadLoop polls for certificate file changes on a fixed interval and calls
// load when the mtime of certFile advances. It exits when stopCh is closed.
func (cl *CertLoader) reloadLoop() {
	defer cl.wg.Done()

	ticker := time.NewTicker(certReloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-cl.stopCh:
			return
		case <-ticker.C:
			cl.checkAndReload()
		}
	}
}

// checkAndReload stats the certificate file and reloads only if it has changed.
// Errors during reload are ignored (logged to stderr) so the service continues
// serving with the last good certificate rather than crashing.
func (cl *CertLoader) checkAndReload() {
	info, err := os.Stat(cl.certFile)
	if err != nil {
		// File may be temporarily absent during an atomic rename from Vault agent.
		// Do not treat this as fatal; the next tick will retry.
		fmt.Fprintf(os.Stderr, "mtls: cert_loader: stat(%s): %v\n", cl.certFile, err)
		return
	}

	cl.mu.RLock()
	changed := info.ModTime().After(cl.lastMod)
	cl.mu.RUnlock()

	if !changed {
		return
	}

	if err := cl.load(); err != nil {
		fmt.Fprintf(os.Stderr, "mtls: cert_loader: reload failed (keeping previous cert): %v\n", err)
		return
	}
}
