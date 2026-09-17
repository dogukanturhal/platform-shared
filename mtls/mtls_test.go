// SPDX-License-Identifier: Apache-2.0

package mtls_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/platform-shared/mtls"
)

// ---------------------------------------------------------------------------
// Test helpers: generate self-signed certificates in memory
// ---------------------------------------------------------------------------

type testCA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey
}

// newTestCA creates a self-signed root CA using P-256 (ECDSA).
func newTestCA(t *testing.T) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate CA key")

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err, "create CA certificate")

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return &testCA{cert: cert, certPEM: certPEM, key: key}
}

type testCert struct {
	certPEM []byte
	keyPEM  []byte
}

// issueLeafCert issues a leaf certificate signed by ca with the given common
// name and optional SPIFFE URI SAN.
func issueLeafCert(t *testing.T, ca *testCA, cn string, spiffeID string) testCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate leaf key")

	var uris []*url.URL
	if spiffeID != "" {
		u, err := url.Parse(spiffeID)
		require.NoError(t, err)
		uris = append(uris, u)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:         uris,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err, "create leaf certificate")

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return testCert{certPEM: certPEM, keyPEM: keyPEM}
}

// writeTempFiles writes cert PEM files to a temp directory and returns the
// paths for certFile, keyFile, and caFile.
func writeTempFiles(t *testing.T, cert testCert, ca *testCA) (certFile, keyFile, caFile string) {
	t.Helper()

	dir := t.TempDir()
	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	caFile = filepath.Join(dir, "ca.crt")

	require.NoError(t, os.WriteFile(certFile, cert.certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyFile, cert.keyPEM, 0o600))
	require.NoError(t, os.WriteFile(caFile, ca.certPEM, 0o600))

	return certFile, keyFile, caFile
}

// ---------------------------------------------------------------------------
// ConfigFromEnv
// ---------------------------------------------------------------------------

func TestConfigFromEnv_Defaults(t *testing.T) {
	// Ensure no env vars leak from other tests.
	for _, key := range []string{"MTLS_MODE", "MTLS_CERT_FILE", "MTLS_KEY_FILE", "MTLS_CA_FILE", "SERVICE_NAME", "MTLS_SPIFFE_ID"} {
		t.Setenv(key, "")
	}

	cfg := mtls.ConfigFromEnv()

	assert.Equal(t, mtls.ModeDisabled, cfg.Mode)
	assert.Equal(t, "/vault/tls/tls.crt", cfg.CertFile)
	assert.Equal(t, "/vault/tls/tls.key", cfg.KeyFile)
	assert.Equal(t, "/vault/tls/ca.crt", cfg.CAFile)
	assert.Equal(t, "unknown", cfg.ServiceName)
	assert.Equal(t, "", cfg.SpiffeID)
}

func TestConfigFromEnv_Override(t *testing.T) {
	t.Setenv("MTLS_MODE", "strict")
	t.Setenv("MTLS_CERT_FILE", "/etc/tls/svc.crt")
	t.Setenv("MTLS_KEY_FILE", "/etc/tls/svc.key")
	t.Setenv("MTLS_CA_FILE", "/etc/tls/ca-bundle.crt")
	t.Setenv("SERVICE_NAME", "crm")
	t.Setenv("MTLS_SPIFFE_ID", "spiffe://example.local/ns/business/sa/crm")

	cfg := mtls.ConfigFromEnv()

	assert.Equal(t, mtls.ModeStrict, cfg.Mode)
	assert.Equal(t, "/etc/tls/svc.crt", cfg.CertFile)
	assert.Equal(t, "/etc/tls/svc.key", cfg.KeyFile)
	assert.Equal(t, "/etc/tls/ca-bundle.crt", cfg.CAFile)
	assert.Equal(t, "crm", cfg.ServiceName)
	assert.Equal(t, "spiffe://example.local/ns/business/sa/crm", cfg.SpiffeID)
}

// ---------------------------------------------------------------------------
// CertLoader
// ---------------------------------------------------------------------------

func TestCertLoader_LoadsValidCert(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueLeafCert(t, ca, "crm.example.local", "")
	certFile, keyFile, _ := writeTempFiles(t, leaf, ca)

	loader, err := mtls.NewCertLoader(certFile, keyFile)
	require.NoError(t, err)
	t.Cleanup(loader.Stop)

	cert, err := loader.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert)
}

func TestCertLoader_RejectsInvalidCert(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "bad.crt")
	keyFile := filepath.Join(dir, "bad.key")

	require.NoError(t, os.WriteFile(certFile, []byte("not a cert"), 0o600))
	require.NoError(t, os.WriteFile(keyFile, []byte("not a key"), 0o600))

	_, err := mtls.NewCertLoader(certFile, keyFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "initial certificate load failed")
}

func TestCertLoader_GetClientCertificate(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueLeafCert(t, ca, "billing.example.local", "")
	certFile, keyFile, _ := writeTempFiles(t, leaf, ca)

	loader, err := mtls.NewCertLoader(certFile, keyFile)
	require.NoError(t, err)
	t.Cleanup(loader.Stop)

	cert, err := loader.GetClientCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert)
}

func TestCertLoader_ReloadsOnFileChange(t *testing.T) {
	ca := newTestCA(t)
	leaf1 := issueLeafCert(t, ca, "svc-v1.example.local", "")
	certFile, keyFile, _ := writeTempFiles(t, leaf1, ca)

	loader, err := mtls.NewCertLoader(certFile, keyFile)
	require.NoError(t, err)
	t.Cleanup(loader.Stop)

	cert1, err := loader.GetCertificate(nil)
	require.NoError(t, err)
	// Capture the raw DER of the first load for comparison.
	// tls.Certificate.Leaf is lazy-parsed and will be nil here; comparing
	// the raw DER bytes is both safe and sufficient.
	rawDER1 := make([]byte, len(cert1.Certificate[0]))
	copy(rawDER1, cert1.Certificate[0])

	// Issue a second certificate and overwrite the files.
	leaf2 := issueLeafCert(t, ca, "svc-v2.example.local", "")
	// Ensure mtime advances even on filesystems with 1 s resolution.
	future := time.Now().Add(2 * time.Second)
	require.NoError(t, os.WriteFile(certFile, leaf2.certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyFile, leaf2.keyPEM, 0o600))
	require.NoError(t, os.Chtimes(certFile, future, future))

	// Drive the reload immediately instead of waiting 30 s.
	loader.ForceReload()

	cert2, err := loader.GetCertificate(nil)
	require.NoError(t, err)

	// The raw DER of the second load must differ — they were issued with
	// different CNs and serial numbers.
	assert.NotEqual(t, rawDER1, cert2.Certificate[0],
		"raw certificate DER must differ after reload")
}

// ---------------------------------------------------------------------------
// NewServerTLSConfig
// ---------------------------------------------------------------------------

func TestNewServerTLSConfig_DisabledReturnsNil(t *testing.T) {
	cfg := mtls.Config{Mode: mtls.ModeDisabled}
	tlsCfg, err := mtls.NewServerTLSConfig(cfg)
	require.NoError(t, err)
	assert.Nil(t, tlsCfg)
}

func TestNewServerTLSConfig_StrictRequiresClientCert(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueLeafCert(t, ca, "server.example.local", "")
	certFile, keyFile, caFile := writeTempFiles(t, leaf, ca)

	cfg := mtls.Config{
		Mode:     mtls.ModeStrict,
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	}

	tlsCfg, err := mtls.NewServerTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	assert.Equal(t, tls.RequireAndVerifyClientCert, tlsCfg.ClientAuth)
	assert.Equal(t, uint16(tls.VersionTLS13), tlsCfg.MinVersion)
}

func TestNewServerTLSConfig_PermissiveAcceptsBoth(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueLeafCert(t, ca, "server.example.local", "")
	certFile, keyFile, caFile := writeTempFiles(t, leaf, ca)

	cfg := mtls.Config{
		Mode:     mtls.ModePermissive,
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	}

	tlsCfg, err := mtls.NewServerTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	assert.Equal(t, tls.VerifyClientCertIfGiven, tlsCfg.ClientAuth)
	assert.Equal(t, uint16(tls.VersionTLS13), tlsCfg.MinVersion)
}

func TestNewServerTLSConfig_MissingCAFileErrors(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueLeafCert(t, ca, "server.example.local", "")
	certFile, keyFile, _ := writeTempFiles(t, leaf, ca)

	cfg := mtls.Config{
		Mode:     mtls.ModeStrict,
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   "/does/not/exist/ca.crt",
	}

	_, err := mtls.NewServerTLSConfig(cfg)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// NewClientTransport
// ---------------------------------------------------------------------------

func TestNewClientTransport_DisabledReturnsDefault(t *testing.T) {
	cfg := mtls.Config{Mode: mtls.ModeDisabled}
	transport, err := mtls.NewClientTransport(cfg)
	require.NoError(t, err)
	assert.Equal(t, http.DefaultTransport, transport)
}

func TestNewClientTransport_StrictIncludesClientCert(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueLeafCert(t, ca, "crm.example.local", "")
	certFile, keyFile, caFile := writeTempFiles(t, leaf, ca)

	cfg := mtls.Config{
		Mode:     mtls.ModeStrict,
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	}

	transport, err := mtls.NewClientTransport(cfg)
	require.NoError(t, err)
	require.NotNil(t, transport)

	tr, ok := transport.(*http.Transport)
	require.True(t, ok, "expected *http.Transport")
	require.NotNil(t, tr.TLSClientConfig)
	assert.Equal(t, uint16(tls.VersionTLS13), tr.TLSClientConfig.MinVersion)
	assert.NotNil(t, tr.TLSClientConfig.GetClientCertificate)
	assert.NotNil(t, tr.TLSClientConfig.RootCAs)
}

// ---------------------------------------------------------------------------
// IdentityBindingMiddleware
// ---------------------------------------------------------------------------

func newTestGinContext(t *testing.T, tlsState *tls.ConnectionState) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	if tlsState != nil {
		req.TLS = tlsState
	}

	c, _ := gin.CreateTestContext(w)
	c.Request = req
	return c, w
}

func TestIdentityBinding_NoClientCert_Permissive(t *testing.T) {
	c, w := newTestGinContext(t, nil)

	handler := mtls.IdentityBindingMiddleware(mtls.ModePermissive, zap.NewNop())
	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.False(t, c.IsAborted())
	identity, exists := c.Get(mtls.ContextKeyMTLSIdentity)
	assert.False(t, exists, "no identity should be set without a cert")
	assert.Nil(t, identity)
}

func TestIdentityBinding_NoClientCert_Strict(t *testing.T) {
	c, w := newTestGinContext(t, nil)

	handler := mtls.IdentityBindingMiddleware(mtls.ModeStrict, zap.NewNop())
	handler(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestIdentityBinding_ValidClientCert_SetsContext(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueLeafCert(t, ca, "crm.example.local", "spiffe://example.local/ns/business/sa/crm")
	certFile, keyFile, _ := writeTempFiles(t, leaf, ca)

	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(tlsCert.Certificate[0])
	require.NoError(t, err)

	tlsState := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{parsed},
	}

	c, _ := newTestGinContext(t, tlsState)

	handler := mtls.IdentityBindingMiddleware(mtls.ModePermissive, zap.NewNop())
	handler(c)

	assert.False(t, c.IsAborted())

	identity, ok := c.Get(mtls.ContextKeyMTLSIdentity)
	assert.True(t, ok)
	assert.Equal(t, "crm.example.local", identity)

	spiffeID, ok := c.Get(mtls.ContextKeyMTLSSpiffeID)
	assert.True(t, ok)
	assert.Equal(t, "spiffe://example.local/ns/business/sa/crm", spiffeID)

	verified, ok := c.Get(mtls.ContextKeyMTLSVerified)
	assert.True(t, ok)
	assert.Equal(t, true, verified)
}

func TestIdentityBinding_MatchingIdentities_Pass(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueLeafCert(t, ca, "crm.example.local", "")
	certFile, keyFile, _ := writeTempFiles(t, leaf, ca)

	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(tlsCert.Certificate[0])
	require.NoError(t, err)

	tlsState := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{parsed}}

	c, w := newTestGinContext(t, tlsState)
	c.Set("client_id", "svc-crm") // JWT identity

	handler := mtls.IdentityBindingMiddleware(mtls.ModeStrict, zap.NewNop())
	handler(c)

	assert.False(t, c.IsAborted(), "matching identities should pass")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestIdentityBinding_MismatchedIdentities_Returns403(t *testing.T) {
	ca := newTestCA(t)
	// mTLS says "crm" but JWT says "billing"
	leaf := issueLeafCert(t, ca, "crm.example.local", "")
	certFile, keyFile, _ := writeTempFiles(t, leaf, ca)

	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(tlsCert.Certificate[0])
	require.NoError(t, err)

	tlsState := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{parsed}}

	c, w := newTestGinContext(t, tlsState)
	c.Set("client_id", "svc-billing") // Mismatched JWT identity

	// Use a real logger to verify it does not panic (SECURITY log line).
	log, err := zap.NewDevelopment()
	require.NoError(t, err)

	handler := mtls.IdentityBindingMiddleware(mtls.ModeStrict, log)
	handler(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "identity_mismatch")
}

func TestIdentityBinding_NoJWTClientID_DoesNotCheck(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueLeafCert(t, ca, "crm.example.local", "")
	certFile, keyFile, _ := writeTempFiles(t, leaf, ca)

	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(tlsCert.Certificate[0])
	require.NoError(t, err)

	tlsState := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{parsed}}

	// No "client_id" set in context — identity binding must not error.
	c, w := newTestGinContext(t, tlsState)

	handler := mtls.IdentityBindingMiddleware(mtls.ModePermissive, zap.NewNop())
	handler(c)

	assert.False(t, c.IsAborted())
	assert.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// AllowedIdentities middleware
// ---------------------------------------------------------------------------

func TestAllowedIdentities_Permitted(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueLeafCert(t, ca, "billing.example.local", "")
	certFile, keyFile, _ := writeTempFiles(t, leaf, ca)

	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(tlsCert.Certificate[0])
	require.NoError(t, err)

	tlsState := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{parsed}}

	c, w := newTestGinContext(t, tlsState)
	c.Set(mtls.ContextKeyMTLSIdentity, "billing.example.local")

	mtls.AllowedIdentities("crm", "billing", "integration-bus")(c)

	assert.False(t, c.IsAborted())
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAllowedIdentities_NotPermitted(t *testing.T) {
	c, w := newTestGinContext(t, nil)
	c.Set(mtls.ContextKeyMTLSIdentity, "rogue-service.example.local")

	mtls.AllowedIdentities("crm", "billing")(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "identity_not_permitted")
}

func TestAllowedIdentities_NoIdentity(t *testing.T) {
	c, w := newTestGinContext(t, nil)
	// ContextKeyMTLSIdentity not set

	mtls.AllowedIdentities("crm")(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "identity_required")
}

// ---------------------------------------------------------------------------
// RequireMTLS middleware
// ---------------------------------------------------------------------------

func TestRequireMTLS_VerifiedPasses(t *testing.T) {
	c, w := newTestGinContext(t, nil)
	c.Set(mtls.ContextKeyMTLSVerified, true)

	mtls.RequireMTLS()(c)

	assert.False(t, c.IsAborted())
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireMTLS_UnverifiedRejects(t *testing.T) {
	c, w := newTestGinContext(t, nil)
	// ContextKeyMTLSVerified not set

	mtls.RequireMTLS()(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ---------------------------------------------------------------------------
// identitiesMatch (internal) — tested via the middleware behavior above.
// Extra table-driven test for normalisation edge cases.
// ---------------------------------------------------------------------------

func TestIdentityBinding_NormalisationEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		mtlsCN   string
		jwtID    string
		wantPass bool
	}{
		{
			name:     "both already bare",
			mtlsCN:   "crm",
			jwtID:    "crm",
			wantPass: true,
		},
		{
			name:     "mtls has .example.local suffix, jwt has svc- prefix",
			mtlsCN:   "crm.example.local",
			jwtID:    "svc-crm",
			wantPass: true,
		},
		{
			name:     "only suffix on mtls, no prefix on jwt",
			mtlsCN:   "billing.example.local",
			jwtID:    "billing",
			wantPass: true,
		},
		{
			name:     "only prefix on jwt, no suffix on mtls",
			mtlsCN:   "billing",
			jwtID:    "svc-billing",
			wantPass: true,
		},
		{
			name:     "completely different services",
			mtlsCN:   "crm.example.local",
			jwtID:    "svc-billing",
			wantPass: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ca := newTestCA(t)
			leaf := issueLeafCert(t, ca, tc.mtlsCN, "")
			certFile, keyFile, _ := writeTempFiles(t, leaf, ca)

			tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
			require.NoError(t, err)
			parsed, err := x509.ParseCertificate(tlsCert.Certificate[0])
			require.NoError(t, err)

			tlsState := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{parsed}}

			c, w := newTestGinContext(t, tlsState)
			c.Set("client_id", tc.jwtID)

			mtls.IdentityBindingMiddleware(mtls.ModeStrict, zap.NewNop())(c)

			if tc.wantPass {
				assert.False(t, c.IsAborted(), "expected pass for %s/%s", tc.mtlsCN, tc.jwtID)
				assert.Equal(t, http.StatusOK, w.Code)
			} else {
				assert.True(t, c.IsAborted(), "expected reject for %s/%s", tc.mtlsCN, tc.jwtID)
				assert.Equal(t, http.StatusForbidden, w.Code)
				assert.True(t, strings.Contains(w.Body.String(), "identity_mismatch"),
					"body: %s", w.Body.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// IsMTLSVerified / GetMTLSIdentity / GetMTLSSpiffeID helpers
// ---------------------------------------------------------------------------

func TestHelpers_AbsentContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	identity, ok := mtls.GetMTLSIdentity(c)
	assert.False(t, ok)
	assert.Empty(t, identity)

	spiffe, ok := mtls.GetMTLSSpiffeID(c)
	assert.False(t, ok)
	assert.Empty(t, spiffe)

	assert.False(t, mtls.IsMTLSVerified(c))
}
