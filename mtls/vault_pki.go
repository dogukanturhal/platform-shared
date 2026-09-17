// SPDX-License-Identifier: Apache-2.0

package mtls

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

const (
	// pkiDefaultTTL is the certificate TTL requested from Vault when none is
	// configured explicitly. 4h follows Netflix's short-lived cert pattern —
	// shorter certs reduce compromise window and eliminate the need for CRL/OCSP.
	pkiDefaultTTL = "4h"

	// pkiRenewalFraction is the fraction of the TTL after which the certificate
	// is proactively renewed. 2/3 means a 4h cert is renewed at the 2h40m mark,
	// giving a 1h20m window for retries before the cert expires.
	pkiRenewalFraction = 2.0 / 3.0

	// pkiRetryBase is the initial backoff duration when a renewal attempt fails.
	pkiRetryBase = 30 * time.Second

	// pkiRetryMax is the maximum backoff duration between renewal retries.
	pkiRetryMax = 10 * time.Minute
)

// VaultPKICertProvider issues and automatically renews TLS certificates from a
// Vault PKI secrets engine. It writes the certificate, private key, and CA
// chain to disk so that CertLoader can pick them up without a service restart.
//
// Vault PKI mount layout expected:
//
//	pki-services/issue/{role}   — for business service certificates
//	pki-infra/issue/{role}      — for infrastructure / sidecar certificates
type VaultPKICertProvider struct {
	vaultClient *vaultapi.Client
	pkiMount    string // e.g. "pki-services" or "pki-infra"
	role        string // Vault PKI role name, e.g. "crm"
	commonName  string // certificate CN, e.g. "crm.example.local"
	ttl         string // certificate lifetime, e.g. "24h"
	outputDir   string // directory for cert/key/ca files, e.g. "/vault/tls"
	uriSANs     string // comma-separated SPIFFE URI SANs

	log *zap.Logger
}

// VaultPKIConfig holds the configuration for VaultPKICertProvider.
type VaultPKIConfig struct {
	// VaultClient is a pre-authenticated Vault API client.
	// Use vault.DefaultManager(...).Client().Raw() to obtain one.
	VaultClient *vaultapi.Client

	// PKIMount is the Vault mount path for the PKI secrets engine.
	// Default: "pki-services"
	PKIMount string

	// Role is the Vault PKI role that controls the allowed CN/SANs/TTL.
	// Typically matches the service slug, e.g. "crm".
	Role string

	// CommonName is the certificate's Common Name, e.g. "crm.example.local".
	CommonName string

	// TTL controls the requested certificate lifetime.
	// Default: "24h"
	TTL string

	// OutputDir is the directory where cert.pem, key.pem, and ca.pem are written.
	// Default: "/vault/tls"
	OutputDir string

	// URISANs is an optional SPIFFE URI SAN, e.g.
	// "spiffe://example.local/ns/business/sa/crm".
	URISANs string

	// Logger for renewal events and errors.
	Logger *zap.Logger
}

// NewVaultPKICertProvider creates a VaultPKICertProvider from cfg.
// It validates required fields but does not issue a certificate; call
// IssueCertificate for that.
func NewVaultPKICertProvider(cfg VaultPKIConfig) (*VaultPKICertProvider, error) {
	if cfg.VaultClient == nil {
		return nil, fmt.Errorf("mtls: VaultPKICertProvider: VaultClient must not be nil")
	}
	if cfg.Role == "" {
		return nil, fmt.Errorf("mtls: VaultPKICertProvider: Role must not be empty")
	}
	if cfg.CommonName == "" {
		return nil, fmt.Errorf("mtls: VaultPKICertProvider: CommonName must not be empty")
	}

	pkiMount := cfg.PKIMount
	if pkiMount == "" {
		pkiMount = "pki-services"
	}

	ttl := cfg.TTL
	if ttl == "" {
		ttl = pkiDefaultTTL
	}

	outputDir := cfg.OutputDir
	if outputDir == "" {
		outputDir = "/vault/tls"
	}

	log := cfg.Logger
	if log == nil {
		log = zap.NewNop()
	}

	return &VaultPKICertProvider{
		vaultClient: cfg.VaultClient,
		pkiMount:    pkiMount,
		role:        cfg.Role,
		commonName:  cfg.CommonName,
		ttl:         ttl,
		outputDir:   outputDir,
		uriSANs:     cfg.URISANs,
		log:         log.Named("vault_pki"),
	}, nil
}

// IssueCertificate requests a new certificate from Vault PKI and writes the
// certificate, private key, and CA chain to the configured output directory.
//
// File layout:
//
//	{outputDir}/tls.crt — leaf certificate (PEM)
//	{outputDir}/tls.key — private key (PEM)
//	{outputDir}/ca.crt  — issuing CA chain (PEM)
//
// This matches the default paths expected by ConfigFromEnv so no additional
// environment variables need to be changed.
//
// Returns an error if the Vault request fails or the files cannot be written.
// On error, any previously valid files on disk are left untouched.
func (p *VaultPKICertProvider) IssueCertificate(ctx context.Context) error {
	issuePath := fmt.Sprintf("%s/issue/%s", p.pkiMount, p.role)

	data := map[string]interface{}{
		"common_name": p.commonName,
		"ttl":         p.ttl,
	}
	if p.uriSANs != "" {
		data["uri_sans"] = p.uriSANs
	}

	secret, err := p.vaultClient.Logical().WriteWithContext(ctx, issuePath, data)
	if err != nil {
		return fmt.Errorf("mtls: IssueCertificate: Vault PKI issue failed: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return fmt.Errorf("mtls: IssueCertificate: empty response from Vault PKI")
	}

	cert, err := extractStringField(secret.Data, "certificate")
	if err != nil {
		return fmt.Errorf("mtls: IssueCertificate: %w", err)
	}
	key, err := extractStringField(secret.Data, "private_key")
	if err != nil {
		return fmt.Errorf("mtls: IssueCertificate: %w", err)
	}

	// Build CA chain: prefer "ca_chain" (array), fall back to "issuing_ca" (string).
	caChain, caErr := buildCAChain(secret.Data)
	if caErr != nil {
		return fmt.Errorf("mtls: IssueCertificate: %w", caErr)
	}

	if err := p.writeFiles(cert, key, caChain); err != nil {
		return fmt.Errorf("mtls: IssueCertificate: %w", err)
	}

	p.log.Info("Certificate issued from Vault PKI",
		zap.String("common_name", p.commonName),
		zap.String("role", p.role),
		zap.String("ttl", p.ttl),
		zap.String("output_dir", p.outputDir),
	)

	return nil
}

// StartAutoRenewal launches a background goroutine that renews the certificate
// at 2/3 of the TTL to ensure the service always holds a valid cert.
//
// ctx cancellation stops the renewal loop cleanly. Call this once after the
// first IssueCertificate call in your service startup sequence.
//
// On renewal failure the goroutine retries with exponential backoff up to
// pkiRetryMax; it does NOT exit the loop so subsequent renewal windows are
// still attempted.
func (p *VaultPKICertProvider) StartAutoRenewal(ctx context.Context) {
	go p.renewalLoop(ctx)
}

// renewalLoop implements the renewal loop with exponential backoff on failure.
func (p *VaultPKICertProvider) renewalLoop(ctx context.Context) {
	ttlDuration, err := time.ParseDuration(p.ttl)
	if err != nil {
		// Fallback: treat 24 h as the TTL if the value is non-parseable.
		// Vault accepts strings like "24h" but not "86400" (no unit).
		p.log.Warn("mtls: renewalLoop: could not parse TTL; defaulting to 24h",
			zap.String("ttl", p.ttl),
			zap.Error(err),
		)
		ttlDuration = 24 * time.Hour
	}

	renewAt := time.Duration(float64(ttlDuration) * pkiRenewalFraction)

	p.log.Info("Certificate auto-renewal started",
		zap.Duration("ttl", ttlDuration),
		zap.Duration("renew_at", renewAt),
	)

	timer := time.NewTimer(renewAt)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			p.log.Info("Certificate auto-renewal stopped")
			return
		case <-timer.C:
			p.attemptRenewalWithBackoff(ctx)
			// Reset for next cycle.
			timer.Reset(renewAt)
		}
	}
}

// attemptRenewalWithBackoff calls IssueCertificate and retries on failure
// with exponential backoff up to pkiRetryMax.
func (p *VaultPKICertProvider) attemptRenewalWithBackoff(ctx context.Context) {
	backoff := pkiRetryBase

	for attempt := 1; ; attempt++ {
		if err := p.IssueCertificate(ctx); err != nil {
			p.log.Warn("mtls: certificate renewal failed; will retry",
				zap.Int("attempt", attempt),
				zap.Duration("backoff", backoff),
				zap.Error(err),
			)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > pkiRetryMax {
				backoff = pkiRetryMax
			}
			continue
		}
		p.log.Info("Certificate renewed successfully from Vault PKI",
			zap.Int("attempts", attempt),
			zap.String("common_name", p.commonName),
		)
		return
	}
}

// writeFiles atomically writes cert, key, and CA chain to disk using a
// write-then-rename strategy so CertLoader never observes a partial file.
func (p *VaultPKICertProvider) writeFiles(cert, key, caChain string) error {
	if err := os.MkdirAll(p.outputDir, 0o750); err != nil {
		return fmt.Errorf("writeFiles: MkdirAll(%s): %w", p.outputDir, err)
	}

	files := []struct {
		name    string
		content string
		mode    os.FileMode
	}{
		{"tls.crt", cert, 0o644},
		{"tls.key", key, 0o600}, // key is secret; restrict to owner
		{"ca.crt", caChain, 0o644},
	}

	for _, f := range files {
		target := filepath.Join(p.outputDir, f.name)
		tmp := target + ".tmp"

		if err := os.WriteFile(tmp, []byte(f.content), f.mode); err != nil {
			return fmt.Errorf("writeFiles: WriteFile(%s): %w", tmp, err)
		}
		if err := os.Rename(tmp, target); err != nil {
			_ = os.Remove(tmp) // best-effort cleanup
			return fmt.Errorf("writeFiles: Rename(%s → %s): %w", tmp, target, err)
		}
	}

	return nil
}

// extractStringField extracts a named string field from a Vault secret data map.
func extractStringField(data map[string]interface{}, field string) (string, error) {
	raw, ok := data[field]
	if !ok {
		return "", fmt.Errorf("field %q missing from Vault PKI response", field)
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("field %q in Vault PKI response is not a non-empty string", field)
	}
	return s, nil
}

// buildCAChain constructs a PEM CA chain from the Vault PKI response.
// Vault may return the chain as either a []interface{} of PEM strings
// ("ca_chain") or a single string ("issuing_ca"). We prefer ca_chain.
func buildCAChain(data map[string]interface{}) (string, error) {
	if chain := extractCAChain(data); chain != "" {
		return chain, nil
	}

	// Fallback to single issuing CA.
	if raw, ok := data["issuing_ca"]; ok {
		if s, ok := raw.(string); ok && s != "" {
			return s, nil
		}
	}

	return "", fmt.Errorf("no CA chain found in Vault PKI response (expected ca_chain or issuing_ca)")
}

// extractCAChain extracts and concatenates PEM strings from the ca_chain key.
func extractCAChain(data map[string]interface{}) string {
	raw, ok := data["ca_chain"]
	if !ok {
		return ""
	}
	chain, ok := raw.([]interface{})
	if !ok || len(chain) == 0 {
		return ""
	}
	var sb string
	for _, c := range chain {
		if s, ok := c.(string); ok {
			sb += s + "\n"
		}
	}
	return sb
}
