// SPDX-License-Identifier: Apache-2.0

// Package domain provides shared constants for domain verification
// used across platform services (domain-management, falcon-id, etc.).
package domain

const (
	// VerificationDNSPrefix is the DNS TXT record name prefix used for
	// domain ownership verification. The full lookup host is:
	//   _hexxlock-verify.<domain>
	VerificationDNSPrefix = "_hexxlock-verify"

	// VerificationTokenPrefix is the expected value prefix inside the DNS TXT
	// record. The full record value is:
	//   hexxlock-verify=<hex-token>
	VerificationTokenPrefix = "hexxlock-verify=" //nolint:gosec // DNS TXT prefix, not a credential
)
