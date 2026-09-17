// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"strings"
)

// KafkaSASLConfig holds SASL authentication and TLS configuration for Kafka.
// When SASLEnabled is false, connections use plaintext (suitable for development).
// When SASLEnabled is true, SCRAM-SHA-512 authentication is enforced (production).
type KafkaSASLConfig struct {
	SASLEnabled   bool
	SASLMechanism string // "SCRAM-SHA-256" or "SCRAM-SHA-512"
	SASLUsername  string
	SASLPassword  string
	TLSEnabled    bool
	TLSCACertPath string
	TLSSkipVerify bool
}

// LoadKafkaSASLConfig loads SASL configuration from environment variables.
// All settings default to disabled/empty so existing dev environments are unaffected.
func LoadKafkaSASLConfig() KafkaSASLConfig {
	return KafkaSASLConfig{
		SASLEnabled:   GetEnvBool("KAFKA_SASL_ENABLED", false),
		SASLMechanism: GetEnv("KAFKA_SASL_MECHANISM", "SCRAM-SHA-512"),
		SASLUsername:  GetEnv("KAFKA_SASL_USERNAME", ""),
		SASLPassword:  GetEnv("KAFKA_SASL_PASSWORD", ""),
		TLSEnabled:    GetEnvBool("KAFKA_SSL_ENABLED", false),
		TLSCACertPath: GetEnv("KAFKA_SSL_CA_CERT", ""),
		TLSSkipVerify: GetEnvBool("KAFKA_SSL_INSECURE_SKIP_VERIFY", false),
	}
}

// Validate checks that required SASL fields are set when SASL is enabled.
func (c KafkaSASLConfig) Validate() error {
	if !c.SASLEnabled {
		return nil
	}

	if c.SASLUsername == "" {
		return fmt.Errorf("KAFKA_SASL_USERNAME is required when KAFKA_SASL_ENABLED=true")
	}
	if c.SASLPassword == "" {
		return fmt.Errorf("KAFKA_SASL_PASSWORD is required when KAFKA_SASL_ENABLED=true")
	}

	switch c.SASLMechanism {
	case "SCRAM-SHA-256", "SCRAM-SHA-512":
		// valid
	default:
		return fmt.Errorf("unsupported KAFKA_SASL_MECHANISM: %s (supported: SCRAM-SHA-256, SCRAM-SHA-512)", c.SASLMechanism)
	}

	return nil
}

// NewTLSConfig builds a *tls.Config when TLS is enabled.
// Returns nil if TLS is disabled.
func (c KafkaSASLConfig) NewTLSConfig() (*tls.Config, error) {
	if !c.TLSEnabled {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.TLSSkipVerify, // #nosec G402 -- value is from trusted operator config, not hardcoded
		MinVersion:         tls.VersionTLS12,
	}

	if c.TLSCACertPath != "" {
		caCert, err := os.ReadFile(c.TLSCACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate at %s: %w", c.TLSCACertPath, err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate at %s", c.TLSCACertPath)
		}
		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}

// ValidateProductionKafkaSSL logs a warning when ENVIRONMENT is "production"
// but KAFKA_SSL_ENABLED is not set to true. This is a safety net to catch
// production misconfigurations where Kafka traffic flows unencrypted.
//
// Call this function at startup after loading the Kafka configuration.
func ValidateProductionKafkaSSL() {
	env := strings.ToLower(os.Getenv("ENVIRONMENT"))
	if env != "production" {
		return
	}

	sslEnabled := GetEnvBool("KAFKA_SSL_ENABLED", false)
	if !sslEnabled {
		log.Printf("WARNING: ENVIRONMENT=production but KAFKA_SSL_ENABLED is not true. " +
			"Kafka connections may be unencrypted. Set KAFKA_SSL_ENABLED=true for production.")
	}
}
