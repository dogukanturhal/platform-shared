// SPDX-License-Identifier: Apache-2.0

// Package vault provides configuration loading integration with Viper.
package vault

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/viper"
)

const envValueTrue = "true"

// ConfigLoader provides integration between Vault secrets and Viper configuration.
type ConfigLoader struct {
	vaultClient   *Client
	transitClient *TransitClient
	dbClient      *DatabaseClient

	// Secret path mappings
	pathMappings map[string]SecretMapping
}

// SecretMapping defines how a Vault secret maps to configuration.
type SecretMapping struct {
	// VaultPath is the path in Vault (e.g., "example/platform/jwt")
	VaultPath string

	// VaultKey is the key within the secret
	VaultKey string

	// EnvVar is the environment variable to fall back to
	EnvVar string

	// Required indicates if this secret is required
	Required bool
}

// NewConfigLoader creates a new configuration loader.
func NewConfigLoader(vaultClient *Client) *ConfigLoader {
	return &ConfigLoader{
		vaultClient:  vaultClient,
		pathMappings: make(map[string]SecretMapping),
	}
}

// SetTransitClient sets the Transit client for encryption operations.
func (c *ConfigLoader) SetTransitClient(tc *TransitClient) {
	c.transitClient = tc
}

// SetDatabaseClient sets the Database client for dynamic credentials.
func (c *ConfigLoader) SetDatabaseClient(dc *DatabaseClient) {
	c.dbClient = dc
}

// AddMapping adds a secret mapping.
func (c *ConfigLoader) AddMapping(name string, mapping SecretMapping) {
	c.pathMappings[name] = mapping
}

// LoadConfigFromEnv loads Vault configuration from environment variables.
func LoadConfigFromEnv() Config {
	cfg := DefaultConfig()

	if v := os.Getenv("VAULT_ENABLED"); v != "" {
		cfg.Enabled = v == envValueTrue || v == "1"
	}

	if v := os.Getenv("VAULT_ADDR"); v != "" {
		cfg.Address = v
	}

	if v := os.Getenv("VAULT_ROLE_ID"); v != "" {
		cfg.RoleID = v
	}

	if v := os.Getenv("VAULT_SECRET_ID"); v != "" {
		cfg.SecretID = v
	}

	if v := os.Getenv("VAULT_NAMESPACE"); v != "" {
		cfg.Namespace = v
	}

	if v := os.Getenv("VAULT_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.CacheTTL = d
		}
	}

	if v := os.Getenv("VAULT_TOKEN_RENEWAL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.TokenRenewalInterval = d
		}
	}

	if v := os.Getenv("VAULT_MOUNT_PATH"); v != "" {
		cfg.MountPath = v
	}

	if v := os.Getenv("VAULT_RETRY_MAX"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RetryMax = n
		}
	}

	return cfg
}

// LoadTransitConfigFromEnv loads Transit configuration from environment variables.
func LoadTransitConfigFromEnv() TransitConfig {
	cfg := DefaultTransitConfig()

	if v := os.Getenv("VAULT_TRANSIT_ENABLED"); v != "" {
		cfg.Enabled = v == envValueTrue || v == "1"
	}

	if v := os.Getenv("VAULT_TRANSIT_MOUNT_PATH"); v != "" {
		cfg.MountPath = v
	}

	if v := os.Getenv("VAULT_TRANSIT_DEFAULT_KEY"); v != "" {
		cfg.DefaultKeyName = v
	}

	return cfg
}

// LoadDatabaseConfigFromEnv loads Database configuration from environment variables.
func LoadDatabaseConfigFromEnv() DatabaseConfig {
	cfg := DefaultDatabaseConfig()

	if v := os.Getenv("VAULT_DATABASE_ENABLED"); v != "" {
		cfg.Enabled = v == envValueTrue || v == "1"
	}

	if v := os.Getenv("VAULT_DATABASE_MOUNT_PATH"); v != "" {
		cfg.MountPath = v
	}

	if v := os.Getenv("VAULT_DATABASE_ROLE"); v != "" {
		cfg.RoleName = v
	}

	if v := os.Getenv("VAULT_DATABASE_RENEWAL_BUFFER"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.RenewalBuffer = d
		}
	}

	return cfg
}

// LoadSecret loads a secret value by mapping name.
func (c *ConfigLoader) LoadSecret(ctx context.Context, name string) (string, error) {
	mapping, ok := c.pathMappings[name]
	if !ok {
		return "", fmt.Errorf("no mapping found for %s", name)
	}

	// Try Vault first if enabled
	if c.vaultClient != nil && c.vaultClient.IsEnabled() {
		value, err := c.vaultClient.GetSecretValue(ctx, mapping.VaultPath, mapping.VaultKey)
		if err == nil && value != "" {
			return value, nil
		}
		// Log the error but fall through to env var
		if err != nil {
			fmt.Printf("WARNING: Failed to load secret %s from Vault: %v\n", name, err)
		}
	}

	// Fall back to environment variable
	value := os.Getenv(mapping.EnvVar)
	if value == "" && mapping.Required {
		return "", fmt.Errorf("required secret %s not found in Vault or environment", name)
	}

	return value, nil
}

// LoadAllSecrets loads all mapped secrets and returns them as a map.
func (c *ConfigLoader) LoadAllSecrets(ctx context.Context) (map[string]string, error) {
	secrets := make(map[string]string)

	for name := range c.pathMappings {
		value, err := c.LoadSecret(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("LoadAllSecrets: LoadSecret failed: %w", err)
		}
		secrets[name] = value
	}

	return secrets, nil
}

// SetViperDefaults sets Viper defaults from loaded secrets.
func (c *ConfigLoader) SetViperDefaults(ctx context.Context) error {
	for name, mapping := range c.pathMappings {
		value, err := c.LoadSecret(ctx, name)
		if err != nil {
			if mapping.Required {
				return fmt.Errorf("SetViperDefaults: %w", err)
			}
			continue
		}

		if value != "" {
			viper.SetDefault(mapping.EnvVar, value)
		}
	}

	return nil
}

// StandardMappings returns the standard ExampleSuite secret mappings.
func StandardMappings() map[string]SecretMapping {
	return map[string]SecretMapping{
		"jwt_secret": {
			VaultPath: "example/platform/jwt",
			VaultKey:  "secret",
			EnvVar:    "JWT_SECRET",
			Required:  true,
		},
		"jwt_issuer": {
			VaultPath: "example/platform/jwt",
			VaultKey:  "issuer",
			EnvVar:    "JWT_ISSUER",
			Required:  false,
		},
		"token_hash_salt": {
			VaultPath: "example/platform/token-salt",
			VaultKey:  "salt",
			EnvVar:    "TOKEN_HASH_SALT",
			Required:  true,
		},
		"encryption_key": {
			VaultPath: "example/platform/encryption-keys/primary",
			VaultKey:  "key",
			EnvVar:    "ENCRYPTION_KEY",
			Required:  true,
		},
		"internal_api_key": {
			VaultPath: "example/platform/internal-api-key",
			VaultKey:  "key",
			EnvVar:    "INTERNAL_API_KEY",
			Required:  true,
		},
		"postgres_password": {
			VaultPath: "example/infrastructure/postgres/master",
			VaultKey:  "password",
			EnvVar:    "POSTGRES_PASSWORD",
			Required:  true,
		},
		"redis_password": {
			VaultPath: "example/infrastructure/redis",
			VaultKey:  "password",
			EnvVar:    "REDIS_PASSWORD",
			Required:  true,
		},
		"stripe_secret_key": {
			VaultPath: "example/payment-providers/stripe",
			VaultKey:  "secret-key",
			EnvVar:    "STRIPE_SECRET_KEY",
			Required:  false,
		},
		"stripe_webhook_secret": {
			VaultPath: "example/payment-providers/stripe",
			VaultKey:  "webhook-secret",
			EnvVar:    "STRIPE_WEBHOOK_SECRET",
			Required:  false,
		},
		"google_client_id": {
			VaultPath: "example/identity-providers/google",
			VaultKey:  "client-id",
			EnvVar:    "GOOGLE_CLIENT_ID",
			Required:  false,
		},
		"google_client_secret": {
			VaultPath: "example/identity-providers/google",
			VaultKey:  "client-secret",
			EnvVar:    "GOOGLE_CLIENT_SECRET",
			Required:  false,
		},
		"microsoft_client_id": {
			VaultPath: "example/identity-providers/microsoft",
			VaultKey:  "client-id",
			EnvVar:    "MICROSOFT_CLIENT_ID",
			Required:  false,
		},
		"microsoft_client_secret": {
			VaultPath: "example/identity-providers/microsoft",
			VaultKey:  "client-secret",
			EnvVar:    "MICROSOFT_CLIENT_SECRET",
			Required:  false,
		},
		"smtp_password": {
			VaultPath: "example/messaging/smtp/default",
			VaultKey:  "password",
			EnvVar:    "SMTP_PASSWORD",
			Required:  false,
		},
		"twilio_auth_token": {
			VaultPath: "example/messaging/twilio",
			VaultKey:  "auth-token",
			EnvVar:    "TWILIO_AUTH_TOKEN",
			Required:  false,
		},
		"sendgrid_api_key": {
			VaultPath: "example/messaging/sendgrid",
			VaultKey:  "api-key",
			EnvVar:    "SENDGRID_API_KEY",
			Required:  false,
		},
		"spicedb_token": {
			VaultPath: "example/infrastructure/spicedb",
			VaultKey:  "token",
			EnvVar:    "SPICEDB_GRPC_PRESHARED_KEY",
			Required:  false,
		},
		"ldap_bind_password": {
			VaultPath: "example/infrastructure/ldap",
			VaultKey:  "password",
			EnvVar:    "LDAP_BIND_PASSWORD",
			Required:  false,
		},
		"minio_access_key": {
			VaultPath: "example/infrastructure/minio",
			VaultKey:  "access-key",
			EnvVar:    "MINIO_ACCESS_KEY",
			Required:  false,
		},
		"minio_secret_key": {
			VaultPath: "example/infrastructure/minio",
			VaultKey:  "secret-key",
			EnvVar:    "MINIO_SECRET_KEY",
			Required:  false,
		},
		"cloudflare_api_token": {
			VaultPath: "example/external/cloudflare",
			VaultKey:  "api-token",
			EnvVar:    "CLOUDFLARE_API_TOKEN",
			Required:  false,
		},
		"iyzico_api_key": {
			VaultPath: "example/payment-providers/iyzico",
			VaultKey:  "api-key",
			EnvVar:    "IYZICO_API_KEY",
			Required:  false,
		},
		"iyzico_secret_key": {
			VaultPath: "example/payment-providers/iyzico",
			VaultKey:  "secret-key",
			EnvVar:    "IYZICO_SECRET_KEY",
			Required:  false,
		},
		"docusign_integration_key": {
			VaultPath: "example/external/docusign",
			VaultKey:  "integration-key",
			EnvVar:    "DOCUSIGN_INTEGRATION_KEY",
			Required:  false,
		},
		"docusign_webhook_secret": {
			VaultPath: "example/external/docusign",
			VaultKey:  "webhook-secret",
			EnvVar:    "DOCUSIGN_WEBHOOK_SECRET",
			Required:  false,
		},
		"livekit_api_key": {
			VaultPath: "example/infrastructure/livekit",
			VaultKey:  "api-key",
			EnvVar:    "LIVEKIT_API_KEY",
			Required:  false,
		},
		"livekit_api_secret": {
			VaultPath: "example/infrastructure/livekit",
			VaultKey:  "api-secret",
			EnvVar:    "LIVEKIT_API_SECRET",
			Required:  false,
		},
		"grafana_password": {
			VaultPath: "example/monitoring/grafana",
			VaultKey:  "password",
			EnvVar:    "GF_SECURITY_ADMIN_PASSWORD",
			Required:  false,
		},
		"kafka_brokers": {
			VaultPath: "example/infrastructure/kafka",
			VaultKey:  "brokers",
			EnvVar:    "KAFKA_BROKERS",
			Required:  false,
		},
		"kafka_sasl_username": {
			VaultPath: "example/infrastructure/kafka",
			VaultKey:  "sasl-username",
			EnvVar:    "KAFKA_SASL_USERNAME",
			Required:  false,
		},
		"kafka_sasl_password": {
			VaultPath: "example/infrastructure/kafka",
			VaultKey:  "sasl-password",
			EnvVar:    "KAFKA_SASL_PASSWORD",
			Required:  false,
		},
		"kafka_ssl_keystore_password": {
			VaultPath: "example/infrastructure/kafka",
			VaultKey:  "ssl-keystore-password",
			EnvVar:    "KAFKA_SSL_KEYSTORE_PASSWORD",
			Required:  false,
		},
		"kafka_ssl_truststore_password": {
			VaultPath: "example/infrastructure/kafka",
			VaultKey:  "ssl-truststore-password",
			EnvVar:    "KAFKA_SSL_TRUSTSTORE_PASSWORD",
			Required:  false,
		},
		// NATS removed: all messaging consolidated to Kafka
		"cassandra_host": {
			VaultPath: "example/infrastructure/cassandra",
			VaultKey:  "host",
			EnvVar:    "CASSANDRA_HOST",
			Required:  false,
		},
		"opnsense_api_key": {
			VaultPath: "example/external/opnsense",
			VaultKey:  "api-key",
			EnvVar:    "OPNSENSE_API_KEY",
			Required:  false,
		},
		"opnsense_api_secret": {
			VaultPath: "example/external/opnsense",
			VaultKey:  "api-secret",
			EnvVar:    "OPNSENSE_API_SECRET",
			Required:  false,
		},
		"exchange_password": {
			VaultPath: "example/external/exchange",
			VaultKey:  "password",
			EnvVar:    "EXCHANGE_SERVICE_PASSWORD",
			Required:  false,
		},
	}
}

// InitVaultClients initializes all Vault clients with default configurations.
// Returns the base client, transit client, and database client.
func InitVaultClients(ctx context.Context) (*Client, *TransitClient, *DatabaseClient, error) {
	// Load configurations from environment
	vaultCfg := LoadConfigFromEnv()
	transitCfg := LoadTransitConfigFromEnv()
	dbCfg := LoadDatabaseConfigFromEnv()

	// Create base Vault client
	vaultClient, err := NewClient(vaultCfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Create Transit client
	transitClient, err := NewTransitClient(vaultClient, transitCfg)
	if err != nil {
		_ = vaultClient.Close()
		return nil, nil, nil, fmt.Errorf("failed to create Transit client: %w", err)
	}

	// Create Database client
	dbClient, err := NewDatabaseClient(vaultClient, dbCfg)
	if err != nil {
		_ = vaultClient.Close()
		return nil, nil, nil, fmt.Errorf("failed to create Database client: %w", err)
	}

	// Start database credential management if enabled
	if dbCfg.Enabled && vaultCfg.Enabled {
		if err := dbClient.Start(ctx); err != nil {
			_ = vaultClient.Close()
			return nil, nil, nil, fmt.Errorf("failed to start database credential management: %w", err)
		}
	}

	return vaultClient, transitClient, dbClient, nil
}

// InitConfigLoader creates and initializes a config loader with standard mappings.
func InitConfigLoader(vaultClient *Client) *ConfigLoader {
	loader := NewConfigLoader(vaultClient)

	// Add all standard mappings
	for name, mapping := range StandardMappings() {
		loader.AddMapping(name, mapping)
	}

	return loader
}

// MustGetSecret retrieves a secret or returns error if not found.
// Despite the name, this function no longer panics and returns an error instead.
//
// Deprecated: Use LoadSecret directly for better error handling.
func (c *ConfigLoader) MustGetSecret(ctx context.Context, name string) (string, error) {
	value, err := c.LoadSecret(ctx, name)
	if err != nil {
		return "", fmt.Errorf("failed to load required secret %s: %w", name, err)
	}
	return value, nil
}

// GetSecretWithDefault retrieves a secret with a default fallback.
func (c *ConfigLoader) GetSecretWithDefault(ctx context.Context, name, defaultValue string) string {
	value, err := c.LoadSecret(ctx, name)
	if err != nil || value == "" {
		return defaultValue
	}
	return value
}
