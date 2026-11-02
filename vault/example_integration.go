// SPDX-License-Identifier: Apache-2.0

// Package vault provides example integration code for platform services.
// This file is for documentation purposes only.
package vault

/*
VAULT INTEGRATION GUIDE

This file shows how to integrate HashiCorp Vault into a service.
Copy the relevant sections into your service's main.go.

==============================================================================
1. BASIC INTEGRATION (Recommended for most services)
==============================================================================

Add these imports to your main.go:

	import (
		"github.com/dogukanturhal/platform-shared/vault"
	)

Add Vault initialization after loading config:

	func main() {
		// Load configuration (existing code)
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Printf("Failed to load config: %v\n", err)
			os.Exit(1)
		}

		// Initialize logger (existing code)
		logger.InitLogger(cfg.LogLevel, cfg.Environment)
		defer logger.Sync()

		// === NEW: Initialize Vault ===
		vaultManager, err := vault.DefaultManager(cfg.ServiceName, logger.Log)
		if err != nil {
			// Vault init failure is not fatal - service works with env vars
			logger.Warn("Failed to initialize Vault, using environment variables",
				zap.Error(err),
			)
		} else {
			defer vaultManager.Close()

			// Pre-load secrets from Vault (optional but recommended)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := vaultManager.LoadStandardSecrets(ctx); err != nil {
				logger.Warn("Failed to load secrets from Vault", zap.Error(err))
			}
			cancel()

			logger.Info("Vault integration initialized",
				zap.Bool("enabled", vaultManager.IsEnabled()),
			)
		}

		// Rest of your service initialization...
	}

==============================================================================
2. USING SECRETS IN YOUR SERVICE
==============================================================================

For secrets that are already loaded through config:
	- No changes needed! Vault pre-loads secrets and they're available via config

For dynamically fetching secrets:

	// Get a secret with automatic fallback to env var
	ctx := context.Background()
	jwtSecret := vaultManager.GetSecret(ctx, "example/platform/jwt", "secret", "JWT_SECRET")

	// Get a required secret (panics if not found - use during init only)
	encryptionKey := vaultManager.MustGetSecret(ctx, "example/platform/encryption-keys/primary", "key", "ENCRYPTION_KEY")

==============================================================================
3. ADDING VAULT STATUS TO HEALTH CHECK
==============================================================================

In your health check endpoint, add Vault status:

	router.GET("/health/ready", func(c *gin.Context) {
		status := gin.H{"status": "ready"}
		healthy := true

		// Existing health checks...

		// === NEW: Add Vault status ===
		if vaultManager != nil {
			status["vault"] = vaultManager.GetStatus(c.Request.Context())
			// Note: Vault failure doesn't mark service unhealthy (graceful fallback)
		}

		if !healthy {
			status["status"] = "not ready"
			c.JSON(http.StatusServiceUnavailable, status)
			return
		}
		c.JSON(http.StatusOK, status)
	})

==============================================================================
4. USING TRANSIT ENCRYPTION (Replace ENCRYPTION_KEY usage)
==============================================================================

Before Vault (using local encryption):

	key := []byte(cfg.EncryptionKey)
	ciphertext, err := encryptWithAES(plaintext, key)

After Vault (using Transit engine):

	if vaultManager.Transit() != nil && vaultManager.Transit().IsEnabled() {
		ciphertext, err := vaultManager.Transit().EncryptString(ctx, plaintext)
		if err != nil {
			// Fall back to local encryption
			key := []byte(cfg.EncryptionKey)
			ciphertext, err = encryptWithAES(plaintext, key)
		}
	} else {
		// Vault Transit not enabled, use local encryption
		key := []byte(cfg.EncryptionKey)
		ciphertext, err := encryptWithAES(plaintext, key)
	}

==============================================================================
5. ENVIRONMENT VARIABLES FOR SERVICES
==============================================================================

Add these to your docker-compose service definition:

	environment:
		# Existing env vars...

		# Vault Integration
		VAULT_ENABLED: ${VAULT_ENABLED:-false}
		VAULT_ADDR: ${VAULT_ADDR:-http://vault:8200}
		VAULT_ROLE_ID: ${VAULT_ROLE_ID_<SERVICE_NAME>:-}
		VAULT_SECRET_ID: ${VAULT_SECRET_ID_<SERVICE_NAME>:-}
		VAULT_CACHE_TTL: ${VAULT_CACHE_TTL:-5m}

		# Optional: Transit encryption
		VAULT_TRANSIT_ENABLED: ${VAULT_TRANSIT_ENABLED:-false}

Replace <SERVICE_NAME> with your service name (e.g., IAM, BILLING, etc.)

==============================================================================
6. GRACEFUL DEGRADATION
==============================================================================

The Vault integration is designed for graceful degradation:

1. If VAULT_ENABLED=false: All secrets come from environment variables
2. If Vault is unreachable: Falls back to environment variables
3. If a secret is not in Vault: Falls back to environment variable
4. If Transit is disabled: Uses local ENCRYPTION_KEY

This ensures services can run without Vault for:
- Local development
- Emergency recovery
- Testing

==============================================================================
*/
