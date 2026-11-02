// SPDX-License-Identifier: Apache-2.0

// Package vault provides integration helpers for platform services.
package vault

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Manager provides centralized Vault management for a service.
// It handles initialization, health checks, and graceful shutdown.
type Manager struct {
	client        *Client
	transitClient *TransitClient
	dbClient      *DatabaseClient
	configLoader  *ConfigLoader
	logger        *zap.Logger

	mu     sync.RWMutex
	closed bool
}

// ManagerConfig configures the Vault manager.
type ManagerConfig struct {
	// ServiceName is used for logging and metrics.
	ServiceName string

	// Logger for Vault operations.
	Logger *zap.Logger

	// EnableTransit enables the Transit encryption engine.
	EnableTransit bool

	// EnableDatabase enables dynamic database credentials.
	EnableDatabase bool

	// OnDatabaseCredsUpdate is called when database credentials are updated.
	OnDatabaseCredsUpdate func(creds *DatabaseCredentials)
}

// NewManager creates a new Vault manager with the provided configuration.
// Returns a manager even if Vault is disabled (for graceful fallback).
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}

	m := &Manager{
		logger: cfg.Logger.Named("vault"),
	}

	// Load Vault configuration from environment
	vaultCfg := LoadConfigFromEnv()

	// Create Vault client (works even if disabled)
	var err error
	m.client, err = NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	if !vaultCfg.Enabled {
		m.logger.Info("Vault is disabled, using environment variables for secrets")
		return m, nil
	}

	m.logger.Info("Vault client initialized",
		zap.String("address", vaultCfg.Address),
		zap.Duration("cache_ttl", vaultCfg.CacheTTL),
	)

	// Initialize Transit client if enabled
	if cfg.EnableTransit {
		transitCfg := LoadTransitConfigFromEnv()
		if transitCfg.Enabled {
			m.transitClient, err = NewTransitClient(m.client, transitCfg)
			if err != nil {
				m.logger.Warn("Failed to create Transit client", zap.Error(err))
			} else {
				m.logger.Info("Transit encryption enabled",
					zap.String("key", transitCfg.DefaultKeyName),
				)
			}
		}
	}

	// Initialize Database client if enabled
	if cfg.EnableDatabase {
		m.initDatabaseClient(cfg)
	}

	// Initialize config loader with standard mappings
	m.configLoader = InitConfigLoader(m.client)

	return m, nil
}

// initDatabaseClient sets up the dynamic-credentials database client when enabled.
func (m *Manager) initDatabaseClient(cfg ManagerConfig) {
	dbCfg := LoadDatabaseConfigFromEnv()
	if !dbCfg.Enabled {
		return
	}
	var err error
	m.dbClient, err = NewDatabaseClient(m.client, dbCfg)
	if err != nil {
		m.logger.Warn("Failed to create Database client", zap.Error(err))
		return
	}
	if cfg.OnDatabaseCredsUpdate != nil {
		m.dbClient.SetCredentialsUpdateCallback(cfg.OnDatabaseCredsUpdate)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := m.dbClient.Start(ctx); err != nil {
		m.logger.Warn("Failed to start database credential management", zap.Error(err))
		return
	}
	m.logger.Info("Database dynamic credentials enabled",
		zap.String("role", dbCfg.RoleName),
	)
}

// Client returns the Vault client.
func (m *Manager) Client() *Client {
	return m.client
}

// Transit returns the Transit client (may be nil if not enabled).
func (m *Manager) Transit() *TransitClient {
	return m.transitClient
}

// Database returns the Database client (may be nil if not enabled).
func (m *Manager) Database() *DatabaseClient {
	return m.dbClient
}

// ConfigLoader returns the config loader.
func (m *Manager) ConfigLoader() *ConfigLoader {
	return m.configLoader
}

// IsEnabled returns whether Vault is enabled.
func (m *Manager) IsEnabled() bool {
	return m.client != nil && m.client.IsEnabled()
}

// GetSecret retrieves a secret with fallback to environment variable.
func (m *Manager) GetSecret(ctx context.Context, vaultPath, vaultKey, envVar string) string {
	if m.client == nil {
		return m.client.GetOrEnv(ctx, vaultPath, vaultKey, envVar)
	}
	return m.client.GetOrEnv(ctx, vaultPath, vaultKey, envVar)
}

// MustGetSecret retrieves a secret or returns error if not found.
// Despite the name, this function no longer panics and returns an error instead.
//
// Deprecated: Use GetSecret directly and check for empty values.
func (m *Manager) MustGetSecret(ctx context.Context, vaultPath, vaultKey, envVar string) (string, error) {
	value := m.GetSecret(ctx, vaultPath, vaultKey, envVar)
	if value == "" {
		return "", fmt.Errorf("required secret not found: vault=%s/%s env=%s", vaultPath, vaultKey, envVar)
	}
	return value, nil
}

// LoadStandardSecrets loads all standard secrets and sets them in the environment
// for backward compatibility with existing config loading.
func (m *Manager) LoadStandardSecrets(ctx context.Context) error {
	if !m.IsEnabled() {
		return nil // Nothing to load, use existing env vars
	}

	secrets, err := m.configLoader.LoadAllSecrets(ctx)
	if err != nil {
		m.logger.Warn("Failed to load some secrets from Vault", zap.Error(err))
		// Don't return error - allow fallback to env vars
	}

	for name, value := range secrets {
		if mapping, ok := StandardMappings()[name]; ok && value != "" {
			m.logger.Debug("Loaded secret from Vault",
				zap.String("name", name),
				zap.String("env_var", mapping.EnvVar),
			)
		}
	}

	return nil
}

// HealthCheck verifies Vault connectivity.
func (m *Manager) HealthCheck(ctx context.Context) error {
	if !m.IsEnabled() {
		return nil
	}
	return m.client.HealthCheck(ctx)
}

// GetStatus returns the Vault status for health endpoints.
func (m *Manager) GetStatus(ctx context.Context) map[string]interface{} {
	status := map[string]interface{}{
		"enabled": m.IsEnabled(),
	}

	if !m.IsEnabled() {
		return status
	}

	vaultStatus := m.client.GetStatus(ctx)
	status["connected"] = vaultStatus.Connected
	if !vaultStatus.TokenExpiry.IsZero() {
		status["token_expires_at"] = vaultStatus.TokenExpiry.Format(time.RFC3339)
	}

	if m.transitClient != nil {
		status["transit_enabled"] = m.transitClient.IsEnabled()
	}

	if m.dbClient != nil {
		dbStatus := m.dbClient.GetStatus()
		status["database"] = dbStatus
	}

	return status
}

// Close gracefully shuts down all Vault connections.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}
	m.closed = true

	m.logger.Info("Shutting down Vault manager")

	if m.dbClient != nil {
		m.dbClient.Stop()
	}

	if m.client != nil {
		return m.client.Close()
	}

	return nil
}

// DefaultManager is a convenience function that creates a manager with common settings.
func DefaultManager(serviceName string, logger *zap.Logger) (*Manager, error) {
	return NewManager(ManagerConfig{
		ServiceName:    serviceName,
		Logger:         logger,
		EnableTransit:  true,
		EnableDatabase: false, // Most services don't need dynamic DB creds
	})
}
