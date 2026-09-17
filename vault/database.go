// SPDX-License-Identifier: Apache-2.0

// Package vault provides dynamic database credential management using Vault's Database engine.
package vault

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// DatabaseConfig holds configuration for the Database secrets engine.
type DatabaseConfig struct {
	// Enabled determines if dynamic database credentials are active.
	Enabled bool `mapstructure:"VAULT_DATABASE_ENABLED"`

	// MountPath is the mount path for the Database engine.
	MountPath string `mapstructure:"VAULT_DATABASE_MOUNT_PATH"`

	// RoleName is the role to use for credential generation.
	RoleName string `mapstructure:"VAULT_DATABASE_ROLE"`

	// RenewalBuffer is how long before expiry to attempt renewal.
	RenewalBuffer time.Duration `mapstructure:"VAULT_DATABASE_RENEWAL_BUFFER"`

	// MinRenewalInterval prevents too-frequent renewal attempts.
	MinRenewalInterval time.Duration `mapstructure:"VAULT_DATABASE_MIN_RENEWAL_INTERVAL"`
}

// DefaultDatabaseConfig returns a DatabaseConfig with sensible defaults.
func DefaultDatabaseConfig() DatabaseConfig {
	return DatabaseConfig{
		Enabled:            false,
		MountPath:          "database",
		RoleName:           "example-service",
		RenewalBuffer:      5 * time.Minute,
		MinRenewalInterval: 1 * time.Minute,
	}
}

// DatabaseCredentials holds dynamic database credentials.
type DatabaseCredentials struct {
	Username string
	Password string
	LeaseID  string
	TTL      time.Duration
	Expiry   time.Time
}

// DatabaseClient provides dynamic database credential management.
type DatabaseClient struct {
	vaultClient *Client
	config      DatabaseConfig

	// Current credentials
	creds   *DatabaseCredentials
	credsMu sync.RWMutex

	// Lifecycle management
	stopCh      chan struct{}
	wg          sync.WaitGroup
	lastRenew   time.Time
	lastRenewMu sync.Mutex

	// Callback for credential updates
	onCredentialsUpdate func(creds *DatabaseCredentials)
}

// NewDatabaseClient creates a new Database client.
func NewDatabaseClient(vaultClient *Client, cfg DatabaseConfig) (*DatabaseClient, error) {
	if vaultClient == nil {
		return nil, fmt.Errorf("vault client is required")
	}

	c := &DatabaseClient{
		vaultClient: vaultClient,
		config:      cfg,
		stopCh:      make(chan struct{}),
	}

	return c, nil
}

// SetCredentialsUpdateCallback sets a callback function that will be called
// when credentials are updated. This can be used to reconfigure database connections.
func (d *DatabaseClient) SetCredentialsUpdateCallback(callback func(creds *DatabaseCredentials)) {
	d.onCredentialsUpdate = callback
}

// Start begins the credential management lifecycle.
// It fetches initial credentials and starts the renewal loop.
func (d *DatabaseClient) Start(ctx context.Context) error {
	if !d.config.Enabled || !d.vaultClient.IsEnabled() {
		return nil
	}

	// Get initial credentials
	if err := d.fetchCredentials(ctx); err != nil {
		return fmt.Errorf("failed to fetch initial credentials: %w", err)
	}

	// Start renewal loop
	d.wg.Add(1)
	go d.renewalLoop() //nolint:gosec // renewal loop runs independently of any request context

	return nil
}

// Stop gracefully shuts down the credential management.
func (d *DatabaseClient) Stop() {
	if d.stopCh != nil {
		close(d.stopCh)
	}
	d.wg.Wait()

	// Revoke the current lease if we have one
	d.credsMu.RLock()
	leaseID := ""
	if d.creds != nil {
		leaseID = d.creds.LeaseID
	}
	d.credsMu.RUnlock()

	if leaseID != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = d.revokeCredentials(ctx, leaseID)
	}
}

// GetCredentials returns the current database credentials.
func (d *DatabaseClient) GetCredentials() *DatabaseCredentials {
	d.credsMu.RLock()
	defer d.credsMu.RUnlock()

	if d.creds == nil {
		return nil
	}

	// Return a copy
	return &DatabaseCredentials{
		Username: d.creds.Username,
		Password: d.creds.Password,
		LeaseID:  d.creds.LeaseID,
		TTL:      d.creds.TTL,
		Expiry:   d.creds.Expiry,
	}
}

// GetConnectionString builds a PostgreSQL connection string with the current credentials.
func (d *DatabaseClient) GetConnectionString(host string, port int, database string, sslmode string) string {
	creds := d.GetCredentials()
	if creds == nil {
		return ""
	}

	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		creds.Username,
		creds.Password,
		host,
		port,
		database,
		sslmode,
	)
}

// fetchCredentials retrieves new credentials from Vault.
func (d *DatabaseClient) fetchCredentials(ctx context.Context) error {
	path := fmt.Sprintf("%s/creds/%s", d.config.MountPath, d.config.RoleName)

	secret, err := d.vaultClient.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to read database credentials: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return fmt.Errorf("empty credentials response from Vault")
	}

	username, ok := secret.Data["username"].(string)
	if !ok {
		return fmt.Errorf("invalid username in credentials response")
	}

	password, ok := secret.Data["password"].(string)
	if !ok {
		return fmt.Errorf("invalid password in credentials response")
	}

	ttl := time.Duration(secret.LeaseDuration) * time.Second

	creds := &DatabaseCredentials{
		Username: username,
		Password: password,
		LeaseID:  secret.LeaseID,
		TTL:      ttl,
		Expiry:   time.Now().Add(ttl),
	}

	d.credsMu.Lock()
	d.creds = creds
	d.credsMu.Unlock()

	// Notify callback if set
	if d.onCredentialsUpdate != nil {
		d.onCredentialsUpdate(creds)
	}

	return nil
}

// renewCredentials attempts to renew the current credentials.
func (d *DatabaseClient) renewCredentials(ctx context.Context) error {
	d.credsMu.RLock()
	leaseID := ""
	if d.creds != nil {
		leaseID = d.creds.LeaseID
	}
	d.credsMu.RUnlock()

	if leaseID == "" {
		return fmt.Errorf("no lease to renew")
	}

	secret, err := d.vaultClient.client.Sys().RenewWithContext(ctx, leaseID, 0)
	if err != nil {
		return fmt.Errorf("lease renewal failed: %w", err)
	}

	if secret == nil {
		return fmt.Errorf("empty renewal response from Vault")
	}

	ttl := time.Duration(secret.LeaseDuration) * time.Second

	d.credsMu.Lock()
	d.creds.TTL = ttl
	d.creds.Expiry = time.Now().Add(ttl)
	d.credsMu.Unlock()

	return nil
}

// revokeCredentials revokes a lease.
func (d *DatabaseClient) revokeCredentials(ctx context.Context, leaseID string) error {
	return d.vaultClient.client.Sys().RevokeWithContext(ctx, leaseID)
}

// renewalLoop periodically checks and renews credentials.
func (d *DatabaseClient) renewalLoop() {
	defer d.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.credsMu.RLock()
			var expiry time.Time
			if d.creds != nil {
				expiry = d.creds.Expiry
			}
			d.credsMu.RUnlock()

			if expiry.IsZero() {
				continue
			}

			// Check if we need to renew
			timeUntilExpiry := time.Until(expiry)
			if timeUntilExpiry > d.config.RenewalBuffer {
				continue
			}

			// Check minimum renewal interval
			d.lastRenewMu.Lock()
			if time.Since(d.lastRenew) < d.config.MinRenewalInterval {
				d.lastRenewMu.Unlock()
				continue
			}
			d.lastRenew = time.Now()
			d.lastRenewMu.Unlock()

			// Attempt renewal
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := d.renewCredentials(ctx); err != nil {
				// Renewal failed, try to get new credentials
				fmt.Printf("WARNING: Database credential renewal failed: %v. Fetching new credentials.\n", err)
				if err := d.fetchCredentials(ctx); err != nil {
					fmt.Printf("ERROR: Failed to fetch new database credentials: %v\n", err)
				}
			}
			cancel()
		}
	}
}

// IsEnabled returns whether dynamic database credentials are enabled.
func (d *DatabaseClient) IsEnabled() bool {
	return d.config.Enabled && d.vaultClient.IsEnabled()
}

// DatabaseStatus returns the current status of database credentials.
type DatabaseStatus struct {
	Enabled    bool       `json:"enabled"`
	HasCreds   bool       `json:"has_credentials"`
	Username   string     `json:"username,omitempty"`
	Expiry     *time.Time `json:"expiry,omitempty"`
	TTLSeconds int        `json:"ttl_seconds,omitempty"`
}

// GetStatus returns the current status of database credentials.
func (d *DatabaseClient) GetStatus() DatabaseStatus {
	status := DatabaseStatus{
		Enabled: d.config.Enabled && d.vaultClient.IsEnabled(),
	}

	d.credsMu.RLock()
	defer d.credsMu.RUnlock()

	if d.creds != nil {
		status.HasCreds = true
		status.Username = d.creds.Username
		status.Expiry = &d.creds.Expiry
		status.TTLSeconds = int(time.Until(d.creds.Expiry).Seconds())
	}

	return status
}

// ForceRefresh forces a credential refresh.
func (d *DatabaseClient) ForceRefresh(ctx context.Context) error {
	if !d.config.Enabled || !d.vaultClient.IsEnabled() {
		return fmt.Errorf("dynamic database credentials are not enabled")
	}

	return d.fetchCredentials(ctx)
}
