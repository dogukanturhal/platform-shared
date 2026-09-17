// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// CredentialEncryptor encrypts/decrypts connection strings.
type CredentialEncryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

// CredentialStore persists rotated credentials.
type CredentialStore interface {
	UpdateConnectionString(ctx context.Context, instanceDBID string, encryptedConnStr []byte) error
}

// CredentialRotator handles periodic rotation of silo database credentials.
//
// Rotation sequence for each silo database:
//  1. Generate a cryptographically secure random password.
//  2. ALTER ROLE in PostgreSQL with the new password.
//  3. Encrypt the new connection string via CredentialEncryptor.
//  4. Persist the encrypted connection string via CredentialStore.
//  5. Invalidate cached pools and DB info via the ProductConnectionRouter.
//
// Steps 3 and 4 are logged as CRITICAL failures if they occur after step 2
// has already succeeded, because the live password has already changed and
// manual reconciliation is required.
type CredentialRotator struct {
	masterPool *pgxpool.Pool
	encryption CredentialEncryptor
	store      CredentialStore
	router     *ProductConnectionRouter
	log        *zap.Logger
	interval   time.Duration
	mu         sync.Mutex
}

// CredentialRotatorConfig configures the credential rotator.
type CredentialRotatorConfig struct {
	// MasterPool is a connection pool with superuser or CREATEROLE privileges,
	// used to execute ALTER ROLE statements.
	MasterPool *pgxpool.Pool

	// Encryption handles AES-GCM (or equivalent) envelope encryption for
	// connection strings at rest.
	Encryption CredentialEncryptor

	// Store persists the updated encrypted connection string back to the
	// authoritative source (typically the Falcon-ID database via its internal API).
	Store CredentialStore

	// Router is the ProductConnectionRouter whose in-memory and Redis caches
	// must be invalidated after a successful rotation.
	Router *ProductConnectionRouter

	Log *zap.Logger

	// Interval controls how often the rotation loop fires. Default: 24 hours.
	Interval time.Duration
}

// NewCredentialRotator creates a new CredentialRotator from the supplied config.
// If Interval is zero it defaults to 24 hours.
func NewCredentialRotator(cfg CredentialRotatorConfig) *CredentialRotator {
	if cfg.Interval == 0 {
		cfg.Interval = 24 * time.Hour
	}
	return &CredentialRotator{
		masterPool: cfg.MasterPool,
		encryption: cfg.Encryption,
		store:      cfg.Store,
		router:     cfg.Router,
		log:        cfg.Log,
		interval:   cfg.Interval,
	}
}

// RotateCredentials rotates the password for a silo database role.
//
// The caller supplies the current connection parameters so the rotator can
// reconstruct the connection string after the password has changed. The
// instanceDBID is the stable identifier used to persist the result in the store.
//
// The method is serialized by an internal mutex so concurrent calls for
// different databases are safe, but do not run in parallel — this is
// intentional to avoid saturating the master database with concurrent
// ALTER ROLE statements during a bulk rotation sweep.
func (cr *CredentialRotator) RotateCredentials(
	ctx context.Context,
	instanceDBID string,
	username string,
	host string,
	port int,
	dbName string,
	sslMode string,
) error {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	// 1. Generate new secure password.
	newPassword, err := generateRotationPassword(32)
	if err != nil {
		return fmt.Errorf("generate password: %w", err)
	}

	// 2. ALTER ROLE with new password.
	// SECURITY: quoteIdentRouter double-quotes the identifier; quoteLiteral
	// single-quotes the password value. Both prevent SQL injection.
	alterSQL := fmt.Sprintf(
		"ALTER ROLE %s WITH PASSWORD %s",
		quoteIdentRouter(username),
		quoteLiteral(newPassword),
	)
	if _, err = cr.masterPool.Exec(ctx, alterSQL); err != nil {
		return fmt.Errorf("alter role password: %w", err)
	}

	// From this point forward the live PostgreSQL password has changed.
	// Any failure must be logged as CRITICAL so on-call can reconcile.

	// 3. Build and encrypt new connection string.
	newConnStr := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		username, newPassword, host, port, dbName, sslMode,
	)
	encrypted, err := cr.encryption.Encrypt(newConnStr)
	if err != nil {
		if cr.log != nil {
			cr.log.Error("CRITICAL: password changed but encryption failed — manual intervention required",
				zap.String("instance_db_id", instanceDBID),
				zap.String("username", username),
				zap.Error(err),
			)
		}
		return fmt.Errorf("encrypt new connection string: %w", err)
	}

	// 4. Persist encrypted connection string.
	if err = cr.store.UpdateConnectionString(ctx, instanceDBID, []byte(encrypted)); err != nil {
		if cr.log != nil {
			cr.log.Error("CRITICAL: password changed and encrypted but store failed — manual intervention required",
				zap.String("instance_db_id", instanceDBID),
				zap.String("username", username),
				zap.Error(err),
			)
		}
		return fmt.Errorf("persist rotated credentials: %w", err)
	}

	// 5. Cache invalidation is the caller's responsibility via InvalidateAfterRotation
	// because the tenantID is not available at this layer.

	if cr.log != nil {
		cr.log.Info("Rotated silo database credentials",
			zap.String("instance_db_id", instanceDBID),
			zap.String("username", username),
			zap.String("database", dbName),
		)
	}
	return nil
}

// InvalidateAfterRotation invalidates the in-memory pool and both L1/L2 DB-info
// cache entries for the given tenant and database. Call this immediately after a
// successful RotateCredentials so the next request establishes a fresh connection
// with the new password rather than reusing a cached pool opened with the old one.
func (cr *CredentialRotator) InvalidateAfterRotation(ctx context.Context, tenantID, databaseName string) {
	if cr.router == nil {
		return
	}
	cr.router.InvalidatePool(tenantID, databaseName)
	cr.router.InvalidateDBInfo(ctx, tenantID, databaseName)
}

// StartRotationLoop starts a background goroutine that calls rotationFn on every
// interval tick. The loop exits when ctx is canceled.
//
// rotationFn is supplied by the caller and is responsible for enumerating the
// silo databases that require rotation, calling RotateCredentials for each, and
// calling InvalidateAfterRotation afterwards. This inversion of control keeps the
// rotator free of any dependency on the data store schema.
//
// Example wiring in cmd/services.go:
//
//	rotator.StartRotationLoop(ctx, func(ctx context.Context, r *database.CredentialRotator) error {
//	    return siloRepo.RotateAll(ctx, r)
//	})
func (cr *CredentialRotator) StartRotationLoop(
	ctx context.Context,
	rotationFn func(ctx context.Context, rotator *CredentialRotator) error,
) {
	go func() {
		ticker := time.NewTicker(cr.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := rotationFn(ctx, cr); err != nil {
					if cr.log != nil {
						cr.log.Error("Credential rotation loop error", zap.Error(err))
					}
				}
			}
		}
	}()
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// generateRotationPassword returns a cryptographically secure random password of
// exactly length printable characters drawn from the base64url alphabet
// (A-Z, a-z, 0-9, -, _). This avoids special characters that can be
// misinterpreted in connection strings while still providing high entropy:
// 32 characters from a 64-character alphabet = ~192 bits of entropy.
func generateRotationPassword(length int) (string, error) {
	// Over-allocate raw bytes to ensure the base64 output is long enough after
	// encoding. base64url expands 3 bytes into 4 characters, so we need at least
	// ceil(length * 3/4) source bytes.
	nBytes := (length*3 + 3) / 4
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	// RawURLEncoding produces no padding characters, keeping the output clean.
	encoded := base64.RawURLEncoding.EncodeToString(b)
	return encoded[:length], nil
}

// quoteLiteral quotes a PostgreSQL string literal to prevent SQL injection.
// It wraps the value in single quotes and escapes any embedded single quotes
// by doubling them (standard SQL escaping).
//
// Example:
//
//	quoteLiteral("O'Brien") → "'O''Brien'"
func quoteLiteral(s string) string {
	result := make([]byte, 0, len(s)+2)
	result = append(result, '\'')
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			result = append(result, '\'', '\'')
		} else {
			result = append(result, s[i])
		}
	}
	result = append(result, '\'')
	return string(result)
}
