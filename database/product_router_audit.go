// SPDX-License-Identifier: Apache-2.0

package database

import (
	"go.uber.org/zap"
)

// RouterAuditLogger provides structured audit logging for connection routing
// decisions and security events. All routing-sensitive operations are logged
// through this to provide a unified audit trail.
type RouterAuditLogger struct {
	log *zap.Logger
}

// NewRouterAuditLogger creates a new audit logger.
func NewRouterAuditLogger(log *zap.Logger) *RouterAuditLogger {
	return &RouterAuditLogger{log: log}
}

// ConnectionRouted logs a successful routing decision.
func (a *RouterAuditLogger) ConnectionRouted(tenantID, database, isolationMode, source string) {
	if a.log == nil {
		return
	}
	a.log.Info("connection.routed",
		zap.String("tenant_id", tenantID),
		zap.String("database", database),
		zap.String("isolation_mode", isolationMode),
		zap.String("source", source), // "l1_cache", "l2_cache", "remote", "fallback"
	)
}

// CacheHit logs a cache hit at a specific layer.
func (a *RouterAuditLogger) CacheHit(tenantID, database, cacheLayer string) {
	if a.log == nil {
		return
	}
	a.log.Debug("connection.cache_hit",
		zap.String("tenant_id", tenantID),
		zap.String("database", database),
		zap.String("cache_layer", cacheLayer),
	)
}

// CacheMiss logs a cache miss.
func (a *RouterAuditLogger) CacheMiss(tenantID, database string) {
	if a.log == nil {
		return
	}
	a.log.Debug("connection.cache_miss",
		zap.String("tenant_id", tenantID),
		zap.String("database", database),
	)
}

// LookupFailed logs a failed database lookup.
func (a *RouterAuditLogger) LookupFailed(tenantID, database string, err error) {
	if a.log == nil {
		return
	}
	a.log.Warn("connection.lookup_failed",
		zap.String("tenant_id", tenantID),
		zap.String("database", database),
		zap.Error(err),
	)
}

// PoolCreated logs a new connection pool creation.
func (a *RouterAuditLogger) PoolCreated(tenantID, database, isolationMode string, poolCount int32) {
	if a.log == nil {
		return
	}
	a.log.Info("connection.pool_created",
		zap.String("tenant_id", tenantID),
		zap.String("database", database),
		zap.String("isolation_mode", isolationMode),
		zap.Int32("active_pools", poolCount),
	)
}

// PoolEvicted logs a pool eviction.
func (a *RouterAuditLogger) PoolEvicted(tenantID, database, reason string) {
	if a.log == nil {
		return
	}
	a.log.Info("connection.pool_evicted",
		zap.String("tenant_id", tenantID),
		zap.String("database", database),
		zap.String("reason", reason), // "lru", "invalidate", "idle", "unhealthy", "rotation"
	)
}

// SignatureMismatch logs a cache entry with an invalid HMAC signature.
// This is a SECURITY ALERT — potential cache poisoning attack.
func (a *RouterAuditLogger) SignatureMismatch(tenantID, database string) {
	if a.log == nil {
		return
	}
	a.log.Error("SECURITY: connection.signature_mismatch",
		zap.String("tenant_id", tenantID),
		zap.String("database", database),
		zap.String("severity", "critical"),
	)
}

// OwnershipMismatch logs a cross-tenant routing attempt.
// This is a SECURITY ALERT — potential tenant isolation bypass.
func (a *RouterAuditLogger) OwnershipMismatch(tenantID, database, returnedDB, isolationMode string) {
	if a.log == nil {
		return
	}
	a.log.Error("SECURITY: connection.ownership_mismatch",
		zap.String("tenant_id", tenantID),
		zap.String("database", database),
		zap.String("returned_db", returnedDB),
		zap.String("isolation_mode", isolationMode),
		zap.String("severity", "critical"),
	)
}

// RLSContextSet logs that RLS tenant context was set on a connection.
func (a *RouterAuditLogger) RLSContextSet(tenantID, database string) {
	if a.log == nil {
		return
	}
	a.log.Debug("connection.rls_set",
		zap.String("tenant_id", tenantID),
		zap.String("database", database),
	)
}

// CredentialRotated logs a successful credential rotation.
func (a *RouterAuditLogger) CredentialRotated(tenantID, database, username string) {
	if a.log == nil {
		return
	}
	a.log.Info("connection.credential_rotated",
		zap.String("tenant_id", tenantID),
		zap.String("database", database),
		zap.String("username", username),
	)
}

// CredentialRotationFailed logs a failed credential rotation.
func (a *RouterAuditLogger) CredentialRotationFailed(tenantID, database string, err error) {
	if a.log == nil {
		return
	}
	a.log.Error("connection.credential_rotation_failed",
		zap.String("tenant_id", tenantID),
		zap.String("database", database),
		zap.Error(err),
	)
}
