// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AdminAuditEntry is a structured record of an administrative or destructive operation.
// It is logged at WARN level because admin actions are always noteworthy and warrant
// operator attention, even when they succeed.
type AdminAuditEntry struct {
	// Action describes what was done, e.g. "DELETE_TENANT", "RESET_PASSWORD".
	Action string `json:"action"`

	// PerformedBy is the user ID (or service account ID) that triggered the action.
	PerformedBy string `json:"performed_by"`

	// TenantID identifies the tenant the action was performed within, if applicable.
	TenantID string `json:"tenant_id,omitempty"`

	// ResourceID identifies the specific resource that was affected, if applicable.
	ResourceID string `json:"resource_id,omitempty"`

	// Details carries any additional structured context about the action.
	Details map[string]interface{} `json:"details,omitempty"`

	// Timestamp is the moment the action was recorded (UTC).
	Timestamp time.Time `json:"timestamp"`

	// RequestID is the trace/correlation ID of the HTTP request, if available.
	RequestID string `json:"request_id,omitempty"`

	// IPAddress is the originating client IP from the HTTP request.
	IPAddress string `json:"ip_address,omitempty"`
}

// LogAdminAction records an administrative action performed during the given Gin request.
// It extracts user_id, tenant_id, request_id, and client IP automatically from the context.
// The entry is written at WARN level so that it surfaces in production log aggregators
// even when INFO-level logging is disabled.
//
// Example usage in a handler:
//
//	audit.LogAdminAction(c, logger, "DELETE_TENANT", map[string]interface{}{
//	    "tenant_slug": slug,
//	    "reason":      body.Reason,
//	})
func LogAdminAction(c *gin.Context, logger Logger, action string, details map[string]interface{}) {
	entry := AdminAuditEntry{
		Action:    action,
		Timestamp: time.Now().UTC(),
		Details:   details,
		IPAddress: c.ClientIP(),
	}

	// Extract user identity from the Gin context (set by auth middleware).
	if v := c.GetString("user_id"); v != "" {
		entry.PerformedBy = v
	}

	// Extract tenant ID; the value may be a string or a uuid.UUID.
	if v, ok := c.Get("tenant_id"); ok {
		entry.TenantID = stringVal(v)
	}

	// Extract request / correlation ID from context or header.
	if reqID := c.GetString("request_id"); reqID != "" {
		entry.RequestID = reqID
	} else if reqID := c.GetHeader("X-Request-ID"); reqID != "" {
		entry.RequestID = reqID
	}

	logger.Log(adminAuditToEntry(entry))
}

// adminAuditToEntry converts an AdminAuditEntry to the shared Entry format so it
// can be emitted through the existing Logger interface.
func adminAuditToEntry(a AdminAuditEntry) *Entry {
	return &Entry{
		ID:          uuid.New().String(),
		Timestamp:   a.Timestamp,
		TenantID:    a.TenantID,
		UserID:      a.PerformedBy,
		ServiceName: "admin",
		Action:      a.Action,
		ResourceID:  a.ResourceID,
		RequestID:   a.RequestID,
		IPAddress:   a.IPAddress,
		Method:      "ADMIN",
	}
}

// AdminZapLogger logs AdminAuditEntry records at WARN level using a zap.Logger.
// It deliberately logs at WARN (not INFO) so admin actions surface in production
// alerting pipelines regardless of configured log level.
type AdminZapLogger struct {
	logger *zap.Logger
}

// NewAdminZapLogger creates an AdminZapLogger backed by the provided zap.Logger.
func NewAdminZapLogger(logger *zap.Logger) *AdminZapLogger {
	return &AdminZapLogger{logger: logger.Named("admin-audit")}
}

// LogAdminEntry records a structured admin audit entry at WARN level.
func (l *AdminZapLogger) LogAdminEntry(entry AdminAuditEntry) {
	fields := []zap.Field{
		zap.String("action", entry.Action),
		zap.String("performed_by", entry.PerformedBy),
		zap.String("tenant_id", entry.TenantID),
		zap.String("resource_id", entry.ResourceID),
		zap.String("request_id", entry.RequestID),
		zap.String("ip_address", entry.IPAddress),
		zap.Time("timestamp", entry.Timestamp),
	}

	// Append arbitrary detail fields.
	for k, v := range entry.Details {
		fields = append(fields, zap.Any(k, v))
	}

	l.logger.Warn("admin_action", fields...)
}

// Log satisfies the audit.Logger interface by logging the entry at WARN level.
func (l *AdminZapLogger) Log(e *Entry) {
	l.logger.Warn("admin_action",
		zap.String("audit_id", e.ID),
		zap.String("action", e.Action),
		zap.String("performed_by", e.UserID),
		zap.String("tenant_id", e.TenantID),
		zap.String("resource_id", e.ResourceID),
		zap.String("request_id", e.RequestID),
		zap.String("ip_address", e.IPAddress),
		zap.Time("timestamp", e.Timestamp),
	)
}
