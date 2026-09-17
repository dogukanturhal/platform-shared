// SPDX-License-Identifier: Apache-2.0

package audit

// DBMiddleware and AuditEntry extend the shared audit package with a
// PostgreSQL-backed persistence layer.  All mutating HTTP requests
// (POST / PUT / PATCH / DELETE) are recorded asynchronously so that the
// calling service's request latency is never affected by audit-write
// performance.
//
// Usage:
//
//	dbLogger := audit.NewDBLogger(pool, zapLogger)
//	router.Use(audit.DBMiddleware(audit.DBConfig{
//	    ServiceName: "crm",
//	    DBLogger:    dbLogger,
//	}))

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// AuditEntry is the canonical record written to the audit_log table.
// It mirrors the SQL schema defined in migrations/shared/001_audit_log.sql.
type AuditEntry struct { //nolint:revive // public API stability
	ID         uuid.UUID       `json:"id"`
	TenantID   uuid.UUID       `json:"tenant_id"`
	UserID     uuid.UUID       `json:"user_id"`
	Action     string          `json:"action"`      // "create", "update", "delete"
	Resource   string          `json:"resource"`    // "crm.contact", "crm.deal", etc.
	ResourceID string          `json:"resource_id"` // entity ID extracted from path
	Method     string          `json:"method"`
	Path       string          `json:"path"`
	StatusCode int             `json:"status_code"`
	IPAddress  string          `json:"ip_address"`
	UserAgent  string          `json:"user_agent"`
	Changes    json.RawMessage `json:"changes"` // sanitized request body
	CreatedAt  time.Time       `json:"created_at"`
}

// DBLogger persists AuditEntry records to the audit_log table in PostgreSQL.
// Writes are fire-and-forget: they are dispatched in a goroutine and any error
// is logged via the provided zap.Logger but never propagated to the caller.
type DBLogger struct {
	db     *pgxpool.Pool
	logger *zap.Logger
}

// NewDBLogger creates a DBLogger backed by the provided connection pool.
func NewDBLogger(db *pgxpool.Pool, logger *zap.Logger) *DBLogger {
	return &DBLogger{
		db:     db,
		logger: logger.Named("audit-db"),
	}
}

// Insert writes the entry to the database. It is called inside a goroutine by
// DBMiddleware so it must not block long or panic.
func (l *DBLogger) Insert(entry AuditEntry) {
	const q = `
		INSERT INTO audit_log (
			id, tenant_id, user_id, action, resource, resource_id,
			method, path, status_code, ip_address, user_agent, changes, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := l.db.Exec(ctx, q,
		entry.ID,
		entry.TenantID,
		entry.UserID,
		entry.Action,
		entry.Resource,
		entry.ResourceID,
		entry.Method,
		entry.Path,
		entry.StatusCode,
		entry.IPAddress,
		entry.UserAgent,
		entry.Changes,
		entry.CreatedAt,
	); err != nil {
		l.logger.Warn("audit insert failed",
			zap.String("path", entry.Path),
			zap.String("tenant_id", entry.TenantID.String()),
			zap.Error(err),
		)
	}
}

// DBConfig holds configuration for DBMiddleware.
type DBConfig struct {
	// ServiceName is used to namespace the resource field, e.g. "crm".
	// The derived resource becomes "<ServiceName>.<entity>".
	ServiceName string

	// DBLogger writes entries to PostgreSQL.  If nil, the middleware falls back
	// to a no-op so services can opt out of DB audit logging without code changes.
	DBLogger *DBLogger

	// MaxBodyBytes caps how many request body bytes are captured (default 4096).
	MaxBodyBytes int
}

// DBMiddleware returns a Gin middleware that records all state-mutating requests
// (POST / PUT / PATCH / DELETE) to the audit_log table.
//
// The write is dispatched asynchronously in a detached goroutine so the HTTP
// handler response time is never affected.  context.Background() is used for
// the write — not the request context — so canceling the request does not
// silently drop the audit record.
func DBMiddleware(cfg DBConfig) gin.HandlerFunc {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 4096
	}

	return func(c *gin.Context) {
		method := c.Request.Method

		// Skip non-mutating methods.
		switch method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}

		start := time.Now()

		// Read and restore the request body so downstream handlers are unaffected.
		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, _ = io.ReadAll(io.LimitReader(c.Request.Body, int64(cfg.MaxBodyBytes)))
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		sanitized := sanitizeBody(bodyBytes)

		// Execute the actual handler chain.
		c.Next()

		// Capture after-response state.
		statusCode := c.Writer.Status()
		now := time.Now()
		path := c.Request.URL.Path
		fullPath := c.FullPath()

		// Extract tenant / user from context (populated by the service's own auth middleware).
		tenantID := extractUUID(c, "tenant_id")
		userID := extractUUID(c, "user_id")

		resource, resourceID := deriveResource(cfg.ServiceName, fullPath, c)
		action := methodToAction(method)

		entry := AuditEntry{
			ID:         uuid.New(),
			TenantID:   tenantID,
			UserID:     userID,
			Action:     action,
			Resource:   resource,
			ResourceID: resourceID,
			Method:     method,
			Path:       path,
			StatusCode: statusCode,
			IPAddress:  c.ClientIP(),
			UserAgent:  c.Request.UserAgent(),
			Changes:    sanitized,
			CreatedAt:  start,
		}

		_ = now // suppress unused warning

		if cfg.DBLogger == nil {
			return
		}

		// Fire-and-forget — use a background context so request cancellation
		// does not discard the audit record.
		go cfg.DBLogger.Insert(entry)
	}
}

// --- helpers ---

// deriveResource maps a Gin full-path pattern and its params to a dot-separated
// resource name and resource ID.
//
// Examples (serviceName="crm"):
//   - "/api/v1/crm/contacts/:id"  → resource="crm.contact",  resourceID=<id param>
//   - "/api/v1/contacts/:id"       → resource="crm.contact",  resourceID=<id param>
//   - "/api/v1/deals"              → resource="crm.deal",     resourceID=""
func deriveResource(serviceName, fullPath string, c *gin.Context) (resource, resourceID string) {
	resourceID = c.Param("id")

	parts := splitPathSegments(fullPath)
	// Walk backwards: find the last non-param, non-version, non-"api" segment.
	entitySegment := ""
	for i := len(parts) - 1; i >= 0; i-- {
		seg := parts[i]
		if seg == "" || seg[0] == ':' || seg[0] == '*' {
			continue
		}
		// Skip common path prefixes.
		if seg == "api" || seg == "v1" || seg == "v2" || seg == "admin" {
			continue
		}
		entitySegment = seg
		break
	}

	// Singularise: "contacts" → "contact", "deals" → "deal"
	entity := singularise(entitySegment)

	if serviceName != "" {
		resource = fmt.Sprintf("%s.%s", serviceName, entity)
	} else {
		resource = entity
	}
	return resource, resourceID
}

// singularise performs simple English singularisation for common ERP nouns.
// It is intentionally minimal — exact accuracy is not required for audit logs.
func singularise(s string) string {
	switch {
	case strings.HasSuffix(s, "ies"):
		return s[:len(s)-3] + "y" // activities → activity
	case strings.HasSuffix(s, "ses"):
		return s[:len(s)-2] // processes → process
	case strings.HasSuffix(s, "s") && len(s) > 1:
		return s[:len(s)-1] // contacts → contact
	default:
		return s
	}
}

// methodToAction converts an HTTP method to an audit action verb.
func methodToAction(method string) string {
	switch method {
	case http.MethodPost:
		return "create"
	case http.MethodPut, http.MethodPatch:
		return "update"
	case http.MethodDelete:
		return "delete"
	default:
		return strings.ToLower(method)
	}
}

// extractUUID reads a uuid.UUID from the Gin context by key.
// Returns uuid.Nil when the key is absent or the value is not a UUID.
func extractUUID(c *gin.Context, key string) uuid.UUID {
	v, ok := c.Get(key)
	if !ok {
		return uuid.Nil
	}
	switch id := v.(type) {
	case uuid.UUID:
		return id
	case string:
		parsed, err := uuid.Parse(id)
		if err != nil {
			return uuid.Nil
		}
		return parsed
	default:
		return uuid.Nil
	}
}

// splitPathSegments splits a URL path by "/" dropping empty tokens.
func splitPathSegments(p string) []string {
	var parts []string
	for _, seg := range strings.Split(p, "/") {
		if seg != "" {
			parts = append(parts, seg)
		}
	}
	return parts
}
