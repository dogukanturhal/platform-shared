// SPDX-License-Identifier: Apache-2.0

// Package audit provides middleware and helpers for recording mutation audit trails.
package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Entry represents a single audit log entry.
type Entry struct {
	ID           string          `json:"id"`
	Timestamp    time.Time       `json:"timestamp"`
	TenantID     string          `json:"tenant_id,omitempty"`
	UserID       string          `json:"user_id,omitempty"`
	UserEmail    string          `json:"user_email,omitempty"`
	ServiceName  string          `json:"service_name"`
	Action       string          `json:"action"` // CREATE, UPDATE, DELETE
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id,omitempty"`
	Method       string          `json:"method"`
	Path         string          `json:"path"`
	StatusCode   int             `json:"status_code"`
	RequestBody  json.RawMessage `json:"request_body,omitempty"`
	RequestID    string          `json:"request_id,omitempty"`
	IPAddress    string          `json:"ip_address,omitempty"`
	DurationMs   int64           `json:"duration_ms"`
}

// Logger is the interface for persisting audit entries.
type Logger interface {
	Log(entry *Entry)
}

// ZapLogger logs audit entries using a zap logger with a dedicated "audit" field.
type ZapLogger struct {
	logger *zap.Logger
}

// NewZapLogger creates a ZapLogger from an existing zap.Logger.
func NewZapLogger(logger *zap.Logger) *ZapLogger {
	return &ZapLogger{logger: logger.Named("audit")}
}

// Log writes the audit entry as a structured log line.
func (l *ZapLogger) Log(e *Entry) {
	l.logger.Info("audit",
		zap.String("audit_id", e.ID),
		zap.String("tenant_id", e.TenantID),
		zap.String("user_id", e.UserID),
		zap.String("user_email", e.UserEmail),
		zap.String("service", e.ServiceName),
		zap.String("action", e.Action),
		zap.String("resource_type", e.ResourceType),
		zap.String("resource_id", e.ResourceID),
		zap.String("method", e.Method),
		zap.String("path", e.Path),
		zap.Int("status_code", e.StatusCode),
		zap.String("request_id", e.RequestID),
		zap.String("ip_address", e.IPAddress),
		zap.Int64("duration_ms", e.DurationMs),
	)
}

// Config holds configuration for the audit middleware.
type Config struct {
	ServiceName  string
	Logger       Logger
	MaxBodyBytes int  // Max request body bytes to capture (default 4096).
	SkipReadOps  bool // If true, only log POST/PUT/PATCH/DELETE (default true).
}

// Middleware returns a Gin middleware that records audit entries for mutations.
func Middleware(cfg Config) gin.HandlerFunc {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 4096
	}

	return func(c *gin.Context) {
		method := c.Request.Method

		// Skip read operations if configured (default).
		if cfg.SkipReadOps && (method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions) {
			c.Next()
			return
		}

		start := time.Now()

		// Capture request body (limited size).
		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, _ = io.ReadAll(io.LimitReader(c.Request.Body, int64(cfg.MaxBodyBytes)))
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		// Sanitize body — redact sensitive fields.
		sanitized := sanitizeBody(bodyBytes)

		c.Next()

		// Build entry.
		entry := &Entry{
			ID:          uuid.New().String(),
			Timestamp:   start,
			ServiceName: cfg.ServiceName,
			Method:      method,
			Path:        c.Request.URL.Path,
			StatusCode:  c.Writer.Status(),
			RequestBody: sanitized,
			IPAddress:   c.ClientIP(),
			DurationMs:  time.Since(start).Milliseconds(),
		}

		// Extract action from HTTP method.
		switch method {
		case http.MethodPost:
			entry.Action = "CREATE"
		case http.MethodPut, http.MethodPatch:
			entry.Action = "UPDATE"
		case http.MethodDelete:
			entry.Action = "DELETE"
		default:
			entry.Action = method
		}

		// Extract user info from gin context (set by auth middleware).
		if tenantID, ok := c.Get("tenant_id"); ok {
			entry.TenantID = stringVal(tenantID)
		}
		if userID := c.GetString("user_id"); userID != "" {
			entry.UserID = userID
		}
		if email := c.GetString("user_email"); email != "" {
			entry.UserEmail = email
		}

		// Extract request ID from header or context.
		if reqID := c.GetHeader("X-Request-ID"); reqID != "" {
			entry.RequestID = reqID
		} else if reqID := c.GetString("request_id"); reqID != "" {
			entry.RequestID = reqID
		}

		// Extract resource type and ID from path.
		entry.ResourceType = extractResourceType(c.FullPath())
		if id := c.Param("id"); id != "" {
			entry.ResourceID = id
		}

		cfg.Logger.Log(entry)
	}
}

// sanitizeBody removes sensitive fields from a JSON body.
func sanitizeBody(body []byte) json.RawMessage {
	if len(body) == 0 {
		return nil
	}

	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil // Non-JSON body — don't log.
	}

	sensitiveKeys := map[string]bool{
		"password": true, "secret": true, "token": true,
		"api_key": true, "apikey": true, "access_token": true,
		"refresh_token": true, "private_key": true, "secret_key": true,
		"authorization": true, "credential": true, "credentials": true,
	}

	for k := range obj {
		if sensitiveKeys[k] {
			obj[k] = "[REDACTED]"
		}
	}

	sanitized, _ := json.Marshal(obj)
	return sanitized
}

// extractResourceType derives the resource type from a Gin route pattern.
// e.g., "/api/v1/compute/workloads/:id" → "workloads"
func extractResourceType(fullPath string) string {
	if fullPath == "" {
		return "unknown"
	}
	// Walk segments backwards, find the first non-param segment.
	parts := splitPath(fullPath)
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "" && parts[i][0] != ':' && parts[i][0] != '*' {
			return parts[i]
		}
	}
	return "unknown"
}

func splitPath(p string) []string {
	var parts []string
	current := ""
	for _, ch := range p {
		if ch == '/' {
			if current != "" {
				parts = append(parts, current)
			}
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func stringVal(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	if u, ok := v.(uuid.UUID); ok {
		return u.String()
	}
	return ""
}
