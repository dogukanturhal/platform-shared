// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureLogger records every Entry passed to Log so tests can inspect them.
type captureLogger struct {
	mu      sync.Mutex
	entries []*Entry
}

func (l *captureLogger) Log(e *Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
}

func (l *captureLogger) last() *Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) == 0 {
		return nil
	}
	return l.entries[len(l.entries)-1]
}

func (l *captureLogger) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// newAdminContext creates a *gin.Context seeded with the provided context values.
func newAdminContext(kvs ...interface{}) *gin.Context {
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete, "/admin/tenants/t-1", nil)
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	for i := 0; i+1 < len(kvs); i += 2 {
		c.Set(kvs[i].(string), kvs[i+1])
	}

	return c
}

// ---------------------------------------------------------------------------
// LogAdminAction
// ---------------------------------------------------------------------------

func TestLogAdminAction_ExtractsUserIDFromContext(t *testing.T) {
	logger := &captureLogger{}
	c := newAdminContext("user_id", "user-abc")

	LogAdminAction(c, logger, "DELETE_TENANT", nil)

	require.Equal(t, 1, logger.count())
	assert.Equal(t, "user-abc", logger.last().UserID)
}

func TestLogAdminAction_ExtractsTenantIDString(t *testing.T) {
	logger := &captureLogger{}
	c := newAdminContext("user_id", "u1", "tenant_id", "tenant-xyz")

	LogAdminAction(c, logger, "BULK_DELETE", nil)

	require.Equal(t, 1, logger.count())
	assert.Equal(t, "tenant-xyz", logger.last().TenantID)
}

func TestLogAdminAction_ExtractsTenantIDUUID(t *testing.T) {
	logger := &captureLogger{}
	tid := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	c := newAdminContext("user_id", "u1", "tenant_id", tid)

	LogAdminAction(c, logger, "SUSPEND_TENANT", nil)

	require.Equal(t, 1, logger.count())
	assert.Equal(t, "22222222-2222-2222-2222-222222222222", logger.last().TenantID)
}

func TestLogAdminAction_ExtractsRequestIDFromContext(t *testing.T) {
	logger := &captureLogger{}
	c := newAdminContext("user_id", "u1", "request_id", "req-999")

	LogAdminAction(c, logger, "FORCE_LOGOUT", nil)

	require.Equal(t, 1, logger.count())
	assert.Equal(t, "req-999", logger.last().RequestID)
}

func TestLogAdminAction_ExtractsRequestIDFromHeader(t *testing.T) {
	logger := &captureLogger{}
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "/admin/reset", nil)
	req.Header.Set("X-Request-ID", "hdr-req-42")
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("user_id", "u2")

	LogAdminAction(c, logger, "RESET_PASSWORD", nil)

	require.Equal(t, 1, logger.count())
	assert.Equal(t, "hdr-req-42", logger.last().RequestID)
}

func TestLogAdminAction_IncludesAction(t *testing.T) {
	logger := &captureLogger{}
	c := newAdminContext()

	LogAdminAction(c, logger, "GRANT_SUPERADMIN", nil)

	require.Equal(t, 1, logger.count())
	assert.Equal(t, "GRANT_SUPERADMIN", logger.last().Action)
}

func TestLogAdminAction_IncludesIPAddress(t *testing.T) {
	logger := &captureLogger{}
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete, "/", nil)
	// Set RemoteAddr so Gin can extract a real IP from the request.
	req.RemoteAddr = "203.0.113.5:12345"
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	LogAdminAction(c, logger, "TERMINATE_SESSION", nil)

	require.Equal(t, 1, logger.count())
	assert.NotEmpty(t, logger.last().IPAddress)
}

func TestLogAdminAction_NoUserIDInContext(t *testing.T) {
	logger := &captureLogger{}
	c := newAdminContext() // no user_id set

	LogAdminAction(c, logger, "ANON_ACTION", nil)

	require.Equal(t, 1, logger.count())
	// PerformedBy should be empty when no user_id is in context.
	assert.Empty(t, logger.last().UserID)
}

func TestLogAdminAction_EntryHasNonEmptyID(t *testing.T) {
	logger := &captureLogger{}
	c := newAdminContext()

	LogAdminAction(c, logger, "TEST_ACTION", nil)

	require.Equal(t, 1, logger.count())
	assert.NotEmpty(t, logger.last().ID, "audit entry must have a unique ID")
}

func TestLogAdminAction_EntryHasTimestamp(t *testing.T) {
	logger := &captureLogger{}
	c := newAdminContext()

	LogAdminAction(c, logger, "TEST_ACTION", nil)

	require.Equal(t, 1, logger.count())
	assert.False(t, logger.last().Timestamp.IsZero(), "audit entry timestamp must be set")
}

// ---------------------------------------------------------------------------
// AdminAuditEntry — structural output format
// ---------------------------------------------------------------------------

func TestAdminAuditEntry_StructuredOutput(t *testing.T) {
	logger := &captureLogger{}
	c := newAdminContext(
		"user_id", "admin-1",
		"tenant_id", "tenant-a",
		"request_id", "req-77",
	)

	details := map[string]interface{}{
		"affected_users": 42,
		"reason":         "compliance",
	}
	LogAdminAction(c, logger, "BULK_SUSPEND", details)

	require.Equal(t, 1, logger.count())
	e := logger.last()

	assert.Equal(t, "BULK_SUSPEND", e.Action)
	assert.Equal(t, "admin-1", e.UserID)
	assert.Equal(t, "tenant-a", e.TenantID)
	assert.Equal(t, "req-77", e.RequestID)
	assert.Equal(t, "admin", e.ServiceName)
	assert.Equal(t, "ADMIN", e.Method)
}
