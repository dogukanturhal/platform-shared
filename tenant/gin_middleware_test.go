// SPDX-License-Identifier: Apache-2.0

package tenant

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// newTestRouter creates a minimal Gin engine with the given middleware chain and a
// GET /test handler that records whether it was reached.
func newTestRouter(middleware ...gin.HandlerFunc) (*gin.Engine, *bool) {
	reached := false
	r := gin.New()
	r.Use(middleware...)
	r.GET("/test", func(c *gin.Context) {
		reached = true
		c.Status(http.StatusOK)
	})
	return r, &reached
}

// --- ExtractTenantID -------------------------------------------------------

func TestExtractTenantID_FromHeader(t *testing.T) {
	t.Parallel()

	tenantID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	var captured uuid.UUID
	r := gin.New()
	r.Use(ExtractTenantID())
	r.GET("/test", func(c *gin.Context) {
		captured, _ = GetTenantID(c)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("X-Tenant-ID", tenantID.String())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, tenantID, captured)
}

func TestExtractTenantID_FromContext(t *testing.T) {
	t.Parallel()

	// Simulate upstream auth middleware that already set the tenant_id.
	tenantID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	preSet := func(c *gin.Context) {
		c.Set(TenantIDKey, tenantID)
		c.Next()
	}

	var captured uuid.UUID
	r := gin.New()
	r.Use(preSet, ExtractTenantID())
	r.GET("/test", func(c *gin.Context) {
		captured, _ = GetTenantID(c)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, tenantID, captured)
}

func TestExtractTenantID_NoSource_PassesThrough(t *testing.T) {
	t.Parallel()

	r, reached := newTestRouter(ExtractTenantID())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "ExtractTenantID must not abort without a source")
	assert.True(t, *reached)
}

func TestExtractTenantID_InvalidHeader_PassesThrough(t *testing.T) {
	t.Parallel()

	r, reached := newTestRouter(ExtractTenantID())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("X-Tenant-ID", "not-a-uuid")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Invalid UUID in header must not abort")
	assert.True(t, *reached)
}

// --- RequireTenantID -------------------------------------------------------

func TestRequireTenantID_Missing_Returns400(t *testing.T) {
	t.Parallel()

	r, reached := newTestRouter(RequireTenantID())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.False(t, *reached, "handler must not be called when tenant is missing")
}

func TestRequireTenantID_Present_PassesThrough(t *testing.T) {
	t.Parallel()

	tenantID := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	r, reached := newTestRouter(RequireTenantID())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("X-Tenant-ID", tenantID.String())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, *reached)
}

// --- GetTenantID -----------------------------------------------------------

func TestGetTenantID_NotSet_ReturnsFalse(t *testing.T) {
	t.Parallel()

	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		id, ok := GetTenantID(c)
		assert.False(t, ok)
		assert.Equal(t, uuid.Nil, id)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetTenantID_StringValue_Parsed(t *testing.T) {
	t.Parallel()

	tenantID := uuid.MustParse("44444444-4444-4444-4444-444444444444")
	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		// Store as string to exercise the string branch.
		c.Set(TenantIDKey, tenantID.String())
		id, ok := GetTenantID(c)
		assert.True(t, ok)
		assert.Equal(t, tenantID, id)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// --- GetRealmID ------------------------------------------------------------

func TestGetRealmID_NotSet_ReturnsFalse(t *testing.T) {
	t.Parallel()

	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		id, ok := GetRealmID(c)
		assert.False(t, ok)
		assert.Equal(t, uuid.Nil, id)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// --- RLSMiddlewareSqlx -----------------------------------------------------

// TestRLSMiddlewareSqlx_SetsTenantContext verifies that the middleware executes
// SET LOCAL app.current_tenant_id against the underlying *sql.DB.
func TestRLSMiddlewareSqlx_SetsTenantContext(t *testing.T) {
	t.Parallel()

	tenantID := uuid.MustParse("55555555-5555-5555-5555-555555555555")

	// Build a sqlmock DB.
	rawDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = rawDB.Close() }()

	db := sqlx.NewDb(rawDB, "postgres")

	// sqlmock expects: BEGIN (Conn acquisition), then SET LOCAL, then the connection
	// close triggered by defer inside the middleware.
	mock.ExpectExec(`SET LOCAL app\.current_tenant_id = \$1`).
		WithArgs(tenantID.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))

	preSet := func(c *gin.Context) {
		c.Set(TenantIDKey, tenantID)
		c.Next()
	}

	reached := false
	r := gin.New()
	r.Use(preSet, RLSMiddlewareSqlx(db))
	r.GET("/test", func(c *gin.Context) {
		// The db_conn key should be present.
		conn, exists := c.Get("db_conn")
		assert.True(t, exists, "db_conn must be set in context")
		assert.IsType(t, &sql.Conn{}, conn)
		reached = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, reached)
	// sqlmock validates that all expected calls were made.
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRLSMiddlewareSqlx_NoTenant_SkipsSetLocal(t *testing.T) {
	t.Parallel()

	rawDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = rawDB.Close() }()

	db := sqlx.NewDb(rawDB, "postgres")
	// No expectations — no DB calls should be made.

	r, reached := newTestRouter(RLSMiddlewareSqlx(db))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, *reached)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRLSMiddlewareSqlx_WithRealm_SetsBothGUCs(t *testing.T) {
	t.Parallel()

	tenantID := uuid.MustParse("66666666-6666-6666-6666-666666666666")
	realmID := uuid.MustParse("77777777-7777-7777-7777-777777777777")

	rawDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = rawDB.Close() }()

	db := sqlx.NewDb(rawDB, "postgres")
	mock.ExpectExec(`SET LOCAL app\.current_tenant_id = \$1`).
		WithArgs(tenantID.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SET LOCAL app\.current_realm_id = \$1`).
		WithArgs(realmID.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))

	preSet := func(c *gin.Context) {
		c.Set(TenantIDKey, tenantID)
		c.Set(RealmIDKey, realmID)
		c.Next()
	}

	r := gin.New()
	r.Use(preSet, RLSMiddlewareSqlx(db))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}
