// SPDX-License-Identifier: Apache-2.0

package tenant

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- mock Execer -----------------------------------------------------------

// mockExecer records every call to ExecContext so tests can assert on the queries
// and arguments without requiring a real database connection.
type mockExecer struct {
	calls []execCall
	err   error // non-nil forces an error on the next call
}

type execCall struct {
	query string
	args  []interface{}
}

func (m *mockExecer) ExecContext(_ context.Context, query string, args ...interface{}) (sql.Result, error) {
	m.calls = append(m.calls, execCall{query: query, args: args})
	if m.err != nil {
		return nil, m.err
	}
	return driver.RowsAffected(1), nil
}

// --- SetLocalTenant --------------------------------------------------------

func TestSetLocalTenant_Success(t *testing.T) {
	t.Parallel()

	tenantID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	ex := &mockExecer{}

	err := SetLocalTenant(context.Background(), ex, tenantID)

	require.NoError(t, err)
	require.Len(t, ex.calls, 1)
	assert.Equal(t, "SET LOCAL app.current_tenant_id = $1", ex.calls[0].query)
	assert.Equal(t, []interface{}{tenantID.String()}, ex.calls[0].args)
}

func TestSetLocalTenant_NilUUID_Skips(t *testing.T) {
	t.Parallel()

	ex := &mockExecer{}

	err := SetLocalTenant(context.Background(), ex, uuid.Nil)

	require.NoError(t, err, "nil UUID must be a no-op without error")
	assert.Empty(t, ex.calls, "no DB call should be made for uuid.Nil")
}

func TestSetLocalTenant_DBError_Wraps(t *testing.T) {
	t.Parallel()

	tenantID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	dbErr := fmt.Errorf("connection refused")
	ex := &mockExecer{err: dbErr}

	err := SetLocalTenant(context.Background(), ex, tenantID)

	require.Error(t, err)
	assert.ErrorIs(t, err, dbErr)
	assert.Contains(t, err.Error(), "app.current_tenant_id")
}

// --- SetLocalRealm ---------------------------------------------------------

func TestSetLocalRealm_Success(t *testing.T) {
	t.Parallel()

	realmID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	ex := &mockExecer{}

	err := SetLocalRealm(context.Background(), ex, realmID)

	require.NoError(t, err)
	require.Len(t, ex.calls, 1)
	assert.Equal(t, "SET LOCAL app.current_realm_id = $1", ex.calls[0].query)
	assert.Equal(t, []interface{}{realmID.String()}, ex.calls[0].args)
}

func TestSetLocalRealm_NilUUID_Skips(t *testing.T) {
	t.Parallel()

	ex := &mockExecer{}

	err := SetLocalRealm(context.Background(), ex, uuid.Nil)

	require.NoError(t, err)
	assert.Empty(t, ex.calls)
}

func TestSetLocalRealm_DBError_Wraps(t *testing.T) {
	t.Parallel()

	realmID := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	dbErr := fmt.Errorf("timeout")
	ex := &mockExecer{err: dbErr}

	err := SetLocalRealm(context.Background(), ex, realmID)

	require.Error(t, err)
	assert.ErrorIs(t, err, dbErr)
	assert.Contains(t, err.Error(), "app.current_realm_id")
}

// --- Context helpers -------------------------------------------------------

func TestContextWithTenantID_RoundTrip(t *testing.T) {
	t.Parallel()

	tenantID := uuid.MustParse("cccccccc-cccc-cccc-cccc-cccccccccccc")
	ctx := ContextWithTenantID(context.Background(), tenantID)

	got, ok := TenantIDFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, tenantID, got)
}

func TestContextWithRealmID_RoundTrip(t *testing.T) {
	t.Parallel()

	realmID := uuid.MustParse("dddddddd-dddd-dddd-dddd-dddddddddddd")
	ctx := ContextWithRealmID(context.Background(), realmID)

	got, ok := RealmIDFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, realmID, got)
}

func TestTenantIDFromContext_Missing_ReturnsFalse(t *testing.T) {
	t.Parallel()

	id, ok := TenantIDFromContext(context.Background())
	assert.False(t, ok)
	assert.Equal(t, uuid.Nil, id)
}

func TestRealmIDFromContext_Missing_ReturnsFalse(t *testing.T) {
	t.Parallel()

	id, ok := RealmIDFromContext(context.Background())
	assert.False(t, ok)
	assert.Equal(t, uuid.Nil, id)
}

func TestTenantIDFromContext_NilUUID_ReturnsFalse(t *testing.T) {
	t.Parallel()

	ctx := ContextWithTenantID(context.Background(), uuid.Nil)
	_, ok := TenantIDFromContext(ctx)
	assert.False(t, ok, "uuid.Nil stored in context must be treated as absent")
}
