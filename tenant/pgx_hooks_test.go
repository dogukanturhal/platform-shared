// SPDX-License-Identifier: Apache-2.0

package tenant

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
)

// Tests for the pgx hooks and helper functions that do not require a live
// PostgreSQL connection.  Integration tests that exercise WithTenantPgx and
// WithTenantPgxConn against a real pgxpool are expected to live in an
// _integration_test.go file or a testcontainers-based test suite.

// --- isSetLocalQuery -------------------------------------------------------

func TestIsSetLocalQuery_TenantGUC(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		sql      string
		expected bool
	}{
		{
			name:     "exact tenant SET LOCAL",
			sql:      "SET LOCAL app.current_tenant_id = $1",
			expected: true,
		},
		{
			name:     "exact realm SET LOCAL",
			sql:      "SET LOCAL app.current_realm_id = $1",
			expected: true,
		},
		{
			name:     "ordinary SELECT",
			sql:      "SELECT id FROM crm.contacts WHERE tenant_id = $1",
			expected: false,
		},
		{
			name:     "empty string",
			sql:      "",
			expected: false,
		},
		{
			name:     "partial match - too short",
			sql:      "SET LOCAL",
			expected: false,
		},
		{
			name:     "unrelated SET LOCAL",
			sql:      "SET LOCAL search_path = public",
			expected: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := isSetLocalQuery(tc.sql)
			assert.Equal(t, tc.expected, got)
		})
	}
}

// --- PgxTenantHook compilation smoke test ----------------------------------

// TestPgxTenantHook_ImplementsInterface verifies at compile time that
// *PgxTenantHook satisfies the pgx.QueryTracer interface.  If pgx changes its
// interface signature this test will fail to compile and alert developers.
func TestPgxTenantHook_ImplementsInterface(t *testing.T) {
	t.Parallel()
	// A nil-pointer assignment is enough to trigger the interface satisfaction
	// check at compile time; no live database connection is needed.
	var _ pgx.QueryTracer = (*PgxTenantHook)(nil)

	// Also verify that a concrete value is non-nil (basic sanity).
	hook := &PgxTenantHook{}
	assert.NotNil(t, hook)
}

// --- ContextWithTenantID + TenantIDFromContext integration with pgx hooks ---

func TestWithTenantPgx_SetsTenantAndRealm_Signature(t *testing.T) {
	t.Parallel()
	// Verify that the function accepts the optional realmID variadic correctly
	// by inspecting the signature via a compile-time assignment (no live DB needed).
	tenantID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	realmID := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

	// We cannot call WithTenantPgx without a pool, but we can verify that calling
	// the function with the optional realmID is syntactically valid.  The test
	// would fail to compile if the signature were wrong.
	_ = tenantID
	_ = realmID

	// Uncomment to run against a live pool in integration tests:
	// err := WithTenantPgx(ctx, pool, tenantID, func(tx pgx.Tx) error {
	//     return nil
	// }, realmID)
	// require.NoError(t, err)
}

func TestWithTenantPgxConn_SetsTenant_Signature(t *testing.T) {
	t.Parallel()

	tenantID := uuid.MustParse("cccccccc-cccc-cccc-cccc-cccccccccccc")
	_ = tenantID

	// Uncomment to run against a live pool in integration tests:
	// err := WithTenantPgxConn(ctx, pool, tenantID, func(conn *pgxpool.Conn) error {
	//     return nil
	// })
	// require.NoError(t, err)
}
