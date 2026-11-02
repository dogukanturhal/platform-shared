// SPDX-License-Identifier: Apache-2.0

//go:build integration
// +build integration

package database

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests target the exact defect fixed in this file: a session-scoped
// set_config('app.current_tenant_id', v, false) does not respect transaction
// (and therefore PgBouncer transaction-pooling) boundaries, while
// set_config(..., true) (SET LOCAL semantics), applied inside the same
// transaction as the tenant-scoped query, does.
//
// We cannot spin up a real PgBouncer transaction-mode pooler in this suite,
// but the property that matters is reproducible without one: does the setting
// survive past the boundary where a pooler would be free to hand the
// underlying backend to a different logical caller? For a session-scoped
// set_config that boundary is "connection released back to the pool, then
// reacquired" — which is exactly what these tests force by capping the pool
// at a single connection (MaxConns=1), so both acquisitions are guaranteed to
// be the same physical backend. For a transaction-scoped set_config the
// boundary is "the transaction that set it commits" — no pool trickery
// needed, since SET LOCAL / is_local=true is defined to not survive COMMIT.
//
// TestNegativeControl proves the harness can detect persistence at all: it
// exercises the OLD buggy form (is_local=false, no explicit transaction) and
// asserts the tenant setting DOES persist across a connection handoff. If
// this test failed to observe persistence, the harness itself would be
// broken and the positive test below would prove nothing.
//
// TestWithTenantContextPgx_DoesNotLeakAcrossTransactions proves the FIX:
// the same connection, immediately after WithTenantContextPgx commits, no
// longer reports the tenant setting.
//
// Run with: go test -tags=integration ./database/... -run TenantContextPooling
// Requires POSTGRES_HOST/POSTGRES_PORT/POSTGRES_USER/POSTGRES_PASSWORD/POSTGRES_DB
// (defaults match the local qsvc-test-pg dev container: localhost:15432).

func poolingTestDSN() string {
	host := getEnvOrDefault("POSTGRES_HOST", "localhost")
	port := getEnvOrDefault("POSTGRES_PORT", "15432")
	user := getEnvOrDefault("POSTGRES_USER", "postgres")
	password := getEnvOrDefault("POSTGRES_PASSWORD", "test")
	dbname := getEnvOrDefault("POSTGRES_DB", "testdb")
	return "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbname + "?sslmode=disable"
}

func newSingleConnPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(poolingTestDSN())
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg.MaxConns = 1
	cfg.MinConns = 1
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	return pool
}

func readCurrentTenantSetting(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	var val string
	// current_setting(..., true) => missing_ok, returns '' rather than erroring
	// when the GUC has never been set on this backend.
	if err := pool.QueryRow(ctx, "SELECT current_setting('app.current_tenant_id', true)").Scan(&val); err != nil {
		t.Fatalf("read current_setting: %v", err)
	}
	return val
}

// TestNegativeControl_SessionScopedSetConfigPersistsAcrossAcquire demonstrates
// the OLD (removed) bug in isolation: is_local=false, executed outside an
// explicit transaction, on a pool capped to one physical connection. The
// value set by one logical "request" is still visible to the very next
// acquire — exactly the hazard that made the old RLSMiddleware unsafe under
// PgBouncer transaction pooling (a different tenant's next statement can
// land on a backend that still carries this value).
//
// This test is expected to PASS (i.e. observe persistence). If it started
// failing, the discriminating property below would need re-validation, not
// silent deletion.
func TestNegativeControl_SessionScopedSetConfigPersistsAcrossAcquire(t *testing.T) {
	ctx := context.Background()
	pool := newSingleConnPool(t)

	tenantA := uuid.New()

	// Reproduce the exact removed statement shape: SELECT set_config(..., false),
	// executed directly on the pool (no explicit BEGIN), as the old
	// RLSMiddleware did via conn.Exec on an acquired connection.
	if _, err := pool.Exec(ctx, "SELECT set_config('app.current_tenant_id', $1, false)", tenantA.String()); err != nil {
		t.Fatalf("set_config (session-scoped): %v", err)
	}

	// Acquire again — with MaxConns=1 this is guaranteed to be the same
	// physical backend connection, simulating the pool/pooler handing the
	// same backend to the next logical caller.
	got := readCurrentTenantSetting(t, ctx, pool)
	if got != tenantA.String() {
		t.Fatalf("harness invariant broken: expected session-scoped set_config to persist across reacquire, got %q want %q — the discriminating test below cannot be trusted until this is understood", got, tenantA.String())
	}
	t.Logf("confirmed: session-scoped set_config(..., false) leaked tenant %s across a connection handoff — this is the bug the middleware removal fixes", tenantA)
}

// TestWithTenantContextPgx_DoesNotLeakAcrossTransactions proves the fix:
// after WithTenantContextPgx sets the tenant and commits, the SAME backend
// connection no longer reports that tenant when queried outside a
// transaction that re-sets it. Uses the same MaxConns=1 pool as the negative
// control, so this is the same physical backend that the control proved
// retains session-scoped state — demonstrating the transaction-scoped form
// behaves differently on that same connection.
func TestWithTenantContextPgx_DoesNotLeakAcrossTransactions(t *testing.T) {
	ctx := context.Background()
	pool := newSingleConnPool(t)

	tenantB := uuid.New()

	if err := WithTenantContextPgx(ctx, pool, tenantB, func(tx pgx.Tx) error {
		// No-op query inside the tenant-scoped transaction, just to exercise
		// the real call shape a repository would use.
		var one int
		return tx.QueryRow(ctx, "SELECT 1").Scan(&one)
	}); err != nil {
		t.Fatalf("WithTenantContextPgx: %v", err)
	}

	got := readCurrentTenantSetting(t, ctx, pool)
	if got == tenantB.String() {
		t.Fatalf("regression: transaction-scoped set_config leaked past COMMIT — got %q, expected empty (or a different value)", got)
	}
	t.Logf("confirmed: WithTenantContextPgx's set_config(..., true) for tenant %s did NOT survive past commit (observed %q) — fix verified", tenantB, got)
}
