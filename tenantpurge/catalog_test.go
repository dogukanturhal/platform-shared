// SPDX-License-Identifier: Apache-2.0

package tenantpurge

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsTenantColumn(t *testing.T) {
	extra := map[string]struct{}{"org_ref": {}}
	for _, c := range []string{"tenant_id", "TENANT_ID", "owner_tenant_id", "source_tenant_id", "org_ref"} {
		assert.True(t, IsTenantColumn(c, extra), c)
	}
	for _, c := range []string{"tenant", "tenantid", "tenant_name", "tenant_id_hash", "user_id", "org"} {
		assert.False(t, IsTenantColumn(c, extra), c)
	}
}

func TestTenantColumnsOnlyIDTypes(t *testing.T) {
	tbl := Table{Ref: ref("t"), Columns: []Column{
		{"id", "uuid"}, {"tenant_id", "uuid"}, {"owner_tenant_id", "text"}, {"legacy_tenant_id", "integer"},
	}}
	cols := tbl.TenantColumns(nil)
	assert.Equal(t, []Column{{"tenant_id", "uuid"}, {"owner_tenant_id", "text"}}, cols)
}

func TestQuoteIdent(t *testing.T) {
	assert.Equal(t, `"a"`, quoteIdent("a"))
	assert.Equal(t, `"a""b"`, quoteIdent(`a"b`))
	assert.Equal(t, `"public"."order lines"`, TableRef{"public", "order lines"}.quoted())
}

func TestTenantPredicate(t *testing.T) {
	got := tenantPredicate([]Column{{"tenant_id", "uuid"}, {"owner_tenant_id", "text"}})
	assert.Equal(t, `("tenant_id" = ($1::text)::uuid OR "owner_tenant_id"::text = $1::text)`, got)
}

func TestValuePredicate(t *testing.T) {
	assert.Equal(t, "", valuePredicate([]Column{{"n", "integer"}, {"at", "timestamp with time zone"}}))
	got := valuePredicate([]Column{{"id", "uuid"}, {"payload", "jsonb"}, {"key", "text"}, {"n", "integer"}})
	assert.Equal(t, `("id" = ($1::text)::uuid OR "payload"::text LIKE '%' || $1::text || '%' OR "key"::text LIKE '%' || $1::text || '%')`, got)
}

func TestRetainKeepExpr(t *testing.T) {
	assert.Equal(t, "true", Retain{Table: "t", Basis: "b"}.keepExpr())
	assert.Equal(t, "COALESCE((status <> 'draft'), false)", Retain{Table: "t", Where: "status <> 'draft'"}.keepExpr())
	assert.Equal(t, TableRef{"public", "t"}, Retain{Table: "t"}.ref())
}

func TestInList(t *testing.T) {
	assert.Equal(t, "$1,$2,$3", inList(1, 3))
}
