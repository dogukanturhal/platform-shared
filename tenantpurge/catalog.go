// SPDX-License-Identifier: Apache-2.0

package tenantpurge

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Column is one column from information_schema.
type Column struct {
	Name     string
	DataType string // information_schema data_type, e.g. "uuid", "text", "jsonb"
}

// Table is a catalog table with all its columns.
type Table struct {
	Ref     TableRef
	Columns []Column
}

// IsTenantColumn reports whether a column name looks like a tenant reference:
// tenant_id, owner_tenant_id, source_tenant_id, ... plus any name in extra.
func IsTenantColumn(name string, extra map[string]struct{}) bool {
	n := strings.ToLower(name)
	if n == "tenant_id" || strings.HasSuffix(n, "_tenant_id") {
		return true
	}
	_, ok := extra[n]
	return ok
}

// isIDType reports whether the column type can hold a tenant id as a plain value.
func isIDType(dataType string) bool {
	switch dataType {
	case "uuid", "text", "character varying", "character":
		return true
	}
	return false
}

func isTextType(dataType string) bool {
	switch dataType {
	case "text", "character varying", "character":
		return true
	}
	return false
}

func isJSONType(dataType string) bool { return dataType == "json" || dataType == "jsonb" }

// TenantColumns returns the tenant-like, id-typed columns of t.
func (t Table) TenantColumns(extra map[string]struct{}) []Column {
	var out []Column
	for _, c := range t.Columns {
		if IsTenantColumn(c.Name, extra) && isIDType(c.DataType) {
			out = append(out, c)
		}
	}
	return out
}

// quoteIdent quotes a SQL identifier.
func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

func (r TableRef) quoted() string { return quoteIdent(r.Schema) + "." + quoteIdent(r.Name) }

// tenantPredicate builds "(col = $1 OR ...)" for the given columns; the tenant id
// is always parameter $1 typed text so uuid and text columns can mix.
func tenantPredicate(cols []Column) string {
	parts := make([]string, 0, len(cols))
	for _, c := range cols {
		if c.DataType == "uuid" {
			parts = append(parts, quoteIdent(c.Name)+" = ($1::text)::uuid")
		} else {
			parts = append(parts, quoteIdent(c.Name)+"::text = $1::text")
		}
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

// valuePredicate builds a predicate matching the tenant id anywhere in the table:
// equality on uuid columns, containment on text and json columns. Returns "" when
// the table has no searchable column. A canonical uuid holds only hex and '-', so
// it is safe inside LIKE.
func valuePredicate(cols []Column) string {
	var parts []string
	for _, c := range cols {
		switch {
		case c.DataType == "uuid":
			parts = append(parts, quoteIdent(c.Name)+" = ($1::text)::uuid")
		case isTextType(c.DataType), isJSONType(c.DataType):
			parts = append(parts, quoteIdent(c.Name)+"::text LIKE '%' || $1::text || '%'")
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

func inList(start, n int) string {
	ph := make([]string, n)
	for i := range ph {
		ph[i] = fmt.Sprintf("$%d", start+i)
	}
	return strings.Join(ph, ",")
}

func stringArgs(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// loadTables reads every base table (with all columns) of the schemas.
func loadTables(ctx context.Context, tx Tx, schemas []string) (map[TableRef]*Table, error) {
	q := `SELECT c.table_schema, c.table_name, c.column_name, c.data_type
FROM information_schema.columns c
JOIN information_schema.tables t
  ON t.table_schema = c.table_schema AND t.table_name = c.table_name
WHERE t.table_type = 'BASE TABLE' AND c.table_schema IN (` + inList(1, len(schemas)) + `)
ORDER BY c.table_schema, c.table_name, c.ordinal_position`
	rows, err := tx.Query(ctx, q, stringArgs(schemas)...)
	if err != nil {
		return nil, fmt.Errorf("tenantpurge: load catalog: %w", err)
	}
	defer rows.Close()
	tables := make(map[TableRef]*Table)
	for rows.Next() {
		var sch, tbl, col, dt string
		if err := rows.Scan(&sch, &tbl, &col, &dt); err != nil {
			return nil, fmt.Errorf("tenantpurge: scan catalog: %w", err)
		}
		ref := TableRef{Schema: sch, Name: tbl}
		t := tables[ref]
		if t == nil {
			t = &Table{Ref: ref}
			tables[ref] = t
		}
		t.Columns = append(t.Columns, Column{Name: col, DataType: dt})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tenantpurge: load catalog: %w", err)
	}
	return tables, nil
}

// loadFKs reads foreign keys whose child lives in the schemas.
func loadFKs(ctx context.Context, tx Tx, schemas []string) ([]FKEdge, error) {
	q := `SELECT cn.nspname, cc.relname, pn.nspname, pc.relname
FROM pg_constraint k
JOIN pg_class cc ON cc.oid = k.conrelid
JOIN pg_namespace cn ON cn.oid = cc.relnamespace
JOIN pg_class pc ON pc.oid = k.confrelid
JOIN pg_namespace pn ON pn.oid = pc.relnamespace
WHERE k.contype = 'f' AND cn.nspname IN (` + inList(1, len(schemas)) + `)`
	rows, err := tx.Query(ctx, q, stringArgs(schemas)...)
	if err != nil {
		return nil, fmt.Errorf("tenantpurge: load foreign keys: %w", err)
	}
	defer rows.Close()
	var edges []FKEdge
	for rows.Next() {
		var cs, cn, ps, pn string
		if err := rows.Scan(&cs, &cn, &ps, &pn); err != nil {
			return nil, fmt.Errorf("tenantpurge: scan foreign keys: %w", err)
		}
		edges = append(edges, FKEdge{Child: TableRef{cs, cn}, Parent: TableRef{ps, pn}})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tenantpurge: load foreign keys: %w", err)
	}
	return edges, nil
}

// sweepSet is the catalog view one run works from.
type sweepSet struct {
	all     map[TableRef]*Table // every base table of the schemas (value sweep)
	ordered []*Table            // tenant-column tables in delete order
	cyclic  []TableRef
}

func buildSweepSet(ctx context.Context, tx Tx, schemas []string, extra map[string]struct{}) (*sweepSet, error) {
	all, err := loadTables(ctx, tx, schemas)
	if err != nil {
		return nil, err
	}
	edges, err := loadFKs(ctx, tx, schemas)
	if err != nil {
		return nil, err
	}
	var refs []TableRef
	for ref, t := range all {
		if len(t.TenantColumns(extra)) > 0 {
			refs = append(refs, ref)
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].String() < refs[j].String() })
	ordered, cyclic := OrderForDelete(refs, edges)
	set := &sweepSet{all: all, cyclic: cyclic}
	for _, r := range ordered {
		set.ordered = append(set.ordered, all[r])
	}
	return set, nil
}
