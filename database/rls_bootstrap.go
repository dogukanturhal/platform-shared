// SPDX-License-Identifier: Apache-2.0

package database

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"strings"
	"text/template"
	"time"
)

// RLSMigrationParams holds the parameters required to generate an RLS migration
// for a single database schema.
type RLSMigrationParams struct {
	// ModuleName is the human-readable module name used in SQL comments.
	// Example: "Accounting", "Inventory", "CMMS"
	ModuleName string

	// MigrationID is the migration file base name without extension.
	// Example: "003_enable_rls"
	MigrationID string

	// Date is the migration date string inserted into the file header.
	// Defaults to today (YYYY-MM-DD) if empty.
	Date string

	// Schema is the PostgreSQL schema where the tables live.
	// Use "public" for modules that do not define a custom schema.
	// Example: "public", "invoicing", "pm"
	Schema string

	// Tables is the list of tables that are created by SQL migrations and are
	// guaranteed to exist when this RLS migration runs. RLS is applied
	// unconditionally for these tables (with an existence guard for safety).
	Tables []string

	// EFTables is the list of tables managed by Entity Framework Core that may
	// or may not exist at the time the RLS migration executes. RLS is applied
	// conditionally — only if the table exists AND has a tenant_id column.
	EFTables []string
}

// upTemplate is the SQL template for the .up migration.
// It uses Go text/template syntax. The schemaPrefix helper produces
// an empty string for "public" and "schema." for all other schemas,
// matching the idiomatic PostgreSQL approach of omitting the schema
// qualifier for the default search_path schema.
const upTemplate = `-- =====================================================
-- {{.ModuleName}} Module — Enable Row-Level Security
-- Migration: {{.MigrationID}}.up.sql
-- =====================================================
-- Description: Enables RLS on all tenant-scoped {{.ModuleName}} tables to
--              provide database-level tenant isolation. The policy enforces:
--
--                tenant_id = current_setting('app.current_tenant_id', true)::UUID
--
--              This requires the application to SET LOCAL app.current_tenant_id
--              at the start of each request (handled by shared RLSMiddleware).
-- Date: {{.Date}}
-- Schema: {{.Schema}}
-- =====================================================
{{if .Tables}}
-- =====================================================
-- 1. Enable RLS on migration-managed tables
-- =====================================================

DO $$
DECLARE
    tbl TEXT;
    table_list TEXT[] := ARRAY[{{range $i, $t := .Tables}}{{if $i}}, {{end}}'{{$t}}'{{end}}];
BEGIN
    FOREACH tbl IN ARRAY table_list
    LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = '{{.Schema}}'
            AND information_schema.tables.table_name = tbl
        ) THEN
            EXECUTE format('ALTER TABLE {{schemaPrefix .Schema}}%%I ENABLE ROW LEVEL SECURITY', tbl);
            EXECUTE format('ALTER TABLE {{schemaPrefix .Schema}}%%I FORCE ROW LEVEL SECURITY', tbl);
            EXECUTE format('DROP POLICY IF EXISTS tenant_isolation_policy ON {{schemaPrefix .Schema}}%%I', tbl);
            EXECUTE format('CREATE POLICY tenant_isolation_policy ON {{schemaPrefix .Schema}}%%I
                FOR ALL
                USING (tenant_id = current_setting(''app.current_tenant_id'', true)::UUID)
                WITH CHECK (tenant_id = current_setting(''app.current_tenant_id'', true)::UUID)', tbl);
            RAISE NOTICE 'RLS enabled on {{.Schema}}.%%', tbl;
        ELSE
            RAISE NOTICE 'Skipping {{.Schema}}.%% (does not exist)', tbl;
        END IF;
    END LOOP;
END $$;
{{end}}{{if .EFTables}}
-- =====================================================
-- 2. Enable RLS on EF Core managed tables (conditional)
-- =====================================================
-- These tables may not exist at migration time. Applied only if the table
-- exists AND has a tenant_id column.

DO $$
DECLARE
    tbl TEXT;
    table_list TEXT[] := ARRAY[{{range $i, $t := .EFTables}}{{if $i}}, {{end}}'{{$t}}'{{end}}];
BEGIN
    FOREACH tbl IN ARRAY table_list
    LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = '{{.Schema}}'
            AND information_schema.tables.table_name = tbl
        ) THEN
            IF EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = '{{.Schema}}'
                AND table_name = tbl
                AND column_name = 'tenant_id'
            ) THEN
                EXECUTE format('ALTER TABLE {{schemaPrefix .Schema}}%%I ENABLE ROW LEVEL SECURITY', tbl);
                EXECUTE format('ALTER TABLE {{schemaPrefix .Schema}}%%I FORCE ROW LEVEL SECURITY', tbl);
                EXECUTE format('DROP POLICY IF EXISTS tenant_isolation_policy ON {{schemaPrefix .Schema}}%%I', tbl);
                EXECUTE format('CREATE POLICY tenant_isolation_policy ON {{schemaPrefix .Schema}}%%I
                    FOR ALL
                    USING (tenant_id = current_setting(''app.current_tenant_id'', true)::UUID)
                    WITH CHECK (tenant_id = current_setting(''app.current_tenant_id'', true)::UUID)', tbl);
                RAISE NOTICE 'RLS enabled on {{.Schema}}.%% (EF-managed)', tbl;
            ELSE
                RAISE NOTICE 'Skipping {{.Schema}}.%% (no tenant_id column)', tbl;
            END IF;
        ELSE
            RAISE NOTICE 'Skipping {{.Schema}}.%% (does not exist yet — EF-managed)', tbl;
        END IF;
    END LOOP;
END $$;
{{end}}
-- =====================================================
-- {{if .EFTables}}3{{else}}2{{end}}. Ensure tenant_id indexes exist for RLS performance
-- =====================================================

DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT table_name
        FROM information_schema.columns
        WHERE table_schema = '{{.Schema}}'
        AND column_name = 'tenant_id'
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_indexes
            WHERE schemaname = '{{.Schema}}'
            AND tablename = r.table_name
            AND indexname LIKE '%%tenant_id%%'
        ) THEN
            EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_%%I_tenant_id ON {{schemaPrefix .Schema}}%%I(tenant_id)',
                r.table_name, r.table_name
            );
            RAISE NOTICE 'Created missing tenant_id index on {{.Schema}}.%%', r.table_name;
        END IF;
    END LOOP;
END $$;
`

// downTemplate is the SQL template for the .down rollback migration.
const downTemplate = `-- =====================================================
-- {{.ModuleName}} Module — Disable Row-Level Security
-- Migration: {{.MigrationID}}.down.sql
-- =====================================================
-- Description: Rolls back RLS on all tenant-scoped {{.ModuleName}} tables.
--              Drops tenant isolation policies and disables RLS enforcement.
-- Date: {{.Date}}
-- WARNING: Disabling RLS removes database-level tenant isolation.
--          Only use this rollback in controlled environments.
-- =====================================================

DO $$
DECLARE
    tbl TEXT;
    table_list TEXT[] := ARRAY[{{range $i, $t := .AllTables}}{{if $i}}, {{end}}'{{$t}}'{{end}}];
BEGIN
    FOREACH tbl IN ARRAY table_list
    LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = '{{.Schema}}'
            AND information_schema.tables.table_name = tbl
        ) THEN
            EXECUTE format('DROP POLICY IF EXISTS tenant_isolation_policy ON {{schemaPrefix .Schema}}%%I', tbl);
            EXECUTE format('ALTER TABLE {{schemaPrefix .Schema}}%%I NO FORCE ROW LEVEL SECURITY', tbl);
            EXECUTE format('ALTER TABLE {{schemaPrefix .Schema}}%%I DISABLE ROW LEVEL SECURITY', tbl);
            RAISE NOTICE 'RLS disabled on {{.Schema}}.%%', tbl;
        END IF;
    END LOOP;
END $$;
`

// templateData is the data passed to both up and down templates.
type templateData struct {
	RLSMigrationParams
	// AllTables is Tables + EFTables, used by the down template.
	AllTables []string
}

// schemaPrefix returns an empty string for the "public" schema (which is
// always in the default search_path), and "schema." for all others so that
// the generated SQL correctly qualifies schema-prefixed tables.
func schemaPrefix(schema string) string {
	if schema == schemaPublic || schema == "" {
		return ""
	}
	return schema + "."
}

var tmplFuncs = template.FuncMap{
	"schemaPrefix": schemaPrefix,
}

// GenerateRLSMigration produces the up and down SQL migration strings for
// enabling tenant-isolation RLS on the given set of tables.
//
// Parameters:
//   - params.Tables    — tables created by SQL migrations (always exist)
//   - params.EFTables  — tables managed by EF Core (conditional guards applied)
//
// Returns (upSQL, downSQL, error).
func GenerateRLSMigration(params RLSMigrationParams) (up string, down string, err error) {
	if params.Date == "" {
		params.Date = time.Now().Format("2006-01-02")
	}
	if params.Schema == "" {
		params.Schema = schemaPublic
	}

	allTables := make([]string, 0, len(params.Tables)+len(params.EFTables))
	allTables = append(allTables, params.Tables...)
	allTables = append(allTables, params.EFTables...)

	data := templateData{
		RLSMigrationParams: params,
		AllTables:          allTables,
	}

	upSQL, err := renderTemplate("rls_up", upTemplate, data)
	if err != nil {
		return "", "", fmt.Errorf("rendering up template for %s: %w", params.ModuleName, err)
	}

	downSQL, err := renderTemplate("rls_down", downTemplate, data)
	if err != nil {
		return "", "", fmt.Errorf("rendering down template for %s: %w", params.ModuleName, err)
	}

	return upSQL, downSQL, nil
}

func renderTemplate(name, tmplStr string, data templateData) (string, error) {
	t, err := template.New(name).Funcs(tmplFuncs).Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("parsing template %q: %w", name, err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("executing template %q: %w", name, err)
	}
	return buf.String(), nil
}

// DiscoverTenantTables queries the information_schema of the given database
// connection to find all tables in the specified schema that have a tenant_id
// column. This is useful for automatically building the table list when
// onboarding a new module into the RLS bootstrap process.
//
// The returned slice is sorted alphabetically for deterministic output.
//
// Usage:
//
//	db, _ := sql.Open("postgres", dsn)
//	tables, err := DiscoverTenantTables(ctx, db, "public")
func DiscoverTenantTables(ctx context.Context, db *sql.DB, schema string) ([]string, error) {
	if schema == "" {
		schema = "public"
	}

	const query = `
		SELECT table_name
		FROM information_schema.columns
		WHERE table_schema = $1
		  AND column_name = 'tenant_id'
		ORDER BY table_name ASC
	`

	rows, err := db.QueryContext(ctx, query, schema)
	if err != nil {
		return nil, fmt.Errorf("querying tenant tables in schema %q: %w", schema, err)
	}
	defer func() { _ = rows.Close() }()

	var tables []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}
		tables = append(tables, tableName)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	return tables, nil
}

// DiscoverRLSStatus returns a map of table name to whether RLS is currently
// enabled on that table. This is useful for auditing which tables in a schema
// have RLS enabled vs. still need it.
//
// Usage:
//
//	status, err := DiscoverRLSStatus(ctx, db, "public")
//	for table, enabled := range status {
//	    fmt.Printf("%s: RLS=%v\n", table, enabled)
//	}
func DiscoverRLSStatus(ctx context.Context, db *sql.DB, schema string) (map[string]bool, error) {
	if schema == "" {
		schema = "public"
	}

	const query = `
		SELECT c.relname, c.relrowsecurity
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1
		  AND c.relkind = 'r'
		ORDER BY c.relname ASC
	`

	rows, err := db.QueryContext(ctx, query, schema)
	if err != nil {
		return nil, fmt.Errorf("querying RLS status for schema %q: %w", schema, err)
	}
	defer func() { _ = rows.Close() }()

	status := make(map[string]bool)
	for rows.Next() {
		var tableName string
		var rlsEnabled bool
		if err := rows.Scan(&tableName, &rlsEnabled); err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}
		status[tableName] = rlsEnabled
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	return status, nil
}

// MissingRLSTables returns the list of tables in the given schema that have a
// tenant_id column but do NOT yet have RLS enabled. This is the primary
// entrypoint for RLS compliance auditing.
//
// Usage:
//
//	missing, err := MissingRLSTables(ctx, db, "public")
//	if len(missing) > 0 {
//	    log.Printf("WARNING: %d tables missing RLS: %s", len(missing), strings.Join(missing, ", "))
//	}
func MissingRLSTables(ctx context.Context, db *sql.DB, schema string) ([]string, error) {
	tenantTables, err := DiscoverTenantTables(ctx, db, schema)
	if err != nil {
		return nil, err
	}

	rlsStatus, err := DiscoverRLSStatus(ctx, db, schema)
	if err != nil {
		return nil, err
	}

	var missing []string
	for _, table := range tenantTables {
		if enabled, found := rlsStatus[table]; !found || !enabled {
			missing = append(missing, table)
		}
	}
	return missing, nil
}

// FormatTableList formats a slice of table names as a PostgreSQL ARRAY literal
// for use in generated SQL. This is a convenience helper for building migration
// files programmatically.
//
// Example:
//
//	FormatTableList([]string{"accounts", "journal_entries"})
//	// Returns: "ARRAY['accounts', 'journal_entries']"
func FormatTableList(tables []string) string {
	if len(tables) == 0 {
		return "ARRAY[]::TEXT[]"
	}
	quoted := make([]string, len(tables))
	for i, t := range tables {
		quoted[i] = "'" + t + "'"
	}
	return "ARRAY[" + strings.Join(quoted, ", ") + "]"
}
