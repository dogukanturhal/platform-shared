-- =====================================================
-- HexxLock Platform — RLS Migration Template
-- File: platform-services/shared/database/rls_template.sql
-- =====================================================
-- Description: Reusable SQL template for enabling tenant-isolation
--              Row-Level Security (RLS) on a business module database.
--
-- Usage: This file is a Go text/template. Placeholders:
--   {{.ModuleName}}   — Human-readable module name (e.g. "Accounting")
--   {{.MigrationID}}  — Migration file name (e.g. "003_enable_rls")
--   {{.Date}}         — Migration date (e.g. "2026-02-28")
--   {{.Schema}}       — PostgreSQL schema name (e.g. "public", "invoicing", "pm")
--   {{.Tables}}       — Slice of table names that carry a tenant_id column
--   {{.EFTables}}     — Slice of EF Core managed table names (conditional, may not exist)
--
-- Generated migrations should be placed at:
--   business-modules/<module>/migrations/<id>_enable_rls.up.sql
-- The corresponding down migration is generated separately via rls_bootstrap.go.
-- =====================================================

-- =====================================================
-- {{.ModuleName}} Module — Enable Row-Level Security
-- Migration: {{.MigrationID}}.up.sql
-- Date: {{.Date}}
-- Schema: {{.Schema}}
-- =====================================================

{{- if .Tables}}
-- =====================================================
-- 1. Enable RLS on migration-managed tables
-- =====================================================
-- These tables are created by the module's initial schema migration
-- and are always present. RLS is applied unconditionally.

DO $$
DECLARE
    tbl TEXT;
    table_list TEXT[] := ARRAY[
{{- range $i, $t := .Tables}}
        '{{$t}}'{{if not (last $i $.Tables)}},{{end}}
{{- end}}
    ];
BEGIN
    FOREACH tbl IN ARRAY table_list
    LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = '{{.Schema}}'
            AND information_schema.tables.table_name = tbl
        ) THEN
            EXECUTE format('ALTER TABLE {{schemaPrefix .Schema}}%I ENABLE ROW LEVEL SECURITY', tbl);
            EXECUTE format('ALTER TABLE {{schemaPrefix .Schema}}%I FORCE ROW LEVEL SECURITY', tbl);
            EXECUTE format('DROP POLICY IF EXISTS tenant_isolation_policy ON {{schemaPrefix .Schema}}%I', tbl);
            EXECUTE format('CREATE POLICY tenant_isolation_policy ON {{schemaPrefix .Schema}}%I
                FOR ALL
                USING (tenant_id = current_setting(''app.current_tenant_id'', true)::UUID)
                WITH CHECK (tenant_id = current_setting(''app.current_tenant_id'', true)::UUID)', tbl);
            RAISE NOTICE 'RLS enabled on {{.Schema}}.%', tbl;
        ELSE
            RAISE NOTICE 'Skipping {{.Schema}}.% (does not exist)', tbl;
        END IF;
    END LOOP;
END $$;
{{- end}}

{{- if .EFTables}}
-- =====================================================
-- 2. Enable RLS on EF Core managed tables (conditional)
-- =====================================================
-- These tables are managed by EF Core and may not exist at migration
-- time. RLS is applied only if the table exists AND has a tenant_id column.

DO $$
DECLARE
    tbl TEXT;
    table_list TEXT[] := ARRAY[
{{- range $i, $t := .EFTables}}
        '{{$t}}'{{if not (last $i $.EFTables)}},{{end}}
{{- end}}
    ];
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
                EXECUTE format('ALTER TABLE {{schemaPrefix .Schema}}%I ENABLE ROW LEVEL SECURITY', tbl);
                EXECUTE format('ALTER TABLE {{schemaPrefix .Schema}}%I FORCE ROW LEVEL SECURITY', tbl);
                EXECUTE format('DROP POLICY IF EXISTS tenant_isolation_policy ON {{schemaPrefix .Schema}}%I', tbl);
                EXECUTE format('CREATE POLICY tenant_isolation_policy ON {{schemaPrefix .Schema}}%I
                    FOR ALL
                    USING (tenant_id = current_setting(''app.current_tenant_id'', true)::UUID)
                    WITH CHECK (tenant_id = current_setting(''app.current_tenant_id'', true)::UUID)', tbl);
                RAISE NOTICE 'RLS enabled on {{.Schema}}.% (EF-managed)', tbl;
            ELSE
                RAISE NOTICE 'Skipping {{.Schema}}.% (no tenant_id column)', tbl;
            END IF;
        ELSE
            RAISE NOTICE 'Skipping {{.Schema}}.% (does not exist yet — EF-managed)', tbl;
        END IF;
    END LOOP;
END $$;
{{- end}}

-- =====================================================
-- {{if .EFTables}}3{{else}}2{{end}}. Ensure tenant_id indexes exist for RLS performance
-- =====================================================
-- RLS policies that filter on tenant_id require a supporting index to
-- avoid sequential scans on every query. We create one if missing.

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
            AND indexname LIKE '%tenant_id%'
        ) THEN
            EXECUTE format(
                'CREATE INDEX IF NOT EXISTS idx_%I_tenant_id ON {{schemaPrefix .Schema}}%I(tenant_id)',
                r.table_name, r.table_name
            );
            RAISE NOTICE 'Created missing tenant_id index on {{.Schema}}.%', r.table_name;
        END IF;
    END LOOP;
END $$;
