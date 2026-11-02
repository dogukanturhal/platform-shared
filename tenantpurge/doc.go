// SPDX-License-Identifier: Apache-2.0

// Package tenantpurge is the participant side of the tenant-purge saga.
//
// tenant-management (TM) drives a purge run over two Kafka topics:
//
//	example.tenant.purge.command  TM -> services  {run_id, tenant_id, kind, phase, attempt, statutory_override}
//	example.tenant.purge.ack      services -> TM  {run_id, tenant_id, service, phase, status, counts, retained, external, error}
//
// Phases a participant handles are plan (dry-run counts and blockers), quiesce
// (stop external activity) and erase (delete the data). The finalize phase runs
// inside TM only.
//
// # Wiring
//
//	p, err := tenantpurge.New(tenantpurge.Config{
//		Service: "billing",
//		DB:      tenantpurge.NewPgxDB(pool),   // or NewSQLDB(*sql.DB)
//		Schemas: []string{"public"},
//		Retain: []tenantpurge.Retain{{
//			Table: "our_invoices", Where: "status <> 'draft'",
//			Basis: "VUK 253: issued invoices kept 10 years (HexxLock is the issuer)",
//		}},
//		Hooks:   myHooks{},                    // embed tenantpurge.NopHooks
//		Brokers: brokers,
//		SASL:    config.LoadKafkaSASLConfig(),
//		Logger:  logger,
//	})
//	go p.Run(ctx)
//
// # Guarantees
//
//   - Protected tenant ids (see ProtectedTenantIDs) are refused before any work.
//   - The sweep is catalog driven: every base table in Config.Schemas that has a
//     tenant-like column is deleted in foreign-key order inside one transaction
//     that carries app.current_tenant_id (so FORCE RLS does not hide rows) and
//     app.tenant_purge='on' (so immutability triggers allow the delete).
//   - Before commit a value sweep looks for the tenant id in every uuid, text and
//     json column of every table in the schemas. Anything left except the declared
//     Retain rows rolls the transaction back and the ack is failed.
//   - Everything is idempotent: deletes of nothing succeed, and an external
//     "not found" outcome counts as ok.
//
// Child tables that have no tenant column and no ON DELETE CASCADE make the
// delete fail loudly (FK violation, whole transaction rolled back). Fix those
// in the service's own migration; the library never guesses.
package tenantpurge
