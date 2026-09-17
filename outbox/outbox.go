// SPDX-License-Identifier: Apache-2.0

// Package outbox provides a reusable Transactional Outbox implementation
// for Go services that need to coordinate a local DB write with one or
// more external side-effects (API calls, message-broker publishes, etc).
//
// This is the canonical pattern documented at:
//   - https://microservices.io/patterns/data/transactional-outbox.html
//   - https://docs.aws.amazon.com/prescriptive-guidance/latest/cloud-design-patterns/transactional-outbox.html
//
// # Why this package exists
//
// Every service in the HexxLock platform that registers a tenant resource
// (a domain, a notification, a subscription, a webhook subscription)
// faces the same dual-write problem: persist the resource AND fire one or
// more downstream side-effects, atomically. Pre-this-package each service
// rolled its own ad-hoc solution (fire-and-forget goroutines, blocking
// inline calls, retry-on-next-request patterns) — all of which lose work
// on process crashes or wedge the request path on upstream flap.
//
// # Usage
//
// Each adopting service:
//
//  1. Creates its own outbox table by running outbox.MigrationSQL(tableName)
//     against its DB (see internal/services/outbox_worker.go in the
//     domain-management service for a concrete example).
//  2. Constructs a Repository for that table:
//
//	repo := outbox.NewRepository(pool, "my_service_outbox")
//
//  3. Defines handlers — one per event_type — implementing the Handler
//     interface (or wrap a func via HandlerFunc).
//  4. Constructs and starts a Worker:
//
//	worker := outbox.NewWorker(repo, registry, logger, outbox.WorkerOptions{})
//	worker.Start(ctx)
//	defer worker.Stop()
//
//  5. From request handlers, enqueue events inside the same pgx.Tx as the
//     local resource INSERT:
//
//	tx, _ := pool.BeginTx(ctx, pgx.TxOptions{})
//	// INSERT resource row via tx...
//	repo.Enqueue(ctx, tx, resourceID, "send.email", payload)
//	tx.Commit(ctx)
//
// # What this package is NOT
//
//   - Not a general-purpose job queue (use a real broker if you need
//     priorities, fan-out, or cross-service routing).
//   - Not a saga orchestrator (no compensating actions; failed events
//     just retry with backoff or end up in 'failed' status).
//   - Not a message bus (events never leave the service that enqueued
//     them — they're processed by THIS service's workers).
//
// # Guarantees
//
//   - At-least-once delivery: handlers MUST be idempotent.
//   - FIFO per (entity_id, event_type): the UNIQUE constraint dedupes
//     re-enqueues onto the same row, but ordering across different keys
//     is best-effort (worker pool picks earliest-due first).
//   - Distributed-safe: multiple worker pods coexist via
//     FOR UPDATE SKIP LOCKED on Claim.
//   - Crash-safe: rows mid-handler (status=in_progress) released back
//     to pending by the reaper after AbandonedClaimAge.
package outbox

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Status enumerates the lifecycle of an outbox event.
type Status string

const (
	// StatusPending — ready for a worker to claim.
	StatusPending Status = "pending"

	// StatusInProgress — claimed by a worker but handler hasn't
	// returned yet.
	StatusInProgress Status = "in_progress"

	// StatusDelivered — handler returned nil; terminal.
	StatusDelivered Status = "delivered"

	// StatusFailed — exceeded max_retries; terminal. Fires alert.
	StatusFailed Status = "failed"
)

// Event is the in-memory view of one outbox row. Services usually don't
// construct this directly — Repository.Enqueue takes (entityID, eventType,
// payload) and the worker pulls Events back out via Claim.
type Event struct {
	ID          uuid.UUID
	EntityID    uuid.UUID
	EventType   string
	Payload     []byte // raw JSONB; handlers Unmarshal into their own struct
	Status      Status
	RetryCount  int
	MaxRetries  int
	NextRetryAt time.Time
	LastError   *string
	ClaimedAt   *time.Time
	ClaimedBy   *string
	DeliveredAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Handler executes one outbox event. Returning nil marks the event
// delivered; returning a non-nil error schedules a retry with
// exponential backoff (or marks failed if retry budget is exhausted).
//
// Handlers MUST be idempotent — the at-least-once contract means a
// handler that succeeds but crashes before MarkDelivered will re-run
// on the next claim.
//
// The context carries a per-handler timeout set by the worker
// (WorkerOptions.HandlerTimeout, default 60s). Handlers should respect
// it for any blocking I/O.
type Handler interface {
	Handle(ctx context.Context, ev *Event) error
}

// HandlerFunc is the function-adapter for Handler — lets services
// register plain functions instead of struct receivers.
type HandlerFunc func(ctx context.Context, ev *Event) error

// Handle satisfies the Handler interface.
func (f HandlerFunc) Handle(ctx context.Context, ev *Event) error { return f(ctx, ev) }

// HandlerRegistry maps event_type strings to handlers. Built once at
// startup and shared (read-only) across worker goroutines.
//
// An event whose event_type is not in the registry will be marked
// failed on first claim with a clear "no handler" error — protects
// against typo'd event types silently spinning forever.
type HandlerRegistry map[string]Handler
