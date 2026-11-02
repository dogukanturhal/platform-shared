# platform-shared/outbox

Reusable Transactional Outbox implementation for Go services on the
HexxLock platform.

## What this solves

When a service needs to persist a row AND call one or more external
APIs atomically (e.g. "register a domain, then publish DNS records,
then provision a mail-server entry"), it has a **dual-write problem**:
the DB commit succeeding and the API call succeeding aren't atomic.
A naive implementation loses work on every process crash.

The Transactional Outbox pattern fixes this by:

1. Persisting the row AND a row in an `outbox` table in the **same DB
   transaction**.
2. A background worker drains pending outbox rows and executes the
   corresponding side-effect.
3. Failed side-effects are retried with exponential backoff; permanently
   failed rows go to a terminal `failed` state with an alerting metric.

See [microservices.io](https://microservices.io/patterns/data/transactional-outbox.html)
and [AWS Prescriptive Guidance](https://docs.aws.amazon.com/prescriptive-guidance/latest/cloud-design-patterns/transactional-outbox.html)
for the canonical write-ups.

## Quick start

```go
import (
    "github.com/dogukanturhal/platform-shared/outbox"
)

// 1. Provision the outbox table (in your migration tooling, OR via
//    outbox.EnsureSchema for dev/tests).
outbox.EnsureSchema(ctx, pool, "my_service_outbox")

// 2. Construct the repository — one per service-owned outbox table.
repo := outbox.NewRepository(pool, "my_service_outbox")

// 3. Define handlers — one per event_type your service emits.
registry := outbox.HandlerRegistry{
    "stripe.create_subscription": outbox.HandlerFunc(func(ctx context.Context, ev *outbox.Event) error {
        var p MyPayload
        if err := json.Unmarshal(ev.Payload, &p); err != nil { return err }
        return callStripe(ctx, p)
    }),
}

// 4. Start the worker pool.
worker := outbox.NewWorker(repo, registry, logger, outbox.WorkerOptions{})
worker.Start(ctx)
defer worker.Stop()

// 5. Enqueue from request handlers (inside an existing tx, atomically
//    with the resource INSERT).
tx, _ := pool.BeginTx(ctx, pgx.TxOptions{})
// ... INSERT resource row via tx ...
repo.Enqueue(ctx, tx, resourceID, "stripe.create_subscription", payload)
tx.Commit(ctx)
```

## Guarantees

- **At-least-once delivery** — handlers MUST be idempotent.
- **Crash-safe** — abandoned in-progress rows released after
  `AbandonedClaimAge` (default 5m).
- **Horizontal-scale safe** — `FOR UPDATE SKIP LOCKED` lets multiple
  worker pods coexist without coordination.
- **Idempotent enqueue** — `(entity_id, event_type)` UNIQUE constraint
  dedupes re-enqueues.
- **Bounded retry** — exponential backoff with jitter, capped at 15m;
  after `max_retries` (default 10) the row becomes `failed`.

## What this is NOT

- Not a general-purpose job queue (use NATS / RabbitMQ for cross-service
  pub/sub).
- Not a saga orchestrator (no compensating actions).
- Not a message bus — events are produced AND consumed by the same
  service.

## Operational concerns

- Each service owns its outbox table (not shared) so FK CASCADE works
  cleanly and operational ops (truncate / vacuum / partition) are
  independent.
- Periodic archive: delivered rows accumulate. Run a nightly
  `DELETE FROM <table> WHERE status='delivered' AND delivered_at <
  now() - interval '30 days'` (or move to cold storage).
- Alert on `outbox_events_failed_total` counter (wire via
  `WorkerOptions.OnFailed`).

## Reference implementation

The first adopter was a DNS-management service.
See `internal/services/outbox_handlers.go` there for an example of
list-before-create idempotency on a Cloudflare DNS publish handler.
