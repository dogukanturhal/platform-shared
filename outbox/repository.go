// SPDX-License-Identifier: Apache-2.0

package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository is the data-access layer for one outbox table. Stateless;
// safe to share across goroutines.
//
// Construct one Repository per outbox table at startup. The tableName
// is interpolated directly into SQL (not parameterized) — see the
// MigrationSQL comment for why this is safe when callers hard-code
// the name in their wiring.
type Repository struct {
	pool      *pgxpool.Pool
	tableName string

	// Pre-computed query strings — built once at construction so the
	// hot-path Claim doesn't fmt.Sprintf per call.
	claimQuery       string
	markDeliveredSQL string
	markFailedSQL    string
	releaseSQL       string
	listByEntitySQL  string
	resetSQL         string
	enqueueSQL       string
	getRetrySQL      string
}

// NewRepository constructs a Repository bound to the given outbox table.
// The table must already exist (call EnsureSchema or run MigrationSQL
// via migration tooling first).
func NewRepository(pool *pgxpool.Pool, tableName string) *Repository {
	if tableName == "" {
		panic("outbox.NewRepository: tableName is required")
	}
	r := &Repository{pool: pool, tableName: tableName}
	r.buildQueries()
	return r
}

func (r *Repository) buildQueries() {
	r.enqueueSQL = fmt.Sprintf(`
		INSERT INTO %s (entity_id, event_type, payload)
		VALUES ($1, $2, $3::jsonb)
		ON CONFLICT (entity_id, event_type) DO UPDATE
		    SET payload = EXCLUDED.payload,
		        updated_at = now()
		RETURNING id`, r.tableName)

	r.claimQuery = fmt.Sprintf(`
		WITH due AS (
		    SELECT id
		    FROM %s
		    WHERE status = 'pending'
		      AND next_retry_at <= now()
		    ORDER BY next_retry_at
		    FOR UPDATE SKIP LOCKED
		    LIMIT $1
		)
		UPDATE %s o
		   SET status      = 'in_progress',
		       claimed_at  = now(),
		       claimed_by  = $2,
		       updated_at  = now()
		  FROM due
		 WHERE o.id = due.id
		RETURNING o.id, o.entity_id, o.event_type, o.payload, o.status,
		          o.retry_count, o.max_retries, o.next_retry_at, o.last_error,
		          o.claimed_at, o.claimed_by, o.delivered_at, o.created_at, o.updated_at`,
		r.tableName, r.tableName)

	r.markDeliveredSQL = fmt.Sprintf(`
		UPDATE %s
		   SET status        = 'delivered',
		       delivered_at  = now(),
		       claimed_by    = NULL,
		       claimed_at    = NULL,
		       last_error    = NULL,
		       updated_at    = now()
		 WHERE id = $1`, r.tableName)

	r.markFailedSQL = fmt.Sprintf(`
		UPDATE %s
		   SET retry_count   = retry_count + 1,
		       last_error    = $2,
		       next_retry_at = $3,
		       status        = CASE
		                          WHEN retry_count + 1 >= max_retries THEN 'failed'
		                          ELSE 'pending'
		                       END,
		       claimed_by    = NULL,
		       claimed_at    = NULL,
		       updated_at    = now()
		 WHERE id = $1`, r.tableName)

	r.releaseSQL = fmt.Sprintf(`
		UPDATE %s
		   SET status        = 'pending',
		       claimed_at    = NULL,
		       claimed_by    = NULL,
		       updated_at    = now()
		 WHERE status = 'in_progress'
		   AND claimed_at < now() - $1::interval`, r.tableName)

	r.listByEntitySQL = fmt.Sprintf(`
		SELECT id, entity_id, event_type, payload, status,
		       retry_count, max_retries, next_retry_at, last_error,
		       claimed_at, claimed_by, delivered_at, created_at, updated_at
		  FROM %s
		 WHERE entity_id = $1
		 ORDER BY created_at`, r.tableName)

	r.resetSQL = fmt.Sprintf(`
		UPDATE %s
		   SET status        = 'pending',
		       retry_count   = 0,
		       next_retry_at = now(),
		       last_error    = NULL,
		       claimed_at    = NULL,
		       claimed_by    = NULL,
		       updated_at    = now()
		 WHERE entity_id = $1
		   AND status IN ('failed','pending','in_progress')`, r.tableName)

	r.getRetrySQL = fmt.Sprintf(
		`SELECT retry_count FROM %s WHERE id = $1`, r.tableName)
}

// TableName returns the table this repository is bound to. Used by
// services that need to reference the table from outside the package
// (e.g. for an operator query in a different repo).
func (r *Repository) TableName() string { return r.tableName }

// Enqueue inserts an outbox row. tx may be nil to use the pool directly.
//
// Idempotent on (entity_id, event_type): a second call with the same
// key updates the existing row's payload and returns its id; no extra
// row is created and the retry counter is preserved (so a re-enqueue
// after partial failure cannot reset the backoff window and stampede
// the upstream).
//
// payload may be nil — marshalled to an empty JSONB object in that case.
// Any json-marshallable value works (struct, map, slice).
func (r *Repository) Enqueue(
	ctx context.Context,
	tx pgx.Tx,
	entityID uuid.UUID,
	eventType string,
	payload any,
) (uuid.UUID, error) {
	if eventType == "" {
		return uuid.Nil, errors.New("outbox.Enqueue: eventType is required")
	}

	var payloadJSON []byte
	if payload == nil {
		payloadJSON = []byte("{}")
	} else if b, ok := payload.([]byte); ok {
		// Caller pre-marshalled (common in re-enqueue paths where the
		// payload is just being copied forward).
		payloadJSON = b
	} else {
		raw, err := json.Marshal(payload)
		if err != nil {
			return uuid.Nil, fmt.Errorf("outbox.Enqueue: marshal payload: %w", err)
		}
		payloadJSON = raw
	}

	var id uuid.UUID
	var err error
	if tx != nil {
		err = tx.QueryRow(ctx, r.enqueueSQL, entityID, eventType, payloadJSON).Scan(&id)
	} else {
		err = r.pool.QueryRow(ctx, r.enqueueSQL, entityID, eventType, payloadJSON).Scan(&id)
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("outbox.Enqueue(%s): %w", eventType, err)
	}
	return id, nil
}

// Claim pulls up to `limit` due+pending rows and atomically transitions
// them to in_progress stamped with workerID. FOR UPDATE SKIP LOCKED
// makes this safe across multiple worker pods.
//
// Returns claimed rows ready for handler execution. An empty slice is
// not an error — it means there's nothing due.
//
// workerID should be stable per-process (hostname + pid) so the
// abandoned-claim reaper can attribute orphans in audit logs.
func (r *Repository) Claim(
	ctx context.Context,
	workerID string,
	limit int,
) ([]*Event, error) {
	rows, err := r.pool.Query(ctx, r.claimQuery, limit, workerID)
	if err != nil {
		return nil, fmt.Errorf("outbox.Claim: %w", err)
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("outbox.Claim: scan: %w", err)
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("outbox.Claim: rows: %w", err)
	}
	return events, nil
}

// MarkDelivered marks a successfully-processed row as delivered. The row
// stays in the table (for audit + replay) — callers should run a
// periodic archive job to move delivered rows to cold storage if the
// table grows large.
func (r *Repository) MarkDelivered(ctx context.Context, id uuid.UUID) error {
	if _, err := r.pool.Exec(ctx, r.markDeliveredSQL, id); err != nil {
		return fmt.Errorf("outbox.MarkDelivered: %w", err)
	}
	return nil
}

// MarkFailed increments retry_count, records the error message, and
// schedules next_retry_at via exponential backoff with jitter:
//
//	attempt 1 → 1m  ± 25%
//	attempt 2 → 2m  ± 25%
//	attempt 3 → 4m  ± 25%
//	attempt 4 → 8m  ± 25%
//	attempt 5+ → 15m ± 25%   (capped)
//
// Once retry_count reaches max_retries, the row transitions to status
// 'failed' and stops being claimed. Services should expose a metric
// (counter on outbox_events_failed_total) for alerting.
func (r *Repository) MarkFailed(
	ctx context.Context,
	id uuid.UUID,
	handlerErr error,
) error {
	next := r.nextRetryAt(ctx, id)
	errStr := ""
	if handlerErr != nil {
		errStr = handlerErr.Error()
		const maxErrLen = 2000
		if len(errStr) > maxErrLen {
			errStr = errStr[:maxErrLen] + "...[truncated]"
		}
	}
	if _, err := r.pool.Exec(ctx, r.markFailedSQL, id, errStr, next); err != nil {
		return fmt.Errorf("outbox.MarkFailed: %w", err)
	}
	return nil
}

// ReleaseAbandoned releases in_progress rows whose claim is older than
// maxClaimAge. Returns the number of rows released.
//
// Called periodically by the worker's reaper goroutine to recover rows
// stranded by crashed/network-partitioned worker pods.
func (r *Repository) ReleaseAbandoned(
	ctx context.Context,
	maxClaimAge time.Duration,
) (int64, error) {
	res, err := r.pool.Exec(ctx, r.releaseSQL, maxClaimAge.String())
	if err != nil {
		return 0, fmt.Errorf("outbox.ReleaseAbandoned: %w", err)
	}
	return res.RowsAffected(), nil
}

// ListByEntity returns all outbox rows for an entity (any status).
// Used for operator status views ("show all events for this domain")
// and for the API rollup endpoint that surfaces provisioning progress
// back to the UI.
func (r *Repository) ListByEntity(
	ctx context.Context,
	entityID uuid.UUID,
) ([]*Event, error) {
	rows, err := r.pool.Query(ctx, r.listByEntitySQL, entityID)
	if err != nil {
		return nil, fmt.Errorf("outbox.ListByEntity: %w", err)
	}
	defer rows.Close()

	var out []*Event
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("outbox.ListByEntity: scan: %w", err)
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("outbox.ListByEntity: rows: %w", err)
	}
	return out, nil
}

// ResetForRetry flips failed / pending / in_progress rows for an entity
// back to pending+retry_count=0 so the worker picks them up immediately.
// Used by retry endpoints when an operator wants to force-retry after
// fixing an upstream issue.
//
// Returns the number of rows reset.
func (r *Repository) ResetForRetry(
	ctx context.Context,
	entityID uuid.UUID,
) (int64, error) {
	res, err := r.pool.Exec(ctx, r.resetSQL, entityID)
	if err != nil {
		return 0, fmt.Errorf("outbox.ResetForRetry: %w", err)
	}
	return res.RowsAffected(), nil
}

// ───────────────────────────────────────────────────────────────────────────
// helpers
// ───────────────────────────────────────────────────────────────────────────

func scanEvent(row pgx.Row) (*Event, error) {
	ev := &Event{}
	var status string
	var payloadRaw []byte
	err := row.Scan(
		&ev.ID, &ev.EntityID, &ev.EventType, &payloadRaw, &status,
		&ev.RetryCount, &ev.MaxRetries, &ev.NextRetryAt, &ev.LastError,
		&ev.ClaimedAt, &ev.ClaimedBy, &ev.DeliveredAt, &ev.CreatedAt, &ev.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	ev.Status = Status(status)
	ev.Payload = payloadRaw
	return ev, nil
}

// nextRetryAt computes the timestamp for the NEXT attempt using
// exponential backoff with jitter. Reads the current retry_count
// inline so the caller doesn't need to plumb the value through.
//
// Math: base = min(2^(retry_count), 15) minutes
//       jitter = uniform(-25%, +25%) × base
//       result = now + base + jitter
//
// Per "How to implement the Outbox Pattern in Go and Postgres"
// (packagemain.tech) + the jitter recommendation from AWS Architecture
// Blog "Exponential Backoff and Jitter".
func (r *Repository) nextRetryAt(ctx context.Context, id uuid.UUID) time.Time {
	var rc int
	if err := r.pool.QueryRow(ctx, r.getRetrySQL, id).Scan(&rc); err != nil {
		// Fall back to a 1-minute retry if we can't read the row
		// (highly unlikely — we just locked it). Better than crashing
		// the worker on a transient DB blip.
		return time.Now().Add(time.Minute)
	}
	// MarkFailed bumps retry_count by 1 in the same UPDATE that calls
	// us, so the effective "next attempt" index is rc+1.
	effective := rc + 1

	shift := effective - 1
	if shift < 0 {
		shift = 0
	} else if shift > 4 {
		shift = 4 // cap at 16m raw, then min() against 15m below
	}
	base := time.Duration(1<<shift) * time.Minute
	if base > 15*time.Minute {
		base = 15 * time.Minute
	}
	return time.Now().Add(base + jitter(base))
}

// jitter returns a uniformly-distributed offset in ±25% of base.
// crypto/rand isn't necessary here — jitter is a load-spreading
// heuristic, not security-sensitive.
func jitter(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	// rand/v2.Float64 returns [0, 1.0)
	r := (rand.Float64() * 2) - 1 // #nosec G404 -- retry jitter is a load-spreading heuristic, not security-sensitive; see doc comment above
	return time.Duration(r * 0.25 * float64(base))
}

// ErrNoRows is returned by ListByEntity-style queries when no rows
// match. Kept in the package's API surface (rather than letting pgx's
// own sentinel leak) so callers don't need to import pgx for the
// error check.
var ErrNoRows = errors.New("outbox: no rows")
