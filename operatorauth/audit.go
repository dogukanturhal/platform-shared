// SPDX-License-Identifier: Apache-2.0

package operatorauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/segmentio/kafka-go"

	"github.com/dogukanturhal/platform-shared/outbox"
)

const (
	// AuditTopic is the Kafka topic every service publishes operator audit
	// events to; falcon-id consumes it into platform_admin_audit_log.
	AuditTopic = "platform.ops-audit.v1"
	// AuditEventType is the outbox event_type of an audit event. Register
	// AuditHandler under it in the service's outbox HandlerRegistry.
	AuditEventType = "ops.audit"
)

// AuditEvent is one operator action. The JSON shape is the wire format
// falcon-id's internal/opsaudit consumer decodes; keep them in sync.
type AuditEvent struct {
	EventID       uuid.UUID       `json:"event_id"`
	OccurredAt    time.Time       `json:"occurred_at"`
	SourceService string          `json:"source_service"`
	ActorUserID   uuid.UUID       `json:"actor_user_id"`
	ActorEmail    string          `json:"actor_email,omitempty"`
	ElevationID   string          `json:"elevation_id,omitempty"`
	ApprovalID    string          `json:"approval_id,omitempty"`
	Action        string          `json:"action"`
	TenantID      string          `json:"tenant_id,omitempty"`
	Resource      string          `json:"resource,omitempty"`
	ReasonCode    string          `json:"reason_code,omitempty"`
	Reason        string          `json:"reason,omitempty"`
	RequestID     string          `json:"request_id,omitempty"`
	BeforeHash    string          `json:"before_hash,omitempty"`
	AfterHash     string          `json:"after_hash,omitempty"`
	Success       bool            `json:"success"`
	IPAddress     string          `json:"ip_address,omitempty"`
	UserAgent     string          `json:"user_agent,omitempty"`
	Details       json.RawMessage `json:"details,omitempty"`
	// ApprovalMode is "four_eyes" or "platform_admin_bypass" (see RequireApproval).
	ApprovalMode string `json:"approval_mode,omitempty"`
}

// NewAuditEvent starts an event for action from the verified operator in c
// (actor, elevation, request id, client ip, user agent). The caller adds the
// target, reason, hashes and Success. Returns ok=false when c carries no
// verified operator, so an unauthenticated path can never emit as a person.
func NewAuditEvent(c *gin.Context, action string) (AuditEvent, bool) {
	actor := ActorFrom(c)
	if actor == nil {
		return AuditEvent{}, false
	}
	return AuditEvent{
		EventID:      uuid.New(),
		OccurredAt:   time.Now().UTC(),
		ActorUserID:  actor.UserID,
		ActorEmail:   actor.Email,
		ElevationID:  actor.ElevationID,
		Action:       action,
		RequestID:    c.GetHeader("X-Request-ID"),
		IPAddress:    c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
		ApprovalMode: ApprovalModeFrom(c),
	}, true
}

// WithReason copies a validated reason onto the event.
func (e AuditEvent) WithReason(r Reason) AuditEvent {
	e.ReasonCode, e.Reason = string(r.Code), r.Text
	return e
}

// HashJSON returns the hex sha256 of v's JSON encoding, for before/after
// hashes (the audit row stores hashes, not the data).
func HashJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Emitter publishes an audit event. tx may be nil (autocommit); pass the
// handler's transaction to make the audit record atomic with the change.
type Emitter interface {
	Emit(ctx context.Context, tx pgx.Tx, ev AuditEvent) error
}

// OutboxEmitter enqueues events into the service's transactional outbox.
type OutboxEmitter struct {
	repo   *outbox.Repository
	source string
}

// NewOutboxEmitter builds an emitter writing to repo (the service's own
// outbox table) and stamping source_service.
func NewOutboxEmitter(repo *outbox.Repository, sourceService string) (*OutboxEmitter, error) {
	if repo == nil || sourceService == "" {
		return nil, errors.New("operatorauth: outbox repository and source service are required")
	}
	return &OutboxEmitter{repo: repo, source: sourceService}, nil
}

// Emit enqueues ev. Idempotent on EventID.
func (o *OutboxEmitter) Emit(ctx context.Context, tx pgx.Tx, ev AuditEvent) error {
	if ev.EventID == uuid.Nil {
		ev.EventID = uuid.New()
	}
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = time.Now().UTC()
	}
	if ev.ActorUserID == uuid.Nil || ev.Action == "" {
		return errors.New("operatorauth: audit event needs an actor and an action")
	}
	ev.SourceService = o.source
	if _, err := o.repo.Enqueue(ctx, tx, ev.EventID, AuditEventType, ev); err != nil {
		return fmt.Errorf("operatorauth: enqueue audit event: %w", err)
	}
	return nil
}

// MessageWriter is the slice of *kafka.Writer AuditHandler needs.
type MessageWriter interface {
	WriteMessages(ctx context.Context, msgs ...kafka.Message) error
}

// AuditHandler returns the outbox handler that publishes audit events to
// AuditTopic. The writer must be configured for that topic (Writer.Topic) and
// RequiredAcks all. Register: registry[operatorauth.AuditEventType] = h.
func AuditHandler(w MessageWriter) outbox.Handler {
	return outbox.HandlerFunc(func(ctx context.Context, ev *outbox.Event) error {
		var ae AuditEvent
		if err := json.Unmarshal(ev.Payload, &ae); err != nil {
			return fmt.Errorf("operatorauth: decode audit payload: %w", err)
		}
		key := ae.TenantID
		if key == "" {
			key = ae.ActorUserID.String()
		}
		return w.WriteMessages(ctx, kafka.Message{Key: []byte(key), Value: ev.Payload})
	})
}
