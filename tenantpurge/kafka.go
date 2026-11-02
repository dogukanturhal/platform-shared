// SPDX-License-Identifier: Apache-2.0

package tenantpurge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/scram"
	"go.uber.org/zap"

	"github.com/dogukanturhal/platform-shared/config"
)

const (
	retryMin = time.Second
	retryMax = 30 * time.Second
)

// buildSecurity turns the shared SASL/TLS env config into kafka-go primitives.
// It returns an error rather than a partly configured client: a bad mechanism or
// certificate must stop startup, not degrade to an unauthenticated connection.
func buildSecurity(c config.KafkaSASLConfig) (sasl.Mechanism, *tls.Config, error) {
	var mech sasl.Mechanism
	if c.SASLEnabled {
		var algo scram.Algorithm
		switch c.SASLMechanism {
		case "SCRAM-SHA-256":
			algo = scram.SHA256
		case "SCRAM-SHA-512":
			algo = scram.SHA512
		default:
			return nil, nil, fmt.Errorf("unsupported SASL mechanism: %s", c.SASLMechanism)
		}
		if c.SASLUsername == "" || c.SASLPassword == "" {
			return nil, nil, errors.New("KAFKA_SASL_ENABLED is true but username/password are empty")
		}
		m, err := scram.Mechanism(algo, c.SASLUsername, c.SASLPassword)
		if err != nil {
			return nil, nil, fmt.Errorf("create SCRAM mechanism: %w", err)
		}
		mech = m
	}
	tlsCfg, err := c.NewTLSConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("create TLS config: %w", err)
	}
	return mech, tlsCfg, nil
}

// Run consumes the command topic and publishes one ack per command until ctx is
// cancelled. A command's offset is committed only after its ack was written, so a
// crash or an ack write failure re-delivers the command (handlers are idempotent).
// A message that is not valid JSON is logged and skipped: without a run id there
// is nothing to ack, and TM's watchdog re-issues unacked commands.
func (p *Participant) Run(ctx context.Context) error {
	if len(p.cfg.Brokers) == 0 {
		return errors.New("tenantpurge: Config.Brokers is required for Run")
	}
	if err := p.cfg.SASL.Validate(); err != nil {
		return fmt.Errorf("tenantpurge: %w", err)
	}
	mech, tlsCfg, err := buildSecurity(p.cfg.SASL)
	if err != nil {
		return fmt.Errorf("tenantpurge: %w", err)
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:     p.cfg.Brokers,
		GroupID:     p.cfg.GroupID,
		Topic:       p.cfg.CommandTopic,
		MinBytes:    1,
		MaxBytes:    1 << 20,
		StartOffset: kafka.FirstOffset,
		Dialer: &kafka.Dialer{
			Timeout:       10 * time.Second,
			DualStack:     true,
			SASLMechanism: mech,
			TLS:           tlsCfg,
		},
	})
	defer reader.Close()
	writer := &kafka.Writer{
		Addr:         kafka.TCP(p.cfg.Brokers...),
		Topic:        p.cfg.AckTopic,
		Balancer:     &kafka.Hash{},
		RequiredAcks: kafka.RequireAll,
		WriteTimeout: 10 * time.Second,
		Transport:    &kafka.Transport{SASL: mech, TLS: tlsCfg},
	}
	defer writer.Close()

	p.log.Info("tenant purge consumer started", zap.String("topic", p.cfg.CommandTopic), zap.String("group", p.cfg.GroupID))
	backoff := retryMin
	for {
		msg, err := reader.FetchMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			p.log.Error("fetch purge command failed", zap.Error(err))
			if !sleepCtx(ctx, backoff) {
				return nil
			}
			backoff = nextBackoff(backoff)
			continue
		}
		backoff = retryMin

		var cmd Command
		if err := json.Unmarshal(msg.Value, &cmd); err != nil {
			p.log.Error("skipping malformed purge command", zap.Int("partition", msg.Partition), zap.Int64("offset", msg.Offset), zap.Error(err))
			p.commit(ctx, reader, msg)
			continue
		}

		ack := p.Handle(ctx, cmd)
		if ctx.Err() != nil {
			return nil // shutting down mid-phase: do not ack, the command is re-delivered
		}
		if err := p.publishAck(ctx, writer, ack); err != nil {
			return nil // ctx cancelled while retrying; offset stays uncommitted
		}
		p.commit(ctx, reader, msg)
	}
}

// publishAck writes the ack, retrying with backoff until it succeeds or ctx ends.
func (p *Participant) publishAck(ctx context.Context, w *kafka.Writer, ack Ack) error {
	val, err := json.Marshal(ack)
	if err != nil {
		return fmt.Errorf("marshal ack: %w", err) // cannot happen for these types
	}
	backoff := retryMin
	for {
		err := w.WriteMessages(ctx, kafka.Message{Key: []byte(ack.TenantID), Value: val})
		if err == nil {
			return nil
		}
		p.log.Error("publish purge ack failed", zap.String("run_id", ack.RunID), zap.Error(err))
		if !sleepCtx(ctx, backoff) {
			return ctx.Err()
		}
		backoff = nextBackoff(backoff)
	}
}

func (p *Participant) commit(ctx context.Context, r *kafka.Reader, msg kafka.Message) {
	if err := r.CommitMessages(ctx, msg); err != nil && ctx.Err() == nil {
		// A lost commit only means a re-delivery, which is idempotent.
		p.log.Warn("commit purge command offset failed", zap.Error(err))
	}
}

func nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > retryMax {
		return retryMax
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
