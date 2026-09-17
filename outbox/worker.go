// SPDX-License-Identifier: Apache-2.0

package outbox

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"go.uber.org/zap"
)

// WorkerOptions configures a Worker. Zero values get sane defaults so
// `outbox.WorkerOptions{}` is the happy-path constructor argument.
type WorkerOptions struct {
	// PollInterval — how often each worker goroutine attempts to claim
	// new work. Default: 1 second. Lower = near-realtime pickup, but
	// hammers the DB at idle. Higher = lower DB load, more latency.
	PollInterval time.Duration

	// ClaimBatch — max rows pulled per claim. Default: 10.
	ClaimBatch int

	// WorkerCount — goroutine pool size. Default: runtime.NumCPU().
	// I/O-bound workloads can safely set this higher (e.g. 32) if
	// the upstream supports parallelism.
	WorkerCount int

	// AbandonedClaimAge — how long an in_progress row can stay claimed
	// before the reaper releases it. Default: 5 minutes. Must exceed
	// the longest expected HandlerTimeout.
	AbandonedClaimAge time.Duration

	// ReaperInterval — how often the abandoned-claim sweeper runs.
	// Default: 60 seconds.
	ReaperInterval time.Duration

	// HandlerTimeout — caps the runtime of a single handler invocation.
	// Default: 60 seconds. Prevents a stuck upstream from holding a
	// worker goroutine forever.
	HandlerTimeout time.Duration

	// WorkerIDPrefix — prepended to "<hostname>/pid=<pid>" in
	// claimed_by. Useful when running multiple worker pools in the
	// same process (e.g. one per service domain). Default: empty.
	WorkerIDPrefix string

	// OnDelivered — optional callback fired after MarkDelivered. Useful
	// for metrics / tracing. Errors swallowed.
	OnDelivered func(ev *Event, elapsed time.Duration)

	// OnFailed — optional callback fired after MarkFailed. Useful for
	// alerting metrics. Errors swallowed.
	OnFailed func(ev *Event, err error, elapsed time.Duration)
}

func (o *WorkerOptions) applyDefaults() {
	if o.PollInterval <= 0 {
		o.PollInterval = time.Second
	}
	if o.ClaimBatch <= 0 {
		o.ClaimBatch = 10
	}
	if o.WorkerCount <= 0 {
		o.WorkerCount = runtime.NumCPU()
	}
	if o.AbandonedClaimAge <= 0 {
		o.AbandonedClaimAge = 5 * time.Minute
	}
	if o.ReaperInterval <= 0 {
		o.ReaperInterval = 60 * time.Second
	}
	if o.HandlerTimeout <= 0 {
		o.HandlerTimeout = 60 * time.Second
	}
}

// Worker drains an outbox table via a pool of goroutines that compete
// for due rows via FOR UPDATE SKIP LOCKED. See package doc for the full
// architecture.
//
// One Worker per outbox table (= per adopting service domain). Multiple
// service-level workers can run in the same process when a service has
// more than one outbox table (rare).
type Worker struct {
	repo     *Repository
	registry HandlerRegistry
	logger   *zap.Logger
	opts     WorkerOptions
	workerID string

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewWorker constructs a Worker. Call Start to launch the pool; Stop
// drains the pool on shutdown (blocks until all in-flight handlers
// complete or HandlerTimeout fires).
//
// registry MUST contain a handler for every event_type the service can
// enqueue — events with no registered handler are marked failed
// immediately rather than spinning forever.
func NewWorker(
	repo *Repository,
	registry HandlerRegistry,
	logger *zap.Logger,
	opts WorkerOptions,
) *Worker {
	opts.applyDefaults()
	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}
	wid := fmt.Sprintf("%s/pid=%d", host, os.Getpid())
	if opts.WorkerIDPrefix != "" {
		wid = opts.WorkerIDPrefix + "/" + wid
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Worker{
		repo:     repo,
		registry: registry,
		logger:   logger,
		opts:     opts,
		workerID: wid,
	}
}

// Start launches the worker pool + the abandoned-claim reaper. Returns
// immediately; goroutines run until Stop or ctx cancellation.
func (w *Worker) Start(ctx context.Context) {
	ctx, w.cancel = context.WithCancel(ctx)

	w.logger.Info("Outbox worker pool starting",
		zap.String("table", w.repo.TableName()),
		zap.Int("worker_count", w.opts.WorkerCount),
		zap.Duration("poll_interval", w.opts.PollInterval),
		zap.Int("claim_batch", w.opts.ClaimBatch),
		zap.Duration("handler_timeout", w.opts.HandlerTimeout),
		zap.String("worker_id", w.workerID),
	)

	for i := 0; i < w.opts.WorkerCount; i++ {
		w.wg.Add(1)
		go w.runWorker(ctx, i)
	}

	w.wg.Add(1)
	go w.runReaper(ctx)
}

// Stop signals the worker pool to exit and waits for in-flight handlers
// to drain. Safe to call multiple times.
func (w *Worker) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
	w.wg.Wait()
	w.logger.Info("Outbox worker pool stopped",
		zap.String("table", w.repo.TableName()))
}

func (w *Worker) runWorker(ctx context.Context, idx int) {
	defer w.wg.Done()

	ticker := time.NewTicker(w.opts.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.drainOnce(ctx, idx)
		}
	}
}

func (w *Worker) drainOnce(ctx context.Context, workerIdx int) {
	events, err := w.repo.Claim(ctx, w.workerID, w.opts.ClaimBatch)
	if err != nil {
		w.logger.Warn("Outbox claim failed",
			zap.String("table", w.repo.TableName()),
			zap.Int("worker_idx", workerIdx),
			zap.Error(err))
		return
	}
	for _, ev := range events {
		w.process(ctx, ev)
	}
}

func (w *Worker) process(parentCtx context.Context, ev *Event) {
	handler, ok := w.registry[ev.EventType]
	if !ok {
		w.logger.Error("No handler registered for outbox event_type",
			zap.String("table", w.repo.TableName()),
			zap.String("event_type", ev.EventType),
			zap.String("event_id", ev.ID.String()))
		err := fmt.Errorf("no handler for event_type=%q", ev.EventType)
		_ = w.repo.MarkFailed(parentCtx, ev.ID, err)
		w.fireOnFailed(ev, err, 0)
		return
	}

	ctx, cancel := context.WithTimeout(parentCtx, w.opts.HandlerTimeout)
	defer cancel()

	start := time.Now()
	handlerErr := handler.Handle(ctx, ev)
	elapsed := time.Since(start)

	if handlerErr != nil {
		w.logger.Warn("Outbox handler failed; will retry",
			zap.String("table", w.repo.TableName()),
			zap.String("event_id", ev.ID.String()),
			zap.String("event_type", ev.EventType),
			zap.String("entity_id", ev.EntityID.String()),
			zap.Int("retry_count", ev.RetryCount),
			zap.Duration("elapsed", elapsed),
			zap.Error(handlerErr),
		)
		if err := w.repo.MarkFailed(parentCtx, ev.ID, handlerErr); err != nil {
			w.logger.Error("Outbox MarkFailed itself failed — row stays in_progress until reaper",
				zap.String("event_id", ev.ID.String()),
				zap.Error(err))
		}
		w.fireOnFailed(ev, handlerErr, elapsed)
		return
	}

	if err := w.repo.MarkDelivered(parentCtx, ev.ID); err != nil {
		w.logger.Error("Outbox MarkDelivered failed — handler will re-run after reaper",
			zap.String("event_id", ev.ID.String()),
			zap.Error(err))
		return
	}

	w.logger.Info("Outbox event delivered",
		zap.String("table", w.repo.TableName()),
		zap.String("event_id", ev.ID.String()),
		zap.String("event_type", ev.EventType),
		zap.String("entity_id", ev.EntityID.String()),
		zap.Duration("elapsed", elapsed),
	)
	w.fireOnDelivered(ev, elapsed)
}

func (w *Worker) runReaper(ctx context.Context) {
	defer w.wg.Done()

	ticker := time.NewTicker(w.opts.ReaperInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := w.repo.ReleaseAbandoned(ctx, w.opts.AbandonedClaimAge)
			if err != nil {
				w.logger.Warn("Outbox reaper failed",
					zap.String("table", w.repo.TableName()),
					zap.Error(err))
				continue
			}
			if n > 0 {
				w.logger.Info("Outbox reaper released abandoned claims",
					zap.String("table", w.repo.TableName()),
					zap.Int64("count", n),
					zap.Duration("max_claim_age", w.opts.AbandonedClaimAge))
			}
		}
	}
}

func (w *Worker) fireOnDelivered(ev *Event, elapsed time.Duration) {
	if w.opts.OnDelivered != nil {
		defer func() { _ = recover() }()
		w.opts.OnDelivered(ev, elapsed)
	}
}

func (w *Worker) fireOnFailed(ev *Event, err error, elapsed time.Duration) {
	if w.opts.OnFailed != nil {
		defer func() { _ = recover() }()
		w.opts.OnFailed(ev, err, elapsed)
	}
}
