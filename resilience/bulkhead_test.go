// SPDX-License-Identifier: Apache-2.0

package resilience

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readCounter reads the current value of a prometheus.Counter.
func readCounter(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, c.Write(&m))
	return m.GetCounter().GetValue()
}

// readGauge reads the current value of a prometheus.Gauge.
func readGauge(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, g.Write(&m))
	return m.GetGauge().GetValue()
}

func TestNewBulkhead_DefaultsToOneWhenZero(t *testing.T) {
	bh := NewBulkhead("test", 0)
	assert.Equal(t, 1, bh.maxConcurrent)
}

func TestBulkhead_ConcurrentExecutionRespectsMaxLimit(t *testing.T) {
	const maxConcurrent = 3
	bh := NewBulkhead("concurrent-test", maxConcurrent)

	var (
		active  int64
		maxSeen int64
		wg      sync.WaitGroup
		mu      sync.Mutex
	)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := bh.Execute(context.Background(), func() error {
				current := atomic.AddInt64(&active, 1)
				mu.Lock()
				if current > maxSeen {
					maxSeen = current
				}
				mu.Unlock()
				time.Sleep(10 * time.Millisecond)
				atomic.AddInt64(&active, -1)
				return nil
			})
			// All goroutines use Background context so no rejection expected.
			assert.NoError(t, err)
		}()
	}

	wg.Wait()

	// Peak active must never exceed the max concurrent limit.
	assert.LessOrEqual(t, maxSeen, int64(maxConcurrent),
		"peak concurrency %d exceeded limit %d", maxSeen, maxConcurrent)
}

func TestBulkhead_RejectWhenFullWithDeadlineContext(t *testing.T) {
	const maxConcurrent = 2
	bh := NewBulkhead("reject-test", maxConcurrent)

	// Fill all slots.
	require.NoError(t, bh.Acquire(context.Background()))
	require.NoError(t, bh.Acquire(context.Background()))
	defer bh.Release()
	defer bh.Release()

	// An already-expired context must be rejected immediately.
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	err := bh.Acquire(ctx)
	assert.ErrorIs(t, err, ErrBulkheadFull)
}

func TestBulkhead_ReleaseFreesSlot(t *testing.T) {
	bh := NewBulkhead("release-test", 1)

	require.NoError(t, bh.Acquire(context.Background()))
	bh.Release()

	// After release the slot must be available again.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	assert.NoError(t, bh.Acquire(ctx))
	bh.Release()
}

func TestBulkhead_Execute_ConvenienceMethod(t *testing.T) {
	bh := NewBulkhead("execute-test", 5)

	called := false
	err := bh.Execute(context.Background(), func() error {
		called = true
		return nil
	})

	assert.NoError(t, err)
	assert.True(t, called)
}

func TestBulkhead_Execute_ReturnsError(t *testing.T) {
	bh := NewBulkhead("execute-err-test", 5)

	err := bh.Execute(context.Background(), func() error {
		return assert.AnError
	})

	assert.ErrorIs(t, err, assert.AnError)
}

func TestBulkhead_Execute_ReleasesSlotOnPanic(t *testing.T) {
	bh := NewBulkhead("panic-test", 1)

	// Wrap Execute in a goroutine so we can recover from the panic.
	paniced := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				close(paniced)
			}
		}()
		_ = bh.Execute(context.Background(), func() error {
			panic("deliberate panic for test")
		})
	}()

	<-paniced

	// Slot must have been released by the deferred Release inside Execute.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	assert.NoError(t, bh.Acquire(ctx), "slot should be free after panic recovery")
	bh.Release()
}

func TestBulkhead_Metrics_IncrementOnAccept(t *testing.T) {
	reg := prometheus.NewRegistry()
	bh := NewBulkhead("metrics-accept", 5)
	bh.WithMetrics(reg)

	err := bh.Execute(context.Background(), func() error { return nil })
	require.NoError(t, err)

	assert.Equal(t, float64(1), readCounter(t, bh.metrics.Accepted))
	assert.Equal(t, float64(0), readCounter(t, bh.metrics.Rejected))
}

func TestBulkhead_Metrics_IncrementOnReject(t *testing.T) {
	reg := prometheus.NewRegistry()
	bh := NewBulkhead("metrics-reject", 1)
	bh.WithMetrics(reg)

	// Fill the single slot.
	require.NoError(t, bh.Acquire(context.Background()))
	defer bh.Release()

	// Reject via zero-timeout context.
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	err := bh.Acquire(ctx)
	assert.ErrorIs(t, err, ErrBulkheadFull)

	assert.Equal(t, float64(1), readCounter(t, bh.metrics.Accepted))
	assert.Equal(t, float64(1), readCounter(t, bh.metrics.Rejected))
}

func TestBulkhead_Metrics_ActiveGauge(t *testing.T) {
	reg := prometheus.NewRegistry()
	bh := NewBulkhead("metrics-active", 5)
	bh.WithMetrics(reg)

	require.NoError(t, bh.Acquire(context.Background()))
	assert.Equal(t, float64(1), readGauge(t, bh.metrics.Active))

	require.NoError(t, bh.Acquire(context.Background()))
	assert.Equal(t, float64(2), readGauge(t, bh.metrics.Active))

	bh.Release()
	assert.Equal(t, float64(1), readGauge(t, bh.metrics.Active))

	bh.Release()
	assert.Equal(t, float64(0), readGauge(t, bh.metrics.Active))
}
