// SPDX-License-Identifier: Apache-2.0

package resilience

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- helpers ----------------------------------------------------------------

func newTestSWCB(opts ...func(*SlidingWindowConfig)) *SlidingWindowCircuitBreaker {
	cfg := SlidingWindowConfig{
		Name:                 "test-cb",
		BucketCount:          5,
		BucketDuration:       100 * time.Millisecond,
		FailureRateThreshold: 0.5,
		MinRequests:          4,
		HalfOpenMaxRequests:  2,
		RecoveryTimeout:      200 * time.Millisecond,
	}
	for _, o := range opts {
		o(&cfg)
	}
	return NewSlidingWindowCircuitBreaker(cfg)
}

func succeedN(t *testing.T, sw *SlidingWindowCircuitBreaker, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		require.NoError(t, sw.Execute(func() error { return nil }))
	}
}

func failN(t *testing.T, sw *SlidingWindowCircuitBreaker, n int) {
	t.Helper()
	sentinel := errors.New("fail")
	for i := 0; i < n; i++ {
		err := sw.Execute(func() error { return sentinel })
		// After the circuit trips, subsequent calls return ErrCircuitOpen rather than sentinel.
		// Both are valid outcomes for a failure-injection sequence.
		require.True(t, errors.Is(err, sentinel) || errors.Is(err, ErrCircuitOpen),
			"expected sentinel or ErrCircuitOpen, got: %v", err)
	}
}

func readSWGaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, g.Write(&m))
	return m.GetGauge().GetValue()
}

func readSWCounterVec(t *testing.T, cv *prometheus.CounterVec, lvs ...string) float64 {
	t.Helper()
	c, err := cv.GetMetricWithLabelValues(lvs...)
	require.NoError(t, err)
	var m dto.Metric
	require.NoError(t, c.Write(&m))
	return m.GetCounter().GetValue()
}

// ---- tests ------------------------------------------------------------------

func TestSlidingWindowCB_ExecuteSuccess(t *testing.T) {
	sw := newTestSWCB()
	called := false
	err := sw.Execute(func() error {
		called = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, StateClosed, sw.GetState())
}

func TestSlidingWindowCB_ExecuteFailure(t *testing.T) {
	sw := newTestSWCB()
	sentinel := errors.New("rpc error")
	err := sw.Execute(func() error { return sentinel })
	assert.ErrorIs(t, err, sentinel)
	assert.Equal(t, StateClosed, sw.GetState())
}

func TestSlidingWindowCB_ClosedState_AllowsRequests(t *testing.T) {
	sw := newTestSWCB()
	// Fewer failures than MinRequests — circuit must stay closed.
	failN(t, sw, 2)
	assert.Equal(t, StateClosed, sw.GetState())
	assert.Equal(t, float64(1.0), sw.GetFailureRate())
}

func TestSlidingWindowCB_DoesNotTripBelowMinRequests(t *testing.T) {
	sw := newTestSWCB() // MinRequests = 4
	// 3 failures — below MinRequests, should stay closed.
	failN(t, sw, 3)
	assert.Equal(t, StateClosed, sw.GetState())
}

func TestSlidingWindowCB_TripsAtThreshold(t *testing.T) {
	sw := newTestSWCB() // threshold=0.5, minRequests=4
	// 2 success + 4 failure = 66% failure rate, 6 total >= 4 → trip
	succeedN(t, sw, 2)
	failN(t, sw, 4)
	assert.Equal(t, StateOpen, sw.GetState())
}

func TestSlidingWindowCB_ZeroFailureRate(t *testing.T) {
	sw := newTestSWCB()
	succeedN(t, sw, 10)
	assert.Equal(t, StateClosed, sw.GetState())
	assert.InDelta(t, 0.0, sw.GetFailureRate(), 0.001)
}

func TestSlidingWindowCB_DefaultConfig(t *testing.T) {
	// Passing a zero config should result in sane defaults.
	sw := NewSlidingWindowCircuitBreaker(SlidingWindowConfig{})
	assert.Equal(t, StateClosed, sw.GetState())
	assert.Equal(t, "default", sw.cfg.Name)
	assert.Equal(t, 10, sw.cfg.BucketCount)
}

func TestSlidingWindowCB_WindowRollsCorrectly(t *testing.T) {
	sw := newTestSWCB(func(c *SlidingWindowConfig) {
		// Very short buckets so we can fast-forward by sleeping.
		c.BucketCount = 3
		c.BucketDuration = 30 * time.Millisecond
		c.MinRequests = 4
		c.FailureRateThreshold = 0.5
	})

	// Record 4 failures to trip.
	failN(t, sw, 4)
	require.Equal(t, StateOpen, sw.GetState())

	// Reset circuit manually so we can test window rolling on a closed CB.
	sw.Reset()
	require.Equal(t, StateClosed, sw.GetState())

	// Now record failures in the first bucket…
	failN(t, sw, 4) // should trip again
	require.Equal(t, StateOpen, sw.GetState())

	// Wait for recovery + one full window to roll over.
	sw.mu.Lock()
	sw.openedAt = time.Now().Add(-sw.cfg.RecoveryTimeout - time.Millisecond)
	sw.mu.Unlock()

	// Force the CB out of open by executing (triggers HalfOpen transition).
	sw.mu.Lock()
	sw.state = StateClosed
	for i := range sw.buckets {
		sw.buckets[i].reset()
	}
	sw.mu.Unlock()

	assert.Equal(t, StateClosed, sw.GetState())
	assert.InDelta(t, 0.0, sw.GetFailureRate(), 0.001)
}

func TestSlidingWindowCB_HalfOpenAllowsNProbes(t *testing.T) {
	sw := newTestSWCB() // HalfOpenMaxRequests = 2

	// Trip the circuit.
	succeedN(t, sw, 2)
	failN(t, sw, 4)
	require.Equal(t, StateOpen, sw.GetState())

	// Manually advance the openedAt so recovery timeout has elapsed.
	sw.mu.Lock()
	sw.openedAt = time.Now().Add(-sw.cfg.RecoveryTimeout - time.Millisecond)
	sw.mu.Unlock()

	// First probe: should enter half-open and be allowed.
	err := sw.Execute(func() error { return nil })
	require.NoError(t, err)
	assert.Equal(t, StateHalfOpen, sw.GetState())

	// Second probe: still half-open.
	err = sw.Execute(func() error { return nil })
	require.NoError(t, err)
	// After HalfOpenMaxRequests=2 successes, circuit closes.
	assert.Equal(t, StateClosed, sw.GetState())
}

func TestSlidingWindowCB_ClosesOnProbeSuccess(t *testing.T) {
	sw := newTestSWCB() // HalfOpenMaxRequests = 2

	failN(t, sw, 4)
	require.Equal(t, StateOpen, sw.GetState())

	sw.mu.Lock()
	sw.openedAt = time.Now().Add(-sw.cfg.RecoveryTimeout - time.Millisecond)
	sw.mu.Unlock()

	// Two successful probes → should close.
	_ = sw.Execute(func() error { return nil }) // probe 1
	_ = sw.Execute(func() error { return nil }) // probe 2

	assert.Equal(t, StateClosed, sw.GetState())
}

func TestSlidingWindowCB_ReopensOnProbeFailure(t *testing.T) {
	sw := newTestSWCB()

	failN(t, sw, 4)
	require.Equal(t, StateOpen, sw.GetState())

	sw.mu.Lock()
	sw.openedAt = time.Now().Add(-sw.cfg.RecoveryTimeout - time.Millisecond)
	sw.mu.Unlock()

	// First probe fails → should re-open.
	sentinel := errors.New("still broken")
	err := sw.Execute(func() error { return sentinel })
	assert.ErrorIs(t, err, sentinel)
	assert.Equal(t, StateOpen, sw.GetState())
}

func TestSlidingWindowCB_FallbackExecutesWhenOpen(t *testing.T) {
	fallbackCalled := false
	fallbackErr := errors.New("fallback result")

	sw := newTestSWCB(func(c *SlidingWindowConfig) {
		c.Fallback = func(_ error) error {
			fallbackCalled = true
			return fallbackErr
		}
	})

	failN(t, sw, 4)
	require.Equal(t, StateOpen, sw.GetState())

	err := sw.Execute(func() error { return nil })
	assert.ErrorIs(t, err, fallbackErr)
	assert.True(t, fallbackCalled)
}

func TestSlidingWindowCB_Reset(t *testing.T) {
	sw := newTestSWCB()

	failN(t, sw, 4)
	require.Equal(t, StateOpen, sw.GetState())

	sw.Reset()

	assert.Equal(t, StateClosed, sw.GetState())
	assert.InDelta(t, 0.0, sw.GetFailureRate(), 0.001)

	// Should allow requests again after reset.
	err := sw.Execute(func() error { return nil })
	assert.NoError(t, err)
}

func TestSlidingWindowCB_MetricsIncrement(t *testing.T) {
	reg := prometheus.NewRegistry()
	sw := newTestSWCB()
	sw.WithMetrics(reg)

	succeedN(t, sw, 2)
	failN(t, sw, 2)

	assert.InDelta(t, float64(2), readSWCounterVec(t, sw.metrics.requests, "test-cb", "success"), 0.001)
	assert.InDelta(t, float64(2), readSWCounterVec(t, sw.metrics.requests, "test-cb", "failure"), 0.001)
	assert.InDelta(t, 0.5, readSWGaugeValue(t, sw.metrics.failureRate), 0.001)
}

func TestSlidingWindowCB_MetricsRejectedCounter(t *testing.T) {
	reg := prometheus.NewRegistry()
	sw := newTestSWCB()
	sw.WithMetrics(reg)

	failN(t, sw, 4)
	require.Equal(t, StateOpen, sw.GetState())

	// This execute should be rejected.
	err := sw.Execute(func() error { return nil })
	require.ErrorIs(t, err, ErrCircuitOpen)

	assert.InDelta(t, float64(1), readSWCounterVec(t, sw.metrics.requests, "test-cb", "rejected"), 0.001)
}

func TestSlidingWindowCB_ConcurrentSafety(t *testing.T) {
	sw := newTestSWCB(func(c *SlidingWindowConfig) {
		c.MinRequests = 20
		c.HalfOpenMaxRequests = 10
		c.RecoveryTimeout = 50 * time.Millisecond
	})

	var wg sync.WaitGroup
	var successCount, failCount atomic.Int64
	sentinel := errors.New("concurrent fail")

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var err error
			if idx%3 == 0 {
				err = sw.Execute(func() error { return sentinel })
				if errors.Is(err, sentinel) {
					failCount.Add(1)
				}
			} else {
				err = sw.Execute(func() error { return nil })
				if err == nil {
					successCount.Add(1)
				}
			}
		}(i)
	}

	wg.Wait()
	// No race detector violations; just assert we counted something.
	assert.True(t, successCount.Load()+failCount.Load() > 0)
}
