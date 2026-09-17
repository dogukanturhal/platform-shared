// SPDX-License-Identifier: Apache-2.0

package resilience

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readCounterVecValue returns the value for the given label set from a CounterVec.
func readCounterVecValue(t *testing.T, cv *prometheus.CounterVec, lvs ...string) float64 {
	t.Helper()
	c, err := cv.GetMetricWithLabelValues(lvs...)
	require.NoError(t, err)
	var m dto.Metric
	require.NoError(t, c.Write(&m))
	return m.GetCounter().GetValue()
}

// readGaugeValue returns the current value of a prometheus.Gauge.
func readGaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, g.Write(&m))
	return m.GetGauge().GetValue()
}

func TestCircuitBreaker_WithMetrics_StateTransitions(t *testing.T) {
	reg := prometheus.NewRegistry()
	cb := NewCircuitBreakerNamed("svc-a", 2, 50*time.Millisecond)
	cb.WithMetrics(reg)

	// Initial state gauge should reflect Closed (0).
	assert.Equal(t, float64(StateClosed), readGaugeValue(t, cb.metrics.StateGauge))

	// Trigger open.
	cb.RecordFailure()
	cb.RecordFailure()

	assert.Equal(t, StateOpen, cb.GetState())
	assert.Equal(t, float64(StateOpen), readGaugeValue(t, cb.metrics.StateGauge))

	// Closed → Open transition counter.
	assert.Equal(t, float64(1),
		readCounterVecValue(t, cb.metrics.StateTransitions, "svc-a", "closed", "open"))

	// Wait for recovery and move to half-open.
	time.Sleep(60 * time.Millisecond)
	cb.Allow() // triggers Open → HalfOpen

	assert.Equal(t, StateHalfOpen, cb.GetState())
	assert.Equal(t, float64(StateHalfOpen), readGaugeValue(t, cb.metrics.StateGauge))
	assert.Equal(t, float64(1),
		readCounterVecValue(t, cb.metrics.StateTransitions, "svc-a", "open", "half-open"))

	// Success in half-open → closed.
	cb.RecordSuccess()

	assert.Equal(t, StateClosed, cb.GetState())
	assert.Equal(t, float64(StateClosed), readGaugeValue(t, cb.metrics.StateGauge))
	assert.Equal(t, float64(1),
		readCounterVecValue(t, cb.metrics.StateTransitions, "svc-a", "half-open", "closed"))
}

func TestCircuitBreaker_WithMetrics_RequestCounters(t *testing.T) {
	reg := prometheus.NewRegistry()
	cb := NewCircuitBreakerNamed("svc-b", 3, 1*time.Second)
	cb.WithMetrics(reg)

	cb.RecordSuccess()
	cb.RecordSuccess()
	cb.RecordFailure()

	assert.Equal(t, float64(2), readCounterVecValue(t, cb.metrics.Requests, "svc-b", "success"))
	assert.Equal(t, float64(1), readCounterVecValue(t, cb.metrics.Requests, "svc-b", "failure"))

	// Open the circuit.
	cb.RecordFailure()
	cb.RecordFailure()

	// A rejected Allow() increments the rejected counter.
	cb.Allow()

	assert.Equal(t, float64(1), readCounterVecValue(t, cb.metrics.Requests, "svc-b", "rejected"))
}

func TestCircuitBreaker_WithOnStateChange_Callback(t *testing.T) {
	var transitions []string
	cb := NewCircuitBreakerNamed("svc-c", 1, 50*time.Millisecond)
	cb.WithOnStateChange(func(from, to State) {
		transitions = append(transitions, from.String()+"->"+to.String())
	})

	cb.RecordFailure() // closed → open
	assert.Equal(t, []string{"closed->open"}, transitions)

	time.Sleep(60 * time.Millisecond)
	cb.Allow() // open → half-open
	assert.Equal(t, []string{"closed->open", "open->half-open"}, transitions)

	cb.RecordSuccess() // half-open → closed
	assert.Equal(t, []string{"closed->open", "open->half-open", "half-open->closed"}, transitions)
}

func TestCircuitBreaker_Reset_EmitsTransition(t *testing.T) {
	reg := prometheus.NewRegistry()
	cb := NewCircuitBreakerNamed("svc-d", 1, 1*time.Second)
	cb.WithMetrics(reg)

	cb.RecordFailure() // closed → open
	require.Equal(t, StateOpen, cb.GetState())

	cb.Reset() // open → closed

	assert.Equal(t, StateClosed, cb.GetState())
	assert.Equal(t, float64(StateClosed), readGaugeValue(t, cb.metrics.StateGauge))
	assert.Equal(t, float64(1),
		readCounterVecValue(t, cb.metrics.StateTransitions, "svc-d", "open", "closed"))
}
