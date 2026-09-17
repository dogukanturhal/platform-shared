// SPDX-License-Identifier: Apache-2.0

package circuitbreaker

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sony/gobreaker/v2"
)

const (
	stateValueClosed   = 0
	stateValueHalfOpen = 1
	stateValueOpen     = 2
)

// Metrics holds the Prometheus metric descriptors for circuit breaker
// instrumentation. A single Metrics instance should be shared across all
// breakers in a process.
type Metrics struct {
	state       *prometheus.GaugeVec
	transitions *prometheus.CounterVec
	requests    *prometheus.CounterVec
}

// RegisterMetrics creates and registers the circuit breaker metric descriptors
// with reg. If reg is nil, prometheus.DefaultRegisterer is used.
//
// The following metrics are registered:
//
//   - circuit_breaker_state{name}                                    gauge
//   - circuit_breaker_state_transitions_total{name,from,to}          counter
//   - circuit_breaker_requests_total{name,result}                    counter
func RegisterMetrics(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}

	state := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "circuit_breaker_state",
		Help: "Current state of the circuit breaker (0=closed, 1=half-open, 2=open).",
	}, []string{"name"})

	transitions := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "circuit_breaker_state_transitions_total",
		Help: "Total number of circuit breaker state transitions.",
	}, []string{"name", "from", "to"})

	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "circuit_breaker_requests_total",
		Help: "Total number of requests handled by circuit breakers, labeled by result.",
	}, []string{"name", "result"})

	reg.MustRegister(state, transitions, requests)

	return &Metrics{
		state:       state,
		transitions: transitions,
		requests:    requests,
	}
}

// OnStateChange returns a gobreaker-compatible callback that updates the state
// gauge and transitions counter for the given Metrics instance. Wire it into
// the breaker via the WithOnStateChange option.
func (m *Metrics) OnStateChange(name string, from, to gobreaker.State) {
	m.state.WithLabelValues(name).Set(stateFloat(to))
	m.transitions.WithLabelValues(name, StateToString(from), StateToString(to)).Inc()
}

// RecordRequest increments the requests counter for the named breaker.
// result should be one of "success", "failure", or "rejected".
func (m *Metrics) RecordRequest(name, result string) {
	m.requests.WithLabelValues(name, result).Inc()
}

func stateFloat(s gobreaker.State) float64 {
	switch s {
	case gobreaker.StateClosed:
		return stateValueClosed
	case gobreaker.StateHalfOpen:
		return stateValueHalfOpen
	case gobreaker.StateOpen:
		return stateValueOpen
	default:
		return stateValueClosed
	}
}
