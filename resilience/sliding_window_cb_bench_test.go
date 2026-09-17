// SPDX-License-Identifier: Apache-2.0

package resilience

import (
	"errors"
	"testing"
	"time"
)

// BenchmarkSlidingWindowCB_ExecuteSuccess measures the throughput of Execute
// calls when every wrapped function returns nil (the fast path through the
// closed circuit breaker). This is the steady-state cost paid on every
// service-to-service call in production.
func BenchmarkSlidingWindowCB_ExecuteSuccess(b *testing.B) {
	cb := NewSlidingWindowCircuitBreaker(SlidingWindowConfig{
		Name:                 "bench-success",
		FailureRateThreshold: 0.5,
		MinRequests:          10,
		RecoveryTimeout:      30 * time.Second,
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.Execute(func() error { return nil }) //nolint:errcheck,gosec // test helper
	}
}

// BenchmarkSlidingWindowCB_ExecuteFailure measures the throughput of Execute
// calls when every wrapped function returns an error. The failure threshold
// and MinRequests are set high enough that the circuit does not trip during
// the benchmark run, isolating the per-call overhead of recording a failure
// and recomputing the sliding-window failure rate.
func BenchmarkSlidingWindowCB_ExecuteFailure(b *testing.B) {
	cb := NewSlidingWindowCircuitBreaker(SlidingWindowConfig{
		Name:                 "bench-failure",
		FailureRateThreshold: 0.99, // very high threshold — circuit will not trip
		MinRequests:          1_000_000,
		RecoveryTimeout:      30 * time.Second,
	})
	errTest := errors.New("test error")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.Execute(func() error { return errTest }) //nolint:errcheck,gosec // test helper
	}
}

// BenchmarkSlidingWindowCB_ExecuteParallel measures the throughput of Execute
// under contention from multiple goroutines (GOMAXPROCS workers). This
// benchmark surfaces lock-contention cost on the internal mutex and is the
// most representative of high-concurrency microservice workloads.
func BenchmarkSlidingWindowCB_ExecuteParallel(b *testing.B) {
	cb := NewSlidingWindowCircuitBreaker(SlidingWindowConfig{
		Name:                 "bench-parallel",
		FailureRateThreshold: 0.5,
		MinRequests:          10,
		RecoveryTimeout:      30 * time.Second,
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cb.Execute(func() error { return nil }) //nolint:errcheck,gosec // test helper
		}
	})
}

// BenchmarkSlidingWindowCB_GetFailureRate measures the cost of computing the
// failure rate across the ring buffer after the window has been pre-populated
// with a realistic mixed-outcome distribution. This reflects the work done on
// every Execute call to evaluate the trip condition.
func BenchmarkSlidingWindowCB_GetFailureRate(b *testing.B) {
	cb := NewSlidingWindowCircuitBreaker(SlidingWindowConfig{
		Name:                 "bench-rate",
		FailureRateThreshold: 0.5,
		MinRequests:          10,
		RecoveryTimeout:      30 * time.Second,
	})

	// Pre-populate the window with a realistic 1-in-3 failure rate.
	errFail := errors.New("fail")
	for i := 0; i < 100; i++ {
		if i%3 == 0 {
			cb.Execute(func() error { return errFail }) //nolint:errcheck,gosec // test helper
		} else {
			cb.Execute(func() error { return nil }) //nolint:errcheck,gosec // test helper
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.GetFailureRate()
	}
}
