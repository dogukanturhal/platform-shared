// SPDX-License-Identifier: Apache-2.0

package resilience

import (
	"testing"
	"time"
)

func TestNewCircuitBreaker(t *testing.T) {
	cb := NewCircuitBreaker()

	if cb.GetState() != StateClosed {
		t.Errorf("expected initial state to be Closed, got %v", cb.GetState())
	}

	if cb.GetFailureCount() != 0 {
		t.Errorf("expected initial failure count to be 0, got %d", cb.GetFailureCount())
	}
}

func TestNewCircuitBreakerWithConfig(t *testing.T) {
	tests := []struct {
		name              string
		threshold         int
		timeout           time.Duration
		expectedThreshold int
		expectedTimeout   time.Duration
	}{
		{
			name:              "valid config",
			threshold:         3,
			timeout:           10 * time.Second,
			expectedThreshold: 3,
			expectedTimeout:   10 * time.Second,
		},
		{
			name:              "zero threshold uses default",
			threshold:         0,
			timeout:           10 * time.Second,
			expectedThreshold: 5,
			expectedTimeout:   10 * time.Second,
		},
		{
			name:              "negative threshold uses default",
			threshold:         -1,
			timeout:           10 * time.Second,
			expectedThreshold: 5,
			expectedTimeout:   10 * time.Second,
		},
		{
			name:              "zero timeout uses default",
			threshold:         3,
			timeout:           0,
			expectedThreshold: 3,
			expectedTimeout:   30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb := NewCircuitBreakerWithConfig(tt.threshold, tt.timeout)

			if cb.failureThreshold != tt.expectedThreshold {
				t.Errorf("expected threshold %d, got %d", tt.expectedThreshold, cb.failureThreshold)
			}

			if cb.recoveryTimeout != tt.expectedTimeout {
				t.Errorf("expected timeout %v, got %v", tt.expectedTimeout, cb.recoveryTimeout)
			}
		})
	}
}

func TestCircuitBreakerStateClosed(t *testing.T) {
	cb := NewCircuitBreaker()

	// Should allow requests when closed
	if !cb.Allow() {
		t.Error("circuit breaker should allow requests when closed")
	}

	// Record success should reset failure count
	cb.RecordFailure()
	if cb.GetFailureCount() != 1 {
		t.Errorf("expected failure count 1, got %d", cb.GetFailureCount())
	}

	cb.RecordSuccess()
	if cb.GetFailureCount() != 0 {
		t.Errorf("expected failure count to reset to 0, got %d", cb.GetFailureCount())
	}
}

func TestCircuitBreakerTransitionToOpen(t *testing.T) {
	cb := NewCircuitBreakerWithConfig(3, 100*time.Millisecond)

	// Record failures up to threshold
	for i := 0; i < 3; i++ {
		if cb.GetState() != StateClosed {
			t.Errorf("expected state Closed, got %v", cb.GetState())
		}
		cb.RecordFailure()
	}

	// Should transition to Open
	if cb.GetState() != StateOpen {
		t.Errorf("expected state Open after threshold failures, got %v", cb.GetState())
	}

	// Should reject requests when open
	if cb.Allow() {
		t.Error("circuit breaker should reject requests when open")
	}
}

func TestCircuitBreakerTransitionToHalfOpen(t *testing.T) {
	cb := NewCircuitBreakerWithConfig(2, 50*time.Millisecond)

	// Open the circuit
	cb.RecordFailure()
	cb.RecordFailure()

	if cb.GetState() != StateOpen {
		t.Errorf("expected state Open, got %v", cb.GetState())
	}

	// Should reject immediately
	if cb.Allow() {
		t.Error("circuit breaker should reject requests immediately after opening")
	}

	// Wait for recovery timeout
	time.Sleep(60 * time.Millisecond)

	// Should transition to HalfOpen and allow one request
	if !cb.Allow() {
		t.Error("circuit breaker should allow request after timeout (HalfOpen)")
	}

	if cb.GetState() != StateHalfOpen {
		t.Errorf("expected state HalfOpen, got %v", cb.GetState())
	}
}

func TestCircuitBreakerHalfOpenToOpen(t *testing.T) {
	cb := NewCircuitBreakerWithConfig(2, 50*time.Millisecond)

	// Open the circuit
	cb.RecordFailure()
	cb.RecordFailure()

	// Wait for recovery timeout and transition to HalfOpen
	time.Sleep(60 * time.Millisecond)
	cb.Allow() // Transition to HalfOpen

	if cb.GetState() != StateHalfOpen {
		t.Errorf("expected state HalfOpen, got %v", cb.GetState())
	}

	// Record failure in HalfOpen should reopen circuit
	cb.RecordFailure()

	if cb.GetState() != StateOpen {
		t.Errorf("expected state Open after failure in HalfOpen, got %v", cb.GetState())
	}
}

func TestCircuitBreakerHalfOpenToClosed(t *testing.T) {
	cb := NewCircuitBreakerWithConfig(2, 50*time.Millisecond)

	// Open the circuit
	cb.RecordFailure()
	cb.RecordFailure()

	// Wait for recovery timeout and transition to HalfOpen
	time.Sleep(60 * time.Millisecond)
	cb.Allow() // Transition to HalfOpen

	if cb.GetState() != StateHalfOpen {
		t.Errorf("expected state HalfOpen, got %v", cb.GetState())
	}

	// Record success in HalfOpen should close circuit
	cb.RecordSuccess()

	if cb.GetState() != StateClosed {
		t.Errorf("expected state Closed after success in HalfOpen, got %v", cb.GetState())
	}

	if cb.GetFailureCount() != 0 {
		t.Errorf("expected failure count to reset to 0, got %d", cb.GetFailureCount())
	}
}

func TestCircuitBreakerReset(t *testing.T) {
	cb := NewCircuitBreakerWithConfig(2, 50*time.Millisecond)

	// Open the circuit
	cb.RecordFailure()
	cb.RecordFailure()

	if cb.GetState() != StateOpen {
		t.Errorf("expected state Open, got %v", cb.GetState())
	}

	// Reset should close circuit and reset failure count
	cb.Reset()

	if cb.GetState() != StateClosed {
		t.Errorf("expected state Closed after reset, got %v", cb.GetState())
	}

	if cb.GetFailureCount() != 0 {
		t.Errorf("expected failure count 0 after reset, got %d", cb.GetFailureCount())
	}
}

func TestCircuitBreakerConcurrency(t *testing.T) {
	cb := NewCircuitBreakerWithConfig(10, 100*time.Millisecond)

	// Run concurrent operations
	done := make(chan bool)

	// Multiple goroutines recording only failures
	for i := 0; i < 20; i++ {
		go func() {
			for j := 0; j < 5; j++ {
				cb.RecordFailure()
				cb.Allow()
				cb.GetState()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}

	// Circuit should be open due to high failure count (100 failures > 10 threshold)
	if cb.GetState() != StateOpen {
		t.Errorf("expected state Open after concurrent failures, got %v", cb.GetState())
	}

	// Test thread-safety with mixed operations
	cb2 := NewCircuitBreakerWithConfig(50, 100*time.Millisecond)
	done2 := make(chan bool)

	// Mix of concurrent reads and writes
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 10; j++ {
				cb2.RecordFailure()
			}
			done2 <- true
		}()
		go func() {
			for j := 0; j < 10; j++ {
				cb2.Allow()
				cb2.GetState()
				cb2.GetFailureCount()
			}
			done2 <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done2
	}

	// Should have accumulated enough failures (100 > 50)
	if cb2.GetState() != StateOpen {
		t.Errorf("expected state Open for cb2, got %v", cb2.GetState())
	}
}

func TestStateString(t *testing.T) {
	tests := []struct {
		state    State
		expected string
	}{
		{StateClosed, "closed"},
		{StateOpen, "open"},
		{StateHalfOpen, "half-open"},
		{State(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.state.String() != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, tt.state.String())
			}
		})
	}
}

func TestCircuitBreakerPartialFailures(t *testing.T) {
	cb := NewCircuitBreakerWithConfig(5, 100*time.Millisecond)

	// Record some failures (not reaching threshold)
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()

	if cb.GetState() != StateClosed {
		t.Errorf("expected state Closed, got %v", cb.GetState())
	}

	if cb.GetFailureCount() != 3 {
		t.Errorf("expected failure count 3, got %d", cb.GetFailureCount())
	}

	// Success should reset
	cb.RecordSuccess()

	if cb.GetFailureCount() != 0 {
		t.Errorf("expected failure count to reset, got %d", cb.GetFailureCount())
	}

	// Should still allow requests
	if !cb.Allow() {
		t.Error("circuit breaker should allow requests")
	}
}
