// SPDX-License-Identifier: Apache-2.0

package resilience_test

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/dogukanturhal/platform-shared/resilience"
)

// ExampleNewResilientHTTPClient demonstrates basic usage of the resilient HTTP client
func ExampleNewResilientHTTPClient() {
	// Create a resilient HTTP client with default settings
	client := resilience.NewResilientHTTPClient()

	// Make a request
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.example.com/health", nil)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	fmt.Printf("Status: %d\n", resp.StatusCode)
}

// ExampleNewResilientHTTPClient_withOptions demonstrates custom configuration
func ExampleNewResilientHTTPClient_withOptions() {
	// Create a custom circuit breaker
	cb := resilience.NewCircuitBreakerWithConfig(3, 10*time.Second)

	// Create a resilient HTTP client with custom settings
	client := resilience.NewResilientHTTPClient(
		resilience.WithMaxRetries(5),
		resilience.WithRetryDelay(200*time.Millisecond),
		resilience.WithBackoffMultiplier(2.0),
		resilience.WithCircuitBreaker(cb),
	)

	// Make a request with context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.com/data", nil)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	fmt.Printf("Status: %d\n", resp.StatusCode)
}

// ExampleCircuitBreaker demonstrates standalone circuit breaker usage
func ExampleCircuitBreaker() {
	// Create a circuit breaker with 5 failure threshold and 30s recovery timeout
	cb := resilience.NewCircuitBreaker()

	// Check if request is allowed
	if cb.Allow() {
		// Make request
		err := makeRequest()
		if err != nil {
			cb.RecordFailure()
		} else {
			cb.RecordSuccess()
		}
	}

	// Check circuit state
	fmt.Printf("Circuit state: %s\n", cb.GetState())
}

// ExampleNewCircuitBreakerWithConfig demonstrates custom circuit breaker configuration
func ExampleNewCircuitBreakerWithConfig() {
	// Create a circuit breaker with custom settings
	cb := resilience.NewCircuitBreakerWithConfig(
		3,              // failure threshold
		10*time.Second, // recovery timeout
	)

	// Simulate failures
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}

	// Circuit should now be open
	if !cb.Allow() {
		fmt.Println("Circuit is open, requests blocked")
	}

	// After recovery timeout, circuit transitions to half-open
	time.Sleep(11 * time.Second)
	if cb.Allow() {
		fmt.Println("Circuit is half-open, testing recovery")
	}
}

func makeRequest() error {
	// Simulate request
	return nil
}
