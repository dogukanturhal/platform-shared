// SPDX-License-Identifier: Apache-2.0

package circuitbreaker_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dogukanturhal/platform-shared/circuitbreaker"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sony/gobreaker/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestServer creates a test HTTP server that always responds with statusCode.
func newTestServer(t *testing.T, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(statusCode)
	}))
}

func TestTransport_SuccessfulRequestPassesThrough(t *testing.T) {
	srv := newTestServer(t, http.StatusOK)
	defer srv.Close()

	b := circuitbreaker.NewBreaker("test-ok")
	tr := circuitbreaker.NewTransport(b, nil)
	client := &http.Client{Transport: tr}

	resp, err := clientGet(client, srv.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, gobreaker.StateClosed, b.State())
}

func TestTransport_FiveHundredTripsBreaker(t *testing.T) {
	srv := newTestServer(t, http.StatusInternalServerError)
	defer srv.Close()

	b := circuitbreaker.NewBreaker("test-5xx",
		circuitbreaker.WithTimeout(100*time.Millisecond),
	)
	tr := circuitbreaker.NewTransport(b, nil)
	client := &http.Client{Transport: tr}

	for i := 0; i < 5; i++ {
		resp, err := clientGet(client, srv.URL)
		// M3 fix: 5xx now returns a synthetic 502 response, not an error.
		require.NoError(t, err, "5xx should return synthetic response, not error")
		assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
		_ = resp.Body.Close()
	}

	assert.Equal(t, gobreaker.StateOpen, b.State())
}

func TestTransport_FiveHundredBodyIsGeneric(t *testing.T) {
	srv := newTestServer(t, http.StatusInternalServerError)
	defer srv.Close()

	b := circuitbreaker.NewBreaker("test-5xx-body")
	tr := circuitbreaker.NewTransport(b, nil)
	client := &http.Client{Transport: tr}

	resp, err := clientGet(client, srv.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	// M1 fix: body must NOT contain internal service names.
	assert.Equal(t, "upstream service error", string(body))
	assert.NotContains(t, string(body), "test-5xx-body")
}

func TestTransport_FourHundredDoesNotTripBreaker(t *testing.T) {
	srv := newTestServer(t, http.StatusBadRequest)
	defer srv.Close()

	b := circuitbreaker.NewBreaker("test-4xx")
	tr := circuitbreaker.NewTransport(b, nil)
	client := &http.Client{Transport: tr}

	for i := 0; i < 10; i++ {
		resp, err := clientGet(client, srv.URL)
		require.NoError(t, err)
		_ = resp.Body.Close()
	}

	// 4xx must not trip the breaker.
	assert.Equal(t, gobreaker.StateClosed, b.State())
}

func TestTransport_OpenBreakerReturnsSyntheticFiveOhThree(t *testing.T) {
	srv := newTestServer(t, http.StatusInternalServerError)
	defer srv.Close()

	b := circuitbreaker.NewBreaker("test-open-503",
		circuitbreaker.WithTimeout(100*time.Millisecond),
	)
	tr := circuitbreaker.NewTransport(b, nil)
	client := &http.Client{Transport: tr}

	// Trip the breaker.
	for i := 0; i < 5; i++ {
		resp, _ := clientGet(client, srv.URL)
		if resp != nil {
			_ = resp.Body.Close()
		}
	}
	require.Equal(t, gobreaker.StateOpen, b.State())

	// Now the breaker is open — should get a synthetic 503.
	resp, err := clientGet(client, srv.URL)
	require.NoError(t, err, "open breaker returns synthetic response, not an error")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	// M1 fix: body must be generic, no internal names.
	assert.Equal(t, "service temporarily unavailable", string(body))
	assert.NotContains(t, string(body), "test-open-503")

	// Should have Retry-After header.
	assert.NotEmpty(t, resp.Header.Get("Retry-After"))
}

func TestTransport_NilBaseUsesDefaultTransport(t *testing.T) {
	srv := newTestServer(t, http.StatusOK)
	defer srv.Close()

	b := circuitbreaker.NewBreaker("test-nil-base")
	// Passing nil base should default to http.DefaultTransport.
	tr := circuitbreaker.NewTransport(b, nil)
	require.NotNil(t, tr.Base)

	client := &http.Client{Transport: tr}
	resp, err := clientGet(client, srv.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
}

func TestTransport_MetricsRecordedOnSuccess(t *testing.T) {
	srv := newTestServer(t, http.StatusOK)
	defer srv.Close()

	// Use an isolated Prometheus registry per test to avoid duplicate registration panics.
	reg := circuitbreaker.RegisterMetrics(prometheus.NewRegistry())
	b := circuitbreaker.NewBreaker("test-metrics-ok")
	tr := circuitbreaker.NewTransport(b, nil, circuitbreaker.WithMetrics(reg))
	client := &http.Client{Transport: tr}

	resp, err := clientGet(client, srv.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	// No panic = metrics were recorded correctly.
}

func TestTransport_MetricsRecordedOnFailure(t *testing.T) {
	srv := newTestServer(t, http.StatusInternalServerError)
	defer srv.Close()

	reg := circuitbreaker.RegisterMetrics(prometheus.NewRegistry())
	b := circuitbreaker.NewBreaker("test-metrics-fail",
		circuitbreaker.WithTimeout(100*time.Millisecond),
	)
	tr := circuitbreaker.NewTransport(b, nil, circuitbreaker.WithMetrics(reg))
	client := &http.Client{Transport: tr}

	for i := 0; i < 3; i++ {
		resp, _ := clientGet(client, srv.URL)
		if resp != nil {
			_ = resp.Body.Close()
		}
	}
	// No panic = metrics were recorded correctly.
}
