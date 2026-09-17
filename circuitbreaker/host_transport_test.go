// SPDX-License-Identifier: Apache-2.0

package circuitbreaker_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dogukanturhal/platform-shared/circuitbreaker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func clientGet(c *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func TestHostAwareTransport_PerHostIsolation(t *testing.T) {
	// Server A always returns 500.
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srvA.Close()

	// Server B always returns 200.
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srvB.Close()

	reg := circuitbreaker.NewRegistry()
	tr := circuitbreaker.NewHostAwareTransport("test-cb", reg, nil,
		circuitbreaker.WithBreakerOpts(
			circuitbreaker.WithTimeout(100*time.Millisecond),
		),
	)
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	// Trip the breaker for server A (5 consecutive 5xx → open).
	for i := 0; i < 5; i++ {
		resp, err := clientGet(client, srvA.URL)
		require.NoError(t, err)
		_ = resp.Body.Close()
	}

	// Server B should still be reachable — its breaker is independent.
	resp, err := clientGet(client, srvB.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Server A should now get 503 from the open breaker.
	respA, err := clientGet(client, srvA.URL)
	require.NoError(t, err)
	body, _ := io.ReadAll(respA.Body)
	_ = respA.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, respA.StatusCode)
	assert.Equal(t, "service temporarily unavailable", string(body))

	// Verify two separate breakers were created (different host:port).
	all := reg.ListAll()
	assert.Len(t, all, 2, "should have one breaker per host:port")

	// Verify server A's breaker is open and B's is closed.
	openCount := 0
	closedCount := 0
	for _, status := range all {
		switch status.State {
		case "open":
			openCount++
		case "closed":
			closedCount++
		}
	}
	assert.Equal(t, 1, openCount, "server A breaker should be open")
	assert.Equal(t, 1, closedCount, "server B breaker should be closed")
}

func TestHostAwareTransport_BreakerRegisteredInRegistry(t *testing.T) {
	srv := newTestServer(t, http.StatusOK)
	defer srv.Close()

	reg := circuitbreaker.NewRegistry()
	tr := circuitbreaker.NewHostAwareTransport("svc->callback", reg, nil)
	client := &http.Client{Transport: tr}

	resp, err := clientGet(client, srv.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	// The breaker should be registered and visible.
	all := reg.ListAll()
	assert.Len(t, all, 1)

	for _, status := range all {
		assert.Equal(t, "closed", status.State)
		assert.Equal(t, uint32(1), status.Counts.Requests)
		assert.Equal(t, uint32(1), status.Counts.TotalSuccesses)
		assert.Equal(t, uint32(0), status.Counts.TotalFailures)
	}
}
