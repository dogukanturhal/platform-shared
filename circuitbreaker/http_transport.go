// SPDX-License-Identifier: Apache-2.0

package circuitbreaker

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/sony/gobreaker/v2"
)

// errServerError is an internal sentinel used to signal to the breaker that
// a 5xx response should be counted as a failure. It is never surfaced to the
// caller directly.
var errServerError = errors.New("server error (5xx)")

// TransportOption is a functional option for Transport.
type TransportOption func(*Transport)

// WithMetrics attaches a Metrics instance to the Transport. When set, every
// request outcome is recorded via Metrics.RecordRequest.
func WithMetrics(m *Metrics) TransportOption {
	return func(t *Transport) { t.Metrics = m }
}

// Transport is an http.RoundTripper that routes requests through a Breaker.
//
// 5xx responses are counted as failures towards the trip threshold.
// 4xx responses are counted as successes (they indicate the server is healthy
// but the request was bad).
//
// When the breaker is open, RoundTrip returns a synthetic 503 response with a
// plain-text body describing the situation; it never forwards the request.
type Transport struct {
	// Base is the underlying RoundTripper. Defaults to http.DefaultTransport
	// when nil.
	Base    http.RoundTripper
	Breaker *Breaker
	Metrics *Metrics
}

// NewTransport constructs a Transport that wraps base with the given breaker.
// Additional behavior can be configured with TransportOption values.
func NewTransport(breaker *Breaker, base http.RoundTripper, opts ...TransportOption) *Transport {
	if base == nil {
		base = http.DefaultTransport
	}
	t := &Transport{
		Base:    base,
		Breaker: breaker,
	}
	for _, o := range opts {
		o(t)
	}
	return t
}

// syntheticResponse builds a synthetic HTTP response without leaking internal
// service topology. The breaker name is logged server-side but never exposed
// in the response body.
func (t *Transport) syntheticResponse(req *http.Request, statusCode int, body string) *http.Response {
	h := make(http.Header)
	// Provide a Retry-After hint so callers know how long to wait.
	h.Set("Retry-After", strconv.Itoa(int(t.Breaker.Timeout().Seconds())))
	return &http.Response{
		StatusCode: statusCode,
		Status:     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     h,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Request:    req,
	}
}

// RoundTrip implements http.RoundTripper. It executes the request through the
// circuit breaker, handling open-state fast-fails and 5xx trip conditions.
//
// Contract: RoundTrip always returns (*http.Response, nil) for server-side
// failures (5xx and breaker-open). Only transport-level errors (DNS, TLS,
// connection refused) return (nil, error). This gives callers a uniform
// interface.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	result, err := t.Breaker.Execute(func() (any, error) {
		resp, doErr := t.Base.RoundTrip(req)
		if doErr != nil {
			return nil, doErr
		}
		// Count 5xx as failures to trigger the breaker.
		if resp.StatusCode >= 500 {
			// Drain and close the body before returning an error so the
			// underlying connection can be reused.
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			return nil, fmt.Errorf("%w: status %d", errServerError, resp.StatusCode)
		}
		// 4xx and 2xx/3xx are successes from the breaker's perspective.
		return resp, nil
	})
	if err != nil {
		return t.handleRoundTripError(req, err)
	}

	if t.Metrics != nil {
		t.Metrics.RecordRequest(t.Breaker.name, "success")
	}
	return result.(*http.Response), nil
}

// handleRoundTripError converts circuit-breaker and upstream errors to HTTP responses.
func (t *Transport) handleRoundTripError(req *http.Request, err error) (*http.Response, error) {
	// Breaker is open — fast-fail without forwarding the request.
	if errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests) {
		if t.Metrics != nil {
			t.Metrics.RecordRequest(t.Breaker.name, "rejected")
		}
		return t.syntheticResponse(req, http.StatusServiceUnavailable,
			"service temporarily unavailable"), nil
	}

	// 5xx from upstream — return a synthetic 502 so callers always get
	// an *http.Response for server-side problems (M3: uniform interface).
	if errors.Is(err, errServerError) {
		if t.Metrics != nil {
			t.Metrics.RecordRequest(t.Breaker.name, "failure")
		}
		return t.syntheticResponse(req, http.StatusBadGateway,
			"upstream service error"), nil
	}

	// Genuine transport-level failure (DNS, TLS, connection refused).
	if t.Metrics != nil {
		t.Metrics.RecordRequest(t.Breaker.name, "failure")
	}
	return nil, err
}
