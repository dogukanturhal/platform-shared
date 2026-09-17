// SPDX-License-Identifier: Apache-2.0

package circuitbreaker

import (
	"net/http"
	"net/url"
	"sync"
)

// maxHostBreakers is the upper bound on the number of per-host breakers a
// HostAwareTransport will create. Beyond this limit, requests pass through
// without circuit-breaking protection rather than leaking memory.
const maxHostBreakers = 256

// HostAwareTransport is an http.RoundTripper that maintains a separate circuit
// breaker per destination host. This prevents one failing host from tripping
// the breaker for all others — critical for endpoints where the target URL is
// user-influenced (e.g., workflow callback URLs).
//
// Breaker instances are registered in the provided Registry so they appear in
// metrics and health endpoints.
type HostAwareTransport struct {
	Base    http.RoundTripper
	Prefix  string   // prefix for breaker names, e.g. "workflow-engine->callback"
	Opts    []Option // options applied to each new breaker
	Metrics *Metrics
	Reg     *Registry

	mu    sync.Mutex
	hosts map[string]*Transport
	count int
}

// NewHostAwareTransport creates a HostAwareTransport that creates per-host
// breakers on demand. Each breaker is named "{prefix}:{host}" and registered
// in reg.
func NewHostAwareTransport(prefix string, reg *Registry, base http.RoundTripper, opts ...HostAwareOption) *HostAwareTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	t := &HostAwareTransport{
		Base:   base,
		Prefix: prefix,
		Reg:    reg,
		hosts:  make(map[string]*Transport),
	}
	for _, o := range opts {
		o(t)
	}
	return t
}

// HostAwareOption configures a HostAwareTransport.
type HostAwareOption func(*HostAwareTransport)

// WithHostMetrics attaches a Metrics instance to all per-host breakers.
func WithHostMetrics(m *Metrics) HostAwareOption {
	return func(t *HostAwareTransport) { t.Metrics = m }
}

// WithBreakerOpts sets the circuit breaker options for all per-host breakers.
func WithBreakerOpts(opts ...Option) HostAwareOption {
	return func(t *HostAwareTransport) { t.Opts = opts }
}

// RoundTrip routes the request through a per-host circuit breaker. If the
// host cannot be extracted or the per-host limit is reached, the request
// passes through without circuit-breaking.
func (t *HostAwareTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := extractHost(req.URL)
	if host == "" {
		// Cannot determine host — pass through without circuit breaking.
		return t.Base.RoundTrip(req)
	}

	transport := t.getOrCreateTransport(host)
	if transport == nil {
		// Safety limit reached — pass through without circuit breaking.
		return t.Base.RoundTrip(req)
	}

	return transport.RoundTrip(req)
}

func (t *HostAwareTransport) getOrCreateTransport(host string) *Transport {
	t.mu.Lock()
	defer t.mu.Unlock()

	if tr, ok := t.hosts[host]; ok {
		return tr
	}

	if t.count >= maxHostBreakers {
		return nil
	}

	name := t.Prefix + ":" + host
	breaker, err := t.Reg.GetOrCreate(name, t.Opts...)
	if err != nil {
		return nil // registry full — pass through
	}
	var tOpts []TransportOption
	if t.Metrics != nil {
		tOpts = append(tOpts, WithMetrics(t.Metrics))
	}
	tr := NewTransport(breaker, t.Base, tOpts...)
	t.hosts[host] = tr
	t.count++
	return tr
}

// extractHost returns the host:port from a URL. Port is included because
// different services on the same host use different ports and must have
// independent breakers.
func extractHost(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Host
}
