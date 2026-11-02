// SPDX-License-Identifier: Apache-2.0

package quota

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// FailMode is a registry key's behaviour when quota-service is unreachable.
type FailMode string

// FailModeOpen lets the work proceed (soft, flow meters); FailModeClosed refuses it
// (stock meters, where a missed increment is permanent drift).
const (
	FailModeOpen   FailMode = "open"
	FailModeClosed FailMode = "closed"
)

// DefaultRegistryTTL is how long a fetched registry is served before a refresh.
const DefaultRegistryTTL = 30 * time.Second

var registryMismatch = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "quota_registry_mismatch",
	Help: "Declared quota keys that are missing from, or disagree with, the quota-service registry.",
}, []string{"key"})

// RegistryEntry is one row of GET /internal/v1/quota/registry (the subset an SDK needs).
type RegistryEntry struct {
	Key          string   `json:"key"`
	Kind         string   `json:"kind"`
	Unit         string   `json:"unit"`
	MeterClass   *string  `json:"meter_class"`
	ResetPeriod  *string  `json:"reset_period"`
	OwnerService string   `json:"owner_service"`
	Enforcement  string   `json:"enforcement"`
	FailMode     FailMode `json:"fail_mode"`
	RecountMode  string   `json:"recount_mode"`
	Status       string   `json:"status"`
	ReplacedBy   *string  `json:"replaced_by"`
	Aliases      []string `json:"aliases"`
}

// Registry is an immutable snapshot of the quota registry.
type Registry struct {
	Entries  []RegistryEntry
	LoadedAt time.Time

	byKey map[string]*RegistryEntry
	alias map[string]string
}

func newRegistry(entries []RegistryEntry, now time.Time) *Registry {
	r := &Registry{Entries: entries, LoadedAt: now, byKey: make(map[string]*RegistryEntry, len(entries)), alias: map[string]string{}}
	for i := range r.Entries {
		e := &r.Entries[i]
		r.byKey[e.Key] = e
		for _, a := range e.Aliases {
			r.alias[a] = e.Key
		}
	}
	return r
}

// Canonical resolves an alias to its canonical key; unknown keys are returned unchanged.
func (r *Registry) Canonical(key string) string {
	if r == nil {
		return key
	}
	if c, ok := r.alias[key]; ok {
		return c
	}
	return key
}

// Entry returns the registry row for a key or alias.
func (r *Registry) Entry(key string) (*RegistryEntry, bool) {
	if r == nil {
		return nil, false
	}
	e, ok := r.byKey[r.Canonical(key)]
	return e, ok
}

// FailMode returns the key's declared fail mode. Unknown keys fail closed.
func (r *Registry) FailMode(key string) FailMode {
	if e, ok := r.Entry(key); ok && e.FailMode == FailModeOpen {
		return FailModeOpen
	}
	return FailModeClosed
}

// Expected is what a service declares about a key it uses (its quota manifest).
type Expected struct {
	Key        string
	Kind       string // empty = not checked
	MeterClass string // empty = not checked
	Unit       string // empty = not checked
}

// Assert is the read-only startup assertion: every expected key exists in the registry
// with the same kind, meter class and unit. It returns one message per mismatch and bumps
// quota_registry_mismatch{key}; callers log the result and never fail readiness on it.
func (r *Registry) Assert(expected ...Expected) []string {
	var out []string
	for _, x := range expected {
		e, ok := r.Entry(x.Key)
		var msg string
		switch {
		case !ok:
			msg = fmt.Sprintf("%s: not in registry", x.Key)
		case x.Kind != "" && e.Kind != x.Kind:
			msg = fmt.Sprintf("%s: kind %q, registry has %q", x.Key, x.Kind, e.Kind)
		case x.Unit != "" && e.Unit != x.Unit:
			msg = fmt.Sprintf("%s: unit %q, registry has %q", x.Key, x.Unit, e.Unit)
		case x.MeterClass != "" && (e.MeterClass == nil || *e.MeterClass != x.MeterClass):
			msg = fmt.Sprintf("%s: meter_class %q does not match the registry", x.Key, x.MeterClass)
		}
		if msg != "" {
			registryMismatch.WithLabelValues(x.Key).Inc()
			out = append(out, msg)
		}
	}
	return out
}

// registryCache fetches the registry with ETag revalidation and serves a stale copy
// when a refresh fails.
type registryCache struct {
	mu   sync.Mutex
	ttl  time.Duration
	reg  *Registry
	etag string
}

func (c *Client) cachedRegistry() *Registry {
	c.reg.mu.Lock()
	defer c.reg.mu.Unlock()
	return c.reg.reg
}

// Registry returns the cached registry, refreshing it when older than the TTL. A failed
// refresh returns the stale snapshot if there is one, else the error.
func (c *Client) Registry(ctx context.Context) (*Registry, error) {
	c.reg.mu.Lock()
	defer c.reg.mu.Unlock()
	if c.reg.reg != nil && time.Since(c.reg.reg.LoadedAt) < c.reg.ttl {
		return c.reg.reg, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/internal/v1/quota/registry", http.NoBody)
	if err != nil {
		return c.reg.reg, c.staleOr(err)
	}
	if c.reg.etag != "" && c.reg.reg != nil {
		req.Header.Set("If-None-Match", c.reg.etag)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return c.reg.reg, c.staleOr(err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotModified && c.reg.reg != nil:
		c.reg.reg = newRegistry(c.reg.reg.Entries, time.Now())
		return c.reg.reg, nil
	case resp.StatusCode != http.StatusOK:
		return c.reg.reg, c.staleOr(fmt.Errorf("registry returned status %d", resp.StatusCode))
	}
	var env struct {
		Data []RegistryEntry `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return c.reg.reg, c.staleOr(err)
	}
	c.reg.reg = newRegistry(env.Data, time.Now())
	c.reg.etag = strings.TrimSpace(resp.Header.Get("ETag"))
	return c.reg.reg, nil
}

func (c *Client) staleOr(err error) error {
	if c.reg.reg != nil {
		return nil
	}
	return fmt.Errorf("quota registry: %w", err)
}

// Canonical resolves an alias to its canonical key using the cached registry (best effort).
func (c *Client) Canonical(ctx context.Context, key string) string {
	r, _ := c.Registry(ctx)
	return r.Canonical(key)
}
