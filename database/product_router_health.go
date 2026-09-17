// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// PoolHealthStatus represents the health of a cached pool.
type PoolHealthStatus struct {
	CacheKey      string
	IsolationMode string
	TenantID      string
	Healthy       bool
	LastUsed      time.Time
	IdleDuration  time.Duration
}

// ProductRouterHealthChecker monitors the health of dynamically created
// connection pools and evicts idle ones to prevent unbounded growth.
type ProductRouterHealthChecker struct {
	router        *ProductConnectionRouter
	idleTimeout   time.Duration // pools unused for this long are evicted
	checkInterval time.Duration
	log           *zap.Logger
	mu            sync.Mutex
}

// HealthCheckerOption configures the health checker.
type HealthCheckerOption func(*ProductRouterHealthChecker)

// WithIdleTimeout sets how long a pool can be idle before eviction. Default: 30 minutes.
func WithIdleTimeout(d time.Duration) HealthCheckerOption {
	return func(h *ProductRouterHealthChecker) {
		h.idleTimeout = d
	}
}

// WithCheckInterval sets how often health checks run. Default: 5 minutes.
func WithCheckInterval(d time.Duration) HealthCheckerOption {
	return func(h *ProductRouterHealthChecker) {
		h.checkInterval = d
	}
}

// WithHealthLogger sets the logger.
func WithHealthLogger(log *zap.Logger) HealthCheckerOption {
	return func(h *ProductRouterHealthChecker) {
		h.log = log
	}
}

// NewProductRouterHealthChecker creates a health checker for the router's pools.
func NewProductRouterHealthChecker(router *ProductConnectionRouter, opts ...HealthCheckerOption) *ProductRouterHealthChecker {
	h := &ProductRouterHealthChecker{
		router:        router,
		idleTimeout:   30 * time.Minute,
		checkInterval: 5 * time.Minute,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Start begins the periodic health check loop. Cancel the context to stop.
func (h *ProductRouterHealthChecker) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(h.checkInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.check(ctx)
			}
		}
	}()
}

// check runs one health check cycle: ping pools and evict idle ones.
func (h *ProductRouterHealthChecker) check(ctx context.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	var evicted int

	h.router.pools.Range(func(key, value interface{}) bool {
		cp := value.(*cachedPool)
		lastUsed := time.Unix(0, cp.lastUsed.Load())
		idle := now.Sub(lastUsed)

		// Evict idle pools.
		if idle > h.idleTimeout {
			evicted += h.evictPool(key, "idle", func() {
				if h.log != nil {
					h.log.Info("Evicted idle pool",
						zap.String("key", key.(string)),
						zap.Duration("idle", idle),
					)
				}
			})
			return true
		}

		// Ping active pools to verify health.
		pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if err := cp.pool.Ping(pingCtx); err != nil {
			if h.log != nil {
				h.log.Warn("Pool ping failed, evicting",
					zap.String("key", key.(string)),
					zap.Error(err),
				)
			}
			evicted += h.evictPool(key, "unhealthy", nil)
		}

		return true
	})

	if evicted > 0 && h.log != nil {
		h.log.Info("Health check completed",
			zap.Int("evicted", evicted),
			zap.Int32("remaining", h.router.poolCount.Load()),
		)
	}
}

// evictPool removes the pool at key, closes it, decrements the counter, and
// records a metric. The optional logFn is called before eviction for logging.
// Returns 1 if a pool was evicted, 0 otherwise.
func (h *ProductRouterHealthChecker) evictPool(key interface{}, reason string, logFn func()) int {
	removed, ok := h.router.pools.LoadAndDelete(key)
	if !ok {
		return 0
	}
	if logFn != nil {
		logFn()
	}
	removed.(*cachedPool).pool.Close()
	h.router.poolCount.Add(-1)
	if h.router.metrics != nil {
		h.router.metrics.PoolEvictions.WithLabelValues("unknown", reason).Inc()
	}
	return 1
}

// Status returns the current health status of all pools.
func (h *ProductRouterHealthChecker) Status() []PoolHealthStatus {
	var statuses []PoolHealthStatus
	now := time.Now()

	h.router.pools.Range(func(key, value interface{}) bool {
		cp := value.(*cachedPool)
		lastUsed := time.Unix(0, cp.lastUsed.Load())

		// Quick ping check.
		pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		healthy := cp.pool.Ping(pingCtx) == nil
		cancel()

		statuses = append(statuses, PoolHealthStatus{
			CacheKey:      key.(string),
			IsolationMode: cp.isolationMode,
			TenantID:      cp.tenantID,
			Healthy:       healthy,
			LastUsed:      lastUsed,
			IdleDuration:  now.Sub(lastUsed),
		})
		return true
	})

	return statuses
}
