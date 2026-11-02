// SPDX-License-Identifier: Apache-2.0

package quota

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CountProvider is implemented by the owning service: absolute counts for its keys,
// using the same predicate as its gate.
type CountProvider interface {
	Keys() []string
	// Count returns the tenant's current count for key. periodStart is set for flow keys.
	Count(ctx context.Context, tenant uuid.UUID, key string, periodStart *time.Time) (int64, error)
}

// CountsHandler serves the pull-recount contract POST /internal/v1/quota/counts. auth runs
// first (service JWT with quota:counts:read + tenant:act-as); the act-as X-Tenant-ID header
// must match the body's tenant_id. Keys the provider does not own are listed in "unknown".
func CountsHandler(p CountProvider, auth gin.HandlerFunc) gin.HandlerFunc {
	owned := map[string]bool{}
	for _, k := range p.Keys() {
		owned[k] = true
	}
	return func(c *gin.Context) {
		if auth != nil {
			auth(c)
			if c.IsAborted() {
				return
			}
		}
		var req struct {
			TenantID      uuid.UUID  `json:"tenant_id"`
			ResourceTypes []string   `json:"resource_types"`
			PeriodStart   *time.Time `json:"period_start"`
		}
		if c.ShouldBindJSON(&req) != nil || req.TenantID == uuid.Nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"code": "invalid_counts_request"})
			return
		}
		if c.GetHeader("X-Tenant-ID") != req.TenantID.String() {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": "forbidden"})
			return
		}
		type count struct {
			ResourceType string `json:"resource_type"`
			Value        int64  `json:"value"`
		}
		counts := []count{}
		unknown := []string{}
		keys := req.ResourceTypes
		if len(keys) == 0 {
			keys = p.Keys()
		}
		for _, k := range keys {
			if !owned[k] {
				unknown = append(unknown, k)
				continue
			}
			v, err := p.Count(c.Request.Context(), req.TenantID, k, req.PeriodStart)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"code": "count_failed", "resource_type": k})
				return
			}
			counts = append(counts, count{k, v})
		}
		c.JSON(http.StatusOK, gin.H{"tenant_id": req.TenantID, "as_of": time.Now().UTC(), "counts": counts, "unknown": unknown})
	}
}
