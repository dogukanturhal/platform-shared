// SPDX-License-Identifier: Apache-2.0

package quota

import (
	"context"
	"time"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// QuotaMiddleware creates middleware that checks quota before allowing requests
// resourceType: the type of resource to check
// amountFunc: optional function to calculate the amount to check (default 1)
func QuotaMiddleware(client *QuotaClient, resourceType ResourceType, amountFunc func(*gin.Context) int64) gin.HandlerFunc { //nolint:revive // public API stability
	return func(c *gin.Context) {
		// Get tenant ID from context or header
		tenantID, err := getTenantID(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or missing tenant ID"})
			c.Abort()
			return
		}

		// Calculate amount
		amount := int64(1)
		if amountFunc != nil {
			amount = amountFunc(c)
		}

		// Check quota
		result, err := client.CheckQuota(c.Request.Context(), tenantID, resourceType, amount)
		if err != nil {
			// Log error but continue (fail-open)
			c.Set("quota_check_error", err.Error())
			c.Next()
			return
		}

		// Set quota info in context
		c.Set("quota_allowed", result.Allowed)
		c.Set("quota_status", result.Status)
		c.Set("quota_current_usage", result.CurrentUsage)
		c.Set("quota_limit", result.EffectiveLimit)
		c.Set("quota_remaining", result.Remaining)

		// Block if quota exceeded
		if !result.Allowed {
			c.JSON(http.StatusForbidden, gin.H{
				"error":         "Quota exceeded",
				"resource_type": resourceType,
				"current_usage": result.CurrentUsage,
				"limit":         result.EffectiveLimit,
				"message":       result.Message,
			})
			c.Abort()
			return
		}

		// Add warning header if approaching limit
		if result.Status == QuotaStatusWarning {
			c.Header("X-Quota-Warning", result.Message)
			c.Header("X-Quota-Remaining", strconv.FormatInt(result.Remaining, 10))
		}

		c.Next()
	}
}

// QuotaIncrementMiddleware increments quota usage after successful request
func QuotaIncrementMiddleware(client *QuotaClient, resourceType ResourceType, shouldIncrement func(*gin.Context) bool) gin.HandlerFunc { //nolint:revive // public API stability
	return func(c *gin.Context) {
		c.Next()

		// Only increment if request was successful
		if c.Writer.Status() >= 200 && c.Writer.Status() < 300 {
			if shouldIncrement == nil || shouldIncrement(c) {
				tenantID, err := getTenantID(c)
				if err != nil {
					return
				}

				// DETACHED context, deliberately: c.Request.Context() is
				// canceled the instant the response completes, which
				// killed every one of these goroutines mid-flight — the
				// increment silently never reached quota-service (found
				// live 2026-06-06 wiring marketing-automation workflows;
				// affects every adopter of this middleware).
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_, _ = client.IncrementUsage(ctx, tenantID, resourceType, 1)
				}()
			}
		}
	}
}

// QuotaDecrementMiddleware decrements quota usage after successful delete
func QuotaDecrementMiddleware(client *QuotaClient, resourceType ResourceType) gin.HandlerFunc { //nolint:revive // public API stability
	return func(c *gin.Context) {
		c.Next()

		// Only decrement if request was successful
		if c.Writer.Status() >= 200 && c.Writer.Status() < 300 {
			tenantID, err := getTenantID(c)
			if err != nil {
				return
			}

			// Detached context — same post-response cancellation trap as
			// QuotaIncrementMiddleware above.
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = client.DecrementUsage(ctx, tenantID, resourceType, 1)
			}()
		}
	}
}

// Helper to get tenant ID from context or header
func getTenantID(c *gin.Context) (uuid.UUID, error) {
	// Try to get from context first (set by auth middleware)
	if id, exists := c.Get("tenant_id"); exists {
		if tenantID, ok := id.(uuid.UUID); ok {
			return tenantID, nil
		}
		if tenantIDStr, ok := id.(string); ok {
			return uuid.Parse(tenantIDStr)
		}
	}

	// Try to get from header
	tenantIDStr := c.GetHeader("X-Tenant-ID")
	if tenantIDStr != "" {
		return uuid.Parse(tenantIDStr)
	}

	return uuid.Nil, &QuotaExceededError{Message: "Tenant ID not found"}
}

// QuotaInfo holds quota information that can be added to responses
type QuotaInfo struct { //nolint:revive // public API stability
	ResourceType ResourceType `json:"resource_type"`
	CurrentUsage int64        `json:"current_usage"`
	Limit        int64        `json:"limit"`
	Remaining    int64        `json:"remaining"`
	Status       QuotaStatus  `json:"status"`
}

// GetQuotaInfoFromContext extracts quota info from gin context
func GetQuotaInfoFromContext(c *gin.Context, resourceType ResourceType) *QuotaInfo {
	allowed, _ := c.Get("quota_allowed")
	if allowed == nil {
		return nil
	}

	status, _ := c.Get("quota_status")
	currentUsage, _ := c.Get("quota_current_usage")
	limit, _ := c.Get("quota_limit")
	remaining, _ := c.Get("quota_remaining")

	return &QuotaInfo{
		ResourceType: resourceType,
		CurrentUsage: currentUsage.(int64),
		Limit:        limit.(int64),
		Remaining:    remaining.(int64),
		Status:       status.(QuotaStatus),
	}
}
