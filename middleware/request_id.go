// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RequestID generates or propagates a unique request ID for every request.
// If the client sends X-Request-ID, it is reused; otherwise a new UUID is generated.
// The ID is stored in the Gin context as "request_id" and returned in the response header.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

// CorrelationID propagates a correlation ID through multi-service call chains.
// Each service appends its name to X-Correlation-Chain, enabling distributed tracing.
func CorrelationID(serviceName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		correlationID := c.GetHeader("X-Correlation-ID")
		if correlationID == "" {
			correlationID = uuid.New().String()
		}

		chain := c.GetHeader("X-Correlation-Chain")
		if chain != "" {
			chain += "," + serviceName
		} else {
			chain = serviceName
		}

		c.Set("correlation_id", correlationID)
		c.Set("correlation_chain", chain)
		c.Header("X-Correlation-ID", correlationID)
		c.Header("X-Correlation-Chain", chain)
		c.Next()
	}
}
