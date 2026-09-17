// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// RecoveryMiddleware recovers from panics and returns 500 error.
// This is defense-in-depth - fix panic() calls directly, don't rely on this.
//
// Usage:
//
//	import (
//	    "github.com/dogukanturhal/platform-shared/logger"
//	    "github.com/dogukanturhal/platform-shared/middleware"
//	)
//
//	router := gin.New()
//	log := logger.MustNewLogger("info", "production")
//	router.Use(middleware.RecoveryMiddleware(log))
func RecoveryMiddleware(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				stack := string(debug.Stack())

				// Log the panic with full context
				log.Error("PANIC RECOVERED",
					zap.String("panic", fmt.Sprintf("%v", r)),
					zap.String("stack", stack),
					zap.String("path", c.Request.URL.Path),
					zap.String("method", c.Request.Method),
					zap.String("client_ip", c.ClientIP()),
					zap.String("tenant_id", c.GetHeader("X-Tenant-ID")),
					zap.String("user_id", c.GetHeader("X-User-ID")),
				)

				// Return generic error to client (don't leak internals)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error":   "internal_server_error",
					"message": "An unexpected error occurred. Please contact support if the problem persists.",
				})
			}
		}()
		c.Next()
	}
}
