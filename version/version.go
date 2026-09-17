// SPDX-License-Identifier: Apache-2.0

// Package version provides a standard /version endpoint for all services.
package version

import (
	"net/http"
	"runtime"

	"github.com/gin-gonic/gin"
)

// Build-time variables injected via ldflags:
//
//	go build -ldflags "-X version.Version=1.0.0 -X version.Commit=abc123 -X version.BuildTime=2026-03-01"
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// Info holds version metadata for a service.
type Info struct {
	Service   string `json:"service"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
}

// Handler returns a Gin handler for GET /version.
func Handler(serviceName string) gin.HandlerFunc {
	info := Info{
		Service:   serviceName,
		Version:   Version,
		Commit:    Commit,
		BuildTime: BuildTime,
		GoVersion: runtime.Version(),
	}
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, info)
	}
}
