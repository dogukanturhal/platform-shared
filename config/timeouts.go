// SPDX-License-Identifier: Apache-2.0

// Package config provides shared configuration types for platform services,
// including configurable timeout defaults that can be overridden via
// environment variables.
package config

import (
	"fmt"
	"time"
)

// TimeoutConfig holds timeout durations for various operation categories.
// Each value can be overridden via the corresponding environment variable.
type TimeoutConfig struct {
	// DatabaseQuery is the timeout for individual database queries.
	// Env: TIMEOUT_DATABASE_QUERY (default: 5s)
	DatabaseQuery time.Duration

	// HTTPRequest is the timeout for incoming HTTP request handling.
	// Env: TIMEOUT_HTTP_REQUEST (default: 10s)
	HTTPRequest time.Duration

	// ExternalAPI is the timeout for calls to external third-party APIs.
	// Env: TIMEOUT_EXTERNAL_API (default: 15s)
	ExternalAPI time.Duration

	// FileUpload is the timeout for file upload operations.
	// Env: TIMEOUT_FILE_UPLOAD (default: 60s)
	FileUpload time.Duration

	// BackgroundJob is the timeout for background processing jobs.
	// Env: TIMEOUT_BACKGROUND_JOB (default: 5m)
	BackgroundJob time.Duration

	// GracefulShutdown is the timeout for graceful server shutdown.
	// Env: TIMEOUT_GRACEFUL_SHUTDOWN (default: 30s)
	GracefulShutdown time.Duration
}

// DefaultTimeoutConfig returns a TimeoutConfig with sensible defaults
// suitable for most platform services.
func DefaultTimeoutConfig() TimeoutConfig {
	return TimeoutConfig{
		DatabaseQuery:    5 * time.Second,
		HTTPRequest:      10 * time.Second,
		ExternalAPI:      15 * time.Second,
		FileUpload:       60 * time.Second,
		BackgroundJob:    5 * time.Minute,
		GracefulShutdown: 30 * time.Second,
	}
}

// LoadTimeoutConfig reads timeout configuration from environment variables,
// falling back to defaults for any value not set. Environment variables:
//
//	TIMEOUT_DATABASE_QUERY    - database query timeout (default: 5s)
//	TIMEOUT_HTTP_REQUEST      - HTTP request timeout (default: 10s)
//	TIMEOUT_EXTERNAL_API      - external API call timeout (default: 15s)
//	TIMEOUT_FILE_UPLOAD       - file upload timeout (default: 60s)
//	TIMEOUT_BACKGROUND_JOB    - background job timeout (default: 5m)
//	TIMEOUT_GRACEFUL_SHUTDOWN - graceful shutdown timeout (default: 30s)
func LoadTimeoutConfig() TimeoutConfig {
	defaults := DefaultTimeoutConfig()

	return TimeoutConfig{
		DatabaseQuery:    GetEnvDuration("TIMEOUT_DATABASE_QUERY", defaults.DatabaseQuery),
		HTTPRequest:      GetEnvDuration("TIMEOUT_HTTP_REQUEST", defaults.HTTPRequest),
		ExternalAPI:      GetEnvDuration("TIMEOUT_EXTERNAL_API", defaults.ExternalAPI),
		FileUpload:       GetEnvDuration("TIMEOUT_FILE_UPLOAD", defaults.FileUpload),
		BackgroundJob:    GetEnvDuration("TIMEOUT_BACKGROUND_JOB", defaults.BackgroundJob),
		GracefulShutdown: GetEnvDuration("TIMEOUT_GRACEFUL_SHUTDOWN", defaults.GracefulShutdown),
	}
}

// String returns a human-readable summary of the timeout configuration,
// useful for startup logging.
func (c TimeoutConfig) String() string {
	return fmt.Sprintf(
		"TimeoutConfig{DatabaseQuery: %s, HTTPRequest: %s, ExternalAPI: %s, FileUpload: %s, BackgroundJob: %s, GracefulShutdown: %s}",
		c.DatabaseQuery,
		c.HTTPRequest,
		c.ExternalAPI,
		c.FileUpload,
		c.BackgroundJob,
		c.GracefulShutdown,
	)
}
