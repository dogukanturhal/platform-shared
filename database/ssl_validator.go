// SPDX-License-Identifier: Apache-2.0

// Package database provides shared database connection utilities.
// This file implements fail-fast SSL validation for production environments.
package database

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
)

// unsafeSSLModes are sslmode values that must not be used in production.
var unsafeSSLModes = []string{"disable", "prefer"}

// ValidateProductionSSL checks that a PostgreSQL DSN enforces encryption
// when ENVIRONMENT is set to "production". If an unsafe sslmode (disable or
// prefer) is detected, the process terminates with log.Fatal. If no sslmode
// parameter is present, a warning is logged (the default libpq behavior is
// "prefer" which is also unsafe).
//
// Call this function at startup before opening any database connection.
func ValidateProductionSSL(dsn string) {
	env := strings.ToLower(os.Getenv("ENVIRONMENT"))
	if env != "production" {
		return
	}

	mode, found := extractSSLMode(dsn)

	if !found {
		log.Fatalf("FATAL: production database DSN missing sslmode parameter. "+
			"Set sslmode=require or sslmode=verify-full. DSN host: %s", redactDSN(dsn))
	}

	mode = strings.ToLower(mode)
	for _, unsafe := range unsafeSSLModes {
		if mode == unsafe {
			log.Fatalf("FATAL: production database DSN has sslmode=%s which is insecure. "+
				"Use sslmode=require or sslmode=verify-full. DSN host: %s", mode, redactDSN(dsn))
		}
	}
}

// extractSSLMode parses the sslmode value from a PostgreSQL connection string.
// It supports both URI format (postgres://...) and key=value format.
func extractSSLMode(dsn string) (string, bool) {
	// Try URI format first
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		parsed, err := url.Parse(dsn)
		if err == nil {
			mode := parsed.Query().Get("sslmode")
			if mode != "" {
				return mode, true
			}
		}
	}

	// Try key=value format: "host=... sslmode=require ..."
	for _, part := range strings.Fields(dsn) {
		if strings.HasPrefix(strings.ToLower(part), "sslmode=") {
			return strings.SplitN(part, "=", 2)[1], true
		}
	}

	return "", false
}

// redactDSN returns a safe-to-log representation of the DSN, showing only the host.
func redactDSN(dsn string) string {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		parsed, err := url.Parse(dsn)
		if err == nil {
			return fmt.Sprintf("%s:***", parsed.Hostname())
		}
	}
	return "<redacted>"
}
