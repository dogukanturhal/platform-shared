// SPDX-License-Identifier: Apache-2.0

// Package config provides shared configuration utilities and types for platform services.
package config

import (
	"os"
	"strconv"
	"time"
)

// Time duration constants for convenience
const (
	Day  = 24 * time.Hour
	Week = 7 * 24 * time.Hour
)

// GetEnv retrieves an environment variable with a default fallback.
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetEnvWithLookup retrieves an environment variable with a default fallback,
// using os.LookupEnv to distinguish between empty and unset variables.
func GetEnvWithLookup(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// GetEnvInt retrieves an integer environment variable with a default fallback.
// If parsing fails, returns the default value.
func GetEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// GetEnvInt64 retrieves an int64 environment variable with a default fallback.
// If parsing fails, returns the default value.
func GetEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// GetEnvBool retrieves a boolean environment variable with a default fallback.
// If parsing fails, returns the default value.
func GetEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

// GetEnvFloat64 retrieves a float64 environment variable with a default fallback.
// If parsing fails, returns the default value.
func GetEnvFloat64(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
			return floatVal
		}
	}
	return defaultValue
}

// GetEnvDuration retrieves a time.Duration environment variable with a default fallback.
// The value should be a string parseable by time.ParseDuration (e.g. "5s", "10m", "1h").
// If parsing fails, returns the default value.
func GetEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}
