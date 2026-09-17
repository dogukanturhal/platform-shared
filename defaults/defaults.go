// SPDX-License-Identifier: Apache-2.0

// Package defaults provides common default values for HTTP server and application configuration.
package defaults

import "time"

// HTTP Server Timeouts
const (
	// HTTPReadTimeout is the maximum duration for reading the entire request
	HTTPReadTimeout = 15 * time.Second

	// HTTPReadTimeoutLong is for endpoints that handle file uploads or long operations
	HTTPReadTimeoutLong = 30 * time.Second

	// HTTPReadTimeoutXL is for document processing and very long operations
	HTTPReadTimeoutXL = 60 * time.Second

	// HTTPWriteTimeout is the maximum duration before timing out writes of the response
	HTTPWriteTimeout = 15 * time.Second

	// HTTPWriteTimeoutLong is for endpoints that return large responses
	HTTPWriteTimeoutLong = 30 * time.Second

	// HTTPWriteTimeoutXL is for document generation and very long operations
	HTTPWriteTimeoutXL = 60 * time.Second

	// HTTPIdleTimeout is the maximum amount of time to wait for the next request
	HTTPIdleTimeout = 60 * time.Second

	// HTTPIdleTimeoutLong is for WebSocket and SSE connections
	HTTPIdleTimeoutLong = 120 * time.Second
)

// Database Connection Pool Settings
const (
	// DBMaxConnections is the default maximum number of open connections
	DBMaxConnections = 25

	// DBMaxConnectionsLow is for services with light DB usage
	DBMaxConnectionsLow = 10

	// DBMaxConnectionsHigh is for services with heavy DB usage
	DBMaxConnectionsHigh = 50

	// DBMaxIdleConns is the default maximum number of idle connections
	DBMaxIdleConns = 5

	// DBMaxIdleConnsLow is for services with infrequent DB access
	DBMaxIdleConnsLow = 2

	// DBMaxIdleConnsHigh is for services with constant DB access
	DBMaxIdleConnsHigh = 10

	// DBConnMaxLifetime is the maximum lifetime of a connection
	DBConnMaxLifetime = 5 * time.Minute

	// DBConnMaxIdleTime is the maximum time a connection can be idle
	DBConnMaxIdleTime = 1 * time.Minute
)

// Redis Pool Settings
const (
	// RedisPoolSize is the default connection pool size
	RedisPoolSize = 10

	// RedisPoolSizeHigh is for services with heavy Redis usage
	RedisPoolSizeHigh = 20

	// RedisPoolTimeout is the timeout for getting a connection from the pool
	RedisPoolTimeout = 1 * time.Second

	// RedisReadTimeout is the timeout for socket reads
	RedisReadTimeout = 3 * time.Second

	// RedisWriteTimeout is the timeout for socket writes
	RedisWriteTimeout = 3 * time.Second
)

// Cache TTL Settings
const (
	// CacheTTLShort is for frequently changing data (5 minutes)
	CacheTTLShort = 5 * time.Minute

	// CacheTTLMedium is for moderately stable data (15 minutes)
	CacheTTLMedium = 15 * time.Minute

	// CacheTTLLong is for stable data (1 hour)
	CacheTTLLong = 1 * time.Hour

	// CacheTTLXL is for very stable data (6 hours)
	CacheTTLXL = 6 * time.Hour

	// CacheTTLDay is for daily data (24 hours)
	CacheTTLDay = 24 * time.Hour
)

// Kafka Settings
const (
	// KafkaBatchTimeout is the max time to wait before sending a batch
	KafkaBatchTimeout = 10 * time.Millisecond

	// KafkaReadTimeout is the timeout for reading messages
	KafkaReadTimeout = 10 * time.Second

	// KafkaWriteTimeout is the timeout for writing messages
	KafkaWriteTimeout = 10 * time.Second
)

// Context Timeouts
const (
	// ContextTimeoutShort is for quick operations (5 seconds)
	ContextTimeoutShort = 5 * time.Second

	// ContextTimeoutMedium is for normal operations (15 seconds)
	ContextTimeoutMedium = 15 * time.Second

	// ContextTimeoutLong is for slow operations (30 seconds)
	ContextTimeoutLong = 30 * time.Second

	// ContextTimeoutXL is for very slow operations (60 seconds)
	ContextTimeoutXL = 60 * time.Second
)

// Graceful Shutdown
const (
	// ShutdownTimeout is the maximum time to wait for graceful shutdown
	ShutdownTimeout = 30 * time.Second
)

// Rate Limiting
const (
	// RateLimitDefault is the default request limit per window
	RateLimitDefault = 100

	// RateLimitWindow is the default time window for rate limiting
	RateLimitWindow = 1 * time.Minute

	// RateLimitAuth is the limit for authentication endpoints
	RateLimitAuth = 5

	// RateLimitAuthWindow is the window for authentication rate limiting
	RateLimitAuthWindow = 1 * time.Minute
)
