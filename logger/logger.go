// SPDX-License-Identifier: Apache-2.0

// Package logger provides a simple zap-based logger factory for platform services.
package logger

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// NewLogger creates a new zap logger with the specified level and environment.
// It returns the logger instance and any error encountered during initialization.
//
// Parameters:
//   - level: Log level (debug, info, warn, error, fatal)
//   - environment: Environment name (production, development, staging, etc.)
//
// Production mode uses JSON encoding, development mode uses colored console encoding.
func NewLogger(level string, environment string) (*zap.Logger, error) {
	var config zap.Config

	if environment == "production" {
		config = zap.NewProductionConfig()
	} else {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	// Parse log level
	parsedLevel, err := zapcore.ParseLevel(level)
	if err != nil {
		parsedLevel = zapcore.DebugLevel
	}
	config.Level = zap.NewAtomicLevelAt(parsedLevel)

	config.OutputPaths = []string{"stdout"}
	config.ErrorOutputPaths = []string{"stderr"}

	logger, err := config.Build(
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)
	if err != nil {
		return nil, fmt.Errorf("NewLogger: %w", err)
	}

	return logger, nil
}

// MustNewLogger creates a new logger and panics if initialization fails.
// Use this for application bootstrap when logger initialization failure
// should be fatal.
func MustNewLogger(level string, environment string) *zap.Logger {
	logger, err := NewLogger(level, environment)
	if err != nil {
		_, _ = os.Stderr.WriteString("FATAL: Failed to initialize logger: " + err.Error() + "\n")
		os.Exit(1)
	}
	return logger
}

// NewSecurityAuditLogger creates a sub-logger for security audit events.
// All entries from this logger will have "log_type": "security_audit" field,
// making it easy to filter and route security-relevant log lines.
func NewSecurityAuditLogger(baseLogger *zap.Logger) *zap.Logger {
	return baseLogger.With(zap.String("log_type", "security_audit"))
}

// NewNopLogger returns a no-op logger for testing.
func NewNopLogger() *zap.Logger {
	return zap.NewNop()
}
