// SPDX-License-Identifier: Apache-2.0

//go:build integration
// +build integration

package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// TestDB holds the database connection for integration tests
type TestDB struct {
	db     *sql.DB
	schema string
}

// SetupTestDB creates a connection to the test database and creates a test schema
func SetupTestDB(t *testing.T) *TestDB {
	t.Helper()

	// Get connection string from env or use default
	host := getEnvOrDefault("POSTGRES_HOST", "localhost")
	port := getEnvOrDefault("POSTGRES_PORT", "5432")
	user := getEnvOrDefault("POSTGRES_USER", "hexxlock")
	password := getEnvOrDefault("POSTGRES_PASSWORD", "")
	dbname := getEnvOrDefault("POSTGRES_DB", "hexxlock_master")

	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	// Create unique test schema
	schema := fmt.Sprintf("test_shared_db_%s", uuid.New().String()[:8])

	_, err = db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema))
	if err != nil {
		t.Fatalf("Failed to create test schema: %v", err)
	}

	// Create required tables in test schema
	if err := createSharedTestTables(db, schema); err != nil {
		db.Exec(fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", schema))
		t.Fatalf("Failed to create test tables: %v", err)
	}

	return &TestDB{db: db, schema: schema}
}

// Cleanup drops the test schema
func (tdb *TestDB) Cleanup(t *testing.T) {
	t.Helper()
	if tdb.db != nil {
		_, err := tdb.db.Exec(fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", tdb.schema))
		if err != nil {
			t.Logf("Warning: failed to drop test schema: %v", err)
		}
		tdb.db.Close()
	}
}

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func createSharedTestTables(db *sql.DB, schema string) error {
	queries := []string{
		// Tenant connection registry table
		fmt.Sprintf(`
			CREATE TABLE IF NOT EXISTS %s.tenant_connections (
				tenant_id UUID PRIMARY KEY,
				strategy VARCHAR(50) NOT NULL,
				database_name VARCHAR(255),
				schema_name VARCHAR(255),
				host VARCHAR(255) NOT NULL,
				port INT NOT NULL DEFAULT 5432,
				username VARCHAR(255),
				connection_string_encrypted BYTEA,
				is_active BOOLEAN DEFAULT true,
				last_health_check TIMESTAMPTZ,
				health_status VARCHAR(20) DEFAULT 'unknown',
				created_at TIMESTAMPTZ DEFAULT NOW(),
				updated_at TIMESTAMPTZ DEFAULT NOW()
			)
		`, schema),

		// Tenant health records table
		fmt.Sprintf(`
			CREATE TABLE IF NOT EXISTS %s.tenant_health_records (
				id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
				tenant_id UUID NOT NULL,
				status VARCHAR(20) NOT NULL,
				latency_ms INT,
				error_message TEXT,
				checked_at TIMESTAMPTZ DEFAULT NOW()
			)
		`, schema),

		// Connection pool stats table
		fmt.Sprintf(`
			CREATE TABLE IF NOT EXISTS %s.connection_pool_stats (
				id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
				tenant_id UUID NOT NULL,
				pool_size INT,
				active_connections INT,
				idle_connections INT,
				wait_count INT,
				wait_duration_ms INT,
				recorded_at TIMESTAMPTZ DEFAULT NOW()
			)
		`, schema),

		// Create indexes
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_tenant_connections_active ON %s.tenant_connections(is_active)`, schema),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_health_records_tenant ON %s.tenant_health_records(tenant_id)`, schema),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_health_records_checked ON %s.tenant_health_records(checked_at)`, schema),
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %w\nQuery: %s", err, query)
		}
	}

	return nil
}

// =============================================================================
// Connection Registry Integration Tests
// =============================================================================

func TestTenantConnectionRegistry_Integration(t *testing.T) {
	tdb := SetupTestDB(t)
	defer tdb.Cleanup(t)

	ctx := context.Background()

	tenantID := uuid.New()

	t.Run("RegisterConnection", func(t *testing.T) {
		_, err := tdb.db.ExecContext(ctx, fmt.Sprintf(`
			INSERT INTO %s.tenant_connections
			(tenant_id, strategy, database_name, schema_name, host, port, username, is_active, health_status)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`, tdb.schema),
			tenantID, "schema", "hexxlock_master", "tenant_"+tenantID.String()[:8],
			"localhost", 5432, "tenant_user", true, "unknown",
		)
		if err != nil {
			t.Fatalf("Failed to register connection: %v", err)
		}

		// Verify registration
		var count int
		err = tdb.db.QueryRowContext(ctx, fmt.Sprintf(
			`SELECT COUNT(*) FROM %s.tenant_connections WHERE tenant_id = $1`,
			tdb.schema,
		), tenantID).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query: %v", err)
		}

		if count != 1 {
			t.Errorf("Expected 1 registration, got %d", count)
		}
	})

	t.Run("GetConnectionInfo", func(t *testing.T) {
		var strategy, dbName, schemaName, host string
		var port int
		err := tdb.db.QueryRowContext(ctx, fmt.Sprintf(`
			SELECT strategy, database_name, schema_name, host, port
			FROM %s.tenant_connections WHERE tenant_id = $1
		`, tdb.schema), tenantID).Scan(&strategy, &dbName, &schemaName, &host, &port)
		if err != nil {
			t.Fatalf("Failed to get connection info: %v", err)
		}

		if strategy != "schema" {
			t.Errorf("Expected strategy 'schema', got '%s'", strategy)
		}

		if host != "localhost" {
			t.Errorf("Expected host 'localhost', got '%s'", host)
		}

		if port != 5432 {
			t.Errorf("Expected port 5432, got %d", port)
		}
	})

	t.Run("UpdateHealthStatus", func(t *testing.T) {
		_, err := tdb.db.ExecContext(ctx, fmt.Sprintf(`
			UPDATE %s.tenant_connections
			SET health_status = $1, last_health_check = NOW(), updated_at = NOW()
			WHERE tenant_id = $2
		`, tdb.schema), "healthy", tenantID)
		if err != nil {
			t.Fatalf("Failed to update health status: %v", err)
		}

		var status string
		var lastCheck *time.Time
		err = tdb.db.QueryRowContext(ctx, fmt.Sprintf(`
			SELECT health_status, last_health_check FROM %s.tenant_connections WHERE tenant_id = $1
		`, tdb.schema), tenantID).Scan(&status, &lastCheck)
		if err != nil {
			t.Fatalf("Failed to query: %v", err)
		}

		if status != "healthy" {
			t.Errorf("Expected status 'healthy', got '%s'", status)
		}

		if lastCheck == nil {
			t.Error("Expected last_health_check to be set")
		}
	})

	t.Run("DeactivateConnection", func(t *testing.T) {
		_, err := tdb.db.ExecContext(ctx, fmt.Sprintf(`
			UPDATE %s.tenant_connections
			SET is_active = false, updated_at = NOW()
			WHERE tenant_id = $1
		`, tdb.schema), tenantID)
		if err != nil {
			t.Fatalf("Failed to deactivate connection: %v", err)
		}

		var isActive bool
		err = tdb.db.QueryRowContext(ctx, fmt.Sprintf(`
			SELECT is_active FROM %s.tenant_connections WHERE tenant_id = $1
		`, tdb.schema), tenantID).Scan(&isActive)
		if err != nil {
			t.Fatalf("Failed to query: %v", err)
		}

		if isActive {
			t.Error("Expected connection to be inactive")
		}
	})

	t.Run("ListActiveConnections", func(t *testing.T) {
		// Create more tenants
		tenant2ID := uuid.New()
		tenant3ID := uuid.New()

		_, err := tdb.db.ExecContext(ctx, fmt.Sprintf(`
			INSERT INTO %s.tenant_connections
			(tenant_id, strategy, host, port, is_active, health_status)
			VALUES ($1, $2, $3, $4, $5, $6), ($7, $8, $9, $10, $11, $12)
		`, tdb.schema),
			tenant2ID, "schema", "localhost", 5432, true, "healthy",
			tenant3ID, "database", "localhost", 5432, true, "healthy",
		)
		if err != nil {
			t.Fatalf("Failed to create more connections: %v", err)
		}

		// List active connections
		rows, err := tdb.db.QueryContext(ctx, fmt.Sprintf(`
			SELECT tenant_id, strategy FROM %s.tenant_connections WHERE is_active = true
		`, tdb.schema))
		if err != nil {
			t.Fatalf("Failed to list connections: %v", err)
		}
		defer rows.Close()

		var count int
		for rows.Next() {
			count++
		}

		if count != 2 {
			t.Errorf("Expected 2 active connections, got %d", count)
		}
	})
}

// =============================================================================
// Health Recording Integration Tests
// =============================================================================

func TestHealthRecording_Integration(t *testing.T) {
	tdb := SetupTestDB(t)
	defer tdb.Cleanup(t)

	ctx := context.Background()

	tenantID := uuid.New()

	t.Run("RecordHealthCheck", func(t *testing.T) {
		_, err := tdb.db.ExecContext(ctx, fmt.Sprintf(`
			INSERT INTO %s.tenant_health_records
			(tenant_id, status, latency_ms, error_message)
			VALUES ($1, $2, $3, $4)
		`, tdb.schema), tenantID, "healthy", 15, nil)
		if err != nil {
			t.Fatalf("Failed to record health check: %v", err)
		}

		var count int
		err = tdb.db.QueryRowContext(ctx, fmt.Sprintf(
			`SELECT COUNT(*) FROM %s.tenant_health_records WHERE tenant_id = $1`,
			tdb.schema,
		), tenantID).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query: %v", err)
		}

		if count != 1 {
			t.Errorf("Expected 1 record, got %d", count)
		}
	})

	t.Run("RecordMultipleHealthChecks", func(t *testing.T) {
		// Record several health checks
		checks := []struct {
			status    string
			latencyMs int
			errMsg    *string
		}{
			{"healthy", 20, nil},
			{"healthy", 18, nil},
			{"degraded", 150, nil},
			{"unhealthy", 0, strPtr("connection timeout")},
			{"healthy", 12, nil},
		}

		for _, c := range checks {
			_, err := tdb.db.ExecContext(ctx, fmt.Sprintf(`
				INSERT INTO %s.tenant_health_records
				(tenant_id, status, latency_ms, error_message)
				VALUES ($1, $2, $3, $4)
			`, tdb.schema), tenantID, c.status, c.latencyMs, c.errMsg)
			if err != nil {
				t.Fatalf("Failed to record health check: %v", err)
			}
		}

		// Query all records
		var count int
		err := tdb.db.QueryRowContext(ctx, fmt.Sprintf(
			`SELECT COUNT(*) FROM %s.tenant_health_records WHERE tenant_id = $1`,
			tdb.schema,
		), tenantID).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query: %v", err)
		}

		// 1 from previous test + 5 from this one
		if count != 6 {
			t.Errorf("Expected 6 records, got %d", count)
		}
	})

	t.Run("GetRecentHealthHistory", func(t *testing.T) {
		rows, err := tdb.db.QueryContext(ctx, fmt.Sprintf(`
			SELECT status, latency_ms, error_message, checked_at
			FROM %s.tenant_health_records
			WHERE tenant_id = $1
			ORDER BY checked_at DESC
			LIMIT 5
		`, tdb.schema), tenantID)
		if err != nil {
			t.Fatalf("Failed to get history: %v", err)
		}
		defer rows.Close()

		var count int
		var lastStatus string
		for rows.Next() {
			var status string
			var latencyMs int
			var errMsg *string
			var checkedAt time.Time

			if err := rows.Scan(&status, &latencyMs, &errMsg, &checkedAt); err != nil {
				t.Fatalf("Failed to scan row: %v", err)
			}

			if count == 0 {
				lastStatus = status
			}
			count++
		}

		if count != 5 {
			t.Errorf("Expected 5 recent records, got %d", count)
		}

		// Most recent should be 'healthy' (last insert)
		if lastStatus != "healthy" {
			t.Errorf("Expected most recent status to be 'healthy', got '%s'", lastStatus)
		}
	})

	t.Run("CalculateHealthStats", func(t *testing.T) {
		var totalChecks, healthyChecks, unhealthyChecks int
		var avgLatency float64

		err := tdb.db.QueryRowContext(ctx, fmt.Sprintf(`
			SELECT
				COUNT(*) as total,
				COUNT(*) FILTER (WHERE status = 'healthy') as healthy,
				COUNT(*) FILTER (WHERE status = 'unhealthy') as unhealthy,
				AVG(latency_ms) as avg_latency
			FROM %s.tenant_health_records
			WHERE tenant_id = $1
		`, tdb.schema), tenantID).Scan(&totalChecks, &healthyChecks, &unhealthyChecks, &avgLatency)
		if err != nil {
			t.Fatalf("Failed to calculate stats: %v", err)
		}

		if totalChecks != 6 {
			t.Errorf("Expected 6 total checks, got %d", totalChecks)
		}

		if healthyChecks != 4 {
			t.Errorf("Expected 4 healthy checks, got %d", healthyChecks)
		}

		if unhealthyChecks != 1 {
			t.Errorf("Expected 1 unhealthy check, got %d", unhealthyChecks)
		}

		t.Logf("Average latency: %.2f ms", avgLatency)
	})

	t.Run("PruneOldRecords", func(t *testing.T) {
		// Insert an old record
		_, err := tdb.db.ExecContext(ctx, fmt.Sprintf(`
			INSERT INTO %s.tenant_health_records
			(tenant_id, status, latency_ms, checked_at)
			VALUES ($1, $2, $3, $4)
		`, tdb.schema), tenantID, "healthy", 10, time.Now().Add(-48*time.Hour))
		if err != nil {
			t.Fatalf("Failed to insert old record: %v", err)
		}

		// Prune records older than 24 hours
		result, err := tdb.db.ExecContext(ctx, fmt.Sprintf(`
			DELETE FROM %s.tenant_health_records
			WHERE checked_at < NOW() - INTERVAL '24 hours'
		`, tdb.schema))
		if err != nil {
			t.Fatalf("Failed to prune: %v", err)
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected != 1 {
			t.Errorf("Expected 1 row pruned, got %d", rowsAffected)
		}
	})
}

// =============================================================================
// Connection Pool Stats Integration Tests
// =============================================================================

func TestConnectionPoolStats_Integration(t *testing.T) {
	tdb := SetupTestDB(t)
	defer tdb.Cleanup(t)

	ctx := context.Background()

	tenantID := uuid.New()

	t.Run("RecordPoolStats", func(t *testing.T) {
		_, err := tdb.db.ExecContext(ctx, fmt.Sprintf(`
			INSERT INTO %s.connection_pool_stats
			(tenant_id, pool_size, active_connections, idle_connections, wait_count, wait_duration_ms)
			VALUES ($1, $2, $3, $4, $5, $6)
		`, tdb.schema), tenantID, 10, 5, 5, 0, 0)
		if err != nil {
			t.Fatalf("Failed to record pool stats: %v", err)
		}
	})

	t.Run("RecordPoolStatsTimeSeries", func(t *testing.T) {
		// Record multiple stats over time
		for i := 0; i < 5; i++ {
			active := 3 + i
			idle := 10 - active
			waitCount := i * 2
			waitDuration := waitCount * 50

			_, err := tdb.db.ExecContext(ctx, fmt.Sprintf(`
				INSERT INTO %s.connection_pool_stats
				(tenant_id, pool_size, active_connections, idle_connections, wait_count, wait_duration_ms)
				VALUES ($1, $2, $3, $4, $5, $6)
			`, tdb.schema), tenantID, 10, active, idle, waitCount, waitDuration)
			if err != nil {
				t.Fatalf("Failed to record stats: %v", err)
			}
		}

		// Get pool utilization trend
		rows, err := tdb.db.QueryContext(ctx, fmt.Sprintf(`
			SELECT
				active_connections,
				idle_connections,
				pool_size,
				(active_connections::float / pool_size * 100) as utilization_pct,
				recorded_at
			FROM %s.connection_pool_stats
			WHERE tenant_id = $1
			ORDER BY recorded_at DESC
			LIMIT 5
		`, tdb.schema), tenantID)
		if err != nil {
			t.Fatalf("Failed to get stats: %v", err)
		}
		defer rows.Close()

		var count int
		for rows.Next() {
			var active, idle, poolSize int
			var utilization float64
			var recordedAt time.Time

			if err := rows.Scan(&active, &idle, &poolSize, &utilization, &recordedAt); err != nil {
				t.Fatalf("Failed to scan: %v", err)
			}

			t.Logf("Pool: %d/%d active, utilization: %.1f%%", active, poolSize, utilization)
			count++
		}

		if count != 5 {
			t.Errorf("Expected 5 stats records, got %d", count)
		}
	})

	t.Run("GetPoolPressureMetrics", func(t *testing.T) {
		var avgWaitCount float64
		var maxWaitDuration int

		err := tdb.db.QueryRowContext(ctx, fmt.Sprintf(`
			SELECT
				AVG(wait_count) as avg_wait,
				MAX(wait_duration_ms) as max_wait_duration
			FROM %s.connection_pool_stats
			WHERE tenant_id = $1
			AND recorded_at > NOW() - INTERVAL '1 hour'
		`, tdb.schema), tenantID).Scan(&avgWaitCount, &maxWaitDuration)
		if err != nil {
			t.Fatalf("Failed to get pressure metrics: %v", err)
		}

		t.Logf("Pool pressure: avg wait count=%.2f, max wait duration=%dms", avgWaitCount, maxWaitDuration)
	})
}

// =============================================================================
// Full Health Monitoring Flow Integration Test
// =============================================================================

func TestHealthMonitoringFlow_Integration(t *testing.T) {
	tdb := SetupTestDB(t)
	defer tdb.Cleanup(t)

	ctx := context.Background()

	tenantID := uuid.New()

	t.Run("Step1_RegisterTenantConnection", func(t *testing.T) {
		_, err := tdb.db.ExecContext(ctx, fmt.Sprintf(`
			INSERT INTO %s.tenant_connections
			(tenant_id, strategy, database_name, schema_name, host, port, is_active, health_status)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, tdb.schema),
			tenantID, "schema", "hexxlock_master", "tenant_test",
			"localhost", 5432, true, "unknown",
		)
		if err != nil {
			t.Fatalf("Failed to register: %v", err)
		}
	})

	t.Run("Step2_SimulateHealthChecks", func(t *testing.T) {
		// Simulate 10 health checks with varying results
		statuses := []string{
			"healthy", "healthy", "healthy", "degraded", "healthy",
			"healthy", "unhealthy", "unhealthy", "healthy", "healthy",
		}
		latencies := []int{15, 18, 22, 150, 25, 20, 5000, 0, 30, 18}

		for i, status := range statuses {
			var errMsg *string
			if status == "unhealthy" {
				errMsg = strPtr("connection timeout")
			}

			_, err := tdb.db.ExecContext(ctx, fmt.Sprintf(`
				INSERT INTO %s.tenant_health_records
				(tenant_id, status, latency_ms, error_message)
				VALUES ($1, $2, $3, $4)
			`, tdb.schema), tenantID, status, latencies[i], errMsg)
			if err != nil {
				t.Fatalf("Failed to record health: %v", err)
			}

			// Update connection status
			_, err = tdb.db.ExecContext(ctx, fmt.Sprintf(`
				UPDATE %s.tenant_connections
				SET health_status = $1, last_health_check = NOW(), updated_at = NOW()
				WHERE tenant_id = $2
			`, tdb.schema), status, tenantID)
			if err != nil {
				t.Fatalf("Failed to update status: %v", err)
			}
		}
	})

	t.Run("Step3_AnalyzeHealthHistory", func(t *testing.T) {
		// Calculate health metrics
		var totalChecks, healthyChecks, degradedChecks, unhealthyChecks int
		var avgLatency, maxLatency float64
		var currentStatus string

		err := tdb.db.QueryRowContext(ctx, fmt.Sprintf(`
			SELECT
				COUNT(*) as total,
				COUNT(*) FILTER (WHERE status = 'healthy') as healthy,
				COUNT(*) FILTER (WHERE status = 'degraded') as degraded,
				COUNT(*) FILTER (WHERE status = 'unhealthy') as unhealthy,
				AVG(latency_ms) as avg_latency,
				MAX(latency_ms) as max_latency
			FROM %s.tenant_health_records
			WHERE tenant_id = $1
		`, tdb.schema), tenantID).Scan(
			&totalChecks, &healthyChecks, &degradedChecks, &unhealthyChecks,
			&avgLatency, &maxLatency,
		)
		if err != nil {
			t.Fatalf("Failed to analyze: %v", err)
		}

		// Get current status from connection registry
		err = tdb.db.QueryRowContext(ctx, fmt.Sprintf(`
			SELECT health_status FROM %s.tenant_connections WHERE tenant_id = $1
		`, tdb.schema), tenantID).Scan(&currentStatus)
		if err != nil {
			t.Fatalf("Failed to get current status: %v", err)
		}

		t.Logf("Health Summary:")
		t.Logf("  Total checks: %d", totalChecks)
		t.Logf("  Healthy: %d (%.1f%%)", healthyChecks, float64(healthyChecks)/float64(totalChecks)*100)
		t.Logf("  Degraded: %d (%.1f%%)", degradedChecks, float64(degradedChecks)/float64(totalChecks)*100)
		t.Logf("  Unhealthy: %d (%.1f%%)", unhealthyChecks, float64(unhealthyChecks)/float64(totalChecks)*100)
		t.Logf("  Avg latency: %.1f ms", avgLatency)
		t.Logf("  Max latency: %.1f ms", maxLatency)
		t.Logf("  Current status: %s", currentStatus)

		// Verify counts
		if totalChecks != 10 {
			t.Errorf("Expected 10 total checks, got %d", totalChecks)
		}
		if currentStatus != "healthy" {
			t.Errorf("Expected current status 'healthy', got '%s'", currentStatus)
		}
	})

	t.Run("Step4_DetectConsecutiveFailures", func(t *testing.T) {
		// Query for patterns of consecutive failures
		rows, err := tdb.db.QueryContext(ctx, fmt.Sprintf(`
			WITH numbered AS (
				SELECT
					status,
					checked_at,
					ROW_NUMBER() OVER (ORDER BY checked_at) as rn
				FROM %s.tenant_health_records
				WHERE tenant_id = $1
			)
			SELECT status, checked_at
			FROM numbered
			WHERE status = 'unhealthy'
			ORDER BY checked_at
		`, tdb.schema), tenantID)
		if err != nil {
			t.Fatalf("Failed to detect failures: %v", err)
		}
		defer rows.Close()

		var failureCount int
		for rows.Next() {
			failureCount++
		}

		t.Logf("Detected %d unhealthy checks", failureCount)

		if failureCount != 2 {
			t.Errorf("Expected 2 unhealthy checks, got %d", failureCount)
		}
	})

	t.Run("Step5_CalculateAvailability", func(t *testing.T) {
		// Calculate availability percentage over the recorded period
		var availability float64
		err := tdb.db.QueryRowContext(ctx, fmt.Sprintf(`
			SELECT
				(COUNT(*) FILTER (WHERE status = 'healthy')::float / COUNT(*)) * 100 as availability
			FROM %s.tenant_health_records
			WHERE tenant_id = $1
		`, tdb.schema), tenantID).Scan(&availability)
		if err != nil {
			t.Fatalf("Failed to calculate availability: %v", err)
		}

		t.Logf("Availability: %.2f%%", availability)

		// Expect 70% availability (7 healthy out of 10)
		if availability < 60 || availability > 80 {
			t.Errorf("Expected availability around 70%%, got %.2f%%", availability)
		}
	})
}

func strPtr(s string) *string {
	return &s
}
