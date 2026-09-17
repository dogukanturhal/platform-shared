// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ============================================
// Mock TenantConnectionManager for testing
// ============================================

type MockTenantConnectionManager struct {
	mu              sync.Mutex
	connections     map[uuid.UUID]*MockDB
	defaultDB       *MockDB
	getConnErr      error
	invalidateCalls []uuid.UUID
}

type MockDB struct {
	pingErr   error
	pingDelay time.Duration
}

func (m *MockDB) PingContext(_ context.Context) error {
	if m.pingDelay > 0 {
		time.Sleep(m.pingDelay)
	}
	return m.pingErr
}

func (m *MockDB) QueryRowContext(_ context.Context, _ string, _ ...interface{}) *sql.Row {
	return nil // Not used in basic tests
}

func (m *MockDB) Stats() sql.DBStats {
	return sql.DBStats{
		MaxOpenConnections: 10,
		OpenConnections:    5,
		InUse:              2,
		Idle:               3,
	}
}

func NewMockTenantConnectionManager() *MockTenantConnectionManager {
	return &MockTenantConnectionManager{
		connections:     make(map[uuid.UUID]*MockDB),
		defaultDB:       &MockDB{},
		invalidateCalls: make([]uuid.UUID, 0),
	}
}

func (m *MockTenantConnectionManager) GetConnection(_ context.Context, _ uuid.UUID) (*sql.DB, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.getConnErr != nil {
		return nil, m.getConnErr
	}

	// Return nil but no error - tests will use mockDB methods directly
	return nil, nil
}

func (m *MockTenantConnectionManager) InvalidateCache(_ context.Context, tenantID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invalidateCalls = append(m.invalidateCalls, tenantID)
	return nil
}

func (m *MockTenantConnectionManager) SetConnectionError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getConnErr = err
}

func (m *MockTenantConnectionManager) GetInvalidateCalls() []uuid.UUID {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.invalidateCalls
}

// ============================================
// Mock HealthSubscriber for testing
// ============================================

type MockHealthSubscriber struct {
	mu       sync.Mutex
	calls    []healthChangeCall
	callback func(uuid.UUID, HealthStatus, HealthStatus)
}

type healthChangeCall struct {
	TenantID  uuid.UUID
	OldStatus HealthStatus
	NewStatus HealthStatus
}

func NewMockHealthSubscriber() *MockHealthSubscriber {
	return &MockHealthSubscriber{
		calls: make([]healthChangeCall, 0),
	}
}

func (m *MockHealthSubscriber) OnHealthChange(tenantID uuid.UUID, oldStatus, newStatus HealthStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, healthChangeCall{
		TenantID:  tenantID,
		OldStatus: oldStatus,
		NewStatus: newStatus,
	})
	if m.callback != nil {
		m.callback(tenantID, oldStatus, newStatus)
	}
}

func (m *MockHealthSubscriber) GetCalls() []healthChangeCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]healthChangeCall, len(m.calls))
	copy(result, m.calls)
	return result
}

// ============================================
// Unit Tests for DefaultHealthCheckerConfig
// ============================================

func TestDefaultHealthCheckerConfig(t *testing.T) {
	config := DefaultHealthCheckerConfig()

	if config.Interval != 30*time.Second {
		t.Errorf("Interval = %v, want 30s", config.Interval)
	}
	if config.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", config.Timeout)
	}
	if config.UnhealthyThreshold != 3 {
		t.Errorf("UnhealthyThreshold = %d, want 3", config.UnhealthyThreshold)
	}
	if config.DegradedThreshold != 1 {
		t.Errorf("DegradedThreshold = %d, want 1", config.DegradedThreshold)
	}
	if !config.EvictUnhealthy {
		t.Error("EvictUnhealthy should be true")
	}
	if config.MaxLatency != 1*time.Second {
		t.Errorf("MaxLatency = %v, want 1s", config.MaxLatency)
	}
	if config.RecoveryChecks != 2 {
		t.Errorf("RecoveryChecks = %d, want 2", config.RecoveryChecks)
	}
}

// ============================================
// Unit Tests for HealthChecker lifecycle
// ============================================

func TestHealthChecker_StartStop(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	hc := NewHealthChecker(cm, config)

	ctx := context.Background()

	// Start
	hc.Start(ctx)
	if !hc.running {
		t.Error("HealthChecker should be running after Start()")
	}

	// Start again should be no-op
	hc.Start(ctx)
	if !hc.running {
		t.Error("HealthChecker should still be running")
	}

	// Stop
	hc.Stop()
	if hc.running {
		t.Error("HealthChecker should not be running after Stop()")
	}

	// Stop again should be no-op
	hc.Stop()
}

// ============================================
// Unit Tests for RegisterTenant / UnregisterTenant
// ============================================

func TestHealthChecker_RegisterUnregisterTenant(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	hc := NewHealthChecker(cm, config)

	tenantID := uuid.New()

	// Register tenant
	hc.RegisterTenant(tenantID)

	// Should have a record with unknown status
	status := hc.GetHealthStatus(tenantID)
	if status.Status != HealthStatusUnknown {
		t.Errorf("Status = %s, want %s", status.Status, HealthStatusUnknown)
	}

	// Unregister tenant
	hc.UnregisterTenant(tenantID)

	// Should still return unknown (no record)
	status = hc.GetHealthStatus(tenantID)
	if status.Status != HealthStatusUnknown {
		t.Errorf("Status after unregister = %s, want %s", status.Status, HealthStatusUnknown)
	}
}

// ============================================
// Unit Tests for GetHealthStatus
// ============================================

func TestHealthChecker_GetHealthStatus_UnknownTenant(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	hc := NewHealthChecker(cm, config)

	unknownID := uuid.New()
	status := hc.GetHealthStatus(unknownID)

	if status.TenantID != unknownID {
		t.Errorf("TenantID = %v, want %v", status.TenantID, unknownID)
	}
	if status.Status != HealthStatusUnknown {
		t.Errorf("Status = %s, want %s", status.Status, HealthStatusUnknown)
	}
}

// ============================================
// Unit Tests for MarkUnhealthy
// ============================================

func TestHealthChecker_MarkUnhealthy(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	config.EvictUnhealthy = false // Disable to avoid nil pointer
	hc := NewHealthChecker(cm, config)

	tenantID := uuid.New()
	hc.RegisterTenant(tenantID)

	// Add subscriber
	subscriber := NewMockHealthSubscriber()
	hc.Subscribe(subscriber)

	// Mark unhealthy
	hc.MarkUnhealthy(tenantID, "test reason")

	// Give time for async notification
	time.Sleep(50 * time.Millisecond)

	status := hc.GetHealthStatus(tenantID)
	if status.Status != HealthStatusUnhealthy {
		t.Errorf("Status = %s, want %s", status.Status, HealthStatusUnhealthy)
	}

	// Should have notified subscriber
	calls := subscriber.GetCalls()
	if len(calls) != 1 {
		t.Fatalf("Subscriber calls = %d, want 1", len(calls))
	}

	if calls[0].NewStatus != HealthStatusUnhealthy {
		t.Errorf("Notification NewStatus = %s, want %s", calls[0].NewStatus, HealthStatusUnhealthy)
	}
}

// ============================================
// Unit Tests for Subscribe
// ============================================

func TestHealthChecker_Subscribe(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	hc := NewHealthChecker(cm, config)

	subscriber1 := NewMockHealthSubscriber()
	subscriber2 := NewMockHealthSubscriber()

	hc.Subscribe(subscriber1)
	hc.Subscribe(subscriber2)

	hc.mu.RLock()
	count := len(hc.subscribers)
	hc.mu.RUnlock()

	if count != 2 {
		t.Errorf("Subscriber count = %d, want 2", count)
	}
}

// ============================================
// Unit Tests for GetAllHealthStatuses
// ============================================

func TestHealthChecker_GetAllHealthStatuses(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	hc := NewHealthChecker(cm, config)

	// Register multiple tenants
	tenant1 := uuid.New()
	tenant2 := uuid.New()
	tenant3 := uuid.New()

	hc.RegisterTenant(tenant1)
	hc.RegisterTenant(tenant2)
	hc.RegisterTenant(tenant3)

	statuses := hc.GetAllHealthStatuses()

	if len(statuses) != 3 {
		t.Errorf("Status count = %d, want 3", len(statuses))
	}
}

// ============================================
// Unit Tests for GetMetrics
// ============================================

func TestHealthChecker_GetMetrics_Empty(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	hc := NewHealthChecker(cm, config)

	metrics := hc.GetMetrics()

	if metrics.TotalTenants != 0 {
		t.Errorf("TotalTenants = %d, want 0", metrics.TotalTenants)
	}
	if metrics.Healthy != 0 {
		t.Errorf("Healthy = %d, want 0", metrics.Healthy)
	}
}

func TestHealthChecker_GetMetrics_WithTenants(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	config.EvictUnhealthy = false
	hc := NewHealthChecker(cm, config)

	// Register tenants with different statuses
	tenant1 := uuid.New()
	tenant2 := uuid.New()
	tenant3 := uuid.New()

	hc.RegisterTenant(tenant1)
	hc.RegisterTenant(tenant2)
	hc.RegisterTenant(tenant3)

	// Manually set different statuses by manipulating records
	rec1 := hc.getOrCreateRecord(tenant1)
	rec1.Status = HealthStatusHealthy
	hc.records.Store(tenant1, rec1)

	rec2 := hc.getOrCreateRecord(tenant2)
	rec2.Status = HealthStatusDegraded
	hc.records.Store(tenant2, rec2)

	rec3 := hc.getOrCreateRecord(tenant3)
	rec3.Status = HealthStatusUnhealthy
	hc.records.Store(tenant3, rec3)

	metrics := hc.GetMetrics()

	if metrics.TotalTenants != 3 {
		t.Errorf("TotalTenants = %d, want 3", metrics.TotalTenants)
	}
	if metrics.Healthy != 1 {
		t.Errorf("Healthy = %d, want 1", metrics.Healthy)
	}
	if metrics.Degraded != 1 {
		t.Errorf("Degraded = %d, want 1", metrics.Degraded)
	}
	if metrics.Unhealthy != 1 {
		t.Errorf("Unhealthy = %d, want 1", metrics.Unhealthy)
	}
}

// ============================================
// Unit Tests for recordSuccess
// ============================================

func TestHealthChecker_recordSuccess_SetsHealthy(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	config.MaxLatency = 1 * time.Second
	hc := NewHealthChecker(cm, config)

	tenantID := uuid.New()
	latency := 100 * time.Millisecond // Below max latency

	result := hc.recordSuccess(tenantID, latency)

	if result.Status != HealthStatusHealthy {
		t.Errorf("Status = %s, want %s", result.Status, HealthStatusHealthy)
	}
	if result.Latency != latency {
		t.Errorf("Latency = %v, want %v", result.Latency, latency)
	}
}

func TestHealthChecker_recordSuccess_SetsDegradedOnHighLatency(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	config.MaxLatency = 100 * time.Millisecond
	hc := NewHealthChecker(cm, config)

	tenantID := uuid.New()
	latency := 500 * time.Millisecond // Above max latency

	result := hc.recordSuccess(tenantID, latency)

	if result.Status != HealthStatusDegraded {
		t.Errorf("Status = %s, want %s for high latency", result.Status, HealthStatusDegraded)
	}
}

func TestHealthChecker_recordSuccess_ClearsConsecutiveFailures(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	hc := NewHealthChecker(cm, config)

	tenantID := uuid.New()

	// First record some failures
	hc.recordFailure(tenantID, errors.New("test error"), 100*time.Millisecond)
	hc.recordFailure(tenantID, errors.New("test error"), 100*time.Millisecond)

	record := hc.getOrCreateRecord(tenantID)
	if record.ConsecutiveFailures != 2 {
		t.Fatalf("ConsecutiveFailures before success = %d, want 2", record.ConsecutiveFailures)
	}

	// Now record success
	hc.recordSuccess(tenantID, 100*time.Millisecond)

	record = hc.getOrCreateRecord(tenantID)
	if record.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures after success = %d, want 0", record.ConsecutiveFailures)
	}
}

// ============================================
// Unit Tests for recordFailure
// ============================================

func TestHealthChecker_recordFailure_IncreasesConsecutive(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	config.EvictUnhealthy = false
	hc := NewHealthChecker(cm, config)

	tenantID := uuid.New()
	testErr := errors.New("connection failed")

	// First failure
	result1 := hc.recordFailure(tenantID, testErr, 100*time.Millisecond)
	if result1.Consecutive != 1 {
		t.Errorf("Consecutive after 1st failure = %d, want 1", result1.Consecutive)
	}

	// Second failure
	result2 := hc.recordFailure(tenantID, testErr, 100*time.Millisecond)
	if result2.Consecutive != 2 {
		t.Errorf("Consecutive after 2nd failure = %d, want 2", result2.Consecutive)
	}
}

func TestHealthChecker_recordFailure_TransitionsToDegraded(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	config.DegradedThreshold = 1
	config.UnhealthyThreshold = 3
	config.EvictUnhealthy = false
	hc := NewHealthChecker(cm, config)

	tenantID := uuid.New()
	testErr := errors.New("connection failed")

	result := hc.recordFailure(tenantID, testErr, 100*time.Millisecond)

	if result.Status != HealthStatusDegraded {
		t.Errorf("Status after 1 failure = %s, want %s", result.Status, HealthStatusDegraded)
	}
}

func TestHealthChecker_recordFailure_TransitionsToUnhealthy(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	config.DegradedThreshold = 1
	config.UnhealthyThreshold = 3
	config.EvictUnhealthy = false
	hc := NewHealthChecker(cm, config)

	tenantID := uuid.New()
	testErr := errors.New("connection failed")

	// Record 3 failures
	hc.recordFailure(tenantID, testErr, 100*time.Millisecond)
	hc.recordFailure(tenantID, testErr, 100*time.Millisecond)
	result := hc.recordFailure(tenantID, testErr, 100*time.Millisecond)

	if result.Status != HealthStatusUnhealthy {
		t.Errorf("Status after 3 failures = %s, want %s", result.Status, HealthStatusUnhealthy)
	}
}

func TestHealthChecker_recordFailure_NotifiesSubscriber(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	config.DegradedThreshold = 1
	config.EvictUnhealthy = false
	hc := NewHealthChecker(cm, config)

	subscriber := NewMockHealthSubscriber()
	hc.Subscribe(subscriber)

	tenantID := uuid.New()
	testErr := errors.New("connection failed")

	hc.recordFailure(tenantID, testErr, 100*time.Millisecond)

	// Give time for async notification
	time.Sleep(50 * time.Millisecond)

	calls := subscriber.GetCalls()
	if len(calls) != 1 {
		t.Fatalf("Subscriber calls = %d, want 1", len(calls))
	}

	if calls[0].OldStatus != HealthStatusUnknown {
		t.Errorf("OldStatus = %s, want %s", calls[0].OldStatus, HealthStatusUnknown)
	}
	if calls[0].NewStatus != HealthStatusDegraded {
		t.Errorf("NewStatus = %s, want %s", calls[0].NewStatus, HealthStatusDegraded)
	}
}

// ============================================
// Unit Tests for HealthSubscriberFunc
// ============================================

func TestHealthSubscriberFunc(t *testing.T) {
	var called int32
	var receivedTenantID uuid.UUID
	var receivedOld, receivedNew HealthStatus

	fn := HealthSubscriberFunc(func(tenantID uuid.UUID, oldStatus, newStatus HealthStatus) {
		atomic.AddInt32(&called, 1)
		receivedTenantID = tenantID
		receivedOld = oldStatus
		receivedNew = newStatus
	})

	testID := uuid.New()
	fn.OnHealthChange(testID, HealthStatusHealthy, HealthStatusDegraded)

	if atomic.LoadInt32(&called) != 1 {
		t.Error("Function was not called")
	}
	if receivedTenantID != testID {
		t.Errorf("TenantID = %v, want %v", receivedTenantID, testID)
	}
	if receivedOld != HealthStatusHealthy {
		t.Errorf("OldStatus = %s, want %s", receivedOld, HealthStatusHealthy)
	}
	if receivedNew != HealthStatusDegraded {
		t.Errorf("NewStatus = %s, want %s", receivedNew, HealthStatusDegraded)
	}
}

// ============================================
// Unit Tests for HealthCheckService
// ============================================

func TestHealthCheckService_GetStatus(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	hc := NewHealthChecker(cm, config)
	service := NewHealthCheckService(hc)

	tenantID := uuid.New()
	hc.RegisterTenant(tenantID)

	status := service.GetStatus(tenantID)

	if status.TenantID != tenantID {
		t.Errorf("TenantID = %v, want %v", status.TenantID, tenantID)
	}
}

func TestHealthCheckService_GetAllStatuses(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	hc := NewHealthChecker(cm, config)
	service := NewHealthCheckService(hc)

	hc.RegisterTenant(uuid.New())
	hc.RegisterTenant(uuid.New())

	statuses := service.GetAllStatuses()

	if len(statuses) != 2 {
		t.Errorf("Status count = %d, want 2", len(statuses))
	}
}

func TestHealthCheckService_GetMetrics(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	hc := NewHealthChecker(cm, config)
	service := NewHealthCheckService(hc)

	metrics := service.GetMetrics()

	if metrics == nil {
		t.Fatal("GetMetrics() returned nil")
	}
}

// ============================================
// Unit Tests for HealthCheckMiddleware
// ============================================

func TestHealthCheckMiddleware_CheckBeforeConnection_Healthy(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	hc := NewHealthChecker(cm, config)
	middleware := NewHealthCheckMiddleware(hc, true)

	tenantID := uuid.New()
	hc.RegisterTenant(tenantID)

	// Set as healthy
	rec := hc.getOrCreateRecord(tenantID)
	rec.Status = HealthStatusHealthy
	hc.records.Store(tenantID, rec)

	ctx := context.Background()
	err := middleware.CheckBeforeConnection(ctx, tenantID)
	if err != nil {
		t.Errorf("CheckBeforeConnection() error = %v, want nil", err)
	}
}

func TestHealthCheckMiddleware_CheckBeforeConnection_Unhealthy(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	hc := NewHealthChecker(cm, config)
	middleware := NewHealthCheckMiddleware(hc, true)

	tenantID := uuid.New()
	hc.RegisterTenant(tenantID)

	// Set as unhealthy
	rec := hc.getOrCreateRecord(tenantID)
	rec.Status = HealthStatusUnhealthy
	rec.ConsecutiveFailures = 5
	hc.records.Store(tenantID, rec)

	ctx := context.Background()
	err := middleware.CheckBeforeConnection(ctx, tenantID)

	if err == nil {
		t.Error("CheckBeforeConnection() expected error for unhealthy tenant")
	}
}

// ============================================
// Unit Tests for helper functions
// ============================================

func TestBoolToStatus(t *testing.T) {
	tests := []struct {
		input    bool
		expected HealthStatus
	}{
		{true, HealthStatusHealthy},
		{false, HealthStatusUnhealthy},
	}

	for _, tt := range tests {
		result := boolToStatus(tt.input)
		if result != tt.expected {
			t.Errorf("boolToStatus(%v) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

func TestErrToString(t *testing.T) {
	tests := []struct {
		err      error
		expected string
	}{
		{nil, ""},
		{errors.New("test error"), "test error"},
	}

	for _, tt := range tests {
		result := errToString(tt.err)
		if result != tt.expected {
			t.Errorf("errToString(%v) = %s, want %s", tt.err, result, tt.expected)
		}
	}
}

// ============================================
// Integration-style Tests
// ============================================

func TestHealthChecker_FullCycle(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	config.DegradedThreshold = 1
	config.UnhealthyThreshold = 2
	config.EvictUnhealthy = false
	hc := NewHealthChecker(cm, config)

	subscriber := NewMockHealthSubscriber()
	hc.Subscribe(subscriber)

	tenantID := uuid.New()
	hc.RegisterTenant(tenantID)

	// Initial state should be unknown
	status := hc.GetHealthStatus(tenantID)
	if status.Status != HealthStatusUnknown {
		t.Errorf("Initial status = %s, want %s", status.Status, HealthStatusUnknown)
	}

	// Record success - should become healthy
	hc.recordSuccess(tenantID, 50*time.Millisecond)
	status = hc.GetHealthStatus(tenantID)
	if status.Status != HealthStatusHealthy {
		t.Errorf("After success status = %s, want %s", status.Status, HealthStatusHealthy)
	}

	// Record failure - should become degraded
	hc.recordFailure(tenantID, errors.New("error"), 100*time.Millisecond)
	status = hc.GetHealthStatus(tenantID)
	if status.Status != HealthStatusDegraded {
		t.Errorf("After 1 failure status = %s, want %s", status.Status, HealthStatusDegraded)
	}

	// Record another failure - should become unhealthy
	hc.recordFailure(tenantID, errors.New("error"), 100*time.Millisecond)
	status = hc.GetHealthStatus(tenantID)
	if status.Status != HealthStatusUnhealthy {
		t.Errorf("After 2 failures status = %s, want %s", status.Status, HealthStatusUnhealthy)
	}

	// Record success - should recover to healthy
	hc.recordSuccess(tenantID, 50*time.Millisecond)
	status = hc.GetHealthStatus(tenantID)
	if status.Status != HealthStatusHealthy {
		t.Errorf("After recovery status = %s, want %s", status.Status, HealthStatusHealthy)
	}

	// Give time for async notifications
	time.Sleep(100 * time.Millisecond)

	// Check subscriber received notifications
	calls := subscriber.GetCalls()
	if len(calls) < 3 {
		t.Errorf("Expected at least 3 status change notifications, got %d", len(calls))
	}
}

func TestHealthChecker_LatencyTracking(t *testing.T) {
	cm := &TenantConnectionManager{}
	config := DefaultHealthCheckerConfig()
	hc := NewHealthChecker(cm, config)

	tenantID := uuid.New()

	// Record multiple successes with different latencies
	hc.recordSuccess(tenantID, 100*time.Millisecond)
	hc.recordSuccess(tenantID, 200*time.Millisecond)
	hc.recordSuccess(tenantID, 300*time.Millisecond)

	record := hc.getOrCreateRecord(tenantID)

	if record.TotalChecks != 3 {
		t.Errorf("TotalChecks = %d, want 3", record.TotalChecks)
	}

	if record.MaxLatency != 300*time.Millisecond {
		t.Errorf("MaxLatency = %v, want 300ms", record.MaxLatency)
	}

	// Average should be using exponential moving average
	if record.AverageLatency <= 0 {
		t.Error("AverageLatency should be > 0")
	}
}
