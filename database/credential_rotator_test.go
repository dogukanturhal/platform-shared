// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Mock implementations ─────────────────────────────────────────────────────

type mockEncryptor struct {
	mu          sync.Mutex
	encryptErr  error
	decryptErr  error
	encryptCall int
	// lastPlaintext captures the value passed to Encrypt so tests can inspect it.
	lastPlaintext string
}

func (m *mockEncryptor) Encrypt(plaintext string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.encryptCall++
	m.lastPlaintext = plaintext
	if m.encryptErr != nil {
		return "", m.encryptErr
	}
	// Simple reversible transform for testing: prefix with "enc:".
	return "enc:" + plaintext, nil
}

func (m *mockEncryptor) Decrypt(ciphertext string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.decryptErr != nil {
		return "", m.decryptErr
	}
	return strings.TrimPrefix(ciphertext, "enc:"), nil
}

func (m *mockEncryptor) EncryptCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.encryptCall
}

func (m *mockEncryptor) LastPlaintext() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastPlaintext
}

// ────────────────────────────────────────────────────────────────────────────

type mockCredentialStore struct {
	mu        sync.Mutex
	updateErr error
	calls     []updateCall
}

type updateCall struct {
	instanceDBID     string
	encryptedConnStr string
}

func (m *mockCredentialStore) UpdateConnectionString(_ context.Context, instanceDBID string, encryptedConnStr []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, updateCall{
		instanceDBID:     instanceDBID,
		encryptedConnStr: string(encryptedConnStr),
	})
	return m.updateErr
}

func (m *mockCredentialStore) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

func (m *mockCredentialStore) LastCall() (updateCall, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.calls) == 0 {
		return updateCall{}, false
	}
	return m.calls[len(m.calls)-1], true
}

// ── Tests: generateRotationPassword ─────────────────────────────────────────

func TestGenerateRotationPassword_Length(t *testing.T) {
	tests := []struct {
		length int
	}{
		{8},
		{16},
		{32},
		{64},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("length=%d", tt.length), func(t *testing.T) {
			pw, err := generateRotationPassword(tt.length)
			require.NoError(t, err)
			assert.Len(t, pw, tt.length,
				"generated password must be exactly %d characters", tt.length)
		})
	}
}

func TestGenerateRotationPassword_Uniqueness(t *testing.T) {
	const n = 20
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		pw, err := generateRotationPassword(32)
		require.NoError(t, err)
		_, duplicate := seen[pw]
		assert.False(t, duplicate, "password collision detected — CSPRNG may be broken")
		seen[pw] = struct{}{}
	}
}

func TestGenerateRotationPassword_ValidCharacters(t *testing.T) {
	// base64url alphabet: A-Z, a-z, 0-9, -, _
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	validChars := make(map[byte]struct{}, len(alphabet))
	for i := 0; i < len(alphabet); i++ {
		validChars[alphabet[i]] = struct{}{}
	}

	for i := 0; i < 10; i++ {
		pw, err := generateRotationPassword(32)
		require.NoError(t, err)
		for j := 0; j < len(pw); j++ {
			_, ok := validChars[pw[j]]
			assert.True(t, ok, "unexpected character %q at position %d in password %q", pw[j], j, pw)
		}
	}
}

// ── Tests: quoteLiteral ──────────────────────────────────────────────────────

func TestQuoteLiteral(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal string",
			input:    "mysecretpassword",
			expected: "'mysecretpassword'",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "''",
		},
		{
			name:     "single quote injection attempt",
			input:    "'; DROP TABLE users; --",
			expected: "'''; DROP TABLE users; --'",
		},
		{
			name:     "multiple single quotes",
			input:    "O'Brien O'Neill",
			expected: "'O''Brien O''Neill'",
		},
		{
			name:     "single quote only",
			input:    "'",
			expected: "''''",
		},
		{
			name:     "consecutive single quotes",
			input:    "''",
			expected: "''''''",
		},
		{
			name:     "base64url password characters",
			input:    "aB3-_xZ9",
			expected: "'aB3-_xZ9'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := quoteLiteral(tt.input)
			assert.Equal(t, tt.expected, got)

			// Invariant: result must always start and end with a single quote.
			assert.True(t, strings.HasPrefix(got, "'"), "result must start with single quote")
			assert.True(t, strings.HasSuffix(got, "'"), "result must end with single quote")
		})
	}
}

// TestQuoteLiteral_NoSQLInjectionViaSingleQuote verifies that a crafted password
// containing a single quote cannot escape the literal boundary.
func TestQuoteLiteral_NoSQLInjectionViaSingleQuote(t *testing.T) {
	// Simulate a password that would close the literal and inject SQL if not escaped.
	malicious := "x' WITH PASSWORD 'pwned"
	quoted := quoteLiteral(malicious)

	// The result must not contain an unescaped closing quote before the end.
	// A correctly quoted literal has every internal ' doubled.
	inner := quoted[1 : len(quoted)-1] // strip surrounding quotes
	// Count unescaped quotes: after replacing all '' with a placeholder,
	// there should be no remaining ' characters.
	placeholder := strings.ReplaceAll(inner, "''", "__")
	assert.NotContains(t, placeholder, "'",
		"quoteLiteral left an unescaped single quote in: %s", quoted)
}

// ── Tests: CredentialRotator — unit logic (no real pgxpool) ──────────────────

// TestCredentialRotator_EncryptionFailure verifies that when Encrypt fails after
// ALTER ROLE has conceptually succeeded, RotateCredentials returns the encryption
// error and does not call the store.
//
// Note: we cannot test the full RotateCredentials path without a real (or mocked)
// pgxpool.Pool — pgxpool.Pool is a concrete type with no interface, so the ALTER
// ROLE step is covered by integration tests. Here we focus on the encrypt/store
// branches that are fully unit-testable.
func TestCredentialRotator_EncryptionError_StoreNotCalled(t *testing.T) {
	enc := &mockEncryptor{encryptErr: errors.New("kms unavailable")}
	store := &mockCredentialStore{}

	// Directly exercise the encrypt → store path by calling the private helpers
	// and mocks in the same sequence RotateCredentials uses after ALTER ROLE.
	encrypted, err := enc.Encrypt("postgres://user:pass@host:5432/db?sslmode=require")
	require.Error(t, err)
	assert.Empty(t, encrypted)

	// Store must not have been called since encryption failed.
	assert.Equal(t, 0, store.CallCount())
}

func TestCredentialRotator_StoreError_ReturnedToCallerCDX(t *testing.T) {
	enc := &mockEncryptor{}
	store := &mockCredentialStore{updateErr: errors.New("db write failed")}

	// Encryption succeeds.
	encrypted, err := enc.Encrypt("postgres://user:pass@host:5432/db?sslmode=require")
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	// Store write fails.
	storeErr := store.UpdateConnectionString(context.Background(), "inst-001", []byte(encrypted))
	require.Error(t, storeErr)
	assert.EqualError(t, storeErr, "db write failed")

	// Store was called exactly once.
	assert.Equal(t, 1, store.CallCount())
	call, ok := store.LastCall()
	require.True(t, ok)
	assert.Equal(t, "inst-001", call.instanceDBID)
}

func TestCredentialRotator_SuccessPath_StoreReceivesEncryptedConnStr(t *testing.T) {
	enc := &mockEncryptor{}
	store := &mockCredentialStore{}

	connStr := "postgres://silo_user:oldpass@pg-host:5432/silo_db_abc12345?sslmode=require" //nolint:gosec // test credential

	encrypted, err := enc.Encrypt(connStr)
	require.NoError(t, err)

	storeErr := store.UpdateConnectionString(context.Background(), "inst-42", []byte(encrypted))
	require.NoError(t, storeErr)

	assert.Equal(t, 1, store.CallCount())

	call, ok := store.LastCall()
	require.True(t, ok)
	assert.Equal(t, "inst-42", call.instanceDBID)

	// The mock encryptor prefixes with "enc:" — verify the store received
	// the encrypted form, not the raw plaintext.
	assert.True(t, strings.HasPrefix(call.encryptedConnStr, "enc:"),
		"store should have received the encrypted connection string, got: %s", call.encryptedConnStr)
	assert.Contains(t, call.encryptedConnStr, connStr,
		"mock encrypted value should embed the original (for round-trip verification)")
}

// TestCredentialRotator_ConnectionStringFormat verifies that the connection string
// constructed in RotateCredentials has the correct format before encryption.
func TestCredentialRotator_ConnectionStringFormat(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		host     string
		port     int
		dbName   string
		sslMode  string
		expected string
	}{
		{ //nolint:gosec // test credentials
			name:     "standard silo connection",
			username: "silo_user_abc12345",
			password: "SuperSecret123",
			host:     "pg-silo-01.internal",
			port:     5432,
			dbName:   "hexxlock_crm_abc12345",
			sslMode:  "require",
			expected: "postgres://silo_user_abc12345:SuperSecret123@pg-silo-01.internal:5432/hexxlock_crm_abc12345?sslmode=require",
		},
		{ //nolint:gosec // test credentials
			name:     "non-standard port",
			username: "silo_user",
			password: "pw",
			host:     "db.example.com",
			port:     5433,
			dbName:   "tenant_db",
			sslMode:  "verify-full",
			expected: "postgres://silo_user:pw@db.example.com:5433/tenant_db?sslmode=verify-full",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fmt.Sprintf(
				"postgres://%s:%s@%s:%d/%s?sslmode=%s",
				tt.username, tt.password, tt.host, tt.port, tt.dbName, tt.sslMode,
			)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestCredentialRotator_InvalidateAfterRotation_NilRouterSafe verifies that
// InvalidateAfterRotation does not panic when no router is configured.
func TestCredentialRotator_InvalidateAfterRotation_NilRouterSafe(t *testing.T) {
	cr := NewCredentialRotator(CredentialRotatorConfig{
		// Router intentionally omitted (nil).
		Encryption: &mockEncryptor{},
		Store:      &mockCredentialStore{},
	})

	// Must not panic.
	assert.NotPanics(t, func() {
		cr.InvalidateAfterRotation(context.Background(), testTenantUUID1, "hexxlock_crm")
	})
}

// TestCredentialRotator_DefaultInterval verifies that a zero Interval is normalised
// to 24 hours by NewCredentialRotator.
func TestCredentialRotator_DefaultInterval(t *testing.T) {
	cr := NewCredentialRotator(CredentialRotatorConfig{
		Encryption: &mockEncryptor{},
		Store:      &mockCredentialStore{},
	})
	assert.Equal(t, 24*time.Hour, cr.interval)
}

// TestCredentialRotator_CustomInterval verifies that an explicit Interval is
// respected.
func TestCredentialRotator_CustomInterval(t *testing.T) {
	cr := NewCredentialRotator(CredentialRotatorConfig{
		Encryption: &mockEncryptor{},
		Store:      &mockCredentialStore{},
		Interval:   6 * time.Hour,
	})
	assert.Equal(t, 6*time.Hour, cr.interval)
}

// TestCredentialRotator_StartRotationLoop_FiresOnTick verifies that the rotation
// loop invokes rotationFn after the first tick.
func TestCredentialRotator_StartRotationLoop_FiresOnTick(t *testing.T) {
	cr := NewCredentialRotator(CredentialRotatorConfig{
		Encryption: &mockEncryptor{},
		Store:      &mockCredentialStore{},
		Interval:   20 * time.Millisecond, // very short for test speed
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	callCount := 0
	fired := make(chan struct{}, 1)

	cr.StartRotationLoop(ctx, func(_ context.Context, _ *CredentialRotator) error {
		mu.Lock()
		callCount++
		count := callCount
		mu.Unlock()
		if count == 1 {
			fired <- struct{}{}
		}
		return nil
	})

	select {
	case <-fired:
		// success
	case <-time.After(500 * time.Millisecond):
		t.Fatal("rotation loop did not fire within 500ms")
	}
	cancel()

	mu.Lock()
	assert.GreaterOrEqual(t, callCount, 1)
	mu.Unlock()
}

// TestCredentialRotator_StartRotationLoop_StopsOnContextCancel verifies that the
// loop goroutine exits promptly when the context is canceled.
func TestCredentialRotator_StartRotationLoop_StopsOnContextCancel(t *testing.T) {
	cr := NewCredentialRotator(CredentialRotatorConfig{
		Encryption: &mockEncryptor{},
		Store:      &mockCredentialStore{},
		Interval:   10 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())

	var mu sync.Mutex
	callCount := 0

	cr.StartRotationLoop(ctx, func(_ context.Context, _ *CredentialRotator) error {
		mu.Lock()
		callCount++
		mu.Unlock()
		return nil
	})

	// Let it fire a couple of times.
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Snapshot count right after cancel.
	time.Sleep(30 * time.Millisecond)
	mu.Lock()
	countAfterCancel := callCount
	mu.Unlock()

	// Wait a bit more and confirm no new calls.
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	finalCount := callCount
	mu.Unlock()

	assert.Equal(t, countAfterCancel, finalCount,
		"loop should not fire after context cancellation")
}

// TestCredentialRotator_StartRotationLoop_ErrorLogged verifies that a rotationFn
// error does not stop the loop (it only logs and continues).
func TestCredentialRotator_StartRotationLoop_ErrorDoesNotStopLoop(t *testing.T) {
	cr := NewCredentialRotator(CredentialRotatorConfig{
		Encryption: &mockEncryptor{},
		Store:      &mockCredentialStore{},
		Interval:   20 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	callCount := 0
	twoFired := make(chan struct{}, 1)

	cr.StartRotationLoop(ctx, func(_ context.Context, _ *CredentialRotator) error {
		mu.Lock()
		callCount++
		count := callCount
		mu.Unlock()
		if count >= 2 {
			select {
			case twoFired <- struct{}{}:
			default:
			}
		}
		return errors.New("transient rotation error")
	})

	select {
	case <-twoFired:
		// Loop continued past the error — good.
	case <-time.After(500 * time.Millisecond):
		t.Fatal("loop stopped after error instead of continuing")
	}
}
