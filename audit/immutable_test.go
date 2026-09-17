// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildEntry constructs a minimal ImmutableAuditEntry whose EntryHash is
// correctly computed from its content and the supplied prevHash.
func buildEntry(id, tenantID, prevHash, actor, action, resource, resourceID, data string, ts time.Time) ImmutableAuditEntry {
	h := ComputeEntryHash(prevHash, ts, actor, action, resource, resourceID, data)
	return ImmutableAuditEntry{
		ID:         id,
		TenantID:   tenantID,
		PrevHash:   prevHash,
		EntryHash:  h,
		Timestamp:  ts,
		Actor:      actor,
		ActorType:  "user",
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Data:       data,
		Severity:   "info",
	}
}

// buildChain constructs a sequential chain of n entries for tenantID.
func buildChain(n int, base time.Time) []ImmutableAuditEntry {
	tenantID := "tenant-1"
	entries := make([]ImmutableAuditEntry, n)
	prevHash := ""
	for i := 0; i < n; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		e := buildEntry(
			fmt.Sprintf("id-%d", i),
			tenantID,
			prevHash,
			"user-1",
			"CREATE_USER",
			"user",
			fmt.Sprintf("res-%d", i),
			fmt.Sprintf(`{"seq":%d}`, i),
			ts,
		)
		entries[i] = e
		prevHash = e.EntryHash
	}
	return entries
}

// ---------------------------------------------------------------------------
// ComputeEntryHash tests
// ---------------------------------------------------------------------------

func TestComputeEntryHash_Deterministic(t *testing.T) {
	ts := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	args := []string{"prev", "actor", "action", "resource", "resource-1", `{"k":"v"}`}

	h1 := ComputeEntryHash(args[0], ts, args[1], args[2], args[3], args[4], args[5])
	h2 := ComputeEntryHash(args[0], ts, args[1], args[2], args[3], args[4], args[5])

	assert.Equal(t, h1, h2, "same inputs must produce the same hash")
	assert.Len(t, h1, 64, "SHA-256 hex digest must be 64 characters")
}

func TestComputeEntryHash_DifferentInputs(t *testing.T) {
	ts := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

	base := ComputeEntryHash("prev", ts, "actor", "action", "resource", "res-1", "data")

	tests := []struct {
		name string
		hash string
	}{
		{
			name: "different prevHash",
			hash: ComputeEntryHash("OTHER", ts, "actor", "action", "resource", "res-1", "data"),
		},
		{
			name: "different timestamp",
			hash: ComputeEntryHash("prev", ts.Add(time.Nanosecond), "actor", "action", "resource", "res-1", "data"),
		},
		{
			name: "different actor",
			hash: ComputeEntryHash("prev", ts, "other-actor", "action", "resource", "res-1", "data"),
		},
		{
			name: "different action",
			hash: ComputeEntryHash("prev", ts, "actor", "OTHER_ACTION", "resource", "res-1", "data"),
		},
		{
			name: "different resource",
			hash: ComputeEntryHash("prev", ts, "actor", "action", "tenant", "res-1", "data"),
		},
		{
			name: "different resourceID",
			hash: ComputeEntryHash("prev", ts, "actor", "action", "resource", "res-999", "data"),
		},
		{
			name: "different data",
			hash: ComputeEntryHash("prev", ts, "actor", "action", "resource", "res-1", "other-data"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotEqual(t, base, tc.hash, "changing any field must produce a different hash")
		})
	}
}

func TestComputeEntryHash_EmptyFields(t *testing.T) {
	ts := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

	// All-empty inputs must still produce a valid, deterministic hash.
	h1 := ComputeEntryHash("", ts, "", "", "", "", "")
	h2 := ComputeEntryHash("", ts, "", "", "", "", "")

	assert.Equal(t, h1, h2, "empty fields must be deterministic")
	assert.Len(t, h1, 64, "result must be a full SHA-256 hex digest")
}

func TestComputeEntryHash_SpecialCharacters(t *testing.T) {
	ts := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

	// Pipe characters inside field values must not confuse the concatenation.
	h := ComputeEntryHash("prev|extra", ts, "actor|pipe", "act|ion", "res|ource", "id|1", `{"key":"val|ue"}`)
	assert.Len(t, h, 64, "special characters must not break hash computation")

	// The hash must still differ from a clean version.
	clean := ComputeEntryHash("prev", ts, "actor", "action", "resource", "id-1", `{"key":"value"}`)
	assert.NotEqual(t, h, clean)
}

// ---------------------------------------------------------------------------
// VerifyChain tests
// ---------------------------------------------------------------------------

func TestVerifyChain_EmptyChain(t *testing.T) {
	ok, err := VerifyChain(nil)
	require.NoError(t, err)
	assert.True(t, ok, "empty chain must be considered valid")

	ok, err = VerifyChain([]ImmutableAuditEntry{})
	require.NoError(t, err)
	assert.True(t, ok, "empty slice must be considered valid")
}

func TestVerifyChain_GenesisEntry(t *testing.T) {
	ts := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	entry := buildEntry("genesis", "tenant-1", "", "system", "INIT", "system", "", "", ts)

	ok, err := VerifyChain([]ImmutableAuditEntry{entry})
	require.NoError(t, err)
	assert.True(t, ok, "single genesis entry with empty prevHash must be valid")
}

func TestVerifyChain_ValidChain(t *testing.T) {
	base := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	chain := buildChain(10, base)

	ok, err := VerifyChain(chain)
	require.NoError(t, err)
	assert.True(t, ok, "correctly built chain must verify successfully")
}

func TestVerifyChain_TamperedEntry(t *testing.T) {
	base := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	chain := buildChain(5, base)

	// Tamper with the actor field of entry at index 2 without recomputing hashes.
	chain[2].Actor = "malicious-actor"

	ok, err := VerifyChain(chain)
	assert.False(t, ok, "tampered entry must cause verification failure")
	assert.ErrorContains(t, err, "index 2", "error must identify the tampered index")
}

func TestVerifyChain_TamperedHash(t *testing.T) {
	base := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	chain := buildChain(5, base)

	// Directly overwrite the EntryHash of entry 3 with a fabricated value.
	chain[3].EntryHash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	ok, err := VerifyChain(chain)
	assert.False(t, ok)
	// Either entry 3 (hash mismatch) or entry 4 (prev_hash linkage break) triggers first.
	assert.Error(t, err)
}

func TestVerifyChain_OrderMatters(t *testing.T) {
	base := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	chain := buildChain(4, base)

	// Swap entries 1 and 2 — breaks both hash linkage and genesis constraint.
	swapped := []ImmutableAuditEntry{chain[0], chain[2], chain[1], chain[3]}

	ok, err := VerifyChain(swapped)
	assert.False(t, ok, "reordered entries must fail verification")
	assert.Error(t, err)
}

func TestVerifyChain_GenesisEntryWithNonEmptyPrevHash(t *testing.T) {
	ts := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

	// Compute what the hash would be with "fakeprev" as the prev hash.
	fakeHash := ComputeEntryHash("fakeprev", ts, "actor", "action", "resource", "res-0", "")
	entry := ImmutableAuditEntry{
		ID:         "id-0",
		TenantID:   "tenant-1",
		PrevHash:   "fakeprev", // Non-empty on first entry — invalid.
		EntryHash:  fakeHash,
		Timestamp:  ts,
		Actor:      "actor",
		Action:     "action",
		Resource:   "resource",
		ResourceID: "res-0",
	}

	ok, err := VerifyChain([]ImmutableAuditEntry{entry})
	assert.False(t, ok, "genesis entry with non-empty prev_hash must fail")
	assert.ErrorContains(t, err, "genesis entry must have empty prev_hash")
}

func TestVerifyChain_BrokenLinkage(t *testing.T) {
	base := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	chain := buildChain(4, base)

	// Craft a valid-looking entry that points to a non-existent previous hash.
	ts := base.Add(3 * time.Second)
	wrongPrev := "0000000000000000000000000000000000000000000000000000000000000000"
	forgedHash := ComputeEntryHash(wrongPrev, ts, "user-1", "CREATE_USER", "user", "res-3", `{"seq":3}`)
	chain[3].PrevHash = wrongPrev
	chain[3].EntryHash = forgedHash

	ok, err := VerifyChain(chain)
	assert.False(t, ok)
	assert.ErrorContains(t, err, "prev_hash")
}

func TestVerifyChain_ConcurrentAppends(t *testing.T) {
	// Simulate building a chain sequentially (as a store would) but verifying
	// it from a concurrent read perspective. The key guarantee is that the
	// resulting ordered chain is still verifiable.
	const n = 50
	base := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

	// Build chain entries sequentially in a goroutine (simulates serialized append).
	var (
		mu       sync.Mutex
		chain    []ImmutableAuditEntry
		prevHash = ""
		wg       sync.WaitGroup
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			ts := base.Add(time.Duration(i) * time.Second)
			e := buildEntry(
				fmt.Sprintf("id-%d", i),
				"tenant-concurrent",
				prevHash,
				"svc",
				"LOGIN",
				"session",
				fmt.Sprintf("sess-%d", i),
				"",
				ts,
			)
			mu.Lock()
			chain = append(chain, e)
			prevHash = e.EntryHash
			mu.Unlock()
		}
	}()

	wg.Wait()

	mu.Lock()
	snapshot := make([]ImmutableAuditEntry, len(chain))
	copy(snapshot, chain)
	mu.Unlock()

	ok, err := VerifyChain(snapshot)
	require.NoError(t, err)
	assert.True(t, ok, "chain built by sequential goroutine must verify correctly")
	assert.Len(t, snapshot, n)
}
