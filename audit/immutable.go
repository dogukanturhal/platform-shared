// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// ImmutableAuditEntry extends audit entries with hash chain fields.
// Each entry links to its predecessor via PrevHash, forming a tamper-evident
// append-only log. Modifying any field in a committed entry invalidates all
// subsequent hashes in the chain.
type ImmutableAuditEntry struct {
	// ID is the unique identifier for this entry (UUID recommended).
	ID string `json:"id"`

	// TenantID scopes the entry to a specific tenant.
	TenantID string `json:"tenant_id"`

	// PrevHash is the EntryHash of the immediately preceding entry in the chain.
	// It is empty for the genesis (first) entry of a tenant's chain.
	PrevHash string `json:"prev_hash"`

	// EntryHash is the SHA-256 digest of this entry's content concatenated with
	// PrevHash. Use ComputeEntryHash to produce this value.
	EntryHash string `json:"entry_hash"`

	// Timestamp records when the action occurred (UTC).
	Timestamp time.Time `json:"timestamp"`

	// Actor is the identity (user ID, service name, or "system") that performed
	// the action.
	Actor string `json:"actor"`

	// ActorType classifies the actor: "user", "service", or "system".
	ActorType string `json:"actor_type"`

	// Action describes what was done, e.g. "CREATE_USER", "DELETE_TENANT".
	Action string `json:"action"`

	// Resource is the type of resource affected, e.g. "user", "tenant".
	Resource string `json:"resource"`

	// ResourceID is the identifier of the affected resource.
	ResourceID string `json:"resource_id"`

	// Data holds JSON-serialized supplementary context for the entry.
	Data string `json:"data"`

	// Severity classifies the operational impact: "info", "warning", "critical".
	Severity string `json:"severity"`
}

// ComputeEntryHash produces a deterministic SHA-256 digest over the supplied
// fields. The input is constructed by joining all fields with a pipe separator
// and formatting the timestamp as RFC3339Nano so that the output is stable
// across platforms and Go versions.
//
// Formula:
//
//	SHA-256( prevHash | timestamp(RFC3339Nano) | actor | action | resource | resourceID | data )
func ComputeEntryHash(prevHash string, timestamp time.Time, actor, action, resource, resourceID, data string) string {
	raw := prevHash +
		"|" + timestamp.UTC().Format(time.RFC3339Nano) +
		"|" + actor +
		"|" + action +
		"|" + resource +
		"|" + resourceID +
		"|" + data

	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// VerifyChain checks that every entry in the supplied slice is internally
// consistent and correctly linked to its predecessor.
//
// Rules:
//   - An empty slice is considered valid.
//   - The first entry must have an empty PrevHash (genesis rule).
//   - Every subsequent entry's PrevHash must equal the previous entry's
//     EntryHash.
//   - Every entry's EntryHash must equal the value computed by
//     ComputeEntryHash over its own content fields.
//
// On success it returns (true, nil). On failure it returns (false, error)
// describing the first violation found, including the zero-based index and
// entry ID of the offending entry.
func VerifyChain(entries []ImmutableAuditEntry) (bool, error) {
	for i, entry := range entries {
		// Verify genesis constraint.
		if i == 0 {
			if entry.PrevHash != "" {
				return false, fmt.Errorf(
					"chain integrity violation at index %d (id=%s): genesis entry must have empty prev_hash, got %q",
					i, entry.ID, entry.PrevHash,
				)
			}
		} else {
			// Verify linkage: this entry's PrevHash must equal the previous entry's EntryHash.
			prev := entries[i-1] // #nosec G602 -- i > 0 is guaranteed by the else branch of i == 0 check above
			if entry.PrevHash != prev.EntryHash {
				return false, fmt.Errorf(
					"chain integrity violation at index %d (id=%s): prev_hash %q does not match preceding entry_hash %q",
					i, entry.ID, entry.PrevHash, prev.EntryHash,
				)
			}
		}

		// Verify the entry's own hash.
		expected := ComputeEntryHash(
			entry.PrevHash,
			entry.Timestamp,
			entry.Actor,
			entry.Action,
			entry.Resource,
			entry.ResourceID,
			entry.Data,
		)
		if entry.EntryHash != expected {
			return false, fmt.Errorf(
				"chain integrity violation at index %d (id=%s): entry_hash %q does not match computed hash %q",
				i, entry.ID, entry.EntryHash, expected,
			)
		}
	}

	return true, nil
}

// ImmutableAuditStore is the interface for append-only audit storage.
// Implementations must guarantee that entries are never modified or deleted
// once written.
type ImmutableAuditStore interface {
	// Append adds a new entry to the tenant's chain. The implementation is
	// responsible for fetching the last entry, setting PrevHash, computing
	// EntryHash, and persisting the result atomically. It returns the stored
	// entry (with EntryHash populated) or an error.
	Append(ctx context.Context, entry ImmutableAuditEntry) (*ImmutableAuditEntry, error)

	// GetChain retrieves all entries for tenantID whose Timestamp falls within
	// [from, to] inclusive, ordered by Timestamp ascending.
	GetChain(ctx context.Context, tenantID string, from, to time.Time) ([]ImmutableAuditEntry, error)

	// GetLastEntry returns the most recent entry for tenantID. It returns nil
	// without an error when the chain is empty (no entries yet).
	GetLastEntry(ctx context.Context, tenantID string) (*ImmutableAuditEntry, error)

	// VerifyIntegrity checks the full chain integrity for tenantID within
	// [from, to]. It returns (true, nil) if the chain is intact, or
	// (false, error) with details of the first violation.
	VerifyIntegrity(ctx context.Context, tenantID string, from, to time.Time) (bool, error)
}
