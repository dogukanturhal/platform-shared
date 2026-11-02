// SPDX-License-Identifier: Apache-2.0

package tenantpurge

import (
	"crypto/sha256"
	"encoding/hex"
)

// Kafka topics of the contract. Only tenant-management may write the command
// topic (Kafka ACL); that ACL is the authorization.
const (
	DefaultCommandTopic = "example.tenant.purge.command"
	DefaultAckTopic     = "example.tenant.purge.ack"
)

// Phase is the saga phase a command asks a participant to run.
type Phase string

const (
	PhasePlan    Phase = "plan"
	PhaseQuiesce Phase = "quiesce"
	PhaseErase   Phase = "erase"
)

// Kind tells whether the tenant still exists in TM or is an orphan id.
type Kind string

const (
	KindTenant Kind = "tenant"
	KindOrphan Kind = "orphan"
)

// Status is the result a participant reports for one phase.
type Status string

const (
	StatusOK            Status = "ok"
	StatusBlocked       Status = "blocked"
	StatusFailed        Status = "failed"
	StatusNotApplicable Status = "not_applicable"
)

// Command is the message TM writes to example.tenant.purge.command (key = tenant id).
type Command struct {
	RunID             string `json:"run_id"`
	TenantID          string `json:"tenant_id"`
	Kind              Kind   `json:"kind"`
	Phase             Phase  `json:"phase"`
	Attempt           int    `json:"attempt"`
	StatutoryOverride bool   `json:"statutory_override"`
}

// Ack is the message a participant writes to example.tenant.purge.ack (key = tenant id).
type Ack struct {
	RunID    string           `json:"run_id"`
	TenantID string           `json:"tenant_id"`
	Service  string           `json:"service"`
	Phase    Phase            `json:"phase"`
	Status   Status           `json:"status"`
	Counts   map[string]int64 `json:"counts"`
	Retained []RetainedRows   `json:"retained"`
	External []ExternalEffect `json:"external"`
	Error    string           `json:"error,omitempty"`
}

// RetainedRows reports rows deliberately kept, with the legal basis.
type RetainedRows struct {
	Table string `json:"table"`
	N     int64  `json:"n"`
	Basis string `json:"basis"`
}

// External effect outcomes. OutcomeNotFound counts as success: the thing is
// already gone, which is what a purge wants.
const (
	OutcomePlanned  = "planned"
	OutcomeOK       = "ok"
	OutcomeNotFound = "not_found"
	OutcomeFailed   = "failed"
)

// ExternalEffect describes a call to something outside the service database
// (payment provider, e-invoice integrator, MinIO, SpiceDB, ...). The ack carries only a hash of the
// reference so no customer identifiers travel over Kafka.
type ExternalEffect struct {
	Kind    string `json:"kind"`
	RefHash string `json:"ref_hash"`
	Action  string `json:"action"`
	Outcome string `json:"outcome"`
}

// NewExternalEffect builds an ExternalEffect, hashing ref (sha256 hex).
func NewExternalEffect(kind, ref, action, outcome string) ExternalEffect {
	sum := sha256.Sum256([]byte(ref))
	return ExternalEffect{Kind: kind, RefHash: hex.EncodeToString(sum[:]), Action: action, Outcome: outcome}
}
