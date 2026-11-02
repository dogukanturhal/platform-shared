// SPDX-License-Identifier: Apache-2.0

package tenantpurge

import (
	"context"
	"errors"
)

// ErrNotApplicable can be returned by any hook to report the whole phase as
// not_applicable (the service holds nothing for this tenant).
var ErrNotApplicable = errors.New("tenantpurge: not applicable")

// BlockedError makes a phase report status "blocked" instead of "failed". Use it
// for conditions an operator must resolve (statutory records, live e-invoice credits,
// users that need re-homing).
type BlockedError struct{ Reason string }

func (e *BlockedError) Error() string { return e.Reason }

// Blocked builds a *BlockedError.
func Blocked(reason string) error { return &BlockedError{Reason: reason} }

// PlanReport is what a service adds to the dry run.
type PlanReport struct {
	// Blockers make the plan ack "blocked". Texts must not contain personal data.
	Blockers []string
	// External lists effects quiesce/erase would perform (Outcome: OutcomePlanned).
	External []ExternalEffect
}

// Hooks plug external effects into the phases. Embed NopHooks and override what
// the service needs. Every hook must be idempotent: TM re-issues commands, and an
// already-gone external object must be reported as OutcomeNotFound, not failed.
// Hooks must not log or return personal data in errors.
type Hooks interface {
	// Plan runs before the DB dry run; read-only.
	Plan(ctx context.Context, cmd Command) (PlanReport, error)
	// Quiesce stops charges, renewals, sessions, provider activity. No data is deleted.
	Quiesce(ctx context.Context, cmd Command) ([]ExternalEffect, error)
	// BeforeErase runs before the DB transaction, while the rows are still there
	// (e.g. read file_metadata keys and delete the MinIO objects).
	BeforeErase(ctx context.Context, cmd Command) ([]ExternalEffect, error)
	// EraseTx runs inside the erase transaction, after the purge GUCs are set and
	// before the catalog sweep, for service-specific deletes the sweep cannot express.
	EraseTx(ctx context.Context, cmd Command, tx Tx) error
	// AfterErase runs after the transaction committed (e.g. SpiceDB tuples).
	AfterErase(ctx context.Context, cmd Command) ([]ExternalEffect, error)
}

// NopHooks implements Hooks with no effects.
type NopHooks struct{}

func (NopHooks) Plan(context.Context, Command) (PlanReport, error)              { return PlanReport{}, nil }
func (NopHooks) Quiesce(context.Context, Command) ([]ExternalEffect, error)     { return nil, nil }
func (NopHooks) BeforeErase(context.Context, Command) ([]ExternalEffect, error) { return nil, nil }
func (NopHooks) EraseTx(context.Context, Command, Tx) error                     { return nil }
func (NopHooks) AfterErase(context.Context, Command) ([]ExternalEffect, error)  { return nil, nil }
