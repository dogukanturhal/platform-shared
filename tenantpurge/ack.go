// SPDX-License-Identifier: Apache-2.0

package tenantpurge

import (
	"errors"
	"sort"
	"strings"
)

const maxErrorLen = 500

// PhaseResult is what a phase produced; BuildAck turns it into an Ack.
type PhaseResult struct {
	Counts   map[string]int64
	Retained []RetainedRows
	External []ExternalEffect
	Err      error
}

// BuildAck derives the status from the result and assembles the ack:
//
//   - Err is a *BlockedError                -> blocked
//   - Err is ErrNotApplicable               -> not_applicable
//   - any other Err                         -> failed
//   - no Err but an external effect failed  -> failed
//   - otherwise                             -> ok (OutcomeNotFound counts as ok)
//
// Slices and maps are never nil so the JSON has [] and {} not null.
func BuildAck(cmd Command, service string, res PhaseResult) Ack {
	a := Ack{
		RunID:    cmd.RunID,
		TenantID: cmd.TenantID,
		Service:  service,
		Phase:    cmd.Phase,
		Status:   StatusOK,
		Counts:   res.Counts,
		Retained: res.Retained,
		External: res.External,
	}
	if a.Counts == nil {
		a.Counts = map[string]int64{}
	}
	if a.Retained == nil {
		a.Retained = []RetainedRows{}
	}
	if a.External == nil {
		a.External = []ExternalEffect{}
	}
	sort.Slice(a.Retained, func(i, j int) bool { return a.Retained[i].Table < a.Retained[j].Table })

	var blocked *BlockedError
	switch {
	case res.Err == nil:
		var failed []string
		for _, e := range a.External {
			if e.Outcome == OutcomeFailed {
				failed = append(failed, e.Kind+":"+e.Action)
			}
		}
		if len(failed) > 0 {
			a.Status = StatusFailed
			a.Error = "external effect failed: " + strings.Join(failed, ",")
		}
	case errors.As(res.Err, &blocked):
		a.Status = StatusBlocked
		a.Error = res.Err.Error()
	case errors.Is(res.Err, ErrNotApplicable):
		a.Status = StatusNotApplicable
	default:
		a.Status = StatusFailed
		a.Error = res.Err.Error()
	}
	if len(a.Error) > maxErrorLen {
		a.Error = a.Error[:maxErrorLen]
	}
	return a
}
