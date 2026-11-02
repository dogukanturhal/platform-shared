// SPDX-License-Identifier: Apache-2.0

package tenantpurge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type panicHooks struct{ NopHooks }

func (panicHooks) Quiesce(context.Context, Command) ([]ExternalEffect, error) { panic("hook ran") }
func (panicHooks) BeforeErase(context.Context, Command) ([]ExternalEffect, error) {
	panic("hook ran")
}

func nopLogger() *zap.Logger { return zap.NewNop() }

var cmd1 = Command{RunID: "run-1", TenantID: "f6e7c6c3-0000-4000-8000-000000000000", Kind: KindTenant, Phase: PhaseErase}

func TestBuildAckStatuses(t *testing.T) {
	ok := BuildAck(cmd1, "billing", PhaseResult{})
	assert.Equal(t, StatusOK, ok.Status)
	assert.Empty(t, ok.Error)

	assert.Equal(t, StatusBlocked, BuildAck(cmd1, "s", PhaseResult{Err: Blocked("statutory records")}).Status)
	assert.Equal(t, StatusBlocked, BuildAck(cmd1, "s", PhaseResult{Err: fmt.Errorf("wrap: %w", Blocked("x"))}).Status)
	assert.Equal(t, StatusNotApplicable, BuildAck(cmd1, "s", PhaseResult{Err: ErrNotApplicable}).Status)

	failed := BuildAck(cmd1, "s", PhaseResult{Err: errors.New("boom")})
	assert.Equal(t, StatusFailed, failed.Status)
	assert.Equal(t, "boom", failed.Error)
}

func TestBuildAckExternalOutcomes(t *testing.T) {
	notFound := NewExternalEffect("examplepay_subscription", "sub-1", "cancel", OutcomeNotFound)
	assert.Equal(t, StatusOK, BuildAck(cmd1, "s", PhaseResult{External: []ExternalEffect{notFound}}).Status)

	bad := NewExternalEffect("minio_object", "k", "delete", OutcomeFailed)
	a := BuildAck(cmd1, "s", PhaseResult{External: []ExternalEffect{notFound, bad}})
	assert.Equal(t, StatusFailed, a.Status)
	assert.Contains(t, a.Error, "minio_object:delete")
}

func TestExternalEffectHashesRef(t *testing.T) {
	e := NewExternalEffect("nes_customer", "1234567890", "deactivate", OutcomeOK)
	assert.Len(t, e.RefHash, 64)
	assert.NotContains(t, e.RefHash, "1234567890")
	assert.Equal(t, e, NewExternalEffect("nes_customer", "1234567890", "deactivate", OutcomeOK))
}

func TestBuildAckJSONShape(t *testing.T) {
	a := BuildAck(cmd1, "billing", PhaseResult{
		Counts:   map[string]int64{"public.t": 3},
		Retained: []RetainedRows{{Table: "public.z", N: 1, Basis: "VUK"}, {Table: "public.a", N: 2, Basis: "VUK"}},
	})
	raw, err := json.Marshal(a)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	for _, k := range []string{"run_id", "tenant_id", "service", "phase", "status", "counts", "retained", "external"} {
		assert.Contains(t, m, k)
	}
	assert.NotContains(t, m, "error")
	assert.Equal(t, []any{}, m["external"], "external must be [] not null")
	assert.Equal(t, "public.a", a.Retained[0].Table, "retained sorted by table")

	empty := BuildAck(cmd1, "s", PhaseResult{})
	raw, _ = json.Marshal(empty)
	assert.Contains(t, string(raw), `"counts":{}`)
	assert.Contains(t, string(raw), `"retained":[]`)
}

func TestBuildAckTruncatesError(t *testing.T) {
	a := BuildAck(cmd1, "s", PhaseResult{Err: errors.New(strings.Repeat("x", 2000))})
	assert.Len(t, a.Error, maxErrorLen)
}

func TestCommandJSON(t *testing.T) {
	var c Command
	require.NoError(t, json.Unmarshal([]byte(`{"run_id":"r","tenant_id":"t","kind":"orphan","phase":"plan","attempt":2,"statutory_override":true}`), &c))
	assert.Equal(t, Command{RunID: "r", TenantID: "t", Kind: KindOrphan, Phase: PhasePlan, Attempt: 2, StatutoryOverride: true}, c)
}
