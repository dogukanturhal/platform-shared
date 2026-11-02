// SPDX-License-Identifier: Apache-2.0

package tenantpurge

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProtectedSetIsExact(t *testing.T) {
	assert.Equal(t, []string{
		"00000000-0000-0000-0000-000000000000",
		"00000000-0000-0000-0000-000000000001",
		"00000000-0000-0000-0000-000000000002",
		"00000000-0000-0000-0000-000000000004",
	}, ProtectedTenantIDs())
}

func TestCheckTenantID(t *testing.T) {
	for _, id := range ProtectedTenantIDs() {
		_, err := CheckTenantID(id)
		assert.ErrorIs(t, err, ErrProtectedTenant, id)
	}
	// other spellings of a protected id are still refused
	for _, id := range []string{
		"00000000000000000000000000000002",
		"{00000000-0000-0000-0000-000000000002}",
		"urn:uuid:00000000-0000-0000-0000-000000000004",
	} {
		_, err := CheckTenantID(id)
		assert.ErrorIs(t, err, ErrProtectedTenant, id)
	}
	// 0003 is not protected
	got, err := CheckTenantID("00000000-0000-0000-0000-000000000003")
	require.NoError(t, err)
	assert.Equal(t, "00000000-0000-0000-0000-000000000003", got)

	got, err = CheckTenantID("F6E7C6C3-0000-4000-8000-000000000000")
	require.NoError(t, err)
	assert.Equal(t, "f6e7c6c3-0000-4000-8000-000000000000", got)

	for _, bad := range []string{"", "not-a-uuid", "f6e7c6c3"} {
		_, err := CheckTenantID(bad)
		assert.ErrorIs(t, err, ErrInvalidTenantID, bad)
	}
}

func TestHandleRefusesProtectedBeforeAnyWork(t *testing.T) {
	// DB is nil-safe here: New requires one, but a refused command must never touch it.
	p := &Participant{cfg: Config{Service: "svc", Hooks: panicHooks{}}, log: nopLogger()}
	ack := p.Handle(t.Context(), Command{RunID: "r1", TenantID: "00000000-0000-0000-0000-000000000002", Phase: PhaseErase})
	assert.Equal(t, StatusBlocked, ack.Status)
	assert.Equal(t, "r1", ack.RunID)
	assert.Equal(t, "svc", ack.Service)
	assert.Equal(t, PhaseErase, ack.Phase)
}
