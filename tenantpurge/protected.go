// SPDX-License-Identifier: Apache-2.0

package tenantpurge

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

var (
	// ErrInvalidTenantID is returned for a tenant id that is not a UUID.
	ErrInvalidTenantID = errors.New("tenantpurge: tenant id is not a valid uuid")
	// ErrProtectedTenant is returned for ids that must never be purged.
	ErrProtectedTenant = errors.New("tenantpurge: protected tenant id, refusing")
)

// protectedTenantIDs is hard coded on purpose: no config, flag or command field
// can lift it.
//
//	...0000  nil / platform sentinel
//	...0001  default realm
//	...0002  HexxLock internal tenant (models.HexxlockInternalTenantID in falcon-id)
//	...0004  B2C consumer tenant (models.WellKnownTenantConsumer in falcon-id)
var protectedTenantIDs = [...]uuid.UUID{
	uuid.MustParse("00000000-0000-0000-0000-000000000000"),
	uuid.MustParse("00000000-0000-0000-0000-000000000001"),
	uuid.MustParse("00000000-0000-0000-0000-000000000002"),
	uuid.MustParse("00000000-0000-0000-0000-000000000004"),
}

// ProtectedTenantIDs returns a copy of the protected id set (canonical strings).
func ProtectedTenantIDs() []string {
	out := make([]string, 0, len(protectedTenantIDs))
	for _, id := range protectedTenantIDs {
		out = append(out, id.String())
	}
	return out
}

// IsProtected reports whether id is in the protected set. Any spelling uuid.Parse
// accepts is normalised first. An unparsable id is not "protected" but is
// rejected by CheckTenantID.
func IsProtected(id string) bool {
	u, err := uuid.Parse(id)
	if err != nil {
		return false
	}
	for _, p := range protectedTenantIDs {
		if u == p {
			return true
		}
	}
	return false
}

// CheckTenantID parses id and returns its canonical form, or ErrInvalidTenantID /
// ErrProtectedTenant. Run before any work.
func CheckTenantID(id string) (string, error) {
	u, err := uuid.Parse(id)
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrInvalidTenantID, id)
	}
	if IsProtected(u.String()) {
		return "", fmt.Errorf("%w: %s", ErrProtectedTenant, u.String())
	}
	return u.String(), nil
}
