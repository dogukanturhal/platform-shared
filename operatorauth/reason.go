// SPDX-License-Identifier: Apache-2.0

package operatorauth

import (
	"errors"
	"strings"
)

// ReasonCode is the fixed-list reason every operator write carries.
type ReasonCode string

// The fixed reason-code list. Services may accept a subset.
const (
	ReasonCustomerRequest   ReasonCode = "customer_request"
	ReasonSupportTicket     ReasonCode = "support_ticket"
	ReasonBillingCorrection ReasonCode = "billing_correction"
	ReasonFraudReview       ReasonCode = "fraud_review"
	ReasonSecurityIncident  ReasonCode = "security_incident"
	ReasonComplianceRequest ReasonCode = "compliance_request"
	ReasonDataCorrection    ReasonCode = "data_correction"
	ReasonTrialExtension    ReasonCode = "trial_extension"
	ReasonOutageMitigation  ReasonCode = "outage_mitigation"
	ReasonLegalHold         ReasonCode = "legal_hold"
	ReasonOther             ReasonCode = "other"
)

// ReasonPlatformAdmin is reserved for the standing platform_admin acting
// directly. Valid() accepts it, but ReasonCodes() does not list it (it is never
// offered in a dropdown) and DirectReason rejects it from anyone else.
const ReasonPlatformAdmin ReasonCode = "platform_admin"

// PlatformAdminReasonText is the canonical auto-filled justification for a
// direct platform_admin action (at least 32 characters).
func PlatformAdminReasonText(email string) string {
	email = strings.TrimSpace(email)
	if email == "" {
		email = "operator"
	}
	return "platform_admin direct action by " + email
}

// MinReasonTextLen is the minimum length of the free-text justification
// (the console enforces the same number).
const MinReasonTextLen = 20

// ReasonCodes returns the fixed list in display order.
func ReasonCodes() []ReasonCode {
	return []ReasonCode{
		ReasonCustomerRequest, ReasonSupportTicket, ReasonBillingCorrection,
		ReasonFraudReview, ReasonSecurityIncident, ReasonComplianceRequest,
		ReasonDataCorrection, ReasonTrialExtension, ReasonOutageMitigation,
		ReasonLegalHold, ReasonOther,
	}
}

// Valid reports whether c is on the fixed list or is the reserved
// ReasonPlatformAdmin.
func (c ReasonCode) Valid() bool {
	if c == ReasonPlatformAdmin {
		return true
	}
	for _, k := range ReasonCodes() {
		if c == k {
			return true
		}
	}
	return false
}

// Reason is a validated code plus free-text justification.
type Reason struct {
	Code ReasonCode `json:"reason_code"`
	Text string     `json:"reason"`
}

// ErrInvalidReason is returned by ParseReason.
var ErrInvalidReason = errors.New("operatorauth: reason code from the fixed list and a justification of at least 20 characters are required")

// ParseReason validates a code and its justification.
func ParseReason(code, text string) (Reason, error) {
	r := Reason{Code: ReasonCode(strings.TrimSpace(code)), Text: strings.TrimSpace(text)}
	if !r.Code.Valid() || len([]rune(r.Text)) < MinReasonTextLen {
		return Reason{}, ErrInvalidReason
	}
	return r, nil
}
