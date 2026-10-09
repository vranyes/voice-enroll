package enroll

import (
	"errors"
	"strings"
)

// NormalizeE164 canonicalizes a user-supplied phone number to E.164.
//
// Semantics match voice-bridge's allowlist parsing (PLAN.md slice 4):
// "+1 (555) 010-9999" == "15550109999" == "+15550109999".
// All non-digit input is stripped; the result is "+" + digits.
// Valid E.164 is 7-15 digits. Anything else is ErrInvalidPhone.
func NormalizeE164(raw string) (string, error) {
	var b strings.Builder
	for _, r := range raw {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	digits := b.String()
	if len(digits) < 7 || len(digits) > 15 {
		return "", ErrInvalidPhone
	}
	return "+" + digits, nil
}

var ErrInvalidPhone = errors.New("invalid phone number: need 7-15 digits")
