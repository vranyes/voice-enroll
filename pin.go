package enroll

import (
	"crypto/subtle"
	"errors"
)

// PIN bounds: DTMF-compatible digits, user-chosen length. Voice-bridge
// gathers with minimum 4 / maximum 12 + "#" terminator, so enrollment
// must accept the same range.
const (
	PINMinLength = 4
	PINMaxLength = 12
)

var ErrInvalidPIN = errors.New("invalid PIN: need 4-12 digits")

// ValidatePIN rejects empty, non-digit, too-short and too-long candidates.
func ValidatePIN(pin string) error {
	if len(pin) < PINMinLength || len(pin) > PINMaxLength {
		return ErrInvalidPIN
	}
	for i := 0; i < len(pin); i++ {
		if pin[i] < '0' || pin[i] > '9' {
			return ErrInvalidPIN
		}
	}
	return nil
}

// VerifyPIN compares a decrypted stored PIN against a guess in constant
// time. Shape mismatches reject without comparing.
func VerifyPIN(stored, guess string) bool {
	if ValidatePIN(stored) != nil || ValidatePIN(guess) != nil {
		return false
	}
	if len(stored) != len(guess) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(guess)) == 1
}
