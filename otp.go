package enroll

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"
)

const (
	// OTPDigits is the length of the numeric code texted to the user.
	OTPDigits = 6
	// OTPExpiry bounds how long a code is valid. Single-use + expiry means a
	// leaked code is only useful inside this window.
	OTPExpiry = 10 * time.Minute
	// OTPMaxAttempts bounds guesses per code. Exhausted codes must be
	// re-requested (which re-sends and resets the record).
	OTPMaxAttempts = 5
	// OTPSendLimit / OTPSendWindow rate-limit code sends per number so an
	// attacker cannot SMS-bomb a victim or brute-force the send path.
	OTPSendLimit  = 5
	OTPSendWindow = time.Hour
)

var (
	ErrOTPExpired     = errors.New("code expired or not found")
	ErrOTPUsed        = errors.New("code already used")
	ErrOTPAttempts    = errors.New("too many attempts")
	ErrOTPInvalid     = errors.New("invalid code")
	ErrOTPRateLimited = errors.New("too many sends, try later")
	ErrOTPNoRecord    = errors.New("no code requested")
)

// OTPRecord is the stored (never plaintext code) OTP state per number.
type OTPRecord struct {
	CodeHash    [32]byte
	ExpiresAt   time.Time
	Attempts    int
	Used        bool
	SendCount   int
	WindowStart time.Time
}

// HashOTP returns the sha256 of the code. Codes are sha256-hashed at rest;
// the plaintext exists only in the SMS body and the verify request.
func HashOTP(code string) [32]byte { return sha256.Sum256([]byte(code)) }

// GenerateOTP returns a random 6-digit code using crypto/rand.
func GenerateOTP() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n %= 1000000
	return fmt.Sprintf("%06d", n), nil
}

// OTPStore persists OTP records keyed by normalized E.164.
type OTPStore interface {
	GetOTP(phone string) (*OTPRecord, error)
	PutOTP(phone string, rec OTPRecord) error
}

// otpManagerClock allows tests to advance time without sleeping.
type Clock interface{ Now() time.Time }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// RequestSend records a fresh code send, enforcing the per-number rate limit.
// It returns ErrOTPRateLimited when the window budget is exhausted.
func RequestSend(store OTPStore, clock Clock, phone, code string, now time.Time) error {
	rec, err := store.GetOTP(phone)
	if err != nil {
		return err
	}
	r := OTPRecord{WindowStart: now}
	if rec != nil && now.Sub(rec.WindowStart) < OTPSendWindow {
		r.SendCount = rec.SendCount
		r.WindowStart = rec.WindowStart
	}
	if r.SendCount >= OTPSendLimit {
		return ErrOTPRateLimited
	}
	r.SendCount++
	r.CodeHash = HashOTP(code)
	r.ExpiresAt = now.Add(OTPExpiry)
	return store.PutOTP(phone, r)
}

// VerifyOTP checks a guess against the stored record. Every failure mode
// returns without distinguishing expired/unknown/used/wrong to the caller
// except via typed errors for metrics; the HTTP layer maps them all to a
// generic deny (unknown vs wrong must not be distinguishable... except that
// expiry vs wrong is fine to conflate entirely — we return 400 "invalid or
// expired" for all of them).
func VerifyOTP(store OTPStore, phone, guess string, now time.Time) error {
	rec, err := store.GetOTP(phone)
	if err != nil {
		return err
	}
	if rec == nil || now.After(rec.ExpiresAt) {
		return ErrOTPExpired
	}
	if rec.Used {
		return ErrOTPUsed
	}
	if rec.Attempts >= OTPMaxAttempts {
		return ErrOTPAttempts
	}
	got := HashOTP(guess)
	if subtle.ConstantTimeCompare(rec.CodeHash[:], got[:]) != 1 {
		rec.Attempts++
		if err := store.PutOTP(phone, *rec); err != nil {
			return err
		}
		if rec.Attempts >= OTPMaxAttempts {
			return ErrOTPAttempts
		}
		return ErrOTPInvalid
	}
	rec.Used = true
	return store.PutOTP(phone, *rec)
}
