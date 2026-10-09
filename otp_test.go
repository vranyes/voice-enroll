package enroll

import (
	"errors"
	"sync"
	"testing"
	"time"
)

type memOTP struct {
	mu sync.Mutex
	m  map[string]OTPRecord
}

func (s *memOTP) GetOTP(phone string) (*OTPRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[phone]
	if !ok {
		return nil, nil
	}
	c := r
	return &c, nil
}

func (s *memOTP) PutOTP(phone string, rec OTPRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]OTPRecord{}
	}
	s.m[phone] = rec
	return nil
}

func newMemOTP() *memOTP { return &memOTP{m: map[string]OTPRecord{}} }

func TestOTPVerifyRoundTrip(t *testing.T) {
	s, now := newMemOTP(), time.Now()
	if err := RequestSend(s, systemClock{}, "+15550109999", "123456", now); err != nil {
		t.Fatal(err)
	}
	if err := VerifyOTP(s, "+15550109999", "123456", now.Add(time.Minute)); err != nil {
		t.Fatalf("valid code rejected: %v", err)
	}
	// Single-use: second verify must fail.
	if err := VerifyOTP(s, "+15550109999", "123456", now.Add(2*time.Minute)); err == nil {
		t.Fatal("reused code accepted")
	}
}

func TestOTPVerifyWrongCodeAndAttemptLimit(t *testing.T) {
	s, now := newMemOTP(), time.Now()
	if err := RequestSend(s, systemClock{}, "+15550109999", "123456", now); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < OTPMaxAttempts; i++ {
		err := VerifyOTP(s, "+15550109999", "000000", now.Add(time.Minute))
		if i < OTPMaxAttempts-1 && !errors.Is(err, ErrOTPInvalid) {
			t.Fatalf("attempt %d: got %v, want ErrOTPInvalid", i, err)
		}
	}
	// Exhausted: even the right code now fails.
	if err := VerifyOTP(s, "+15550109999", "123456", now.Add(time.Minute)); !errors.Is(err, ErrOTPAttempts) {
		t.Fatalf("exhausted code: got %v, want ErrOTPAttempts", err)
	}
}

func TestOTPExpiry(t *testing.T) {
	s, now := newMemOTP(), time.Now()
	if err := RequestSend(s, systemClock{}, "+15550109999", "123456", now); err != nil {
		t.Fatal(err)
	}
	if err := VerifyOTP(s, "+15550109999", "123456", now.Add(OTPExpiry+time.Second)); !errors.Is(err, ErrOTPExpired) {
		t.Fatalf("expired code: got %v, want ErrOTPExpired", err)
	}
}

func TestOTPSendRateLimit(t *testing.T) {
	s, now := newMemOTP(), time.Now()
	for i := 0; i < OTPSendLimit; i++ {
		if err := RequestSend(s, systemClock{}, "+15550109999", "123456", now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if err := RequestSend(s, systemClock{}, "+15550109999", "123456", now.Add(6*time.Minute)); !errors.Is(err, ErrOTPRateLimited) {
		t.Fatalf("over-limit send: got %v, want ErrOTPRateLimited", err)
	}
	// Window rolls: sends resume after OTPSendWindow.
	if err := RequestSend(s, systemClock{}, "+15550109999", "123456", now.Add(OTPSendWindow+time.Minute)); err != nil {
		t.Fatalf("post-window send rejected: %v", err)
	}
}

func TestOTPUnknownNumberDenies(t *testing.T) {
	s := newMemOTP()
	if err := VerifyOTP(s, "+19998887777", "123456", time.Now()); !errors.Is(err, ErrOTPExpired) {
		t.Fatalf("unknown number: got %v, want deny", err)
	}
}

func TestGenerateOTPFormat(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		c, err := GenerateOTP()
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != 6 {
			t.Fatalf("code %q not 6 digits", c)
		}
		for _, r := range c {
			if r < '0' || r > '9' {
				t.Fatalf("code %q not numeric", c)
			}
		}
		seen[c] = true
	}
	if len(seen) < 40 {
		t.Fatal("OTP output lacks entropy")
	}
}
