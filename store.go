package enroll

import (
	"context"
	"sync"
	"time"
)

// Enrollment is one directory row: a verified E.164 number bound to the
// Kanidm subject that proved ownership of it, plus that subject's
// AES-GCM-encrypted LibreChat Remote Agents API key and AES-GCM-encrypted
// voice PIN (4-12 DTMF digits, chosen at grant time).
//
// Trust note: the pasted key's owner is opaque to us. Binding key→(sub,phone)
// is trust-based by design — holding someone else's key already grants direct
// LibreChat access as them, so binding it here gains an attacker nothing they
// did not already have. Identity in the resolve response comes from the
// verified login session + OTP only, never from the key.
//
// PIN note: the PIN is encrypted under the same DEK as the API key (never
// plaintext at rest) and is only ever compared inside verify-pin or
// decrypted for that comparison. It never appears in resolve responses
// or logs.
type Enrollment struct {
	Phone      string // normalized E.164
	UserSub    string // Kanidm `sub` from the verified login session
	EncKey     []byte // AES-GCM ciphertext of the LibreChat API key
	Nonce      []byte
	EncPIN     []byte // AES-GCM ciphertext of the voice PIN
	PINNonce   []byte
	VerifiedAt time.Time
}

// Store is the enrollment directory. Postgres is the deploy backend;
// memoryStore is the test/standalone backend behind the same interface.
type Store interface {
	OTPStore
	UpsertEnrollment(ctx context.Context, e Enrollment) error
	GetByPhone(ctx context.Context, phone string) (*Enrollment, error)
	// DeleteEnrollment removes the mapping only when both phone and sub
	// match, so one user cannot revoke another's number.
	DeleteEnrollment(ctx context.Context, phone, sub string) (bool, error)
}

type memoryStore struct {
	mu    sync.Mutex
	otps  map[string]OTPRecord
	enrol map[string]Enrollment
}

func NewMemoryStore() Store {
	return &memoryStore{otps: map[string]OTPRecord{}, enrol: map[string]Enrollment{}}
}

func (s *memoryStore) GetOTP(phone string) (*OTPRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.otps[phone]
	if !ok {
		return nil, nil
	}
	c := r
	return &c, nil
}

func (s *memoryStore) PutOTP(phone string, rec OTPRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.otps[phone] = rec
	return nil
}

func (s *memoryStore) UpsertEnrollment(_ context.Context, e Enrollment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enrol[e.Phone] = e
	return nil
}

func (s *memoryStore) GetByPhone(_ context.Context, phone string) (*Enrollment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.enrol[phone]
	if !ok {
		return nil, nil
	}
	c := e
	return &c, nil
}

func (s *memoryStore) DeleteEnrollment(_ context.Context, phone, sub string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.enrol[phone]
	if !ok || e.UserSub != sub {
		return false, nil
	}
	delete(s.enrol, phone)
	return true, nil
}
