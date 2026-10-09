package enroll

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// Key wraps a 32-byte AES-256-GCM data-encryption key. The DEK arrives via a
// SealedSecret env var, is never logged, and only exists in process memory.
type Key struct{ raw []byte }

// NewKey validates DEK length. Anything but 32 bytes is a startup error.
func NewKey(raw []byte) (*Key, error) {
	if len(raw) != 32 {
		return nil, errors.New("DEK must be 32 bytes")
	}
	c := make([]byte, 32)
	copy(c, raw)
	return &Key{raw: c}, nil
}

// Encrypt seals plaintext with a fresh random nonce. Nonce reuse is
// impossible by construction: the nonce is drawn from crypto/rand per call.
func (k *Key) Encrypt(plaintext []byte) (nonce, ciphertext []byte, err error) {
	g, err := k.gcm()
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, g.Seal(nil, nonce, plaintext, nil), nil
}

// Decrypt opens ciphertext. Wrong-key or tampered input fails closed.
func (k *Key) Decrypt(nonce, ciphertext []byte) ([]byte, error) {
	g, err := k.gcm()
	if err != nil {
		return nil, err
	}
	return g.Open(nil, nonce, ciphertext, nil)
}

func (k *Key) gcm() (cipher.AEAD, error) {
	b, err := aes.NewCipher(k.raw)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}
