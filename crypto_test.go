package enroll

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func testKey(t *testing.T) *Key {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	k, err := NewKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestEncryptRoundTrip(t *testing.T) {
	k := testKey(t)
	n, c, err := k.Encrypt([]byte("secret-api-key"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := k.Decrypt(n, c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p, []byte("secret-api-key")) {
		t.Fatalf("roundtrip mismatch: %q", p)
	}
}

func TestEncryptNonceUnique(t *testing.T) {
	k := testKey(t)
	n1, c1, _ := k.Encrypt([]byte("same"))
	n2, c2, _ := k.Encrypt([]byte("same"))
	if bytes.Equal(n1, n2) || bytes.Equal(c1, c2) {
		t.Fatal("nonce reuse: identical outputs for identical input")
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	n, c, err := testKey(t).Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testKey(t).Decrypt(n, c); err == nil {
		t.Fatal("wrong-key decrypt succeeded")
	}
}

func TestDecryptTamperedFails(t *testing.T) {
	k := testKey(t)
	n, c, err := k.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	c[0] ^= 1
	if _, err := k.Decrypt(n, c); err == nil {
		t.Fatal("tampered decrypt succeeded")
	}
}

func TestNewKeyRejectsBadLength(t *testing.T) {
	for _, raw := range [][]byte{nil, make([]byte, 16), make([]byte, 64)} {
		if _, err := NewKey(raw); err == nil {
			t.Fatalf("accepted %d-byte DEK", len(raw))
		}
	}
}
