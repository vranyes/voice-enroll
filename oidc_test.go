package enroll

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeProvider builds an OIDC provider double with a generated RSA key.
type fakeProvider struct {
	t    *testing.T
	srv  *httptest.Server
	priv *rsa.PrivateKey
	iss  string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeProvider{t: t, priv: priv}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": f.iss + "/auth",
			"token_endpoint":         f.iss + "/token",
			"userinfo_endpoint":      f.iss + "/me",
			"jwks_uri":               f.iss + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(f.priv.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.priv.E)).Bytes())
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{
			map[string]string{"kid": "k1", "kty": "RSA", "n": n, "e": e},
		}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		id := f.mint("test-sub", "test-client", "test-nonce", time.Now().Add(time.Hour))
		json.NewEncoder(w).Encode(map[string]string{"id_token": id, "access_token": "at"})
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"sub": "test-sub"})
	})
	f.srv = httptest.NewServer(mux)
	f.iss = f.srv.URL
	return f
}

func (f *fakeProvider) mint(sub, aud, nonce string, exp time.Time) string {
	f.t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k1","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{
		"iss": f.iss, "sub": sub, "aud": aud,
		"exp": exp.Unix(), "iat": time.Now().Unix(), "nonce": nonce,
	})
	p := base64.RawURLEncoding.EncodeToString(payload)
	h := sha256.Sum256([]byte(header + "." + p))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.priv, crypto.SHA256, h[:])
	if err != nil {
		f.t.Fatal(err)
	}
	return header + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestOIDCLoginURL(t *testing.T) {
	f := newFakeProvider(t)
	defer f.srv.Close()
	c := OIDCConfig{Issuer: f.iss, ClientID: "test-client", RedirectURL: "https://enroll/x/cb", HTTPClient: f.srv.Client()}
	u, err := f.srv.Client().Get(f.iss + "/.well-known/openid-configuration")
	_ = u
	if err != nil {
		t.Fatal(err)
	}
	login, err := c.LoginURL(t.Context(), "state123", "nonce123")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"state123", "nonce123", "response_type=code", "test-client"} {
		if !strings.Contains(login, want) {
			t.Fatalf("login URL missing %q: %s", want, login)
		}
	}
}

func TestOIDCExchangeVerifies(t *testing.T) {
	f := newFakeProvider(t)
	defer f.srv.Close()
	c := OIDCConfig{Issuer: f.iss, ClientID: "test-client", ClientSecret: "s", RedirectURL: "https://enroll/x/cb", HTTPClient: f.srv.Client()}
	sub, at, err := c.Exchange(t.Context(), "code", "test-nonce")
	if err != nil {
		t.Fatal(err)
	}
	if sub != "test-sub" || at != "at" {
		t.Fatalf("got sub=%q at=%q", sub, at)
	}
}

func TestOIDCExchangeRejectsBadNonce(t *testing.T) {
	f := newFakeProvider(t)
	defer f.srv.Close()
	c := OIDCConfig{Issuer: f.iss, ClientID: "test-client", ClientSecret: "s", RedirectURL: "https://enroll/x/cb", HTTPClient: f.srv.Client()}
	if _, _, err := c.Exchange(t.Context(), "code", "wrong-nonce"); err == nil {
		t.Fatal("wrong nonce accepted")
	}
}

func TestOIDCRejectsExpired(t *testing.T) {
	f := newFakeProvider(t)
	defer f.srv.Close()
	c := OIDCConfig{Issuer: f.iss, ClientID: "test-client", HTTPClient: f.srv.Client()}
	d, _ := c.discover(t.Context())
	expired := f.mint("test-sub", "test-client", "", time.Now().Add(-time.Hour))
	if _, err := c.verifyIDToken(t.Context(), d, expired, ""); err == nil {
		t.Fatal("expired id_token accepted")
	}
}

func TestOIDCRejectsWrongAud(t *testing.T) {
	f := newFakeProvider(t)
	defer f.srv.Close()
	c := OIDCConfig{Issuer: f.iss, ClientID: "other-client", HTTPClient: f.srv.Client()}
	d, _ := c.discover(t.Context())
	tok := f.mint("test-sub", "test-client", "", time.Now().Add(time.Hour))
	if _, err := c.verifyIDToken(t.Context(), d, tok, ""); err == nil {
		t.Fatal("wrong-audience id_token accepted")
	}
}

func TestSessionCookieRoundTrip(t *testing.T) {
	codec, err := NewSessionCodec([]byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	sess := Session{Sub: "sub-1", VerifiedPhone: "+15550109999", ExpiresAt: time.Now().Add(time.Hour)}
	got, err := codec.Decode(codec.Encode(sess), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got.Sub != sess.Sub || got.VerifiedPhone != sess.VerifiedPhone || got.ExpiresAt.Unix() != sess.ExpiresAt.Unix() {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
}

func TestSessionCookieTamperAndExpiry(t *testing.T) {
	codec, _ := NewSessionCodec([]byte(strings.Repeat("s", 32)))
	sess := Session{Sub: "sub-1", ExpiresAt: time.Now().Add(time.Hour)}
	enc := codec.Encode(sess)
	tampered := enc[:len(enc)-2] + "AA"
	if _, err := codec.Decode(tampered, time.Now()); err == nil {
		t.Fatal("tampered cookie accepted")
	}
	if _, err := codec.Decode(enc, time.Now().Add(2*time.Hour)); err == nil {
		t.Fatal("expired session accepted")
	}
	other, _ := NewSessionCodec([]byte(strings.Repeat("o", 32)))
	if _, err := other.Decode(enc, time.Now()); err == nil {
		t.Fatal("foreign-secret cookie accepted")
	}
}
