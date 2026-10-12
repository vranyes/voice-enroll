package enroll

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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

// fakeProvider builds an OIDC provider double with generated RSA + ECDSA keys.
type fakeProvider struct {
	t    *testing.T
	srv  *httptest.Server
	priv *rsa.PrivateKey
	ec   *ecdsa.PrivateKey
	iss  string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeProvider{t: t, priv: priv, ec: ec}
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
		x := base64.RawURLEncoding.EncodeToString(f.ec.X.Bytes())
		y := base64.RawURLEncoding.EncodeToString(f.ec.Y.Bytes())
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{
			map[string]string{"kid": "k1", "kty": "RSA", "n": n, "e": e},
			map[string]string{"kid": "k2", "kty": "EC", "crv": "P-256", "x": x, "y": y},
		}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.FormValue("code_verifier") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
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

// mintES256 signs an id_token with ECDSA P-256 (JWS raw R||S signature),
// matching what Kanidm issues in production.
func (f *fakeProvider) mintES256(sub, aud, nonce string, exp time.Time) string {
	f.t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"k2","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{
		"iss": f.iss, "sub": sub, "aud": aud,
		"exp": exp.Unix(), "iat": time.Now().Unix(), "nonce": nonce,
	})
	p := base64.RawURLEncoding.EncodeToString(payload)
	h := sha256.Sum256([]byte(header + "." + p))
	r, s, err := ecdsa.Sign(rand.Reader, f.ec, h[:])
	if err != nil {
		f.t.Fatal(err)
	}
	rb := r.Bytes()
	sb := s.Bytes()
	raw := make([]byte, 64)
	copy(raw[32-len(rb):32], rb)
	copy(raw[64-len(sb):64], sb)
	return header + "." + p + "." + base64.RawURLEncoding.EncodeToString(raw)
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
	login, err := c.LoginURL(t.Context(), "state123", "nonce123", "test-verifier")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"state123", "nonce123", "response_type=code", "test-client", "code_challenge_method=S256", "code_challenge="} {
		if !strings.Contains(login, want) {
			t.Fatalf("login URL missing %q: %s", want, login)
		}
	}
	if !strings.Contains(login, CodeChallengeS256("test-verifier")) {
		t.Fatalf("login URL has wrong challenge: %s", login)
	}
}

func TestPKCEChallengeVector(t *testing.T) {
	// RFC 7636 appendix B test vector.
	if got := CodeChallengeS256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("challenge mismatch: %q", got)
	}
	v, err := NewCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 43 {
		t.Fatalf("verifier length %d, want 43", len(v))
	}
}

func TestOIDCExchangeVerifies(t *testing.T) {
	f := newFakeProvider(t)
	defer f.srv.Close()
	c := OIDCConfig{Issuer: f.iss, ClientID: "test-client", ClientSecret: "s", RedirectURL: "https://enroll/x/cb", HTTPClient: f.srv.Client()}
	sub, at, err := c.Exchange(t.Context(), "code", "test-nonce", "test-verifier")
	if err != nil {
		t.Fatal(err)
	}
	if sub != "test-sub" || at != "at" {
		t.Fatalf("got sub=%q at=%q", sub, at)
	}
}

func TestOIDCExchangeRequiresVerifier(t *testing.T) {
	f := newFakeProvider(t)
	defer f.srv.Close()
	c := OIDCConfig{Issuer: f.iss, ClientID: "test-client", ClientSecret: "s", RedirectURL: "https://enroll/x/cb", HTTPClient: f.srv.Client()}
	if _, _, err := c.Exchange(t.Context(), "code", "test-nonce", ""); err == nil {
		t.Fatal("missing verifier accepted")
	}
}

func TestOIDCES256Verifies(t *testing.T) {
	f := newFakeProvider(t)
	defer f.srv.Close()
	c := OIDCConfig{Issuer: f.iss, ClientID: "test-client", HTTPClient: f.srv.Client()}
	d, _ := c.discover(t.Context())
	tok := f.mintES256("es-sub", "test-client", "test-nonce", time.Now().Add(time.Hour))
	sub, err := c.verifyIDToken(t.Context(), d, tok, "test-nonce")
	if err != nil {
		t.Fatal(err)
	}
	if sub != "es-sub" {
		t.Fatalf("sub = %q, want es-sub", sub)
	}
}

func TestOIDCES256RejectsTampered(t *testing.T) {
	f := newFakeProvider(t)
	defer f.srv.Close()
	c := OIDCConfig{Issuer: f.iss, ClientID: "test-client", HTTPClient: f.srv.Client()}
	d, _ := c.discover(t.Context())
	tok := f.mintES256("es-sub", "test-client", "test-nonce", time.Now().Add(time.Hour))
	parts := strings.Split(tok, ".")
	tampered := parts[0] + "." + parts[1] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := c.verifyIDToken(t.Context(), d, tampered, "test-nonce"); err == nil {
		t.Fatal("tampered ES256 signature accepted")
	}
}

func TestOIDCExchangeRejectsBadNonce(t *testing.T) {
	f := newFakeProvider(t)
	defer f.srv.Close()
	c := OIDCConfig{Issuer: f.iss, ClientID: "test-client", ClientSecret: "s", RedirectURL: "https://enroll/x/cb", HTTPClient: f.srv.Client()}
	if _, _, err := c.Exchange(t.Context(), "code", "wrong-nonce", "test-verifier"); err == nil {
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
