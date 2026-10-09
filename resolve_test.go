package enroll

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testServer(t *testing.T) (*Server, *memoryStore) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	k, _ := NewKey(raw)
	codec, _ := NewSessionCodec([]byte(strings.Repeat("s", 32)))
	st := NewMemoryStore()
	s := NewServer(st, OIDCConfig{}, codec, k,
		&TelnyxSender{}, "+15550001111", "https://librechat.vranyes.com")
	return s, st.(*memoryStore)
}

func seedEnrollment(t *testing.T, s *Server, phone, sub, key string) {
	t.Helper()
	seedEnrollmentWithPIN(t, s, phone, sub, key, "482916")
}

func seedEnrollmentWithPIN(t *testing.T, s *Server, phone, sub, key, pin string) {
	t.Helper()
	n, ct, err := s.keys.Encrypt([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	pn, pct, err := s.keys.Encrypt([]byte(pin))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertEnrollment(context.Background(), Enrollment{
		Phone: phone, UserSub: sub, EncKey: ct, Nonce: n,
		EncPIN: pct, PINNonce: pn, VerifiedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
}

func getResolve(t *testing.T, s *Server, phone, reveal string) *httptest.ResponseRecorder {
	t.Helper()
	target := "/resolve?phone=" + phone
	if reveal != "" {
		target += "&reveal=" + reveal
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()
	s.InternalMux().ServeHTTP(rr, req)
	return rr
}

func TestResolveGetsUserSubOnly(t *testing.T) {
	s, _ := testServer(t)
	seedEnrollment(t, s, "+15550109999", "kanidm-sub-1", "live-librechat-key")

	rr := getResolve(t, s, "+15550109999", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("resolve: status %d", rr.Code)
	}
	var out map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["user_sub"] != "kanidm-sub-1" {
		t.Fatalf("resolve: %v", out)
	}
	if _, hasKey := out["api_key"]; hasKey {
		t.Fatal("resolve leaked key material without reveal=key")
	}
}

func TestResolveGetsKeyOnReveal(t *testing.T) {
	s, _ := testServer(t)
	seedEnrollment(t, s, "+15550109999", "kanidm-sub-1", "live-librechat-key")

	rr := getResolve(t, s, "+15550109999", "")
	var out map[string]string
	json.NewDecoder(rr.Body).Decode(&out)
	if _, hasKey := out["api_key"]; hasKey {
		t.Fatal("got key material without reveal=key")
	}

	rr = getResolve(t, s, "+15550109999", "key")
	out = map[string]string{}
	json.NewDecoder(rr.Body).Decode(&out)
	if out["api_key"] != "live-librechat-key" || out["user_sub"] != "kanidm-sub-1" {
		t.Fatalf("reveal: %v", out)
	}
}

func TestResolveUnknownAndUnenrolledIdentical(t *testing.T) {
	s, _ := testServer(t)
	// "+19998887777" was never enrolled at all; "+15550109999" will be
	// enrolled then revoked (unenrolled). Both must deny identically.
	seedEnrollment(t, s, "+15550109999", "kanidm-sub-1", "k")
	if _, err := s.store.DeleteEnrollment(context.Background(), "+15550109999", "kanidm-sub-1"); err != nil {
		t.Fatal(err)
	}
	a := getResolve(t, s, "+19998887777", "")
	b := getResolve(t, s, "+15550109999", "")
	if a.Code != http.StatusNotFound || b.Code != http.StatusNotFound {
		t.Fatalf("statuses %d/%d, want 404/404", a.Code, b.Code)
	}
	if a.Body.String() != b.Body.String() {
		t.Fatalf("distinguishable deny bodies: %q vs %q", a.Body.String(), b.Body.String())
	}
}

func TestResolveNormalizesPhone(t *testing.T) {
	s, _ := testServer(t)
	seedEnrollment(t, s, "+15550109999", "kanidm-sub-1", "k")
	rr := getResolve(t, s, "+1+(555)+010-9999", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("unnormalized caller id denied: %d", rr.Code)
	}
}

// loginAs builds a request carrying a valid session cookie.
func loginAs(s *Server, sub, verifiedPhone string) *http.Cookie {
	sess := Session{Sub: sub, VerifiedPhone: verifiedPhone, ExpiresAt: s.now().Add(time.Hour)}
	return &http.Cookie{Name: "enroll_session", Value: s.sessions.Encode(sess)}
}

func TestGrantRequiresVerifiedPhone(t *testing.T) {
	s, _ := testServer(t)
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer fake.Close()
	s.libreChat = fake.URL
	s.httpClient = fake.Client()

	// Logged in but no verified phone: grant must refuse. Claiming a number
	// without OTP is impossible because the grant path keys off the
	// OTP-set session field, not the request body (which carries no phone).
	req := httptest.NewRequest(http.MethodPost, "/api/grant", strings.NewReader(`{"api_key":"k"}`))
	req.AddCookie(loginAs(s, "sub-1", ""))
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unverified grant: status %d, want 401", rr.Code)
	}
}

func TestGrantStoresLiveKeyRejectsDead(t *testing.T) {
	s, _ := testServer(t)
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer good" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer fake.Close()
	s.libreChat = fake.URL
	s.httpClient = fake.Client()

	post := func(key, pin, phone string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/grant", strings.NewReader(`{"api_key":`+quote(key)+`,"pin":`+quote(pin)+`}`))
		req.AddCookie(loginAs(s, "sub-1", phone))
		rr := httptest.NewRecorder()
		s.PublicMux().ServeHTTP(rr, req)
		return rr.Code
	}
	if code := post("dead", "482916", "+15550109999"); code != http.StatusBadRequest {
		t.Fatalf("dead key: status %d, want 400", code)
	}
	if e, _ := s.store.GetByPhone(context.Background(), "+15550109999"); e != nil {
		t.Fatal("dead key was stored")
	}
	if code := post("good", "482916", "+15550109999"); code != http.StatusCreated {
		t.Fatalf("live key: status %d, want 201", code)
	}
	e, _ := s.store.GetByPhone(context.Background(), "+15550109999")
	if e == nil || e.UserSub != "sub-1" {
		t.Fatalf("live key not stored: %+v", e)
	}
	plain, err := s.keys.Decrypt(e.Nonce, e.EncKey)
	if err != nil || string(plain) != "good" {
		t.Fatal("stored key does not decrypt to the granted key")
	}
	pinPlain, err := s.keys.Decrypt(e.PINNonce, e.EncPIN)
	if err != nil || string(pinPlain) != "482916" {
		t.Fatal("stored PIN does not decrypt to the granted PIN")
	}
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestRevokeDeletesMappingAndResolveDenies(t *testing.T) {
	s, _ := testServer(t)
	seedEnrollment(t, s, "+15550109999", "sub-1", "k")

	req := httptest.NewRequest(http.MethodPost, "/api/revoke", nil)
	req.AddCookie(loginAs(s, "sub-1", "+15550109999"))
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke: status %d", rr.Code)
	}
	// Fail-closed by construction: the next resolve denies.
	rr = getResolve(t, s, "+15550109999", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("post-revoke resolve: status %d, want 404 deny", rr.Code)
	}
}

func TestRevokeCannotDeleteOthersNumber(t *testing.T) {
	s, _ := testServer(t)
	seedEnrollment(t, s, "+15550109999", "victim-sub", "k")

	req := httptest.NewRequest(http.MethodPost, "/api/revoke", nil)
	req.AddCookie(loginAs(s, "attacker-sub", "+15550109999"))
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke: status %d", rr.Code)
	}
	// Attacker's session names the victim's number but the delete is
	// (phone, sub)-scoped: the victim mapping must survive. (And the
	// attacker could never have set VerifiedPhone to the victim's number
	// without receiving the victim's SMS — OTP binding.)
	e, _ := s.store.GetByPhone(context.Background(), "+15550109999")
	if e == nil || e.UserSub != "victim-sub" {
		t.Fatal("cross-user revoke deleted the victim mapping")
	}
}

func TestPublicMuxHasNoResolve(t *testing.T) {
	s, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/resolve?phone=+15550109999", nil)
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatal("public mux serves /resolve — key material route must be internal-only")
	}
	body, _ := io.ReadAll(rr.Body)
	_ = body
}

func TestGrantRejectsBadPIN(t *testing.T) {
	s, _ := testServer(t)
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer fake.Close()
	s.libreChat = fake.URL
	s.httpClient = fake.Client()

	post := func(pin string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/grant", strings.NewReader(`{"api_key":"good","pin":`+quote(pin)+`}`))
		req.AddCookie(loginAs(s, "sub-1", "+15550109999"))
		rr := httptest.NewRecorder()
		s.PublicMux().ServeHTTP(rr, req)
		return rr.Code
	}
	for _, pin := range []string{"", "123", "1234567890123", "12a4", "  "} {
		if code := post(pin); code != http.StatusBadRequest {
			t.Fatalf("pin %q: status %d, want 400", pin, code)
		}
	}
	if e, _ := s.store.GetByPhone(context.Background(), "+15550109999"); e != nil {
		t.Fatal("bad PIN was stored")
	}
	// 4- and 12-digit boundaries store.
	if code := post("1234"); code != http.StatusCreated {
		t.Fatalf("4-digit PIN: status %d, want 201", code)
	}
	if code := post("123456789012"); code != http.StatusCreated {
		t.Fatalf("12-digit PIN: status %d, want 201", code)
	}
}

func postVerifyPIN(t *testing.T, s *Server, phone, pin string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/verify-pin", strings.NewReader(`{"phone":`+quote(phone)+`,"pin":`+quote(pin)+`}`))
	rr := httptest.NewRecorder()
	s.InternalMux().ServeHTTP(rr, req)
	return rr
}

func TestVerifyPINAcceptsCorrectRejectsWrongIdentically(t *testing.T) {
	s, _ := testServer(t)
	seedEnrollmentWithPIN(t, s, "+15550109999", "kanidm-sub-1", "k", "482916")

	rr := postVerifyPIN(t, s, "+15550109999", "482916")
	if rr.Code != http.StatusOK {
		t.Fatalf("correct PIN: status %d, want 200", rr.Code)
	}
	var out map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil || out["user_sub"] != "kanidm-sub-1" {
		t.Fatalf("correct PIN body: %q", rr.Body.String())
	}

	wrong := postVerifyPIN(t, s, "+15550109999", "000000")
	unknown := postVerifyPIN(t, s, "+19998887777", "482916")
	malformed := postVerifyPIN(t, s, "+15550109999", "12")
	if wrong.Code != http.StatusNotFound || unknown.Code != http.StatusNotFound || malformed.Code != http.StatusNotFound {
		t.Fatalf("statuses %d/%d/%d, want 404/404/404", wrong.Code, unknown.Code, malformed.Code)
	}
	if wrong.Body.String() != unknown.Body.String() || wrong.Body.String() != malformed.Body.String() {
		t.Fatalf("distinguishable deny bodies: %q vs %q vs %q", wrong.Body.String(), unknown.Body.String(), malformed.Body.String())
	}
}

func TestVerifyPINRequiresPINAtGrant(t *testing.T) {
	s, _ := testServer(t)
	// Legacy row without PIN material (pre-migration): verify denies.
	n, ct, _ := s.keys.Encrypt([]byte("k"))
	_ = s.store.UpsertEnrollment(context.Background(), Enrollment{
		Phone: "+15550109999", UserSub: "sub-1", EncKey: ct, Nonce: n, VerifiedAt: time.Now(),
	})
	rr := postVerifyPIN(t, s, "+15550109999", "482916")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("PIN-less row: status %d, want 404 deny", rr.Code)
	}
}

func TestPublicMuxHasNoVerifyPIN(t *testing.T) {
	s, _ := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/verify-pin", strings.NewReader(`{}`))
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatal("public mux serves /verify-pin — PIN verifier must be internal-only")
	}
}
