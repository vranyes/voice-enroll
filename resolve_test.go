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
		&TelnyxSender{}, "+15550001111", "https://librechat.vranyes.com",
		"edge-secret", "taskmaster-secret")
	return s, st.(*memoryStore)
}

func seedEnrollment(t *testing.T, s *Server, phone, sub, key string) {
	t.Helper()
	n, ct, err := s.keys.Encrypt([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertEnrollment(context.Background(), Enrollment{
		Phone: phone, UserSub: sub, EncKey: ct, Nonce: n, VerifiedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
}

func getResolve(t *testing.T, s *Server, phone, bearer, reveal string) *httptest.ResponseRecorder {
	t.Helper()
	target := "/resolve?phone=" + phone
	if reveal != "" {
		target += "&reveal=" + reveal
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	s.InternalMux().ServeHTTP(rr, req)
	return rr
}

func TestResolveEdgeGetsUserSubOnly(t *testing.T) {
	s, _ := testServer(t)
	seedEnrollment(t, s, "+15550109999", "kanidm-sub-1", "live-librechat-key")

	rr := getResolve(t, s, "+15550109999", "edge-secret", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("edge resolve: status %d", rr.Code)
	}
	var out map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["user_sub"] != "kanidm-sub-1" {
		t.Fatalf("edge resolve: %v", out)
	}
	if _, hasKey := out["api_key"]; hasKey {
		t.Fatal("edge resolve leaked key material")
	}
}

// TestResolveEdgeNeverGetsKeyMaterial is the explicit least-privilege test:
// even when the edge asks for ?reveal=key, it must not receive it.
func TestResolveEdgeNeverGetsKeyMaterial(t *testing.T) {
	s, _ := testServer(t)
	seedEnrollment(t, s, "+15550109999", "kanidm-sub-1", "live-librechat-key")

	rr := getResolve(t, s, "+15550109999", "edge-secret", "key")
	var out map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if _, hasKey := out["api_key"]; hasKey {
		t.Fatal("EDGE RECEIVED KEY MATERIAL — isolation boundary violated")
	}
	if out["user_sub"] != "kanidm-sub-1" {
		t.Fatalf("edge resolve: %v", out)
	}
}

func TestResolveTaskmasterGetsKeyOnReveal(t *testing.T) {
	s, _ := testServer(t)
	seedEnrollment(t, s, "+15550109999", "kanidm-sub-1", "live-librechat-key")

	rr := getResolve(t, s, "+15550109999", "taskmaster-secret", "")
	var out map[string]string
	json.NewDecoder(rr.Body).Decode(&out)
	if _, hasKey := out["api_key"]; hasKey {
		t.Fatal("taskmaster got key material without reveal=key")
	}

	rr = getResolve(t, s, "+15550109999", "taskmaster-secret", "key")
	out = map[string]string{}
	json.NewDecoder(rr.Body).Decode(&out)
	if out["api_key"] != "live-librechat-key" || out["user_sub"] != "kanidm-sub-1" {
		t.Fatalf("taskmaster reveal: %v", out)
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
	a := getResolve(t, s, "+19998887777", "edge-secret", "")
	b := getResolve(t, s, "+15550109999", "edge-secret", "")
	if a.Code != http.StatusNotFound || b.Code != http.StatusNotFound {
		t.Fatalf("statuses %d/%d, want 404/404", a.Code, b.Code)
	}
	if a.Body.String() != b.Body.String() {
		t.Fatalf("distinguishable deny bodies: %q vs %q", a.Body.String(), b.Body.String())
	}
}

func TestResolveAuth(t *testing.T) {
	s, _ := testServer(t)
	seedEnrollment(t, s, "+15550109999", "kanidm-sub-1", "k")
	// No header at all.
	req := httptest.NewRequest(http.MethodGet, "/resolve?phone=+15550109999", nil)
	rr := httptest.NewRecorder()
	s.InternalMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no auth: status %d, want 401", rr.Code)
	}
	// Wrong secret and mangled secret both deny.
	for _, bearer := range []string{"wrong-secret", "edge-secret ", "Edge-Secret"} {
		rr := getResolve(t, s, "+15550109999", bearer, "")
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("bearer %q: status %d, want 401", bearer, rr.Code)
		}
	}
}

func TestResolveNormalizesPhone(t *testing.T) {
	s, _ := testServer(t)
	seedEnrollment(t, s, "+15550109999", "kanidm-sub-1", "k")
	rr := getResolve(t, s, "+1+(555)+010-9999", "edge-secret", "")
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

	post := func(key, phone string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/grant", strings.NewReader(`{"api_key":`+quote(key)+`}`))
		req.AddCookie(loginAs(s, "sub-1", phone))
		rr := httptest.NewRecorder()
		s.PublicMux().ServeHTTP(rr, req)
		return rr.Code
	}
	if code := post("dead", "+15550109999"); code != http.StatusBadRequest {
		t.Fatalf("dead key: status %d, want 400", code)
	}
	if e, _ := s.store.GetByPhone(context.Background(), "+15550109999"); e != nil {
		t.Fatal("dead key was stored")
	}
	if code := post("good", "+15550109999"); code != http.StatusCreated {
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
	rr = getResolve(t, s, "+15550109999", "edge-secret", "")
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
	req.Header.Set("Authorization", "Bearer taskmaster-secret")
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatal("public mux serves /resolve — key material route must be internal-only")
	}
	body, _ := io.ReadAll(rr.Body)
	_ = body
}
