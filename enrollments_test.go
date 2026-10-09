package enroll

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func getEnrollments(t *testing.T, s *Server, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/enrollments", nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	return rr
}

func postRevoke(t *testing.T, s *Server, cookie *http.Cookie, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *strings.Reader
	if body == "" {
		rdr = strings.NewReader("")
	} else {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/revoke", rdr)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	return rr
}

func decodePhones(t *testing.T, rr *httptest.ResponseRecorder) []string {
	t.Helper()
	var out struct {
		Phones []struct {
			Phone string `json:"phone"`
		} `json:"phones"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode enrollments: %v", err)
	}
	phones := make([]string, 0, len(out.Phones))
	for _, p := range out.Phones {
		phones = append(phones, p.Phone)
	}
	return phones
}

func TestListEnrollmentsRequiresLogin(t *testing.T) {
	s, _ := testServer(t)
	if rr := getEnrollments(t, s, nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous list: status %d, want 401", rr.Code)
	}
}

func TestListEnrollmentsShowsOwnOnly(t *testing.T) {
	s, _ := testServer(t)
	seedEnrollmentWithPIN(t, s, "+15550109999", "sub-1", "k", "482916")
	seedEnrollmentWithPIN(t, s, "+15550108888", "sub-1", "k", "1234")
	seedEnrollmentWithPIN(t, s, "+19998887777", "sub-2", "k", "5678")

	rr := getEnrollments(t, s, loginAs(s, "sub-1", "+15550109999"))
	if rr.Code != http.StatusOK {
		t.Fatalf("list: status %d, want 200", rr.Code)
	}
	phones := decodePhones(t, rr)
	if len(phones) != 2 || phones[0] != "+15550108888" || phones[1] != "+15550109999" {
		t.Fatalf("own phones = %v, want both sub-1 numbers ordered", phones)
	}
}

// TestRevokeExplicitPhoneRemovesOldNumber: after verifying a new number the
// old enrollment stays active by design (keyed by phone); the user can remove
// it by naming it explicitly without re-verifying it.
func TestRevokeExplicitPhoneRemovesOldNumber(t *testing.T) {
	s, _ := testServer(t)
	seedEnrollmentWithPIN(t, s, "+15550109999", "sub-1", "k", "482916")
	seedEnrollmentWithPIN(t, s, "+15550108888", "sub-1", "k", "1234")

	// Session currently points at the new number.
	cookie := loginAs(s, "sub-1", "+15550108888")
	rr := postRevoke(t, s, cookie, `{"phone":"+15550109999"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke old: status %d, want 200", rr.Code)
	}
	if e, _ := s.store.GetByPhone(context.Background(), "+15550109999"); e != nil {
		t.Fatal("old number still enrolled after explicit revoke")
	}
	if e, _ := s.store.GetByPhone(context.Background(), "+15550108888"); e == nil {
		t.Fatal("current number was removed by revoking the old one")
	}
	// Old number now denies on the internal directory.
	req := httptest.NewRequest(http.MethodGet, "/resolve?phone=+15550109999", nil)
	rrec := httptest.NewRecorder()
	s.InternalMux().ServeHTTP(rrec, req)
	if rrec.Code != http.StatusNotFound {
		t.Fatalf("post-revoke resolve: status %d, want 404", rrec.Code)
	}
}

func TestRevokeExplicitPhoneCannotDeleteOthers(t *testing.T) {
	s, _ := testServer(t)
	seedEnrollmentWithPIN(t, s, "+15550109999", "victim-sub", "k", "482916")

	rr := postRevoke(t, s, loginAs(s, "attacker-sub", "+15550108888"), `{"phone":"+15550109999"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke: status %d, want 200", rr.Code)
	}
	var body map[string]bool
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil || body["deleted"] {
		t.Fatalf("cross-user revoke body = %q, want deleted:false", rr.Body.String())
	}
	if e, _ := s.store.GetByPhone(context.Background(), "+15550109999"); e == nil {
		t.Fatal("victim mapping deleted by another user")
	}
}

func TestGrantClearsPendingVerification(t *testing.T) {
	s, _ := testServer(t)
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer fake.Close()
	s.libreChat = fake.URL
	s.httpClient = fake.Client()

	req := httptest.NewRequest(http.MethodPost, "/api/grant",
		strings.NewReader(`{"api_key":"good","pin":"482916"}`))
	req.AddCookie(loginAs(s, "sub-1", "+15550109999"))
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("grant: status %d, want 201", rr.Code)
	}
	var granted *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "enroll_session" {
			granted = c
		}
	}
	if granted == nil {
		t.Fatal("grant did not refresh the session cookie")
	}
	// Back to the clean main view: enrolled list + enroll-new entry point,
	// no pending grant form for the just-enrolled number.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(granted)
	rrec := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rrec, req)
	body := rrec.Body.String()
	if !strings.Contains(body, "Enrolled phone numbers") || !strings.Contains(body, "Enroll new phone number") {
		t.Fatalf("post-grant index missing list view: %q", body)
	}
	if strings.Contains(body, `id="apikey"`) {
		t.Fatal("post-grant index still shows the grant form")
	}
}

func TestIndexMainViewBranches(t *testing.T) {
	s, _ := testServer(t)

	// Anonymous: login only.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), "Log in with Kanidm") {
		t.Fatalf("anonymous index missing login: %q", rr.Body.String())
	}

	// Logged in, nothing pending: enrolled list + enroll-new entry point,
	// verify form present but hidden, no grant form.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(loginAs(s, "sub-1", ""))
	rr = httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, "Enrolled phone numbers") || !strings.Contains(body, `id="enrollNew"`) {
		t.Fatalf("list view missing enrolled list + enroll entry: %q", body)
	}
	if !strings.Contains(body, `id="verifyCard" hidden`) {
		t.Fatalf("verify form not hidden behind enroll entry: %q", body)
	}
	if strings.Contains(body, `id="apikey"`) {
		t.Fatalf("list view shows grant form: %q", body)
	}

	// Pending verification: grant form + a way back to a different number.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(loginAs(s, "sub-1", "+15550109999"))
	rr = httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	body = rr.Body.String()
	if !strings.Contains(body, `id="apikey"`) || !strings.Contains(body, `id="useDifferent"`) {
		t.Fatalf("pending view missing grant form + different-number path: %q", body)
	}
	if strings.Contains(body, "Step 2 — Number verified") {
		t.Fatalf("pending view still has the top verified banner: %q", body)
	}
	listIdx := strings.Index(body, "Enrolled phone numbers")
	grantIdx := strings.Index(body, "Grant voice access")
	if listIdx < 0 || grantIdx < 0 || listIdx > grantIdx {
		t.Fatalf("pending view not list-first: %q", body)
	}
}

func TestRevokeCurrentNumberClearsSession(t *testing.T) {
	s, _ := testServer(t)
	seedEnrollmentWithPIN(t, s, "+15550109999", "sub-1", "k", "482916")

	rr := postRevoke(t, s, loginAs(s, "sub-1", "+15550109999"), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke: status %d, want 200", rr.Code)
	}
	// The response clears VerifiedPhone: a second bare revoke (which falls
	// back to the session number) must now fail as unverified.
	var cleared *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "enroll_session" {
			cleared = c
		}
	}
	if cleared == nil {
		t.Fatal("revoke did not refresh the session cookie")
	}
	req := httptest.NewRequest(http.MethodPost, "/api/revoke", strings.NewReader(""))
	req.AddCookie(cleared)
	rrec := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rrec, req)
	if rrec.Code != http.StatusUnauthorized {
		t.Fatalf("second revoke: status %d, want 401 (session cleared)", rrec.Code)
	}
}
