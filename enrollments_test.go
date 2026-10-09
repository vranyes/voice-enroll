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
