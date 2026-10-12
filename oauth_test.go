package enroll

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func fakeOIDC(t *testing.T) (*fakeProvider, OIDCConfig) {
	t.Helper()
	f := newFakeProvider(t)
	return f, OIDCConfig{
		Issuer: f.iss, ClientID: "test-client", ClientSecret: "s",
		RedirectURL: "https://enroll/x/cb", GrantRedirectURL: "https://enroll/x/grant-cb",
		HTTPClient: f.srv.Client(),
	}
}

func TestLoadConfigGrantRedirect(t *testing.T) {
	setBaseEnv := func() {
		t.Helper()
		t.Setenv("ENROLL_DEK_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
		t.Setenv("ENROLL_SESSION_SECRET_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
		t.Setenv("KANIDM_ISSUER", "https://auth.example.com/oauth2/openid/voice-enroll-app")
		t.Setenv("KANIDM_CLIENT_ID", "voice-enroll-app")
		t.Setenv("KANIDM_CLIENT_SECRET", "s")
		t.Setenv("KANIDM_REDIRECT_URL", "https://enroll.example.com/oauth/callback")
		t.Setenv("ENROLL_PUBLIC_BASE_URL", "https://enroll.example.com")
		t.Setenv("DATABASE_URL", "postgres://x")
		t.Setenv("LIBRECHAT_BASE_URL", "https://librechat.example.com")
		t.Setenv("TELNYX_API_KEY", "k")
		t.Setenv("TELNYX_SENDER_NUMBER", "+15550001111")
	}
	setBaseEnv()
	t.Setenv("KANIDM_GRANT_REDIRECT_URL", "")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.GrantRedirectURL != "https://enroll.example.com/oauth/grant/callback" {
		t.Fatalf("default grant redirect = %q", cfg.OIDC.GrantRedirectURL)
	}
	t.Setenv("KANIDM_GRANT_REDIRECT_URL", "https://enroll.example.com/oauth/grant2/callback")
	cfg, err = LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.GrantRedirectURL != "https://enroll.example.com/oauth/grant2/callback" {
		t.Fatalf("explicit grant redirect = %q", cfg.OIDC.GrantRedirectURL)
	}
}

func TestExchangeTokensCapturesRefresh(t *testing.T) {
	f := newFakeProvider(t)
	defer f.srv.Close()
	c := OIDCConfig{Issuer: f.iss, ClientID: "test-client", ClientSecret: "s", RedirectURL: "https://enroll/x/cb", HTTPClient: f.srv.Client()}
	ts, err := c.ExchangeTokens(t.Context(), "code", "test-nonce", "test-verifier")
	if err != nil {
		t.Fatal(err)
	}
	if ts.Sub != "test-sub" || ts.AccessToken != "at" {
		t.Fatalf("got sub=%q at=%q", ts.Sub, ts.AccessToken)
	}
	if ts.RefreshToken != "good-refresh" {
		t.Fatalf("refresh = %q, want good-refresh", ts.RefreshToken)
	}
	if ts.ExpiresIn != 900*time.Second {
		t.Fatalf("expires = %v, want 900s", ts.ExpiresIn)
	}
}

func TestRefreshTokensRotates(t *testing.T) {
	f := newFakeProvider(t)
	defer f.srv.Close()
	c := OIDCConfig{Issuer: f.iss, ClientID: "test-client", ClientSecret: "s", RedirectURL: "https://enroll/x/cb", HTTPClient: f.srv.Client()}
	ts, err := c.RefreshTokens(t.Context(), "good-refresh", "test-sub")
	if err != nil {
		t.Fatal(err)
	}
	if ts.AccessToken != "at2" || ts.RefreshToken != "good-refresh-2" {
		t.Fatalf("rotated tokens = %+v", ts)
	}
}

func TestRefreshTokensDeadFailsClosed(t *testing.T) {
	f := newFakeProvider(t)
	defer f.srv.Close()
	c := OIDCConfig{Issuer: f.iss, ClientID: "test-client", ClientSecret: "s", RedirectURL: "https://enroll/x/cb", HTTPClient: f.srv.Client()}
	if _, err := c.RefreshTokens(t.Context(), "bad-refresh", "test-sub"); !errors.Is(err, ErrRefreshExpired) {
		t.Fatalf("dead refresh: got %v, want ErrRefreshExpired", err)
	}
	if _, err := c.RefreshTokens(t.Context(), "", "test-sub"); !errors.Is(err, ErrRefreshExpired) {
		t.Fatalf("empty refresh: got %v, want ErrRefreshExpired", err)
	}
}

// oauthTestServer wires a Server whose OIDC client is the fake provider and
// whose LibreChat double accepts the fake's access tokens.
func oauthTestServer(t *testing.T) (*Server, *fakeProvider) {
	t.Helper()
	s, _ := testServer(t)
	f, oidc := fakeOIDC(t)
	t.Cleanup(func() { f.srv.Close() })
	s.oidc = oidc
	fakeLC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Both the code-flow ("at") and refreshed ("at2") bearers are live.
		if a := r.Header.Get("Authorization"); a == "Bearer at" || a == "Bearer at2" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(fakeLC.Close)
	s.libreChat = fakeLC.URL
	s.httpClient = fakeLC.Client()
	return s, f
}

// doGrantStart runs the OAuth-start step and returns the grant cookies.
func doGrantStart(t *testing.T, s *Server, sub, phone, pin string) []*http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/grant/oauth/start",
		strings.NewReader(`{"pin":`+quote(pin)+`}`))
	req.AddCookie(loginAs(s, sub, phone))
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("grant start: status %d, want 200 (%s)", rr.Code, rr.Body.String())
	}
	var body struct {
		LoginURL string `json:"login_url"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil || body.LoginURL == "" {
		t.Fatalf("grant start: no login_url (%s)", rr.Body.String())
	}
	// The grant flow must authorize with the grant callback, never the login
	// callback: Kanidm delivers the code to redirect_uri, and the login
	// handler rejects grant codes as "bad state".
	if !strings.Contains(body.LoginURL, "redirect_uri="+url.QueryEscape("https://enroll/x/grant-cb")) {
		t.Fatalf("grant start login_url uses wrong redirect_uri: %s", body.LoginURL)
	}
	return rr.Result().Cookies()
}

func grantCookies(cookies []*http.Cookie) (state string, jar []*http.Cookie) {
	for _, c := range cookies {
		switch c.Name {
		case "grant_state":
			state = c.Value
			jar = append(jar, c)
		case "grant_nonce":
			// The shared fake always mints nonce "test-nonce"; pin the
			// cookie to it so the exchange verifies.
			c.Value = "test-nonce"
			jar = append(jar, c)
		case "grant_verifier":
			jar = append(jar, c)
		}
	}
	return state, jar
}

func TestGrantOAuthStartRequiresVerifiedPhoneAndPIN(t *testing.T) {
	s, _ := oauthTestServer(t)
	post := func(cookie *http.Cookie, body string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/grant/oauth/start", strings.NewReader(body))
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rr := httptest.NewRecorder()
		s.PublicMux().ServeHTTP(rr, req)
		return rr.Code
	}
	if code := post(nil, `{"pin":"482916"}`); code != http.StatusUnauthorized {
		t.Fatalf("anonymous start: %d, want 401", code)
	}
	if code := post(loginAs(s, "test-sub", ""), `{"pin":"482916"}`); code != http.StatusUnauthorized {
		t.Fatalf("unverified start: %d, want 401", code)
	}
	if code := post(loginAs(s, "test-sub", "+15550109999"), `{"pin":"12"}`); code != http.StatusBadRequest {
		t.Fatalf("bad PIN start: %d, want 400", code)
	}
}

func TestGrantOAuthCallbackStoresTokensAndPreservesPAT(t *testing.T) {
	s, _ := oauthTestServer(t)
	// Existing PAT enrollment for the number: the OAuth grant must keep it.
	seedEnrollmentWithPIN(t, s, "+15550109999", "test-sub", "pat-key", "482916")

	cookies := doGrantStart(t, s, "test-sub", "+15550109999", "482916")
	state, jar := grantCookies(cookies)
	if state == "" {
		t.Fatal("no grant_state cookie")
	}
	sess := loginAs(s, "test-sub", "+15550109999")
	req := httptest.NewRequest(http.MethodGet, "/oauth/grant/callback?code=x&state="+state, nil)
	req.AddCookie(sess)
	for _, c := range jar {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("grant callback: status %d, want 302 (%s)", rr.Code, rr.Body.String())
	}
	e, _ := s.store.GetByPhone(context.Background(), "+15550109999")
	if e == nil || !e.HasOAuth() {
		t.Fatalf("OAuth grant not stored: %+v", e)
	}
	access, err := s.keys.Decrypt(e.AccessNonce, e.EncAccess)
	if err != nil || string(access) != "at" {
		t.Fatal("stored access token does not decrypt to the granted bearer")
	}
	refresh, err := s.keys.Decrypt(e.RefreshNonce, e.EncRefresh)
	if err != nil || string(refresh) != "good-refresh" {
		t.Fatal("stored refresh token missing after grant")
	}
	if e.TokenExpiresAt.IsZero() || e.TokenExpiresAt.Before(s.now().Add(time.Minute)) {
		t.Fatalf("token expiry not recorded: %v", e.TokenExpiresAt)
	}
	pinPlain, err := s.keys.Decrypt(e.PINNonce, e.EncPIN)
	if err != nil || string(pinPlain) != "482916" {
		t.Fatal("stashed PIN not stored at OAuth grant")
	}
	// Dual-auth: the PAT survived the OAuth grant.
	pat, err := s.keys.Decrypt(e.Nonce, e.EncKey)
	if err != nil || string(pat) != "pat-key" {
		t.Fatal("OAuth grant wiped the stored PAT")
	}
	// Resolve serves both bearers.
	rrec := getResolve(t, s, "+15550109999", "key")
	var out map[string]string
	if err := json.NewDecoder(rrec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["access_token"] != "at" || out["api_key"] != "pat-key" || out["user_sub"] != "test-sub" {
		t.Fatalf("resolve reveal: %v", out)
	}
}

func TestGrantOAuthCallbackRejectsSubjectMismatch(t *testing.T) {
	s, _ := oauthTestServer(t)
	// Attacker session for another sub tries to consume a grant whose
	// bearer belongs to test-sub (what the fake mints).
	cookies := doGrantStart(t, s, "attacker-sub", "+15550109999", "482916")
	state, jar := grantCookies(cookies)
	req := httptest.NewRequest(http.MethodGet, "/oauth/grant/callback?code=x&state="+state, nil)
	req.AddCookie(loginAs(s, "attacker-sub", "+15550109999"))
	for _, c := range jar {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("subject mismatch: status %d, want 401", rr.Code)
	}
}

func seedOAuthEnrollment(t *testing.T, s *Server, phone, sub, access, refresh string, expiresAt time.Time) {
	t.Helper()
	an, act, err := s.keys.Encrypt([]byte(access))
	if err != nil {
		t.Fatal(err)
	}
	var rn, rct []byte
	if refresh != "" {
		rn, rct, err = s.keys.Encrypt([]byte(refresh))
		if err != nil {
			t.Fatal(err)
		}
	}
	pn, pct, err := s.keys.Encrypt([]byte("482916"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertEnrollment(context.Background(), Enrollment{
		Phone: phone, UserSub: sub,
		EncPIN: pct, PINNonce: pn,
		EncAccess: act, AccessNonce: an,
		EncRefresh: rct, RefreshNonce: rn,
		TokenExpiresAt: expiresAt, VerifiedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestResolveRefreshesExpiredOAuth(t *testing.T) {
	s, _ := oauthTestServer(t)
	seedOAuthEnrollment(t, s, "+15550109999", "test-sub", "old-at", "good-refresh", time.Now().Add(-time.Minute))

	rrec := getResolve(t, s, "+15550109999", "key")
	var out map[string]string
	if err := json.NewDecoder(rrec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["access_token"] != "at2" {
		t.Fatalf("resolve after expiry: access_token=%q, want refreshed at2", out["access_token"])
	}
	// Rotation persisted: the old refresh is gone.
	e, _ := s.store.GetByPhone(context.Background(), "+15550109999")
	refresh, err := s.keys.Decrypt(e.RefreshNonce, e.EncRefresh)
	if err != nil || string(refresh) != "good-refresh-2" {
		t.Fatalf("rotated refresh not stored: %q (err %v)", refresh, err)
	}
}

func TestResolveFallsBackToPATWhenRefreshDies(t *testing.T) {
	s, _ := oauthTestServer(t)
	seedOAuthEnrollment(t, s, "+15550109999", "test-sub", "old-at", "bad-refresh", time.Now().Add(-time.Minute))
	// Add a PAT to the same row (dual-auth).
	e, _ := s.store.GetByPhone(context.Background(), "+15550109999")
	n, ct, _ := s.keys.Encrypt([]byte("pat-key"))
	e.EncKey, e.Nonce = ct, n
	if err := s.store.UpsertEnrollment(context.Background(), *e); err != nil {
		t.Fatal(err)
	}

	rrec := getResolve(t, s, "+15550109999", "key")
	var out map[string]string
	if err := json.NewDecoder(rrec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if _, hasBearer := out["access_token"]; hasBearer {
		t.Fatalf("dead refresh still serves a bearer: %v", out)
	}
	if out["api_key"] != "pat-key" {
		t.Fatalf("PAT fallback missing: %v", out)
	}
}

func TestResolveDeniesWhenOAuthDeadAndNoPAT(t *testing.T) {
	s, _ := oauthTestServer(t)
	seedOAuthEnrollment(t, s, "+15550109999", "test-sub", "old-at", "bad-refresh", time.Now().Add(-time.Minute))

	rrec := getResolve(t, s, "+15550109999", "key")
	if rrec.Code != http.StatusNotFound {
		t.Fatalf("dead OAuth without PAT: status %d, want 404 deny", rrec.Code)
	}
	// Sub-only resolve still answers (voice-bridge needs it for the edge JWT).
	rrec = getResolve(t, s, "+15550109999", "")
	var out map[string]string
	if err := json.NewDecoder(rrec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["user_sub"] != "test-sub" {
		t.Fatalf("sub-only resolve: %v", out)
	}
}

func TestPATGrantPreservesOAuth(t *testing.T) {
	s, _ := oauthTestServer(t)
	seedOAuthEnrollment(t, s, "+15550109999", "test-sub", "live-at", "good-refresh", time.Now().Add(time.Hour))
	// Fake LibreChat accepts the pasted key "good" (see TestGrantStoresLiveKeyRejectsDead pattern).
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer fake.Close()
	s.libreChat = fake.URL
	s.httpClient = fake.Client()

	req := httptest.NewRequest(http.MethodPost, "/api/grant",
		strings.NewReader(`{"api_key":"good","pin":"1234"}`))
	req.AddCookie(loginAs(s, "test-sub", "+15550109999"))
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("PAT grant: status %d, want 201", rr.Code)
	}
	e, _ := s.store.GetByPhone(context.Background(), "+15550109999")
	if !e.HasOAuth() || !e.HasPAT() {
		t.Fatalf("PAT grant dropped a credential class: oauth=%v pat=%v", e.HasOAuth(), e.HasPAT())
	}
}
