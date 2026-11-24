package enroll

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIDToken builds an unsigned JWT-shaped id_token carrying the account id
// claim the flow reads. Nothing verifies the signature yet, so the shape is
// all that matters.
func fakeIDToken(t *testing.T, account string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"chatgpt_account_id": account})
	if err != nil {
		t.Fatal(err)
	}
	return "h." + base64.RawURLEncoding.EncodeToString(payload) + ".s"
}

type tokenRecorder struct {
	mu   sync.Mutex
	form url.Values
}

func (r *tokenRecorder) record(f url.Values) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.form = f
}

func (r *tokenRecorder) get() url.Values {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.form
}

// fakeChatGPTTokenServer stands in for auth.openai.com/oauth/token.
func fakeChatGPTTokenServer(t *testing.T, access, refresh, account string, expiresIn int) (*httptest.Server, *tokenRecorder) {
	t.Helper()
	rec := &tokenRecorder{}
	idToken := fakeIDToken(t, account)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse token form: %v", err)
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		rec.record(r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  access,
			"refresh_token": refresh,
			"id_token":      idToken,
			"expires_in":    expiresIn,
		})
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func getIndex(t *testing.T, s *Server, cookie *http.Cookie) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("index: status %d", rr.Code)
	}
	return rr.Body.String()
}

func cookieByName(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func doChatGPTCallback(t *testing.T, s *Server, session *http.Cookie, code, queryState, cookieState, verifier string) *httptest.ResponseRecorder {
	t.Helper()
	q := url.Values{}
	q.Set("code", code)
	q.Set("state", queryState)
	req := httptest.NewRequest(http.MethodGet, "/oauth/chatgpt/callback?"+q.Encode(), nil)
	if session != nil {
		req.AddCookie(session)
	}
	for name, value := range map[string]string{
		"cgpt_state":    cookieState,
		"cgpt_verifier": verifier,
	} {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	return rr
}

// seedChatGPTPending stores the state left behind by a ChatGPT connect that
// has not yet been completed with a voice PIN.
func seedChatGPTPending(t *testing.T, s *Server, phone, sub, access, refresh, account string) {
	t.Helper()
	an, act, err := s.keys.Encrypt([]byte(access))
	if err != nil {
		t.Fatal(err)
	}
	rn, rct, err := s.keys.Encrypt([]byte(refresh))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertEnrollment(context.Background(), Enrollment{
		Phone: phone, UserSub: sub, VerifiedAt: time.Now(),
		EncChatGPTAccess: act, ChatGPTAccessNonce: an,
		EncChatGPTRefresh: rct, ChatGPTRefreshNonce: rn,
		ChatGPTExpiresAt: time.Now().Add(time.Hour), ChatGPTAccountID: account,
	}); err != nil {
		t.Fatal(err)
	}
}

// The UI must offer the ChatGPT path, but only once the number is verified:
// the OAuth connect endpoint requires sess.VerifiedPhone.
func TestIndexOffersChatGPTConnectOnlyWhenVerified(t *testing.T) {
	s, _ := testServer(t)
	// The grant card is rendered hidden for a logged-in but unverified
	// session, so its connect link must not be reachable yet.
	if body := getIndex(t, s, loginAs(s, "sub-1", "")); !strings.Contains(body, `id="grantCard" hidden`) {
		t.Fatal("unverified session exposed the grant card")
	}
	body := getIndex(t, s, loginAs(s, "sub-1", "+15550109999"))
	if !strings.Contains(body, `href="/oauth/chatgpt/login"`) {
		t.Fatal("verified session has no ChatGPT connect link")
	}
}

func TestIndexShowsChatGPTGrantModeWhenConnected(t *testing.T) {
	s, _ := testServer(t)
	phone := "+15550109999"
	seedChatGPTPending(t, s, phone, "sub-1", "at-1", "rt-1", "acct-1")

	body := getIndex(t, s, loginAs(s, "sub-1", phone))
	if !strings.Contains(body, `id="cgptStatus"`) {
		t.Fatal("connected credential not reflected in the grant card")
	}
	if strings.Contains(body, `for="apikey"`) {
		t.Fatal("connected credential still asks for a LibreChat key")
	}
}

func TestChatGPTLoginUnavailableWithoutPublicBaseURL(t *testing.T) {
	s, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/oauth/chatgpt/login", nil)
	req.AddCookie(loginAs(s, "sub-1", "+15550109999"))
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("login without PublicBaseURL: status %d, want 503", rr.Code)
	}
}

func TestChatGPTLoginRequiresVerifiedPhone(t *testing.T) {
	s, _ := testServer(t)
	s.PublicBaseURL = "https://enroll.example.com"
	for _, cookie := range []*http.Cookie{nil, loginAs(s, "sub-1", "")} {
		req := httptest.NewRequest(http.MethodGet, "/oauth/chatgpt/login", nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rr := httptest.NewRecorder()
		s.PublicMux().ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("login (cookie=%v): status %d, want 401", cookie != nil, rr.Code)
		}
	}
}

func TestChatGPTLoginRedirectsWithStateAndPKCE(t *testing.T) {
	s, _ := testServer(t)
	s.PublicBaseURL = "https://enroll.example.com"

	req := httptest.NewRequest(http.MethodGet, "/oauth/chatgpt/login", nil)
	req.AddCookie(loginAs(s, "sub-1", "+15550109999"))
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("login: status %d, want 302", rr.Code)
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Scheme+"://"+loc.Host+loc.Path != ChatGPTAuthorizeURL {
		t.Fatalf("authorize endpoint = %s", loc.Scheme+"://"+loc.Host+loc.Path)
	}
	q := loc.Query()
	if q.Get("client_id") != ChatGPTClientID {
		t.Fatalf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "https://enroll.example.com/oauth/chatgpt/callback" {
		t.Fatalf("redirect_uri = %q", q.Get("redirect_uri"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("challenge method = %q", q.Get("code_challenge_method"))
	}
	if q.Get("response_type") != "code" || q.Get("scope") == "" {
		t.Fatalf("missing authorize params: %s", loc.RawQuery)
	}

	cookies := rr.Result().Cookies()
	state := cookieByName(cookies, "cgpt_state")
	verifier := cookieByName(cookies, "cgpt_verifier")
	if state == nil || verifier == nil {
		t.Fatalf("missing flow cookies: %v", cookies)
	}
	if q.Get("state") != state.Value {
		t.Fatal("state param does not match state cookie")
	}
	if q.Get("nonce") != "" {
		t.Fatal("unexpected nonce: the id_token is not used for identity")
	}
	if q.Get("code_challenge") != CodeChallengeS256(verifier.Value) {
		t.Fatal("code_challenge is not S256(verifier)")
	}
}

func TestChatGPTCallbackRejectsBadState(t *testing.T) {
	s, _ := testServer(t)
	s.PublicBaseURL = "https://enroll.example.com"
	tokSrv, _ := fakeChatGPTTokenServer(t, "at-1", "rt-1", "acct-1", 3600)
	s.chatGPTTokenURL = tokSrv.URL

	phone := "+15550109999"
	rr := doChatGPTCallback(t, s, loginAs(s, "sub-1", phone), "code-1", "wrong-state", "right-state", "verifier-1")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad state: status %d, want 400", rr.Code)
	}
	if e, _ := s.store.GetByPhone(context.Background(), phone); e != nil {
		t.Fatal("bad-state callback stored a credential")
	}
}

// The connect flow must be able to create the pending row itself: requiring
// a prior LibreChat grant is what made the feature unreachable.
func TestChatGPTCallbackStoresCredentialForNewEnrollment(t *testing.T) {
	s, _ := testServer(t)
	s.PublicBaseURL = "https://enroll.example.com"
	tokSrv, rec := fakeChatGPTTokenServer(t, "at-1", "rt-1", "acct-1", 3600)
	s.chatGPTTokenURL = tokSrv.URL

	phone := "+15550109999"
	rr := doChatGPTCallback(t, s, loginAs(s, "sub-1", phone), "code-1", "state-1", "state-1", "verifier-1")
	if rr.Code != http.StatusFound {
		t.Fatalf("callback: status %d body %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Location"); got != "/?chatgpt=connected" {
		t.Fatalf("redirect = %q", got)
	}

	form := rec.get()
	if form.Get("grant_type") != "authorization_code" || form.Get("code") != "code-1" {
		t.Fatalf("token form = %v", form)
	}
	if form.Get("code_verifier") != "verifier-1" {
		t.Fatal("token request missing PKCE verifier")
	}
	if form.Get("redirect_uri") != "https://enroll.example.com/oauth/chatgpt/callback" {
		t.Fatalf("token redirect_uri = %q", form.Get("redirect_uri"))
	}

	e, err := s.store.GetByPhone(context.Background(), phone)
	if err != nil || e == nil {
		t.Fatalf("pending enrollment missing: %v", err)
	}
	if e.UserSub != "sub-1" {
		t.Fatalf("pending owner = %q", e.UserSub)
	}
	if len(e.EncPIN) != 0 || len(e.PINNonce) != 0 {
		t.Fatal("connect step must not set a PIN")
	}
	at, err := s.keys.Decrypt(e.ChatGPTAccessNonce, e.EncChatGPTAccess)
	if err != nil || string(at) != "at-1" {
		t.Fatal("access token not stored encrypted")
	}
	rt, err := s.keys.Decrypt(e.ChatGPTRefreshNonce, e.EncChatGPTRefresh)
	if err != nil || string(rt) != "rt-1" {
		t.Fatal("refresh token not stored encrypted")
	}
	if e.ChatGPTAccountID != "acct-1" {
		t.Fatalf("account id = %q", e.ChatGPTAccountID)
	}
	if !e.ChatGPTExpiresAt.After(time.Now()) {
		t.Fatal("expiry not recorded")
	}

	// Half-finished enrollments must not admit calls: the admit gate is
	// resolve, and a pending row has no PIN to verify.
	if rr := getResolve(t, s, phone, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("pending enrollment admitted a call: status %d", rr.Code)
	}
	if rr := getResolve(t, s, phone, "credential"); rr.Code != http.StatusNotFound {
		t.Fatalf("pending enrollment revealed a credential: status %d", rr.Code)
	}
}

func TestGrantWithoutKeyRequiresConnectedChatGPT(t *testing.T) {
	s, _ := testServer(t)
	phone := "+15550109999"

	req := httptest.NewRequest(http.MethodPost, "/api/grant", strings.NewReader(`{"pin":"482916"}`))
	req.AddCookie(loginAs(s, "sub-1", phone))
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("keyless grant without credential: status %d, want 400", rr.Code)
	}
	if e, _ := s.store.GetByPhone(context.Background(), phone); e != nil {
		t.Fatal("keyless grant without credential stored a row")
	}

	// A credential owned by another subject must not complete this grant.
	seedChatGPTPending(t, s, phone, "other-sub", "at-1", "rt-1", "acct-1")
	req = httptest.NewRequest(http.MethodPost, "/api/grant", strings.NewReader(`{"pin":"482916"}`))
	req.AddCookie(loginAs(s, "sub-1", phone))
	rr = httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("keyless grant on foreign credential: status %d, want 400", rr.Code)
	}
	if e, _ := s.store.GetByPhone(context.Background(), phone); e == nil || e.UserSub != "other-sub" {
		t.Fatal("foreign pending credential was modified")
	}
}

// Full OAuth-only journey: verify phone (session), connect ChatGPT, set PIN.
func TestGrantOAuthOnlyCompletesEnrollment(t *testing.T) {
	s, _ := testServer(t)
	s.PublicBaseURL = "https://enroll.example.com"
	tokSrv, _ := fakeChatGPTTokenServer(t, "at-1", "rt-1", "acct-1", 3600)
	s.chatGPTTokenURL = tokSrv.URL

	phone := "+15550109999"
	cookie := loginAs(s, "sub-1", phone)
	if rr := doChatGPTCallback(t, s, cookie, "code-1", "state-1", "state-1", "verifier-1"); rr.Code != http.StatusFound {
		t.Fatalf("connect: status %d", rr.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/grant", strings.NewReader(`{"pin":"482916"}`))
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("keyless grant: status %d body %s", rr.Code, rr.Body.String())
	}

	e, _ := s.store.GetByPhone(context.Background(), phone)
	if e == nil {
		t.Fatal("grant did not complete the enrollment")
	}
	pin, err := s.keys.Decrypt(e.PINNonce, e.EncPIN)
	if err != nil || string(pin) != "482916" {
		t.Fatal("PIN not stored")
	}
	if len(e.EncChatGPTAccess) == 0 {
		t.Fatal("grant dropped the ChatGPT credential")
	}

	if rr := getResolve(t, s, phone, ""); rr.Code != http.StatusOK {
		t.Fatalf("resolve after grant: status %d", rr.Code)
	}
	rr = getResolve(t, s, phone, "credential")
	if rr.Code != http.StatusOK {
		t.Fatalf("reveal after grant: status %d", rr.Code)
	}
	var out map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["credential_kind"] != "chatgpt_oauth" || out["access_token"] != "at-1" {
		t.Fatalf("revealed = %v", out)
	}
	if rr := postVerifyPIN(t, s, phone, "482916"); rr.Code != http.StatusOK {
		t.Fatalf("verify-pin after grant: status %d", rr.Code)
	}
}

// Re-granting a LibreChat key on the same number must keep the ChatGPT
// credential instead of nulling it out.
func TestGrantWithKeyPreservesChatGPTCredential(t *testing.T) {
	s, _ := testServer(t)
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer fake.Close()
	s.libreChat = fake.URL
	s.httpClient = fake.Client()

	phone := "+15550109999"
	seedChatGPTPending(t, s, phone, "sub-1", "at-1", "rt-1", "acct-1")

	req := httptest.NewRequest(http.MethodPost, "/api/grant", strings.NewReader(`{"api_key":"good","pin":"482916"}`))
	req.AddCookie(loginAs(s, "sub-1", phone))
	rr := httptest.NewRecorder()
	s.PublicMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("grant: status %d", rr.Code)
	}
	e, _ := s.store.GetByPhone(context.Background(), phone)
	if e == nil || len(e.EncChatGPTAccess) == 0 || len(e.EncKey) == 0 {
		t.Fatal("grant with key dropped the ChatGPT credential")
	}
	pin, err := s.keys.Decrypt(e.PINNonce, e.EncPIN)
	if err != nil || string(pin) != "482916" {
		t.Fatal("grant with key did not store the PIN")
	}
}

func TestResolveCredentialRefreshesExpiredChatGPTToken(t *testing.T) {
	s, _ := testServer(t)
	tokSrv, rec := fakeChatGPTTokenServer(t, "at-2", "rt-2", "acct-1", 3600)
	s.chatGPTTokenURL = tokSrv.URL

	phone := "+15550109999"
	seedChatGPTEnrollment(t, s, phone, "sub-1", "k", "482916", "at-1", "rt-1", "acct-1", time.Now().Add(-time.Minute))

	rr := getResolve(t, s, phone, "credential")
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh reveal: status %d body %s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["access_token"] != "at-2" {
		t.Fatalf("access = %v, want refreshed token", out["access_token"])
	}

	form := rec.get()
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "rt-1" {
		t.Fatalf("refresh form = %v", form)
	}

	e, _ := s.store.GetByPhone(context.Background(), phone)
	at, err := s.keys.Decrypt(e.ChatGPTAccessNonce, e.EncChatGPTAccess)
	if err != nil || string(at) != "at-2" {
		t.Fatal("rotated access token was not persisted")
	}
	rt, err := s.keys.Decrypt(e.ChatGPTRefreshNonce, e.EncChatGPTRefresh)
	if err != nil || string(rt) != "rt-2" {
		t.Fatal("rotated refresh token was not persisted")
	}
	// The refresh must not rewrite columns it does not own.
	pin, err := s.keys.Decrypt(e.PINNonce, e.EncPIN)
	if err != nil || string(pin) != "482916" {
		t.Fatal("token refresh clobbered the PIN")
	}
	key, err := s.keys.Decrypt(e.Nonce, e.EncKey)
	if err != nil || string(key) != "k" {
		t.Fatal("token refresh clobbered the API key")
	}
}

// A dead refresh token means the credential is unusable: deny like an
// unknown number rather than surfacing a retryable 5xx on every call.
func TestResolveCredentialDeadRefreshDenies(t *testing.T) {
	s, _ := testServer(t)
	tokSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer tokSrv.Close()
	s.chatGPTTokenURL = tokSrv.URL

	phone := "+15550109999"
	seedChatGPTEnrollment(t, s, phone, "sub-1", "k", "482916", "at-1", "rt-dead", "acct-1", time.Now().Add(-time.Minute))

	rr := getResolve(t, s, phone, "credential")
	unknown := getResolve(t, s, "+19998887777", "credential")
	if rr.Code != http.StatusNotFound || unknown.Code != http.StatusNotFound {
		t.Fatalf("dead refresh: %d/%d, want 404/404", rr.Code, unknown.Code)
	}
	if rr.Body.String() != unknown.Body.String() {
		t.Fatalf("dead refresh is distinguishable: %q vs %q", rr.Body.String(), unknown.Body.String())
	}
}

func TestListEnrollmentsReportsActiveAndCredential(t *testing.T) {
	s, _ := testServer(t)
	seedChatGPTPending(t, s, "+15550109999", "sub-1", "at-1", "rt-1", "acct-1")
	seedEnrollment(t, s, "+15550108888", "sub-1", "k")

	rr := getEnrollments(t, s, loginAs(s, "sub-1", ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("list: status %d", rr.Code)
	}
	var out struct {
		Phones []struct {
			Phone      string `json:"phone"`
			Active     bool   `json:"active"`
			Credential string `json:"credential"`
		} `json:"phones"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Phones) != 2 {
		t.Fatalf("phones = %v", out.Phones)
	}
	// Ordered by phone: the complete api_key row sorts first.
	if p := out.Phones[0]; p.Phone != "+15550108888" || !p.Active || p.Credential != "api_key" {
		t.Fatalf("active row = %+v", p)
	}
	if p := out.Phones[1]; p.Phone != "+15550109999" || p.Active || p.Credential != "chatgpt_oauth" {
		t.Fatalf("pending row = %+v", p)
	}
}

// Expired access with no refresh token is unusable: deny, do not 5xx.
func TestResolveCredentialExpiredWithoutRefreshDenies(t *testing.T) {
	s, _ := testServer(t)
	phone := "+15550109999"
	kn, kct, err := s.keys.Encrypt([]byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	pn, pct, err := s.keys.Encrypt([]byte("482916"))
	if err != nil {
		t.Fatal(err)
	}
	an, act, err := s.keys.Encrypt([]byte("at-old"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertEnrollment(context.Background(), Enrollment{
		Phone: phone, UserSub: "sub-1", EncKey: kct, Nonce: kn, EncPIN: pct, PINNonce: pn,
		VerifiedAt: time.Now(), EncChatGPTAccess: act, ChatGPTAccessNonce: an,
		ChatGPTExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	rr := getResolve(t, s, phone, "credential")
	unknown := getResolve(t, s, "+19998887777", "credential")
	if rr.Code != http.StatusNotFound || rr.Body.String() != unknown.Body.String() {
		t.Fatalf("expired no-refresh: %d %q, want 404 deny", rr.Code, rr.Body.String())
	}
}
