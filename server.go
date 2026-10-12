package enroll

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// oauthRefreshSkew refreshes an access token that expires within this window,
// so resolve never hands out a bearer that dies mid-call.
const oauthRefreshSkew = 90 * time.Second

// pendingGrantSkew bounds the grant-via-OAuth handshake: the PIN stashed at
// /api/grant/oauth/start must be consumed by /oauth/grant/callback within
// this window or the user starts over.
const pendingGrantTTL = 10 * time.Minute

// pendingGrant is a PIN awaiting its OAuth grant: the user proved number
// ownership (OTP) and chose a PIN, and must now complete the Kanidm code
// flow. The PIN is AES-GCM-encrypted at stash time, never plaintext at rest.
type pendingGrant struct {
	phone     string
	encPIN    []byte
	pinNonce  []byte
	expiresAt time.Time
}

// Server wires the enrollment flows. Two listeners (see cmd/voice-enroll):
// publicMux serves the browser UI (no /resolve — 404 there by construction);
// internalMux serves GET /resolve only, reachable via ClusterIP alone.
type Server struct {
	store      Store
	oidc       OIDCConfig
	sessions   *SessionCodec
	keys       *Key
	sms        SMSSender
	smsFrom    string
	libreChat  string
	httpClient *http.Client
	now        func() time.Time
	sessionTTL time.Duration

	// Grants-in-flight for the OAuth path (single replica: memory is fine;
	// a restart only forces the user to click "grant" again, fail-closed).
	// refreshMu serializes token refreshes so two concurrent resolves for
	// the same number cannot redeem the same rotating refresh token twice
	// (Kanidm treats reuse as theft and destroys the session).
	pendingMu sync.Mutex
	pending   map[string]pendingGrant // sub -> grant
	refreshMu sync.Mutex
}

func NewServer(store Store, oidc OIDCConfig, sessions *SessionCodec, keys *Key, sms SMSSender, smsFrom, libreChat string) *Server {
	return &Server{
		store: store, oidc: oidc, sessions: sessions, keys: keys,
		sms: sms, smsFrom: smsFrom, libreChat: libreChat,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		now:        time.Now,
		sessionTTL: 12 * time.Hour,
		pending:    map[string]pendingGrant{},
	}
}

// hashID renders a user id safe for logs: truncated sha256, never the raw id.
func hashID(sub string) string {
	h := sha256.Sum256([]byte(sub))
	return hex.EncodeToString(h[:])[:12]
}

func (s *Server) PublicMux() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	m.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	m.HandleFunc("GET /", s.handleIndex)
	m.HandleFunc("GET /login", s.handleLogin)
	m.HandleFunc("GET /oauth/callback", s.handleCallback)
	m.HandleFunc("POST /logout", s.handleLogout)
	m.HandleFunc("POST /api/otp/send", s.handleOTPSend)
	m.HandleFunc("POST /api/otp/verify", s.handleOTPVerify)
	m.HandleFunc("POST /api/grant", s.handleGrant)
	m.HandleFunc("POST /api/grant/oauth/start", s.handleGrantOAuthStart)
	m.HandleFunc("GET /oauth/grant/callback", s.handleGrantOAuthCallback)
	m.HandleFunc("POST /api/revoke", s.handleRevoke)
	m.HandleFunc("GET /api/enrollments", s.handleListEnrollments)
	return m
}

func (s *Server) InternalMux() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	m.HandleFunc("GET /resolve", s.handleResolve)
	m.HandleFunc("POST /verify-pin", s.handleVerifyPIN)
	return m
}

// currentSession returns the verified login session or "". Expiry enforced.
func (s *Server) currentSession(r *http.Request) (Session, bool) {
	c, err := r.Cookie("enroll_session")
	if err != nil {
		return Session{}, false
	}
	sess, err := s.sessions.Decode(c.Value, s.now())
	if err != nil {
		return Session{}, false
	}
	return sess, true
}

func (s *Server) setSession(w http.ResponseWriter, sess Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     "enroll_session",
		Value:    s.sessions.Encode(sess),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := randHex(16)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	nonce, err := randHex(16)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	verifier, err := NewCodeVerifier()
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "oauth_state", Value: state, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.SetCookie(w, &http.Cookie{Name: "oauth_nonce", Value: nonce, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.SetCookie(w, &http.Cookie{Name: "oauth_verifier", Value: verifier, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	dest, err := s.oidc.LoginURL(r.Context(), state, nonce, verifier)
	if err != nil {
		log.Printf("login: discovery failed")
		http.Error(w, "auth unavailable", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("error") != "" {
		http.Error(w, "login denied", http.StatusUnauthorized)
		return
	}
	st, err := r.Cookie("oauth_state")
	nn, err2 := r.Cookie("oauth_nonce")
	pkv, err3 := r.Cookie("oauth_verifier")
	if err != nil || err2 != nil || err3 != nil || pkv.Value == "" || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.Value)) != 1 {
		log.Printf("callback: bad state (missing login cookies or state mismatch)")
		http.Error(w, "bad state", http.StatusBadRequest)
		return
	}
	sub, _, err := s.oidc.Exchange(r.Context(), q.Get("code"), nn.Value, pkv.Value)
	if err != nil {
		// Safe to log: Exchange errors carry status codes and claim
		// mismatches only, never secrets, codes, or verifiers.
		log.Printf("callback: exchange failed: %v", err)
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	log.Printf("login ok sub=%s", hashID(sub))
	s.setSession(w, Session{Sub: sub, ExpiresAt: s.now().Add(s.sessionTTL)})
	http.SetCookie(w, &http.Cookie{Name: "oauth_state", MaxAge: -1, Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: "oauth_nonce", MaxAge: -1, Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: "oauth_verifier", MaxAge: -1, Path: "/"})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Best-effort Kanidm session handling: we clear our own cookie. Kanidm
	// holds no refresh/offline grant for this client (upstream kanidm#4034),
	// so there is no live server-side session of ours to revoke; the login
	// grant dies with the code exchange. Enrollment safety never depends on
	// this — resolve reads the PG mapping, and revocation deletes it.
	http.SetCookie(w, &http.Cookie{Name: "enroll_session", MaxAge: -1, Path: "/"})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type otpSendReq struct {
	Phone string `json:"phone"`
}

func (s *Server) handleOTPSend(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(r)
	if !ok {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	var req otpSendReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	phone, err := NormalizeE164(req.Phone)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	code, err := GenerateOTP()
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := RequestSend(s.store, nil, phone, code, s.now()); err != nil {
		if err == ErrOTPRateLimited {
			http.Error(w, "too many sends, try later", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	// DEBUG: plaintext code in logs so enrollment can be finished from
	// kubectl logs while SMS delivery is unverified. Remove once Telnyx
	// delivery is confirmed — codes in logs defeat the OTP's purpose.
	if err := s.sms.SendSMS(r.Context(), s.smsFrom, phone, "Your voice enrollment code is "+code+". It expires in 10 minutes."); err != nil {
		log.Printf("otp send failed sub=%s code=%s", hashID(sess.Sub), code)
		http.Error(w, "send failed", http.StatusBadGateway)
		return
	}
	log.Printf("otp sent sub=%s code=%s", hashID(sess.Sub), code)
	w.WriteHeader(http.StatusAccepted)
}

type otpVerifyReq struct {
	Phone string `json:"phone"`
	Code  string `json:"code"`
}

func (s *Server) handleOTPVerify(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(r)
	if !ok {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	var req otpVerifyReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	phone, err := NormalizeE164(req.Phone)
	if err != nil || len(req.Code) != OTPDigits {
		http.Error(w, "invalid or expired", http.StatusBadRequest)
		return
	}
	// Claiming a number without OTP is impossible: the session's verified
	// phone is set ONLY here, on a successful code check against the
	// sha256-hashed, single-use, expiring record. Every later grant/revoke
	// keys off sess.VerifiedPhone, never off user-supplied phone alone.
	if err := VerifyOTP(s.store, phone, req.Code, s.now()); err != nil {
		http.Error(w, "invalid or expired", http.StatusBadRequest)
		return
	}
	sess.VerifiedPhone = phone
	s.setSession(w, sess)
	log.Printf("otp verified sub=%s", hashID(sess.Sub))
	w.WriteHeader(http.StatusOK)
}

type grantReq struct {
	APIKey string `json:"api_key"`
	PIN    string `json:"pin"`
}

func (s *Server) handleGrant(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(r)
	if !ok || sess.VerifiedPhone == "" {
		http.Error(w, "login and verified number required", http.StatusUnauthorized)
		return
	}
	var req grantReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	key := strings.TrimSpace(req.APIKey)
	if key == "" || len(key) > 4096 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	pin := strings.TrimSpace(req.PIN)
	if err := ValidatePIN(pin); err != nil {
		http.Error(w, "invalid PIN: need 4-12 digits", http.StatusBadRequest)
		return
	}
	if err := VerifyLibreChatKey(r.Context(), s.httpClient, s.libreChat, key); err != nil {
		if err == ErrInvalidKey {
			http.Error(w, "key rejected by LibreChat", http.StatusBadRequest)
			return
		}
		http.Error(w, "verification unavailable", http.StatusBadGateway)
		return
	}
	nonce, ct, err := s.keys.Encrypt([]byte(key))
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	pinNonce, pinCT, err := s.keys.Encrypt([]byte(pin))
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	// Dual-auth: a PAT (re)grant must not wipe an existing OAuth grant for
	// the same number. Preserve stored bearer material; the OAuth path below
	// preserves the PAT symmetrically.
	e := Enrollment{
		Phone: phoneOf(sess), UserSub: sess.Sub,
		EncKey: ct, Nonce: nonce, EncPIN: pinCT, PINNonce: pinNonce,
		VerifiedAt: s.now(),
	}
	if old, err := s.store.GetByPhone(r.Context(), phoneOf(sess)); err == nil && old != nil && old.UserSub == sess.Sub {
		e.EncAccess, e.AccessNonce = old.EncAccess, old.AccessNonce
		e.EncRefresh, e.RefreshNonce = old.EncRefresh, old.RefreshNonce
		e.TokenExpiresAt = old.TokenExpiresAt
	}
	if err := s.store.UpsertEnrollment(r.Context(), e); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	// The pending verification is consumed: the number is now enrolled, so
	// return the session to the clean list state. Updating the key/PIN later
	// re-verifies ownership via SMS first.
	sess.VerifiedPhone = ""
	s.setSession(w, sess)
	log.Printf("grant stored sub=%s", hashID(sess.Sub))
	w.WriteHeader(http.StatusCreated)
}

// grantOIDC returns the OIDC client for the grant-via-OAuth code flow: same
// issuer/client/secret as login, but the grant callback as redirect_uri so
// the grant code lands on the grant handler (not the login handler, which
// would reject it as "bad state"). Both the authorize URL and the code
// exchange must use this config or Kanidm rejects the redirect mismatch.
func (s *Server) grantOIDC() OIDCConfig {
	gc := s.oidc
	if gc.GrantRedirectURL != "" {
		gc.RedirectURL = gc.GrantRedirectURL
	}
	return gc
}

type grantOAuthStartReq struct {
	PIN string `json:"pin"`
}

// handleGrantOAuthStart begins grant-via-OAuth: the user proved number
// ownership (OTP, in VerifiedPhone) and chose a PIN, and now completes a
// Kanidm code flow instead of pasting a PAT. The PIN is encrypted into a
// short-lived pending grant keyed by sub; the response carries the Kanidm
// login URL the browser must visit. The PAT paste form stays as fallback.
func (s *Server) handleGrantOAuthStart(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(r)
	if !ok || sess.VerifiedPhone == "" {
		http.Error(w, "login and verified number required", http.StatusUnauthorized)
		return
	}
	var req grantOAuthStartReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	pin := strings.TrimSpace(req.PIN)
	if err := ValidatePIN(pin); err != nil {
		http.Error(w, "invalid PIN: need 4-12 digits", http.StatusBadRequest)
		return
	}
	pinNonce, pinCT, err := s.keys.Encrypt([]byte(pin))
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	state, err := randHex(16)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	nonce, err := randHex(16)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	verifier, err := NewCodeVerifier()
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	s.pendingMu.Lock()
	now := s.now()
	for sub, p := range s.pending {
		if !p.expiresAt.After(now) {
			delete(s.pending, sub)
		}
	}
	s.pending[sess.Sub] = pendingGrant{
		phone: phoneOf(sess), encPIN: pinCT, pinNonce: pinNonce,
		expiresAt: now.Add(pendingGrantTTL),
	}
	s.pendingMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "grant_state", Value: state, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.SetCookie(w, &http.Cookie{Name: "grant_nonce", Value: nonce, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.SetCookie(w, &http.Cookie{Name: "grant_verifier", Value: verifier, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	dest, err := s.grantOIDC().LoginURL(r.Context(), state, nonce, verifier)
	if err != nil {
		log.Printf("grant oauth start: discovery failed")
		http.Error(w, "auth unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"login_url": dest})
}

// handleGrantOAuthCallback completes grant-via-OAuth: it exchanges the code
// for bearer material, verifies the access token live against LibreChat
// (fail-closed like the PAT path), and stores it encrypted alongside the
// stashed PIN. Any stored PAT for the number is preserved (dual-auth).
func (s *Server) handleGrantOAuthCallback(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(r)
	if !ok {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	q := r.URL.Query()
	if q.Get("error") != "" {
		http.Error(w, "grant denied", http.StatusUnauthorized)
		return
	}
	st, err := r.Cookie("grant_state")
	nn, err2 := r.Cookie("grant_nonce")
	pkv, err3 := r.Cookie("grant_verifier")
	if err != nil || err2 != nil || err3 != nil || pkv.Value == "" || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.Value)) != 1 {
		log.Printf("grant callback: bad state (missing grant cookies or state mismatch)")
		http.Error(w, "bad state", http.StatusBadRequest)
		return
	}
	ts, err := s.grantOIDC().ExchangeTokens(r.Context(), q.Get("code"), nn.Value, pkv.Value)
	if err != nil {
		log.Printf("grant callback: exchange failed: %v", err)
		http.Error(w, "grant failed", http.StatusUnauthorized)
		return
	}
	// The grant binds to the login session: a code minted for another user
	// cannot enroll this session's number.
	if ts.Sub == "" || subtle.ConstantTimeCompare([]byte(ts.Sub), []byte(sess.Sub)) != 1 {
		log.Printf("grant callback: subject mismatch sub=%s", hashID(sess.Sub))
		http.Error(w, "grant failed", http.StatusUnauthorized)
		return
	}
	if err := VerifyLibreChatKey(r.Context(), s.httpClient, s.libreChat, ts.AccessToken); err != nil {
		if errors.Is(err, ErrInvalidKey) {
			log.Printf("grant callback: LibreChat rejected OAuth bearer sub=%s", hashID(sess.Sub))
			http.Error(w, "LibreChat rejected the grant (is OIDC auth enabled on the Agents API?)", http.StatusBadRequest)
			return
		}
		http.Error(w, "verification unavailable", http.StatusBadGateway)
		return
	}
	s.pendingMu.Lock()
	p, found := s.pending[sess.Sub]
	if found {
		delete(s.pending, sess.Sub)
	}
	s.pendingMu.Unlock()
	if !found || s.now().After(p.expiresAt) {
		http.Error(w, "grant expired, start over", http.StatusBadRequest)
		return
	}
	accNonce, accCT, err := s.keys.Encrypt([]byte(ts.AccessToken))
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	e := Enrollment{
		Phone: p.phone, UserSub: sess.Sub,
		EncPIN: p.encPIN, PINNonce: p.pinNonce,
		EncAccess: accCT, AccessNonce: accNonce,
		VerifiedAt: s.now(),
	}
	if ts.RefreshToken != "" {
		refNonce, refCT, err := s.keys.Encrypt([]byte(ts.RefreshToken))
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		e.EncRefresh, e.RefreshNonce = refCT, refNonce
	}
	e.TokenExpiresAt = s.now().Add(oauthAccessLifetime(ts.ExpiresIn))
	// Dual-auth: preserve any stored PAT for the number.
	if old, err := s.store.GetByPhone(r.Context(), p.phone); err == nil && old != nil && old.UserSub == sess.Sub {
		e.EncKey, e.Nonce = old.EncKey, old.Nonce
	}
	if err := s.store.UpsertEnrollment(r.Context(), e); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	sess.VerifiedPhone = ""
	s.setSession(w, sess)
	http.SetCookie(w, &http.Cookie{Name: "grant_state", MaxAge: -1, Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: "grant_nonce", MaxAge: -1, Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: "grant_verifier", MaxAge: -1, Path: "/"})
	log.Printf("grant oauth stored sub=%s", hashID(sess.Sub))
	http.Redirect(w, r, "/", http.StatusFound)
}

// oauthAccessLifetime bounds the stored access-token expiry. Kanidm mints
// 15-minute access tokens (see its oauth2_refresh_tokens design); when the
// provider omits expires_in we assume that rather than treating the bearer
// as immortal or instantly dead.
func oauthAccessLifetime(expiresIn time.Duration) time.Duration {
	if expiresIn > 0 {
		return expiresIn
	}
	return 15 * time.Minute
}

// freshAccessToken returns a live Kanidm access token for the enrollment,
// redeeming the stored refresh token when the access token is missing,
// expired, or expiring within the skew window. Rotation is honored: a new
// refresh token replaces the old (reuse of an old one destroys the Kanidm
// session). Refreshes serialize across resolves so concurrent calls cannot
// double-redeem. Any failure is fail-closed to the caller, which falls back
// to the stored PAT when one exists and otherwise denies.
func (s *Server) freshAccessToken(ctx context.Context, e *Enrollment) (string, error) {
	if !e.HasOAuth() {
		return "", errors.New("no oauth grant")
	}
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	// Re-read under the lock: a concurrent resolve may have just rotated.
	fresh, err := s.store.GetByPhone(ctx, e.Phone)
	if err != nil || fresh == nil {
		return "", errors.New("unavailable")
	}
	e = fresh
	if !e.HasOAuth() {
		return "", errors.New("no oauth grant")
	}
	access, err := s.keys.Decrypt(e.AccessNonce, e.EncAccess)
	if err != nil {
		return "", err
	}
	if !e.TokenExpiresAt.IsZero() && s.now().Add(oauthRefreshSkew).Before(e.TokenExpiresAt) {
		return string(access), nil
	}
	if len(e.EncRefresh) == 0 {
		// Legacy row (no refresh, unknown lifetime): hand out the bearer and
		// let the downstream call fail closed at use time if it is dead.
		return string(access), nil
	}
	refresh, err := s.keys.Decrypt(e.RefreshNonce, e.EncRefresh)
	if err != nil {
		return "", err
	}
	ts, err := s.oidc.RefreshTokens(ctx, string(refresh), e.UserSub)
	if err != nil {
		return "", err
	}
	accNonce, accCT, err := s.keys.Encrypt([]byte(ts.AccessToken))
	if err != nil {
		return "", err
	}
	e.EncAccess, e.AccessNonce = accCT, accNonce
	if ts.RefreshToken != "" {
		refNonce, refCT, err := s.keys.Encrypt([]byte(ts.RefreshToken))
		if err != nil {
			return "", err
		}
		e.EncRefresh, e.RefreshNonce = refCT, refNonce
	}
	e.TokenExpiresAt = s.now().Add(oauthAccessLifetime(ts.ExpiresIn))
	if err := s.store.UpsertEnrollment(ctx, *e); err != nil {
		return "", err
	}
	return ts.AccessToken, nil
}

func phoneOf(sess Session) string { return sess.VerifiedPhone }

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(r)
	if !ok {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	// Revoking any of the caller's own numbers must not require the session
	// to currently point at that number: after verifying a new number the
	// old one stays active (enrollments are keyed by phone), and the user
	// needs a path back to it. An explicit {"phone"} selects the entry;
	// omitted keeps the legacy verified-number behavior.
	var req struct {
		Phone string `json:"phone"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req)
	target := strings.TrimSpace(req.Phone)
	if target == "" {
		if sess.VerifiedPhone == "" {
			http.Error(w, "login and verified number required", http.StatusUnauthorized)
			return
		}
		target = sess.VerifiedPhone
	}
	phone, err := NormalizeE164(target)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	okDeleted, err := s.store.DeleteEnrollment(r.Context(), phone, sess.Sub)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	// Deleting the mapping fails subsequent calls closed: resolve reads PG
	// live per request (no cache in this service), so the next lookup 404s
	// and the edge denies. LibreChat-key deletion likewise fails closed at
	// use time when the caller presents the now-dead key. The (phone, sub)
	// scope in the store keeps one user from revoking another's number.
	// If the revoked entry is the session's verified number, clear it so a
	// stale session cannot grant again without re-verifying.
	if okDeleted && phone == sess.VerifiedPhone {
		sess.VerifiedPhone = ""
		s.setSession(w, sess)
	}
	log.Printf("revoke sub=%s deleted=%v", hashID(sess.Sub), okDeleted)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"deleted": okDeleted})
}

// handleListEnrollments returns the caller's own enrolled numbers so the UI
// can show every active entry — including numbers verified before the
// session's current one — each removable via POST /api/revoke {"phone"}.
// Login required; the store scopes rows by sub, so no cross-user leakage.
func (s *Server) handleListEnrollments(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(r)
	if !ok {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	rows, err := s.store.ListBySub(r.Context(), sess.Sub)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	type entry struct {
		Phone      string `json:"phone"`
		VerifiedAt string `json:"verified_at"`
	}
	out := make([]entry, 0, len(rows))
	for _, e := range rows {
		out = append(out, entry{Phone: e.Phone, VerifiedAt: e.VerifiedAt.UTC().Format(time.RFC3339)})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"phones": out})
}

// handleResolve is the internal directory the call path queries at runtime.
// Same endpoint serves unknown numbers as deny: unknown vs unenrolled both
// return 404 with an identical body, so callers (and probers) cannot
// distinguish them.
//
// No bearer auth: the listener is ClusterIP-only (no HTTPRoute) and relies
// on cluster networking for isolation. Any in-cluster caller can resolve;
// ?reveal=key returns key material.
func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	phone, err := NormalizeE164(r.URL.Query().Get("phone"))
	if err != nil {
		deny(w)
		return
	}
	e, err := s.store.GetByPhone(r.Context(), phone)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if e == nil {
		deny(w)
		return
	}
	out := map[string]string{"user_sub": e.UserSub}
	if r.URL.Query().Get("reveal") == "key" {
		// Dual-auth: prefer the OAuth bearer when granted, fall back to the
		// PAT when the grant is missing or its refresh died (fail-closed to
		// re-grant when neither yields a bearer).
		if e.HasOAuth() {
			if access, err := s.freshAccessToken(r.Context(), e); err == nil {
				out["access_token"] = access
			} else {
				log.Printf("resolve oauth refresh failed sub=%s err=%v", hashID(e.UserSub), err)
			}
		}
		if e.HasPAT() {
			plain, err := s.keys.Decrypt(e.Nonce, e.EncKey)
			if err != nil {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			out["api_key"] = string(plain)
		}
		if _, hasBearer := out["access_token"]; !hasBearer {
			if _, hasKey := out["api_key"]; !hasKey {
				deny(w)
				return
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// handleVerifyPIN is the internal per-caller PIN check the voice path uses
// at call time. POST /verify-pin {"phone","pin"} returns 200 {user_sub} on
// a match, 404 {error:deny} otherwise. Unknown numbers, missing PINs,
// malformed input and wrong digits all deny identically so probers cannot
// distinguish them. No bearer auth: ClusterIP-only listener, same isolation
// as /resolve. PIN plaintext never leaves this process in logs or captures.
func (s *Server) handleVerifyPIN(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Phone string `json:"phone"`
		PIN   string `json:"pin"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		deny(w)
		return
	}
	phone, err := NormalizeE164(req.Phone)
	if err != nil || ValidatePIN(strings.TrimSpace(req.PIN)) != nil {
		deny(w)
		return
	}
	e, err := s.store.GetByPhone(r.Context(), phone)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if e == nil || len(e.EncPIN) == 0 || len(e.PINNonce) == 0 {
		deny(w)
		return
	}
	plain, err := s.keys.Decrypt(e.PINNonce, e.EncPIN)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !VerifyPIN(string(plain), strings.TrimSpace(req.PIN)) {
		deny(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"user_sub": e.UserSub})
}

func deny(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{"error": "deny"})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	// "GET /" is a subtree match in Go's ServeMux: anything unregistered
	// (notably /resolve) must 404 here so key material is never served on
	// the public listener even if routing is misconfigured.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	sess, loggedIn := s.currentSession(r)
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>Voice enrollment</title><style>` +
		`body{font-family:system-ui,-apple-system,sans-serif;background:#f6f6f4;color:#1a1a1a;margin:0}` +
		`main{max-width:560px;margin:48px auto;padding:0 16px}` +
		`.card{background:#fff;border:1px solid #e2e2e0;border-radius:12px;padding:20px;margin:16px 0}` +
		`h1{font-size:24px;margin:0 0 4px}h2{font-size:16px;margin:20px 0 4px}` +
		`.sub{color:#666;font-size:14px;margin:0}` +
		`label{display:block;font-size:13px;color:#555;margin:12px 0 4px}` +
		`input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #ccc;border-radius:8px;font-size:16px}` +
		`button{padding:10px 16px;border:0;border-radius:8px;font-size:15px;background:#1a1a1a;color:#fff;cursor:pointer}` +
		`button.secondary{background:#e8e8e6;color:#1a1a1a}` +
		`.row{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap}` +
		`#status{min-height:1.4em;font-size:14px;color:#555;margin:12px 0 0}` +
		`#status.ok{color:#0a7d2c}#status.err{color:#b00020}` +
		`.pill{display:inline-block;font-size:13px;background:#eef7ee;color:#0a7d2c;border-radius:999px;padding:2px 10px}` +
		`a.btn{display:inline-block;padding:10px 16px;border-radius:8px;background:#1a1a1a;color:#fff;text-decoration:none}` +
		`ul.numbers{padding-left:20px;margin:8px 0}ul.numbers li{margin:6px 0}ul.numbers li button{padding:4px 10px;font-size:13px;margin-left:8px}` +
		`</style></head><body><main><h1>Voice enrollment</h1>` +
		`<p class="sub">Verify a number, then grant it voice access.</p>` +
		`<p id="status" role="status"></p>`)
	enrolledCard := `<div class="card"><h2>Enrolled phone numbers</h2>` +
		`<p class="sub">All numbers with voice access under your account. Removing one denies its calls.</p>` +
		`<div id="enrolled"><p class="sub">Loading…</p></div></div>`
	verifyCard := func(hidden bool) string {
		hide := ""
		if hidden {
			hide = " hidden"
		}
		return `<div class="card" id="verifyCard"` + hide + `><h2>Step 2 — Verify your number</h2>` +
			`<label for="phone">Phone number</label>` +
			`<input id="phone" type="tel" inputmode="tel" autocomplete="tel" placeholder="+15550109999">` +
			`<div class="row"><button id="send">Send code</button></div>` +
			`<label for="code">6-digit code from SMS</label>` +
			`<input id="code" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" maxlength="6">` +
			`<div class="row"><button id="verify">Verify</button></div></div>`
	}
	// Logged-in main view is always the enrolled list plus the enroll entry
	// point. Verify and grant are progressive disclosure: hidden until the
	// user starts enrolling (or resumes a pending verification after a
	// reload — window.__verifiedPhone carries that state).
	// sess.VerifiedPhone is E.164 ("+" + digits) by construction, so it is
	// safe to embed in a quoted JS string.
	if !loggedIn {
		b.WriteString(`<div class="card"><h2>Step 1 — Log in</h2>` +
			`<p class="sub">Kanidm confirms who you are.</p>` +
			`<div class="row"><a class="btn" href="/login">Log in with Kanidm</a></div></div>`)
	} else {
		enrollHidden, grantHidden, grantPhone := "", " hidden", ""
		if sess.VerifiedPhone != "" {
			enrollHidden, grantHidden = " hidden", ""
			grantPhone = html.EscapeString(sess.VerifiedPhone)
		}
		b.WriteString(enrolledCard +
			`<div class="card" id="enrollCard"` + enrollHidden + `><h2>Enroll new phone number</h2>` +
			`<p class="sub">Verify ownership via SMS, then grant voice access. Numbers you already enrolled stay active.</p>` +
			`<div class="row"><button id="enrollNew">Enroll new phone number</button></div></div>` +
			verifyCard(true) +
			`<div class="card" id="grantCard"` + grantHidden + `><h2>Step 3 — Grant voice access</h2>` +
			`<p><span class="pill" id="grantPhone">` + grantPhone + `</span></p>` +
			`<p class="sub">Choose a 4-12 digit voice PIN for call-time identification, then grant access. Preferred: Kanidm login (no key to copy). Fallback: paste a LibreChat Remote Agents API key, verified live and stored encrypted.</p>` +
			`<label for="pin">Voice PIN (4-12 digits)</label>` +
			`<input id="pin" type="password" inputmode="numeric" autocomplete="off" placeholder="482916" maxlength="12">` +
			`<div class="row"><button id="grantOauth">Grant with Kanidm login</button></div>` +
			`<label for="apikey">LibreChat API key (fallback)</label>` +
			`<input id="apikey" type="password" autocomplete="off" placeholder="lc-…">` +
			`<div class="row"><button id="grant">Grant with pasted key</button>` +
			`<button id="useDifferent" class="secondary">Use a different number</button></div></div>` +
			`<div class="row"><form method="post" action="/logout"><button class="secondary" type="submit">Log out</button></form></div>`)
	}
	b.WriteString(`</main><script>
window.__verifiedPhone="` + html.EscapeString(sess.VerifiedPhone) + `";
const status=document.getElementById('status');
function say(msg,cls){if(!status)return;status.textContent=msg;status.className=cls||'';}
async function post(url,body){
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(!r.ok){let t='';try{t=await r.text();}catch(e){}throw new Error(t||('request failed: '+r.status));}
  return r;
}
function phoneVal(){const el=document.getElementById('phone');return el?el.value:'';}
async function refreshEnrolled(){
  const box=document.getElementById('enrolled');
  if(!box)return;
  try{
    const r=await fetch('/api/enrollments');
    if(!r.ok)throw new Error('load failed: '+r.status);
    const data=await r.json();
    box.textContent='';
    if(!data.phones||!data.phones.length){box.innerHTML='<p class="sub">None yet.</p>';return;}
    const ul=document.createElement('ul');
    ul.className='numbers';
    data.phones.forEach(function(p){
      const li=document.createElement('li');
      li.appendChild(document.createTextNode(p.phone+' '));
      const btn=document.createElement('button');
      btn.textContent='Remove';
      btn.className='secondary';
      btn.onclick=async function(){say('Revoking '+p.phone+'…');try{await post('/api/revoke',{phone:p.phone});say('Removed '+p.phone+'.','ok');refreshEnrolled();}catch(e){say(e.message,'err');}};
      li.appendChild(btn);
      ul.appendChild(li);
    });
    box.appendChild(ul);
  }catch(e){box.textContent='Could not load enrolled numbers.';}
}
refreshEnrolled();
function show(el,on){if(el)el.hidden=!on;}
const enrollNew=document.getElementById('enrollNew');
if(enrollNew)enrollNew.onclick=()=>{show(document.getElementById('verifyCard'),true);show(document.getElementById('enrollCard'),false);};
const useDifferent=document.getElementById('useDifferent');
if(useDifferent)useDifferent.onclick=()=>{show(document.getElementById('grantCard'),false);show(document.getElementById('verifyCard'),true);};
const send=document.getElementById('send');
if(send)send.onclick=async()=>{say('Sending…');try{await post('/api/otp/send',{phone:phoneVal()});say('Code sent — check SMS.','ok');}catch(e){say(e.message,'err');}};
const verify=document.getElementById('verify');
if(verify)verify.onclick=async()=>{say('Verifying…');try{const p=phoneVal();const c=document.getElementById('code').value;await post('/api/otp/verify',{phone:p,code:c});window.__verifiedPhone=p;const gp=document.getElementById('grantPhone');if(gp)gp.textContent=p;show(document.getElementById('verifyCard'),false);show(document.getElementById('enrollCard'),false);show(document.getElementById('grantCard'),true);say('Verified — grant voice access below.','ok');}catch(e){say(e.message,'err');}};
const grant=document.getElementById('grant');
if(grant)grant.onclick=async()=>{say('Verifying key…');try{await post('/api/grant',{api_key:document.getElementById('apikey').value,pin:document.getElementById('pin').value});window.__verifiedPhone='';const ak=document.getElementById('apikey');if(ak)ak.value='';const pk=document.getElementById('pin');if(pk)pk.value='';show(document.getElementById('grantCard'),false);show(document.getElementById('enrollCard'),true);say('Voice access granted.','ok');refreshEnrolled();}catch(e){say(e.message,'err');}};
const grantOauth=document.getElementById('grantOauth');
if(grantOauth)grantOauth.onclick=async()=>{say('Starting Kanidm grant…');try{const r=await post('/api/grant/oauth/start',{pin:document.getElementById('pin').value});const data=await r.json();if(!data.login_url)throw new Error('grant start failed');window.location.href=data.login_url;}catch(e){say(e.message,'err');}};
</script></body></html>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}
