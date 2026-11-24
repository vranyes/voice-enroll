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
	"time"
)

// Server wires the enrollment flows. Two listeners (see cmd/voice-enroll):
// publicMux serves the browser UI (no /resolve — 404 there by construction);
// internalMux serves GET /resolve only, reachable via ClusterIP alone.
type Server struct {
	store         Store
	oidc          OIDCConfig
	sessions      *SessionCodec
	keys          *Key
	sms           SMSSender
	smsFrom       string
	libreChat     string
	PublicBaseURL string
	// chatGPTTokenURL overrides the ChatGPT token endpoint in tests.
	chatGPTTokenURL string
	httpClient      *http.Client
	now             func() time.Time
	sessionTTL      time.Duration
}

func NewServer(store Store, oidc OIDCConfig, sessions *SessionCodec, keys *Key, sms SMSSender, smsFrom, libreChat string) *Server {
	return &Server{
		store: store, oidc: oidc, sessions: sessions, keys: keys,
		sms: sms, smsFrom: smsFrom, libreChat: libreChat,
		chatGPTTokenURL: ChatGPTTokenURL,
		httpClient:      &http.Client{Timeout: 10 * time.Second},
		now:             time.Now,
		sessionTTL:      12 * time.Hour,
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
	m.HandleFunc("GET /oauth/chatgpt/login", s.handleChatGPTLogin)
	m.HandleFunc("GET /oauth/chatgpt/callback", s.handleChatGPTCallback)
	m.HandleFunc("POST /logout", s.handleLogout)
	m.HandleFunc("POST /api/otp/send", s.handleOTPSend)
	m.HandleFunc("POST /api/otp/verify", s.handleOTPVerify)
	m.HandleFunc("POST /api/grant", s.handleGrant)
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

func (s *Server) handleChatGPTLogin(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(r)
	if !ok || sess.VerifiedPhone == "" {
		http.Error(w, "login and verified number required", http.StatusUnauthorized)
		return
	}
	if s.PublicBaseURL == "" {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	state, err := randHex(16)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	verifier, err := NewCodeVerifier()
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "cgpt_state", Value: state, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.SetCookie(w, &http.Cookie{Name: "cgpt_verifier", Value: verifier, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, ChatGPTLoginURL(state, verifier, ChatGPTRedirectURL(s.PublicBaseURL)), http.StatusFound)
}

func (s *Server) handleChatGPTCallback(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(r)
	if !ok || sess.VerifiedPhone == "" {
		http.Error(w, "login and verified number required", http.StatusUnauthorized)
		return
	}
	q := r.URL.Query()
	if q.Get("error") != "" {
		http.Error(w, "login denied", http.StatusUnauthorized)
		return
	}
	st, stateErr := r.Cookie("cgpt_state")
	pkv, verifierErr := r.Cookie("cgpt_verifier")
	if stateErr != nil || verifierErr != nil || pkv.Value == "" || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.Value)) != 1 {
		http.Error(w, "bad state", http.StatusBadRequest)
		return
	}
	tok, err := exchangeChatGPTCode(r.Context(), s.httpClient, s.chatGPTTokenURL, q.Get("code"), pkv.Value, ChatGPTRedirectURL(s.PublicBaseURL))
	if err != nil {
		log.Printf("chatgpt callback: exchange failed sub=%s", hashID(sess.Sub))
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	if err := s.storeChatGPTCredential(r.Context(), sess.VerifiedPhone, sess.Sub, tok); err != nil {
		log.Printf("chatgpt callback: store failed sub=%s", hashID(sess.Sub))
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "cgpt_state", MaxAge: -1, Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: "cgpt_verifier", MaxAge: -1, Path: "/"})
	log.Printf("chatgpt connected sub=%s", hashID(sess.Sub))
	http.Redirect(w, r, "/?chatgpt=connected", http.StatusFound)
}

// storeChatGPTCredential persists the OAuth tokens for phone. A row may not
// exist yet: connecting ChatGPT is a valid first step, and the row stays
// "pending" (no PIN) so the admit gate in handleResolve continues to deny
// until the user completes grant with a voice PIN. Ownership is decided by
// the OTP-verified session (the caller passes sess.VerifiedPhone), so a row
// left behind by a previous owner is replaced.
func (s *Server) storeChatGPTCredential(ctx context.Context, phone, sub string, tok ChatGPTTokens) error {
	e, err := s.store.GetByPhone(ctx, phone)
	if err != nil {
		return err
	}

	eAccessNonce, eAccess, err := s.keys.Encrypt([]byte(tok.AccessToken))
	if err != nil {
		return err
	}
	var eRefreshNonce, eRefresh []byte
	switch {
	case tok.RefreshToken != "":
		eRefreshNonce, eRefresh, err = s.keys.Encrypt([]byte(tok.RefreshToken))
		if err != nil {
			return err
		}
	case e != nil && e.UserSub == sub:
		// Provider did not rotate the refresh token: keep the stored one
		// instead of nulling the column.
		eRefresh, eRefreshNonce = e.EncChatGPTRefresh, e.ChatGPTRefreshNonce
	}

	if e != nil && e.UserSub == sub {
		accountID := tok.AccountID
		if accountID == "" {
			accountID = e.ChatGPTAccountID
		}
		ok, err := s.store.UpdateChatGPTTokens(ctx, phone, sub,
			eRefresh, eRefreshNonce, eAccess, eAccessNonce, tok.ExpiresAt, accountID)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("enrollment changed")
		}
		return nil
	}

	// No row, or one owned by a previous owner: replace it with a pending
	// row for this OTP-verified subject.
	return s.store.UpsertEnrollment(ctx, Enrollment{
		Phone: phone, UserSub: sub, VerifiedAt: s.now(),
		EncChatGPTRefresh: eRefresh, ChatGPTRefreshNonce: eRefreshNonce,
		EncChatGPTAccess: eAccess, ChatGPTAccessNonce: eAccessNonce,
		ChatGPTExpiresAt: tok.ExpiresAt, ChatGPTAccountID: tok.AccountID,
	})
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
	if len(key) > 4096 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	pin := strings.TrimSpace(req.PIN)
	if err := ValidatePIN(pin); err != nil {
		http.Error(w, "invalid PIN: need 4-12 digits", http.StatusBadRequest)
		return
	}
	phone := phoneOf(sess)

	// Load any existing row so a same-subject update can target only the
	// columns it owns: a grant does not rewrite the OAuth credential columns,
	// so a concurrent token refresh cannot be clobbered (and vice versa).
	// A row owned by another subject is replaced by a full upsert: the
	// session's OTP proves ownership of the number now.
	existing, err := s.store.GetByPhone(r.Context(), phone)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	sameOwner := existing != nil && existing.UserSub == sess.Sub

	if key == "" {
		// OAuth-only grant: the user connected ChatGPT first, which created
		// (or updated) the pending row. Refuse if that credential is missing
		// or belongs to someone else.
		if !sameOwner || !hasChatGPTCredential(existing) {
			http.Error(w, "connect ChatGPT first", http.StatusBadRequest)
			return
		}
	} else if err := VerifyLibreChatKey(r.Context(), s.httpClient, s.libreChat, key); err != nil {
		if err == ErrInvalidKey {
			http.Error(w, "key rejected by LibreChat", http.StatusBadRequest)
			return
		}
		http.Error(w, "verification unavailable", http.StatusBadGateway)
		return
	}

	pinNonce, pinCT, err := s.keys.Encrypt([]byte(pin))
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	now := s.now()

	var stored bool
	switch {
	case key == "":
		stored, err = s.store.UpdatePIN(r.Context(), phone, sess.Sub, pinCT, pinNonce, now)
	case sameOwner:
		keyNonce, keyCT, encErr := s.keys.Encrypt([]byte(key))
		if encErr != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		stored, err = s.store.UpdateKeyAndPIN(r.Context(), phone, sess.Sub, keyCT, keyNonce, pinCT, pinNonce, now)
	default:
		keyNonce, keyCT, encErr := s.keys.Encrypt([]byte(key))
		if encErr != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		err = s.store.UpsertEnrollment(r.Context(), Enrollment{
			Phone: phone, UserSub: sess.Sub,
			EncKey: keyCT, Nonce: keyNonce, EncPIN: pinCT, PINNonce: pinNonce,
			VerifiedAt: now,
		})
		stored = err == nil
	}
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !stored {
		// The row disappeared or changed owner between load and update.
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

func phoneOf(sess Session) string { return sess.VerifiedPhone }

// hasPIN reports whether the row is a complete enrollment. Rows without a
// PIN are pending (ChatGPT connected, grant not finished) and must not admit
// calls or reveal credentials.
func hasPIN(e *Enrollment) bool {
	return e != nil && len(e.EncPIN) > 0 && len(e.PINNonce) > 0
}

func hasChatGPTCredential(e *Enrollment) bool {
	return e != nil && len(e.EncChatGPTAccess) > 0 && len(e.ChatGPTAccessNonce) > 0
}

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
		Active     bool   `json:"active"`
		Credential string `json:"credential"`
	}
	out := make([]entry, 0, len(rows))
	for _, e := range rows {
		cred := ""
		switch {
		case hasChatGPTCredential(&e):
			cred = "chatgpt_oauth"
		case len(e.EncKey) > 0 && len(e.Nonce) > 0:
			cred = "api_key"
		}
		out = append(out, entry{
			Phone:      e.Phone,
			VerifiedAt: e.VerifiedAt.UTC().Format(time.RFC3339),
			Active:     hasPIN(&e),
			Credential: cred,
		})
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
// ?reveal=key returns key material; ?reveal=credential returns per-caller
// call credential (chatgpt_oauth or legacy api_key) for voice-bridge.
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
	// Pending enrollments (ChatGPT connected but no voice PIN yet) must not
	// admit calls: the admit gate is this lookup, so require the PIN here as
	// well as in verify-pin. A row without a PIN is indistinguishable from an
	// unknown number.
	if !hasPIN(e) {
		deny(w)
		return
	}
	reveal := r.URL.Query().Get("reveal")
	out := map[string]any{"user_sub": e.UserSub}
	switch reveal {
	case "key":
		if len(e.EncKey) == 0 || len(e.Nonce) == 0 {
			deny(w)
			return
		}
		plain, err := s.keys.Decrypt(e.Nonce, e.EncKey)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		out["api_key"] = string(plain)
	case "credential":
		cred, err := s.resolveCredential(r.Context(), e)
		if err != nil {
			if errors.Is(err, errNoCredential) {
				deny(w)
				return
			}
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		for k, v := range cred {
			out[k] = v
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

var errNoCredential = errors.New("no credential")

func (s *Server) resolveCredential(ctx context.Context, e *Enrollment) (map[string]any, error) {
	// Prefer ChatGPT OAuth credential when present.
	if hasChatGPTCredential(e) {
		access, refresh := "", ""
		expiresAt, accountID := e.ChatGPTExpiresAt, e.ChatGPTAccountID
		if len(e.EncChatGPTRefresh) > 0 && len(e.ChatGPTRefreshNonce) > 0 {
			if rt, err := s.keys.Decrypt(e.ChatGPTRefreshNonce, e.EncChatGPTRefresh); err == nil {
				refresh = string(rt)
			}
		}
		if !expiresAt.IsZero() && time.Now().Add(60*time.Second).After(expiresAt) {
			// Expired or about to expire. Without a refresh token the
			// credential is unusable: deny like an unknown number.
			if refresh == "" {
				return nil, errNoCredential
			}
			tok, err := refreshChatGPTToken(ctx, s.httpClient, s.chatGPTTokenURL, refresh)
			if err != nil {
				// Dead or unusable refresh token: fail closed and deny,
				// rather than surfacing a retryable 5xx on every call. The
				// user reconnects ChatGPT from the UI.
				return nil, errNoCredential
			}
			if err := s.storeChatGPTCredential(ctx, e.Phone, e.UserSub, tok); err != nil {
				return nil, err
			}
			// Answer with the tokens just minted. Do not re-read the row:
			// a concurrent delete would otherwise make us serve the old,
			// already-expired access token.
			access, expiresAt = tok.AccessToken, tok.ExpiresAt
			if tok.RefreshToken != "" {
				refresh = tok.RefreshToken
			}
			if tok.AccountID != "" {
				accountID = tok.AccountID
			}
		} else {
			at, err := s.keys.Decrypt(e.ChatGPTAccessNonce, e.EncChatGPTAccess)
			if err != nil {
				return nil, err
			}
			access = string(at)
		}
		cred := map[string]any{
			"credential_kind": "chatgpt_oauth",
			"access_token":    access,
			"expires_at":      expiresAt.UTC().Format(time.RFC3339),
			"account_id":      accountID,
		}
		if refresh != "" {
			cred["refresh_token"] = refresh
		}
		return cred, nil
	}
	// Legacy API key credential.
	if len(e.EncKey) > 0 && len(e.Nonce) > 0 {
		plain, err := s.keys.Decrypt(e.Nonce, e.EncKey)
		if err != nil {
			return nil, err
		}
		return map[string]any{"credential_kind": "api_key", "api_key": string(plain)}, nil
	}
	return nil, errNoCredential
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
	// If the verified number already has ChatGPT tokens, the grant card asks
	// only for a PIN: that is the OAuth-only path (connect, then grant).
	chatGPTConnected := false
	if loggedIn && sess.VerifiedPhone != "" {
		if e, err := s.store.GetByPhone(r.Context(), sess.VerifiedPhone); err == nil && e != nil && e.UserSub == sess.Sub {
			chatGPTConnected = hasChatGPTCredential(e)
		}
	}
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
		grantCard := `<div class="card" id="grantCard"` + grantHidden + `><h2>Step 3 — Grant voice access</h2>` +
			`<p><span class="pill" id="grantPhone">` + grantPhone + `</span></p>`
		if chatGPTConnected {
			grantCard += `<p class="sub" id="cgptStatus"><span class="pill">ChatGPT connected</span> <a href="/oauth/chatgpt/login">Reconnect</a></p>` +
				`<p class="sub">Choose a 4-12 digit voice PIN for call-time identification.</p>`
		} else {
			grantCard += `<p class="sub">Paste a LibreChat Remote Agents API key, or connect your ChatGPT account. Choose a 4-12 digit voice PIN for call-time identification.</p>` +
				`<label for="apikey">LibreChat API key</label>` +
				`<input id="apikey" type="password" autocomplete="off" placeholder="lc-…">` +
				`<p class="sub"><a href="/oauth/chatgpt/login">Or connect ChatGPT instead</a></p>`
		}
		grantCard += `<label for="pin">Voice PIN (4-12 digits)</label>` +
			`<input id="pin" type="password" inputmode="numeric" autocomplete="off" placeholder="482916" maxlength="12">` +
			`<div class="row"><button id="grant">Grant access</button>` +
			`<button id="useDifferent" class="secondary">Use a different number</button></div></div>`
		b.WriteString(enrolledCard +
			`<div class="card" id="enrollCard"` + enrollHidden + `><h2>Enroll new phone number</h2>` +
			`<p class="sub">Verify ownership via SMS, then grant voice access. Numbers you already enrolled stay active.</p>` +
			`<div class="row"><button id="enrollNew">Enroll new phone number</button></div></div>` +
			verifyCard(true) + grantCard +
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
      if(p.credential){
        const tag=document.createElement('span');
        tag.className='pill';
        tag.textContent=p.credential==='chatgpt_oauth'?'ChatGPT':'API key';
        li.appendChild(tag);
        li.appendChild(document.createTextNode(' '));
      }
      if(!p.active){
        const tag=document.createElement('span');
        tag.className='pill';
        tag.textContent='pending';
        li.appendChild(tag);
        li.appendChild(document.createTextNode(' '));
      }
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
if(new URLSearchParams(location.search).get('chatgpt')==='connected'){say('ChatGPT connected — set a voice PIN to finish.','ok');}
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
if(grant)grant.onclick=async()=>{say('Granting…');try{const ak=document.getElementById('apikey');await post('/api/grant',{api_key:ak?ak.value:'',pin:document.getElementById('pin').value});window.__verifiedPhone='';if(ak)ak.value='';const pk=document.getElementById('pin');if(pk)pk.value='';show(document.getElementById('grantCard'),false);show(document.getElementById('enrollCard'),true);say('Voice access granted.','ok');refreshEnrolled();}catch(e){say(e.message,'err');}};
</script></body></html>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}
