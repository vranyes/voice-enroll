package enroll

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
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
}

func NewServer(store Store, oidc OIDCConfig, sessions *SessionCodec, keys *Key, sms SMSSender, smsFrom, libreChat string) *Server {
	return &Server{
		store: store, oidc: oidc, sessions: sessions, keys: keys,
		sms: sms, smsFrom: smsFrom, libreChat: libreChat,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		now:        time.Now,
		sessionTTL: 12 * time.Hour,
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
	m.HandleFunc("POST /api/revoke", s.handleRevoke)
	return m
}

func (s *Server) InternalMux() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	m.HandleFunc("GET /resolve", s.handleResolve)
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
	// Plaintext code goes only into the SMS body; never logged.
	if err := s.sms.SendSMS(r.Context(), s.smsFrom, phone, "Your voice enrollment code is "+code+". It expires in 10 minutes."); err != nil {
		log.Printf("otp send failed sub=%s", hashID(sess.Sub))
		http.Error(w, "send failed", http.StatusBadGateway)
		return
	}
	log.Printf("otp sent sub=%s", hashID(sess.Sub))
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
	if err := s.store.UpsertEnrollment(r.Context(), Enrollment{
		Phone: phoneOf(sess), UserSub: sess.Sub,
		EncKey: ct, Nonce: nonce, VerifiedAt: s.now(),
	}); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	log.Printf("grant stored sub=%s", hashID(sess.Sub))
	w.WriteHeader(http.StatusCreated)
}

func phoneOf(sess Session) string { return sess.VerifiedPhone }

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(r)
	if !ok || sess.VerifiedPhone == "" {
		http.Error(w, "login and verified number required", http.StatusUnauthorized)
		return
	}
	okDeleted, err := s.store.DeleteEnrollment(r.Context(), sess.VerifiedPhone, sess.Sub)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	// Deleting the mapping fails subsequent calls closed: resolve reads PG
	// live per request (no cache in this service), so the next lookup 404s
	// and the edge denies. LibreChat-key deletion likewise fails closed at
	// use time when the caller presents the now-dead key.
	log.Printf("revoke sub=%s deleted=%v", hashID(sess.Sub), okDeleted)
	w.WriteHeader(http.StatusOK)
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
		plain, err := s.keys.Decrypt(e.Nonce, e.EncKey)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		out["api_key"] = string(plain)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
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
		`</style></head><body><main><h1>Voice enrollment</h1>` +
		`<p class="sub">Verify a number, then grant it voice access.</p>` +
		`<p id="status" role="status"></p>`)
	if !loggedIn {
		b.WriteString(`<div class="card"><h2>Step 1 — Log in</h2>` +
			`<p class="sub">Kanidm confirms who you are.</p>` +
			`<div class="row"><a class="btn" href="/login">Log in with Kanidm</a></div></div>`)
	} else if sess.VerifiedPhone == "" {
		b.WriteString(`<div class="card"><h2>Step 2 — Verify your number</h2>` +
			`<label for="phone">Phone number</label>` +
			`<input id="phone" type="tel" inputmode="tel" autocomplete="tel" placeholder="+15550109999">` +
			`<div class="row"><button id="send">Send code</button></div>` +
			`<label for="code">6-digit code from SMS</label>` +
			`<input id="code" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" maxlength="6">` +
			`<div class="row"><button id="verify">Verify</button></div></div>` +
			`<div class="row"><form method="post" action="/logout"><button class="secondary" type="submit">Log out</button></form></div>`)
	} else {
		b.WriteString(`<div class="card"><h2>Step 2 — Number verified</h2><p><span class="pill">` +
			html.EscapeString(sess.VerifiedPhone) + `</span></p></div>` +
			`<div class="card"><h2>Step 3 — Grant voice access</h2>` +
			`<p class="sub">Paste a LibreChat Remote Agents API key. Verified live, stored encrypted.</p>` +
			`<label for="apikey">LibreChat API key</label>` +
			`<input id="apikey" type="password" autocomplete="off" placeholder="lc-…">` +
			`<div class="row"><button id="grant">Grant access</button>` +
			`<button id="revoke" class="secondary">Revoke access</button></div></div>` +
			`<div class="row"><form method="post" action="/logout"><button class="secondary" type="submit">Log out</button></form></div>`)
	}
	b.WriteString(`</main><script>
const status=document.getElementById('status');
function say(msg,cls){if(!status)return;status.textContent=msg;status.className=cls||'';}
async function post(url,body){
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(!r.ok){let t='';try{t=await r.text();}catch(e){}throw new Error(t||('request failed: '+r.status));}
  return r;
}
function phoneVal(){const el=document.getElementById('phone');return el?el.value:'';}
const send=document.getElementById('send');
if(send)send.onclick=async()=>{say('Sending…');try{await post('/api/otp/send',{phone:phoneVal()});say('Code sent — check SMS.','ok');}catch(e){say(e.message,'err');}};
const verify=document.getElementById('verify');
if(verify)verify.onclick=async()=>{say('Verifying…');try{const c=document.getElementById('code').value;await post('/api/otp/verify',{phone:phoneVal(),code:c});say('Verified.','ok');location.reload();}catch(e){say(e.message,'err');}};
const grant=document.getElementById('grant');
if(grant)grant.onclick=async()=>{say('Verifying key…');try{await post('/api/grant',{api_key:document.getElementById('apikey').value});say('Voice access granted.','ok');}catch(e){say(e.message,'err');}};
const revoke=document.getElementById('revoke');
if(revoke)revoke.onclick=async()=>{say('Revoking…');try{await post('/api/revoke',{});say('Access revoked.','ok');}catch(e){say(e.message,'err');}};
</script></body></html>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}
