package enroll

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OIDCConfig is the Kanidm confidential-client login config. Values arrive
// via env (client secret sealed). The consent prompt stays enabled: the user
// must explicitly approve the voice-enroll client at login.
type OIDCConfig struct {
	Issuer       string // e.g. https://auth.vranyes.com/oauth2/openid/voice-enroll
	ClientID     string
	ClientSecret string
	RedirectURL  string // e.g. https://enroll.vranyes.com/oauth/callback
	HTTPClient   *http.Client
}

type discoveryDoc struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

func (c OIDCConfig) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (c OIDCConfig) discover(ctx context.Context) (*discoveryDoc, error) {
	issuer := strings.TrimSuffix(c.Issuer, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery: status %d", resp.StatusCode)
	}
	var d discoveryDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return nil, err
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, errors.New("oidc discovery: missing endpoints")
	}
	return &d, nil
}

// NewCodeVerifier generates an RFC 7636 code verifier: 32 random bytes as
// 43 base64url chars (valid charset, no padding).
func NewCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CodeChallengeS256 returns BASE64URL-ENCODE(SHA256(verifier)) per RFC 7636.
func CodeChallengeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// LoginURL builds the Kanidm authorization URL with PKCE S256. state and
// nonce are caller generated (crypto random, hex) and round-tripped via
// secure cookies; verifier is the PKCE verifier (challenge derived here).
func (c OIDCConfig) LoginURL(ctx context.Context, state, nonce, verifier string) (string, error) {
	d, err := c.discover(ctx)
	if err != nil {
		return "", err
	}
	q := url.Values{
		"client_id":             {c.ClientID},
		"redirect_uri":          {c.RedirectURL},
		"response_type":         {"code"},
		"scope":                 {"openid email profile"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {CodeChallengeS256(verifier)},
		"code_challenge_method": {"S256"},
	}
	return d.AuthorizationEndpoint + "?" + q.Encode(), nil
}

// Exchange trades the authorization code for tokens and returns the verified
// id_token subject plus the access token for userinfo. verifier is the PKCE
// verifier round-tripped via cookie; Kanidm requires it (S256).
func (c OIDCConfig) Exchange(ctx context.Context, code, wantNonce, verifier string) (sub, accessToken string, err error) {
	if verifier == "" {
		return "", "", errors.New("oidc: missing PKCE verifier")
	}
	d, err := c.discover(ctx)
	if err != nil {
		return "", "", err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.RedirectURL},
		"client_id":     {c.ClientID},
		"client_secret": {c.ClientSecret},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.client().Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("oidc token: status %d", resp.StatusCode)
	}
	var tok struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return "", "", err
	}
	if tok.IDToken == "" {
		return "", "", errors.New("oidc token: no id_token")
	}
	sub, err = c.verifyIDToken(ctx, d, tok.IDToken, wantNonce)
	if err != nil {
		return "", "", err
	}
	return sub, tok.AccessToken, nil
}

// verifyIDToken checks signature (RS256 via JWKS), iss, aud, exp and nonce.
func (c OIDCConfig) verifyIDToken(ctx context.Context, d *discoveryDoc, raw, wantNonce string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", errors.New("oidc: malformed id_token")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	hd, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hd, &header) != nil {
		return "", errors.New("oidc: bad id_token header")
	}
	if header.Alg != "RS256" {
		return "", fmt.Errorf("oidc: unexpected alg %q", header.Alg)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("oidc: bad id_token payload")
	}
	var claims struct {
		Iss   string `json:"iss"`
		Sub   string `json:"sub"`
		Aud   any    `json:"aud"`
		Exp   int64  `json:"exp"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", errors.New("oidc: bad id_token claims")
	}
	issuer := strings.TrimSuffix(c.Issuer, "/")
	if claims.Iss != issuer {
		return "", errors.New("oidc: iss mismatch")
	}
	if !audContains(claims.Aud, c.ClientID) {
		return "", errors.New("oidc: aud mismatch")
	}
	if time.Unix(claims.Exp, 0).Before(time.Now().Add(-30 * time.Second)) {
		return "", errors.New("oidc: id_token expired")
	}
	if wantNonce != "" && subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(wantNonce)) != 1 {
		return "", errors.New("oidc: nonce mismatch")
	}
	if claims.Sub == "" {
		return "", errors.New("oidc: empty sub")
	}
	pub, err := c.fetchKey(ctx, d.JWKSURI, header.Kid)
	if err != nil {
		return "", err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", errors.New("oidc: bad signature")
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
		return "", errors.New("oidc: invalid signature")
	}
	return claims.Sub, nil
}

func audContains(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, v := range a {
			if s, ok := v.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

type jwksDoc struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func (c OIDCConfig) fetchKey(ctx context.Context, jwksURI, kid string) (*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var doc jwksDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	for _, k := range doc.Keys {
		if k.Kid != kid || k.Kty != "RSA" {
			continue
		}
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		e := 0
		for _, b := range eb {
			e = e<<8 + int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
	}
	return nil, errors.New("oidc: signing key not found")
}

// UserInfoSub fetches userinfo as a cross-check that the access token is
// live. The id_token sub remains authoritative for identity.
func (c OIDCConfig) UserInfoSub(ctx context.Context, accessToken string) (string, error) {
	d, err := c.discover(ctx)
	if err != nil {
		return "", err
	}
	if d.UserinfoEndpoint == "" {
		return "", errors.New("oidc: no userinfo endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.UserinfoEndpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := c.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc userinfo: status %d", resp.StatusCode)
	}
	var u struct {
		Sub string `json:"sub"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&u); err != nil {
		return "", err
	}
	return u.Sub, nil
}

// Session is the login state carried in a signed cookie.
type Session struct {
	Sub           string
	VerifiedPhone string // E.164 proven by OTP this login, "" until verified
	ExpiresAt     time.Time
}

// SessionCodec signs/verifies cookies with HMAC-SHA256. Cookies are Secure,
// HttpOnly, SameSite=Lax; the value carries no secrets (sub + phone only).
type SessionCodec struct{ secret []byte }

func NewSessionCodec(secret []byte) (*SessionCodec, error) {
	if len(secret) < 32 {
		return nil, errors.New("session secret must be >= 32 bytes")
	}
	return &SessionCodec{secret: secret}, nil
}

func (s *SessionCodec) Encode(sess Session) string {
	payload := sess.Sub + "\n" + sess.VerifiedPhone + "\n" + fmt.Sprint(sess.ExpiresAt.Unix())
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(sig)
}

func (s *SessionCodec) Decode(cookie string, now time.Time) (Session, error) {
	var zero Session
	parts := strings.Split(cookie, ".")
	if len(parts) != 2 {
		return zero, errors.New("bad session cookie")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return zero, errors.New("bad session cookie")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return zero, errors.New("bad session cookie")
	}
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(pb)
	if subtle.ConstantTimeCompare(mac.Sum(nil), sig) != 1 {
		return zero, errors.New("bad session signature")
	}
	fields := strings.SplitN(string(pb), "\n", 3)
	if len(fields) != 3 {
		return zero, errors.New("bad session payload")
	}
	var exp int64
	if _, err := fmt.Sscan(fields[2], &exp); err != nil {
		return zero, errors.New("bad session expiry")
	}
	sess := Session{Sub: fields[0], VerifiedPhone: fields[1], ExpiresAt: time.Unix(exp, 0)}
	if sess.Sub == "" || now.After(sess.ExpiresAt) {
		return zero, errors.New("session expired")
	}
	return sess, nil
}
