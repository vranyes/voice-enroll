package enroll

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	ChatGPTClientID     = "app_EMoamEEZ73f0CkXaXp7hrann"
	ChatGPTIssuer       = "https://auth.openai.com"
	ChatGPTAuthorizeURL = ChatGPTIssuer + "/oauth/authorize"
	ChatGPTTokenURL     = ChatGPTIssuer + "/oauth/token"
	ChatGPTScopes       = "openid profile email offline_access"
	ChatGPTRedirectPath = "/oauth/chatgpt/callback"
)

type ChatGPTTokens struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresAt    time.Time
	AccountID    string
}

type ChatGPTTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
}

func ChatGPTRedirectURL(publicBaseURL string) string {
	return strings.TrimRight(publicBaseURL, "/") + ChatGPTRedirectPath
}

func ChatGPTLoginURL(state, nonce, verifier, redirectURI string) (string, error) {
	challenge := CodeChallengeS256(verifier)
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", ChatGPTClientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("scope", ChatGPTScopes)
	v.Set("code_challenge", challenge)
	v.Set("code_challenge_method", "S256")
	v.Set("state", state)
	v.Set("nonce", nonce)
	v.Set("id_token_add_organizations", "true")
	v.Set("codex_cli_simplified_flow", "true")
	v.Set("originator", "voice-enroll")
	return ChatGPTAuthorizeURL + "?" + v.Encode(), nil
}

func ExchangeChatGPTCode(ctx context.Context, hc *http.Client, code, verifier, redirectURI string) (ChatGPTTokens, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", ChatGPTClientID)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)
	return postChatGPTToken(ctx, hc, form, "")
}

func RefreshChatGPTToken(ctx context.Context, hc *http.Client, refreshToken string) (ChatGPTTokens, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", ChatGPTClientID)
	return postChatGPTToken(ctx, hc, form, refreshToken)
}

func postChatGPTToken(ctx context.Context, hc *http.Client, form url.Values, fallbackRefresh string) (ChatGPTTokens, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ChatGPTTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return ChatGPTTokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return ChatGPTTokens{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return ChatGPTTokens{}, fmt.Errorf("chatgpt token: %s", resp.Status)
	}
	var tr ChatGPTTokenResponse
	if err := json.Unmarshal(raw, &tr); err != nil {
		return ChatGPTTokens{}, err
	}
	if tr.AccessToken == "" {
		return ChatGPTTokens{}, errors.New("chatgpt token: missing access_token")
	}
	rt := tr.RefreshToken
	if rt == "" {
		rt = fallbackRefresh
	}
	exp := time.Now().Add(55 * time.Minute)
	if tr.ExpiresIn > 0 {
		exp = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	acct := chatGPTAccountIDFromJWT(tr.IDToken)
	if acct == "" {
		acct = chatGPTAccountIDFromJWT(tr.AccessToken)
	}
	return ChatGPTTokens{
		AccessToken:  tr.AccessToken,
		RefreshToken: rt,
		IDToken:      tr.IDToken,
		ExpiresAt:    exp,
		AccountID:    acct,
	}, nil
}

func chatGPTAccountIDFromJWT(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	// Common claim shapes observed in ChatGPT/OpenAI tokens.
	if v, ok := claims["chatgpt_account_id"].(string); ok && v != "" {
		return v
	}
	if v, ok := claims["https://api.openai.com/auth"].(map[string]any); ok {
		if id, ok := v["chatgpt_account_id"].(string); ok && id != "" {
			return id
		}
		if ids, ok := v["chatgpt_account_ids"].([]any); ok && len(ids) > 0 {
			if id, ok := ids[0].(string); ok {
				return id
			}
		}
	}
	if v, ok := claims["sub"].(string); ok && v != "" {
		return v
	}
	return ""
}
