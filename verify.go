package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ErrInvalidKey marks a LibreChat key the server rejected (dead/revoked).
var ErrInvalidKey = errors.New("librechat rejected the key")

// VerifyLibreChatKey checks a pasted Remote Agents API key live before we
// store anything: GET <base>/api/agents/v1/models with
// `Authorization: Bearer <key>`. 200 means a live key with agent access;
// 401/403 means dead. Dead keys are rejected at grant time so a stored
// mapping always starts life valid; later deletion/revocation fails the next
// call closed at use time (fail-closed by construction in the caller).
//
// No key-authenticated "me" route exists in the published Agents API, so
// key-owner == session-sub cannot be enforced; the binding stays trust-based
// (see Enrollment).
func VerifyLibreChatKey(ctx context.Context, client *http.Client, baseURL, key string) error {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/agents/v1/models", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrInvalidKey
	default:
		return fmt.Errorf("librechat models: unexpected status %d", resp.StatusCode)
	}
}

// SMSSender transmits OTP codes. TelnyxSender is the deploy backend.
type SMSSender interface {
	SendSMS(ctx context.Context, from, to, text string) error
}

// TelnyxSender posts to the Telnyx v2 Messages API.
type TelnyxSender struct {
	Client  *http.Client
	APIKey  string
	BaseURL string // default https://api.telnyx.com/v2
}

func (s *TelnyxSender) SendSMS(ctx context.Context, from, to, text string) error {
	base := s.BaseURL
	if base == "" {
		base = "https://api.telnyx.com/v2"
	}
	body, _ := json.Marshal(map[string]string{"from": from, "to": to, "text": text})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/messages", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.APIKey)
	req.Header.Set("Content-Type", "application/json")
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("telnyx messages: unexpected status %d", resp.StatusCode)
	}
	return nil
}
