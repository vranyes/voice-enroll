package enroll

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyKeyAgainstFakeLibreChat(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agents/v1/models" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") == "Bearer live-key" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer fake.Close()

	if err := VerifyLibreChatKey(context.Background(), fake.Client(), fake.URL, "live-key"); err != nil {
		t.Fatalf("live key rejected: %v", err)
	}
	if err := VerifyLibreChatKey(context.Background(), fake.Client(), fake.URL, "dead-key"); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("dead key: got %v, want ErrInvalidKey", err)
	}
}

func TestVerifyKeyServerErrorIsNotInvalidKey(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer fake.Close()
	err := VerifyLibreChatKey(context.Background(), fake.Client(), fake.URL, "k")
	if errors.Is(err, ErrInvalidKey) {
		t.Fatal("5xx misclassified as invalid key (would wrongly reject live keys during outages)")
	}
	if err == nil {
		t.Fatal("5xx returned nil error")
	}
}

func TestTelnyxSenderShape(t *testing.T) {
	var gotAuth, gotCT string
	var gotBody map[string]string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotCT = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer fake.Close()

	s := &TelnyxSender{Client: fake.Client(), APIKey: "tel-key", BaseURL: fake.URL}
	if err := s.SendSMS(context.Background(), "+15550001111", "+15550109999", "code 123456"); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tel-key" {
		t.Fatalf("auth header %q", gotAuth)
	}
	if gotCT != "application/json" {
		t.Fatalf("content-type %q", gotCT)
	}
	if gotBody["from"] != "+15550001111" || gotBody["to"] != "+15550109999" || gotBody["text"] == "" {
		t.Fatalf("body %v", gotBody)
	}
	// Plaintext code travels only in the SMS body; assert the sender never
	// logs it by construction (no log calls exist on this path — compile-time
	// property, documented here).
}

func TestTelnyxSenderFailure(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))
	defer fake.Close()
	s := &TelnyxSender{Client: fake.Client(), APIKey: "k", BaseURL: fake.URL}
	if err := s.SendSMS(context.Background(), "+1", "+2", "x"); err == nil {
		t.Fatal("4xx send returned nil")
	}
}
