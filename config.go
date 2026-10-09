package enroll

import (
	"encoding/base64"
	"errors"
	"os"
	"time"
)

// Config is the full service config. Secrets arrive via env from a
// SealedSecret; nothing secret has a default.
type Config struct {
	Addr         string // public browser + API listener, e.g. :8080
	InternalAddr string // ClusterIP-only resolve listener, e.g. :8082

	PublicBaseURL string // e.g. https://enroll.vranyes.com (OIDC redirect + SMS copy)
	DatabaseURL   string

	DEK           []byte // 32-byte base64 AES-GCM key for LibreChat keys
	SessionSecret []byte // >=32-byte base64 HMAC key for login cookies

	EdgeSecret       string // bearer for phone->user resolve (voice-bridge)
	TaskmasterSecret string // bearer for phone->key resolve (taskmaster only)

	OIDC          OIDCConfig
	TelnyxKey     string
	TelnyxSender  string // E.164 sender number for OTP SMS
	LibreChatBase string // e.g. https://librechat.vranyes.com

	SessionTTL time.Duration
}

func getenv(k string) string { return os.Getenv(k) }

// LoadConfig reads env. Missing secrets are hard errors at startup
// (fail-closed: the service never runs half-configured).
func LoadConfig() (Config, error) {
	var c Config
	c.Addr = getenv("ENROLL_ADDR")
	if c.Addr == "" {
		c.Addr = ":8080"
	}
	c.InternalAddr = getenv("ENROLL_INTERNAL_ADDR")
	if c.InternalAddr == "" {
		c.InternalAddr = ":8082"
	}
	c.PublicBaseURL = getenv("ENROLL_PUBLIC_BASE_URL")
	c.DatabaseURL = getenv("DATABASE_URL")
	c.LibreChatBase = getenv("LIBRECHAT_BASE_URL")
	c.TelnyxKey = getenv("TELNYX_API_KEY")
	c.TelnyxSender = getenv("TELNYX_SENDER_NUMBER")
	c.EdgeSecret = getenv("RESOLVE_EDGE_SECRET")
	c.TaskmasterSecret = getenv("RESOLVE_TASKMASTER_SECRET")

	dek, err := base64.StdEncoding.DecodeString(getenv("ENROLL_DEK_B64"))
	if err != nil || len(dek) != 32 {
		return c, errors.New("ENROLL_DEK_B64 must be base64 of 32 bytes")
	}
	c.DEK = dek
	ss, err := base64.StdEncoding.DecodeString(getenv("ENROLL_SESSION_SECRET_B64"))
	if err != nil || len(ss) < 32 {
		return c, errors.New("ENROLL_SESSION_SECRET_B64 must be base64 of >= 32 bytes")
	}
	c.SessionSecret = ss

	c.OIDC = OIDCConfig{
		Issuer:       getenv("KANIDM_ISSUER"),
		ClientID:     getenv("KANIDM_CLIENT_ID"),
		ClientSecret: getenv("KANIDM_CLIENT_SECRET"),
		RedirectURL:  getenv("KANIDM_REDIRECT_URL"),
	}
	if c.OIDC.Issuer == "" || c.OIDC.ClientID == "" || c.OIDC.ClientSecret == "" || c.OIDC.RedirectURL == "" {
		return c, errors.New("KANIDM_ISSUER/CLIENT_ID/CLIENT_SECRET/REDIRECT_URL all required")
	}
	if c.PublicBaseURL == "" || c.DatabaseURL == "" || c.LibreChatBase == "" {
		return c, errors.New("ENROLL_PUBLIC_BASE_URL/DATABASE_URL/LIBRECHAT_BASE_URL all required")
	}
	if c.TelnyxKey == "" || c.TelnyxSender == "" {
		return c, errors.New("TELNYX_API_KEY/TELNYX_SENDER_NUMBER required")
	}
	if c.EdgeSecret == "" || c.TaskmasterSecret == "" {
		return c, errors.New("RESOLVE_EDGE_SECRET/RESOLVE_TASKMASTER_SECRET required")
	}
	if c.EdgeSecret == c.TaskmasterSecret {
		return c, errors.New("edge and taskmaster resolve secrets must differ")
	}
	c.SessionTTL = 12 * time.Hour
	return c, nil
}
