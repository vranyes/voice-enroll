package enroll

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGStore is the deploy backend: the cnpg Postgres directory.
type PGStore struct{ pool *pgxpool.Pool }

// NewPGStore connects and migrates. Tables are created idempotently so
// first boot self-initializes.
func NewPGStore(ctx context.Context, databaseURL string) (*PGStore, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	s := &PGStore{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

func (s *PGStore) Close() { s.pool.Close() }

func (s *PGStore) migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS enrollments (
  phone       TEXT PRIMARY KEY,
  user_sub    TEXT NOT NULL,
  enc_key     BYTEA NOT NULL,
  nonce       BYTEA NOT NULL,
  verified_at TIMESTAMPTZ NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE enrollments ADD COLUMN IF NOT EXISTS enc_pin BYTEA;
ALTER TABLE enrollments ADD COLUMN IF NOT EXISTS pin_nonce BYTEA;
ALTER TABLE enrollments ALTER COLUMN enc_key DROP NOT NULL;
ALTER TABLE enrollments ALTER COLUMN nonce DROP NOT NULL;
ALTER TABLE enrollments ADD COLUMN IF NOT EXISTS enc_chatgpt_refresh BYTEA;
ALTER TABLE enrollments ADD COLUMN IF NOT EXISTS chatgpt_refresh_nonce BYTEA;
ALTER TABLE enrollments ADD COLUMN IF NOT EXISTS enc_chatgpt_access BYTEA;
ALTER TABLE enrollments ADD COLUMN IF NOT EXISTS chatgpt_access_nonce BYTEA;
ALTER TABLE enrollments ADD COLUMN IF NOT EXISTS chatgpt_expires_at TIMESTAMPTZ;
ALTER TABLE enrollments ADD COLUMN IF NOT EXISTS chatgpt_account_id TEXT;
CREATE TABLE IF NOT EXISTS otp_codes (
  phone        TEXT PRIMARY KEY,
  code_hash    BYTEA NOT NULL,
  expires_at   TIMESTAMPTZ NOT NULL,
  attempts     INT NOT NULL DEFAULT 0,
  used         BOOLEAN NOT NULL DEFAULT FALSE,
  send_count   INT NOT NULL DEFAULT 0,
  window_start TIMESTAMPTZ NOT NULL
);`)
	return err
}

func (s *PGStore) GetOTP(phone string) (*OTPRecord, error) {
	ctx := context.Background()
	var r OTPRecord
	var hash []byte
	err := s.pool.QueryRow(ctx, `SELECT code_hash, expires_at, attempts, used, send_count, window_start
FROM otp_codes WHERE phone=$1`, phone).Scan(&hash, &r.ExpiresAt, &r.Attempts, &r.Used, &r.SendCount, &r.WindowStart)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(hash) == 32 {
		copy(r.CodeHash[:], hash)
	}
	return &r, nil
}

func (s *PGStore) PutOTP(phone string, rec OTPRecord) error {
	_, err := s.pool.Exec(context.Background(), `
INSERT INTO otp_codes (phone, code_hash, expires_at, attempts, used, send_count, window_start)
VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (phone) DO UPDATE SET
  code_hash=EXCLUDED.code_hash, expires_at=EXCLUDED.expires_at,
  attempts=EXCLUDED.attempts, used=EXCLUDED.used,
  send_count=EXCLUDED.send_count, window_start=EXCLUDED.window_start`,
		phone, rec.CodeHash[:], rec.ExpiresAt, rec.Attempts, rec.Used, rec.SendCount, rec.WindowStart)
	return err
}

func (s *PGStore) UpsertEnrollment(ctx context.Context, e Enrollment) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO enrollments (phone, user_sub, enc_key, nonce, enc_pin, pin_nonce, verified_at,
  enc_chatgpt_refresh, chatgpt_refresh_nonce, enc_chatgpt_access, chatgpt_access_nonce, chatgpt_expires_at, chatgpt_account_id, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,now())
ON CONFLICT (phone) DO UPDATE SET
  user_sub=EXCLUDED.user_sub, enc_key=EXCLUDED.enc_key, nonce=EXCLUDED.nonce,
  enc_pin=EXCLUDED.enc_pin, pin_nonce=EXCLUDED.pin_nonce,
  verified_at=EXCLUDED.verified_at,
  enc_chatgpt_refresh=EXCLUDED.enc_chatgpt_refresh, chatgpt_refresh_nonce=EXCLUDED.chatgpt_refresh_nonce,
  enc_chatgpt_access=EXCLUDED.enc_chatgpt_access, chatgpt_access_nonce=EXCLUDED.chatgpt_access_nonce,
  chatgpt_expires_at=EXCLUDED.chatgpt_expires_at, chatgpt_account_id=EXCLUDED.chatgpt_account_id,
  updated_at=now()`,
		e.Phone, e.UserSub, e.EncKey, e.Nonce, e.EncPIN, e.PINNonce, e.VerifiedAt,
		e.EncChatGPTRefresh, e.ChatGPTRefreshNonce, e.EncChatGPTAccess, e.ChatGPTAccessNonce, nullTime(e.ChatGPTExpiresAt), e.ChatGPTAccountID)
	return err
}

func (s *PGStore) UpdateChatGPTTokens(ctx context.Context, phone, sub string, encRefresh, refreshNonce, encAccess, accessNonce []byte, expiresAt time.Time, accountID string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
UPDATE enrollments SET
  enc_chatgpt_refresh=$3, chatgpt_refresh_nonce=$4,
  enc_chatgpt_access=$5, chatgpt_access_nonce=$6,
  chatgpt_expires_at=$7,
  chatgpt_account_id=COALESCE(NULLIF($8,''), chatgpt_account_id),
  updated_at=now()
WHERE phone=$1 AND user_sub=$2`,
		phone, sub, encRefresh, refreshNonce, encAccess, accessNonce, nullTime(expiresAt), accountID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *PGStore) UpdateKeyAndPIN(ctx context.Context, phone, sub string, encKey, keyNonce, encPIN, pinNonce []byte, verifiedAt time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
UPDATE enrollments SET
  enc_key=$3, nonce=$4, enc_pin=$5, pin_nonce=$6, verified_at=$7, updated_at=now()
WHERE phone=$1 AND user_sub=$2`,
		phone, sub, encKey, keyNonce, encPIN, pinNonce, verifiedAt)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *PGStore) UpdatePIN(ctx context.Context, phone, sub string, encPIN, pinNonce []byte, verifiedAt time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
UPDATE enrollments SET enc_pin=$3, pin_nonce=$4, verified_at=$5, updated_at=now()
WHERE phone=$1 AND user_sub=$2`,
		phone, sub, encPIN, pinNonce, verifiedAt)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *PGStore) GetByPhone(ctx context.Context, phone string) (*Enrollment, error) {
	var e Enrollment
	var expiresAt *time.Time
	err := s.pool.QueryRow(ctx, `SELECT phone, user_sub, enc_key, nonce, enc_pin, pin_nonce, verified_at,
  enc_chatgpt_refresh, chatgpt_refresh_nonce, enc_chatgpt_access, chatgpt_access_nonce, chatgpt_expires_at, chatgpt_account_id
FROM enrollments WHERE phone=$1`, phone).Scan(
		&e.Phone, &e.UserSub, &e.EncKey, &e.Nonce, &e.EncPIN, &e.PINNonce, &e.VerifiedAt,
		&e.EncChatGPTRefresh, &e.ChatGPTRefreshNonce, &e.EncChatGPTAccess, &e.ChatGPTAccessNonce, &expiresAt, &e.ChatGPTAccountID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if expiresAt != nil {
		e.ChatGPTExpiresAt = *expiresAt
	}
	return &e, nil
}

func (s *PGStore) ListBySub(ctx context.Context, sub string) ([]Enrollment, error) {
	rows, err := s.pool.Query(ctx, `SELECT phone, user_sub, verified_at FROM enrollments WHERE user_sub=$1 ORDER BY phone`, sub)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Enrollment
	for rows.Next() {
		var e Enrollment
		if err := rows.Scan(&e.Phone, &e.UserSub, &e.VerifiedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *PGStore) DeleteEnrollment(ctx context.Context, phone, sub string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM enrollments WHERE phone=$1 AND user_sub=$2`, phone, sub)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
