# voice-enroll

Self-service enrollment portal + internal directory for the voice call path.
Reference: `PLAN.md` in `~/personal/taskmaster` (auth + isolation sections).

## Flows

1. **Login** — Kanidm OIDC (`GET /login` → `GET /oauth/callback`), confidential
   code flow, consent prompt on, `state`/`nonce` via secure cookies.
2. **Verify number** — `POST /api/otp/send {"phone"}` → Telnyx SMS 6-digit code
   (sha256 at rest, single-use, 10 min expiry, 5 guesses max, 5 sends/hour per
   number) → `POST /api/otp/verify {"phone","code"}`.
3. **Grant access** — `POST /api/grant {"api_key"}` (login + verified number
   required). Key verified live against LibreChat, AES-GCM-encrypted under the
   sealed DEK, stored keyed by E.164 with the Kanidm `sub`.
4. **Internal resolve** — `GET :8082/resolve?phone=<e164>` (ClusterIP only,
   dual shared secrets). Edge gets `{user_sub}`; taskmaster adds
   `?reveal=key` for `{user_sub, api_key}`. Unknown numbers deny identically
   to unenrolled ones.

Revocation: `POST /api/revoke` deletes the mapping; resolve reads PG live per
request, so the next call denies. No caches in this service.

## Develop

```
go test -race ./...   # httptest-backed: OTP/attempt-limit, resolve authz
go vet ./...          # (edge-never-gets-key is asserted explicitly)
gofmt -l .
kustomize build deploy/k8s
```

## Layout

- `phone.go` — E.164 normalization (voice-bridge slice-4 semantics)
- `otp.go` — code lifecycle (hash/attempts/expiry/rate-limit)
- `crypto.go` — AES-GCM DEK envelope
- `store.go` / `pg.go` — directory (memory for tests, cnpg for deploy)
- `verify.go` — live LibreChat key check + Telnyx SMS sender
- `oidc.go` — stdlib Kanidm OIDC (JWKS-verified RS256) + signed sessions
- `server.go` — public UI/API mux + internal resolve mux
- `config.go` — env config, fail-closed on missing secrets
- `cmd/voice-enroll` — dual-listener main
- `deploy/k8s` — manifests (Flux entry + secrets via OPERATOR.md)
