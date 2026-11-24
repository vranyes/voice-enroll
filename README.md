# voice-enroll

Self-service enrollment portal + internal directory for the voice call path.
Reference: `PLAN.md` in `~/personal/taskmaster` (auth + isolation sections).

## Flows

1. **Login** — Kanidm OIDC (`GET /login` → `GET /oauth/callback`), confidential
   code flow, consent prompt on, PKCE S256, `state`/`nonce`/verifier via secure cookies.
2. **Verify number** — `POST /api/otp/send {"phone"}` → Telnyx SMS 6-digit code
   (sha256 at rest, single-use, 10 min expiry, 5 guesses max, 5 sends/hour per
   number) → `POST /api/otp/verify {"phone","code"}`.
3. **Grant access** — `POST /api/grant {"api_key","pin"}` (login + verified
   number required). Key verified live against LibreChat, AES-GCM-encrypted
   under the sealed DEK, stored keyed by E.164 with the Kanidm `sub`. PIN is
   4-12 DTMF digits, AES-GCM-encrypted under the same DEK, never logged.
   `api_key` may be omitted when the number already has a ChatGPT OAuth
   credential (see 4): the call then only sets/replaces the PIN.
4. **Connect ChatGPT** — `GET /oauth/chatgpt/login` → OpenAI authorize
   (PKCE S256, `state`/verifier cookies) →
   `GET /oauth/chatgpt/callback` stores encrypted access/refresh tokens.
   Connecting before granting is allowed: it creates a *pending* row (no
   PIN) that `resolve` and `reveal=credential` deny until grant completes
   with a voice PIN. Re-granting a LibreChat key preserves the OAuth tokens.
5. **Internal resolve** — `GET :8082/resolve?phone=<e164>` (ClusterIP only,
   no auth — relies on cluster networking). Returns `{user_sub}`;
   `?reveal=key` adds `{api_key}`; `?reveal=credential` adds the preferred
   call credential (`{credential_kind:"chatgpt_oauth",access_token,...}` or
   `{credential_kind:"api_key",api_key}`). Rows without a PIN (pending)
   deny identically to unknown numbers.
6. **Internal PIN verify** — `POST :8082/verify-pin {"phone","pin"}`
   (ClusterIP only, same isolation). Returns `{user_sub}` on a match,
   404 `{error:deny}` otherwise. Unknown numbers, missing PINs, malformed
   input and wrong digits all deny identically — voice-bridge uses this to
   identify the caller per-enrollment (no global code).

Revocation: `GET /api/enrollments` lists the caller's own numbers;
`POST /api/revoke {"phone"}` deletes one entry (omitted = session's verified
number). Delete is `(phone, sub)`-scoped so users cannot remove each other's
numbers. Resolve reads PG live per request, so the next call denies. No
caches in this service.

## Develop (everything via make, same shape as voice-bridge)

```
make build test vet fmt test-race manifests
make ko      # local image build (publishes to $KO_DOCKER_REPO)
make push    # CI path: push :latest to ghcr.io/vranyes/voice-enroll
```

CI (`.github/workflows/build.yml`) runs the full suite on every push/PR and
pushes `:latest` on merge to main. Images are built with `ko` on the
chainguard static base (see `.ko.yaml`) — there is no Dockerfile.

## Layout

- `phone.go` — E.164 normalization (voice-bridge slice-4 semantics)
- `otp.go` — code lifecycle (hash/attempts/expiry/rate-limit)
- `pin.go` — voice PIN validation (4-12 digits) + constant-time verify
- `crypto.go` — AES-GCM DEK envelope
- `store.go` / `pg.go` — directory (memory for tests, cnpg for deploy)
- `verify.go` — live LibreChat key check + Telnyx SMS sender
- `chatgpt_oauth.go` — OpenAI/ChatGPT PKCE authorize, token exchange + refresh
- `oidc.go` — stdlib Kanidm OIDC (JWKS-verified RS256/ES256) + signed sessions
- `server.go` — public UI/API mux + internal resolve mux
- `config.go` — env config, fail-closed on missing secrets
- `cmd/voice-enroll` — dual-listener main
- `deploy/k8s` — manifests (Flux entry + secrets via OPERATOR.md)
