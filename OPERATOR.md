# voice-enroll — operator runbook

Self-service enrollment portal + internal directory for the voice call path.
Users log in via Kanidm, prove a phone number via Telnyx SMS OTP, and grant
voice access by pasting a LibreChat Remote Agents API key (verified live) or
connecting their ChatGPT account via OpenAI OAuth (tokens from the provider's
code exchange; all secrets stored AES-GCM-encrypted in Postgres).

> OAuth-grant spike (2026-10-12, reverted): storing Kanidm bearer material at
> grant time instead of a pasted PAT was attempted and removed. The Kanidm
> tokens themselves validate fine against LibreChat's Remote Agents OIDC
> auth, but LibreChat (v0.8.8) binds remote-API users to the token issuer
> (`findOpenIDUser` matches `openidId` + `openidIssuer`), and Kanidm mints a
> distinct issuer per OAuth2 client. Voice-enroll-app tokens can therefore
> never match users created via the librechat-app login — every grant failed
> with `[remoteAgentAuth] OIDC token valid but no matching LibreChat user`.
> Do not retry without multi-issuer trust in LibreChat's remoteApi OIDC
> (upstream feature request). Kanidm's lack of offline sessions (#4034) is a
> second, independent blocker for the same idea.

## Values the operator must supply (nothing works without all of these)

| Key | Where | How to get it |
|---|---|---|
| `DATABASE_URL` | SealedSecret `voice-enroll-secrets` | `postgresql://enroll:<pw>@voice-enroll-pg-rw.voice-enroll.svc:5432/voiceenroll?sslmode=verify-ca&sslrootcert=/run/secrets/pg-ca.crt`, pw = the sealed pg password |
| `ENROLL_DEK_B64` | same | `head -c32 /dev/urandom \| base64` (32-byte AES-GCM DEK; rotate = re-enroll all users) |
| `ENROLL_SESSION_SECRET_B64` | same | `head -c32 /dev/urandom \| base64` (HMAC key for login cookies) |
| `KANIDM_CLIENT_SECRET` | same | created by kaniop for `KanidmOAuth2Client/voice-enroll-app` — read the generated Secret after apply, seal it here |
| `TELNYX_API_KEY` | same | Telnyx portal → API keys (programmable SMS must be enabled on the account) |
| `TELNYX_SENDER_NUMBER` | same | E.164 DID from the Telnyx account used as the OTP sender |
| `ENROLL_PUBLIC_BASE_URL` | `deploy/k8s/deployment.yaml` | public origin (`https://enroll.vranyes.com`); used for the Kanidm redirect and the ChatGPT OAuth redirect |
| pg `username`/`password` | SealedSecret `voice-enroll-pg-credentials` | operator-chosen; `username` must be `enroll`, must match `DATABASE_URL` |

Seal with the command in `deploy/k8s/sealedsecret-app.yaml.example`, then add
both `sealedsecret-*.yaml` to `kustomization.yaml` resources.

## Deploy order

1. `kubectl apply -k deploy/k8s` minus secrets (namespace, cluster, oauth2client, deployment will CrashLoop until secrets exist — fail-closed by design).
2. Wait for kaniop to reconcile `voice-enroll-app`; confirm the client exists in Kanidm.
3. Seal + apply both SealedSecrets; add to kustomization; re-apply.
4. Add Flux entry (`deploy/apps/voice-enroll.yaml` in gitops) + image policy note below.

## Image publishing

Images are built with `ko` in CI (`.github/workflows/build.yml`, driven by
`make push`) and published to `ghcr.io/vranyes/voice-enroll:latest` on every
merge to main. A `:latest` image already exists in GHCR (verified
2026-10-08 via local `make ko`). No Dockerfile — `ko` builds from Go source
directly onto the chainguard static base (`.ko.yaml`).

The deployment carries the `# {"$imagepolicy": "flux-system:voice-enroll"}`
annotation, so once Flux image-automation is configured it pins digests the
same way taskmaster/voice-bridge do.

## ChatGPT OAuth credentials

Enrollments may carry an OpenAI ChatGPT OAuth credential instead of (or in
addition to) the pasted LibreChat key. The UI offers it on the grant card
after SMS verification:

1. `GET /oauth/chatgpt/login` builds the OpenAI authorize URL with PKCE S256
   and `state`/verifier cookies, then redirects.
2. `GET /oauth/chatgpt/callback` exchanges the code and stores the encrypted
   access/refresh tokens. If no enrollment exists yet, it creates a pending
   row (no PIN) owned by the OTP-verified session; `resolve` and
   `reveal=credential` deny pending rows.
3. `POST /api/grant {"pin"}` (no `api_key`) completes the pending row.

`ENROLL_PUBLIC_BASE_URL` builds the redirect URI
(`<base>/oauth/chatgpt/callback`). `reveal=credential` returns the OAuth
credential when present, refreshing it on reveal and persisting rotations;
a dead refresh token denies like an unknown number. The access/refresh tokens
are encrypted under the same DEK as the key and PIN and never logged.

> ASSUMED (operator must confirm with OpenAI): the authorize endpoint accepts
> `ENROLL_PUBLIC_BASE_URL + /oauth/chatgpt/callback` for the public client id
> in `chatgpt_oauth.go` (OpenAI's Codex CLI client). That client's documented
> redirect is a loopback URI (`http://127.0.0.1:<port>/auth/callback`), so a
> hosted redirect may be rejected. Do not claim this flow works until an
> end-to-end connect has succeeded in the deployed environment; if OpenAI
> rejects the redirect, a dedicated OAuth client (or a loopback/device-code
> flow) is required.

## Verified vs assumed (build-time findings)

- VERIFIED live: `GET https://librechat.vranyes.com/api/agents/v1/models`
  with a dead bearer returns **401** — Bearer key auth works, so live key
  verification (200 = live, 401/403 = dead) is confirmed against the real host.
- VERIFIED in docs: LibreChat Agents API key auth is
  `Authorization: Bearer <KEY>` (librechat.ai/docs/features/agents_api).
- VERIFIED absent: no key-authenticated "me" route in the published Agents
  API — key-owner == session-sub cannot be enforced, so binding stays
  trust-based (documented in `store.go`; stealing a key already grants direct
  access, binding gains nothing).
- ASSUMED (operator must confirm in Kanidm): confidential code-flow client
  `voice-enroll` with redirect `https://enroll.vranyes.com/oauth/callback`
  and PKCE S256 enforced; `sub` claim contents for cross-matching LibreChat users. The service stores
  whatever `sub` arrives; LibreChat OIDC matching is sub-first, so a future
  OIDC-bearer path aligns, but the voice path keys on (phone, sub) as stored.
- ASSUMED: Telnyx account has programmable SMS enabled; sender DID supplied
  by operator. Message shape `POST /v2/messages {from,to,text}` is the
  stable Telnyx API (send failures surface as 5xx, fail-closed at grant).
- INFORMATIONAL (not this service): Telnyx STIR/SHAKEN attestation and the
  voice PIN gate live in voice-bridge, not here.
- Kanidm discovery is per-client
  (`.../oauth2/openid/<client>/.well-known/...`); root
  `/.well-known/openid-configuration` returns "Route not found", as expected.
  `KANIDM_ISSUER` must be the full per-client issuer URL.
