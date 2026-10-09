# voice-enroll — operator runbook

Self-service enrollment portal + internal directory for the voice call path.
Users log in via Kanidm, prove a phone number via Telnyx SMS OTP, and grant
voice access by pasting a LibreChat Remote Agents API key (verified live,
stored AES-GCM-encrypted in Postgres).

## Values the operator must supply (nothing works without all of these)

| Key | Where | How to get it |
|---|---|---|
| `DATABASE_URL` | SealedSecret `voice-enroll-secrets` | `postgresql://enroll:<pw>@voice-enroll-pg-rw.voice-enroll.svc:5432/voiceenroll?sslmode=verify-ca&sslrootcert=/run/secrets/pg-ca.crt`, pw = the sealed pg password |
| `ENROLL_DEK_B64` | same | `head -c32 /dev/urandom \| base64` (32-byte AES-GCM DEK; rotate = re-enroll all users) |
| `ENROLL_SESSION_SECRET_B64` | same | `head -c32 /dev/urandom \| base64` (HMAC key for login cookies) |
| `KANIDM_CLIENT_SECRET` | same | created by kaniop for `KanidmOAuth2Client/voice-enroll-app` — read the generated Secret after apply, seal it here |
| `TELNYX_API_KEY` | same | Telnyx portal → API keys (programmable SMS must be enabled on the account) |
| `TELNYX_SENDER_NUMBER` | same | E.164 DID from the Telnyx account used as the OTP sender |
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
