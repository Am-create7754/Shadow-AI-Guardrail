# Gateway API

The gateway is an HTTP service (FastAPI) in front of the AI provider. Interactive
OpenAPI docs are served at `http://127.0.0.1:8000/docs` outside production.

## 1. Running it (Windows PowerShell, from `backend/`)

```powershell
# one-time: database + development keys, then the first administrator
.venv\Scripts\python -m app.audit init-db
.venv\Scripts\python -m app.api.manage create-user admin --role admin     # prompts for a password
.venv\Scripts\python -m app.api.manage create-user alice                  # a developer

# start the gateway
.venv\Scripts\uvicorn --factory app.api.app:create_app --host 127.0.0.1 --port 8000
```

Passwords need at least 12 characters and must not contain the username.
Development keys (JWT, API-key pepper, data key, audit keys) are generated once
under `%LOCALAPPDATA%\guardrail\keys`; production must configure every key
explicitly (see `backend/.env.example`).

## 2. Authentication

Every `/v1/*` endpoint except `/v1/auth/login` needs
`Authorization: Bearer <credential>`, where the credential is either:

* a **session token** from `POST /v1/auth/login` (JWT, HS256, 30 minutes), or
* an **API key** `grk_<prefix>_<secret>` from `POST /v1/me/api-keys`
  (shown once; stored only as a peppered HMAC).

Roles (`developer`, `admin`) are always taken from the database, never from the
token, so deactivating or demoting a user takes effect on their next request.
Logging out or being deactivated invalidates every session token issued before
that moment, even if the account is later reactivated. Each user may hold at
most 20 active API keys. The last active administrator cannot be deactivated.

Login attempts are limited per client IP only. A per-username limit would let
anyone lock a known account (e.g. an administrator) out by spamming wrong
passwords; online guessing is bounded instead by the IP limit, Argon2 cost and
the 12-character password policy.

```powershell
$base = "http://127.0.0.1:8000"
$login = Invoke-RestMethod -Method Post "$base/v1/auth/login" -ContentType "application/json" `
  -Body (@{ username = "alice"; password = "<password>" } | ConvertTo-Json)
$h = @{ Authorization = "Bearer $($login.access_token)" }
```

## 3. Endpoints

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/health`, `/ready` | – | Liveness / database readiness |
| GET | `/app/...` | – | The built web dashboard (static files; own strict CSP). `/` redirects here when it is built |
| GET | `/v1/models` | any | Models this gateway allows (OpenAI `list` format) |
| POST | `/v1/auth/login` | – | Username + password → session token (rate limited per client IP) |
| POST | `/v1/auth/logout` | any | Revoke all of the caller's session tokens (API keys unaffected) |
| GET | `/v1/me` | any | Current user |
| GET / POST / DELETE | `/v1/me/api-keys[/{id}]` | any | List / create / revoke own API keys |
| POST | `/v1/inspect` | any | Inspect text only; never contacts a provider. Optional `source` label (e.g. `extension:chatgpt.com`, lowercase hostname shape) is audited and counted per site; a label that looks sensitive is refused with 400 |
| POST | `/v1/chat/completions` | any | OpenAI-compatible chat (non-streaming) |
| GET | `/v1/approvals` | any | Own approval requests |
| POST | `/v1/approvals/{id}/execute` | requester | Send an approved request (once) |
| GET | `/v1/admin/approvals[/{id}]` | admin | List / review held requests (redacted text only) |
| POST | `/v1/admin/approvals/{id}/approve` · `/deny` | admin | Decide (not on one's own request) |
| GET | `/v1/admin/audit/events` | admin | Audit log, newest first (`limit`, `before_seq`, `event_type`, `actor`) |
| GET | `/v1/admin/audit/verify` | admin | Verify chain integrity |
| GET / POST | `/v1/admin/users` | admin | List / create users |
| PATCH | `/v1/admin/users/{id}` | admin | Activate / deactivate |
| GET | `/v1/admin/metrics?hours=N` | admin | Dashboard metrics for the last N hours (1-2160), computed from audit events: decisions over time, top entities and rules, answer leaks, code findings, risk bands, models. Metadata only - never prompt text |
| GET | `/v1/admin/policy` | admin | The active policy (read-only) |

## 4. Chat completions

Request (OpenAI-compatible subset; other OpenAI fields are accepted and ignored):

```powershell
$body = @{ model = "mock-echo"; messages = @(@{ role = "user"
  content = "Fix this connection string: db_password=admin_pass_123" }) } | ConvertTo-Json -Depth 4
Invoke-RestMethod -Method Post "$base/v1/chat/completions" -Headers $h `
  -ContentType "application/json" -Body $body
```

All messages (system, user and assistant) are inspected together: one policy
decision covers the whole conversation and a placeholder such as `[PASSWORD_1]`
means the same value in every message. The conversation is also scanned joined
end-to-end, so a secret or phrase split across two messages is still found.
The `model` name is inspected too and rejected (`400 invalid_model`) if it looks
sensitive, because it is stored with held requests and in audit events.

| Decision | HTTP | What happens |
|---|---|---|
| ALLOW | 200 | Forwarded unchanged |
| REDACT | 200 | Forwarded with placeholders; `guardrail.placeholders` lists them |
| REQUIRE_APPROVAL | 403 `approval_required` | Nothing forwarded; `details.approval_id` returned |
| BLOCK | 403 `policy_blocked` | Nothing forwarded; `details` lists entity types and reasons |

A successful response is a normal `chat.completion` object plus an extra
`guardrail` field (`request_id`, `action`, `risk_score`, `placeholders`,
`reasons`, `findings`, `sanitized_messages`, `output_inspected`, `output`).
`findings` lists detected entity types, rules, severity and confidence (no
values, no offsets); `sanitized_messages` is exactly the text that was sent to
the provider. Both describe the caller's own request. `guardrail.output` describes what the
gateway did to the **model's answer** (see section 5).
If the post-delivery audit write fails, the answer is still returned with
`audit_incomplete: true` (the pre-forward audit event exists).
### Streaming (`"stream": true`)

The response is a standard OpenAI server-sent-event stream
(`chat.completion.chunk` objects, terminated by `data: [DONE]`), so streaming
clients and the OpenAI SDK work unchanged. Differences a client may notice:

* Text arrives in slightly larger, slightly delayed pieces: the gateway holds
  back the newest ~128 characters and any token or detection that may still be
  growing, so no part of a secret is released before it can be checked.
* The last chunk before `[DONE]` carries the `guardrail` summary.
* Input decisions (BLOCK, approval) and provider errors that happen before the
  first token are normal JSON errors with HTTP status codes. Problems after the
  stream has started (provider failure, output blocked) arrive as a final
  `{"error": {...}}` event, because the status line has already been sent;
  text released before that point was already checked and is safe.

### Model allow-list

With a real provider, only the models in `GUARDRAIL_PROVIDER_MODELS` may be
requested (`400 model_not_allowed` otherwise) — cost control, and the model name
stays a known value. The mock provider accepts any `mock-*` name.

**OpenAI SDK:** works unmodified — set `base_url` to `http://127.0.0.1:8000/v1` and
use a gateway token or API key as the API key. Blocks surface as
`openai.PermissionDeniedError` (verified manually with `openai` 3.31).

## 5. Approval workflow

1. A developer's request is held → `403 approval_required` with `approval_id`.
2. An independent administrator reviews `GET /v1/admin/approvals/{id}` — the
   held text is already redacted — and approves or denies. *Independent* means:
   not the requester, not the administrator who created the requester's account,
   not an account created by the requester, and not an account created by the
   same administrator as the requester's (so one admin cannot approve their own
   request through accounts they made). Users bootstrapped from the CLI have no
   recorded creator; anyone with direct server access is outside this control.
3. The requester calls `POST /v1/approvals/{id}/execute` exactly once before the
   request expires (24 h by default). If forwarding fails (provider error or
   audit outage) the approval is released so the requester can retry.

Held messages are encrypted with AES-256-GCM (key derived via HKDF, bound to the
request id) and erased on execution, denial or expiry.

## 5b. Output security (the model's answer)

Every answer — complete or streamed, including executed approvals — is
inspected with the same detection engine before the client sees it, then
handled by the `output` section of the policy file:

| Default | Effect |
|---|---|
| SECRET / FINANCIAL / PII in the answer | **REDACT** → typed placeholder (numbering never collides with the prompt's) |
| PRIVATE_KEY in the answer | **BLOCK** → `502 output_blocked` (or an error event mid-stream) |
| CONFIDENTIAL markers, internal IPs | allowed (common in explanations) |
| Insecure generated code | **annotate**: `guardrail.output.code_findings` lists rule, CWE, severity, block and line |

`code.mode: block` withholds answers whose code has findings at or above
`block_at` (streams hold each fenced block until it closes, then check it).

Code checks are line-based patterns over fenced blocks — eval/exec, `shell=True`,
`os.system`, unsafe pickle/YAML, SQL built from strings, JS eval/`innerHTML`,
`curl | sh`, `chmod 777`, disabled TLS verification, MD5/SHA-1 for secrets,
non-cryptographic random tokens, Flask debug, wildcard CORS with credentials,
hard-coded credentials (19 rules). They are a linter-style warning, not a proof
that code is safe.

## 6. Errors

Every error has the same shape and never echoes request content:

```json
{"error": {"type": "policy_blocked", "message": "...", "request_id": "…", "details": {}}}
```

| Status | `type` examples |
|---|---|
| 400 | `invalid_request`, `invalid_model`, `model_not_allowed`, `provider_bad_request` |
| 401 | `unauthorized`, `invalid_credentials` |
| 403 | `forbidden`, `policy_blocked`, `approval_required` |
| 404 / 409 | `not_found`, `approval_not_executable`, `approval_not_pending` |
| 413 | `payload_too_large` (HTTP body), `input_too_large` (prompt characters) |
| 422 | `validation_error` (field locations and messages only — no input values; unknown field names shown as `<unknown field>`) |
| 500 | `internal_error` (contained in the middleware: security headers kept, message never logged) |
| 429 | `rate_limited` (with `Retry-After`) |
| 502 | `provider_unavailable`, `provider_bad_response`, `output_blocked` |
| 503 | `provider_rate_limited`, `provider_quota_exhausted`, `audit_unavailable` |
| 504 | `provider_timeout` |

## 7. Mock provider models

`mock-echo` (quotes what it received — shows the redaction), `mock-error`,
`mock-timeout`, `mock-ratelimit`, `mock-leak` (answers with a synthetic AWS key —
shows output redaction) and `mock-code` (answers with insecure Python — shows
the code findings). Streaming works with all of them (7-character chunks, so a
leaked key is split across chunks).

## 8. Using a real provider

Put the provider settings in `backend/.env` (git-ignored; see
`backend/.env.example`), e.g. `GUARDRAIL_PROVIDER=openai` and
`GUARDRAIL_PROVIDER_API_KEY=...`, then restart the gateway. The key is only ever
sent in the `Authorization` header to the configured base URL; it never appears
in logs, errors, audit events or responses, and provider error bodies are never
passed through. Transient failures (429, 5xx, timeouts) are retried twice with
backoff; an exhausted account (`insufficient_quota`) fails immediately with
`503 provider_quota_exhausted`.

Live tests against the configured provider are opt-in (they cost money):

```powershell
$env:GUARDRAIL_LIVE_TESTS = "1"; .venv\Scripts\python -m pytest -m live -q
```
