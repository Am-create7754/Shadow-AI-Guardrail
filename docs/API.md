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
| POST | `/v1/auth/login` | – | Username + password → session token (rate limited per client IP) |
| POST | `/v1/auth/logout` | any | Revoke all of the caller's session tokens (API keys unaffected) |
| GET | `/v1/me` | any | Current user |
| GET / POST / DELETE | `/v1/me/api-keys[/{id}]` | any | List / create / revoke own API keys |
| POST | `/v1/inspect` | any | Inspect text only; never contacts a provider |
| POST | `/v1/chat/completions` | any | OpenAI-compatible chat (non-streaming) |
| GET | `/v1/approvals` | any | Own approval requests |
| POST | `/v1/approvals/{id}/execute` | requester | Send an approved request (once) |
| GET | `/v1/admin/approvals[/{id}]` | admin | List / review held requests (redacted text only) |
| POST | `/v1/admin/approvals/{id}/approve` · `/deny` | admin | Decide (not on one's own request) |
| GET | `/v1/admin/audit/events` | admin | Audit log, newest first (`limit`, `before_seq`, `event_type`, `actor`) |
| GET | `/v1/admin/audit/verify` | admin | Verify chain integrity |
| GET / POST | `/v1/admin/users` | admin | List / create users |
| PATCH | `/v1/admin/users/{id}` | admin | Activate / deactivate |

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
`reasons`, `output_inspected`). `output_inspected` is `false` until Phase 4.
If the post-delivery audit write fails, the answer is still returned with
`audit_incomplete: true` (the pre-forward audit event exists).
`stream=true` is rejected with 400 until streaming inspection exists.

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

## 6. Errors

Every error has the same shape and never echoes request content:

```json
{"error": {"type": "policy_blocked", "message": "...", "request_id": "…", "details": {}}}
```

| Status | `type` examples |
|---|---|
| 400 | `streaming_not_supported`, `invalid_request`, `invalid_model` |
| 401 | `unauthorized`, `invalid_credentials` |
| 403 | `forbidden`, `policy_blocked`, `approval_required` |
| 404 / 409 | `not_found`, `approval_not_executable`, `approval_not_pending` |
| 413 | `payload_too_large` (HTTP body), `input_too_large` (prompt characters) |
| 422 | `validation_error` (field locations and messages only — no input values; unknown field names shown as `<unknown field>`) |
| 500 | `internal_error` (contained in the middleware: security headers kept, message never logged) |
| 429 | `rate_limited` (with `Retry-After`) |
| 502 / 503 / 504 | `provider_unavailable`, `provider_rate_limited`, `audit_unavailable`, `provider_timeout` |

## 7. Mock provider models

`mock-echo` (quotes what it received — shows the redaction), `mock-error`,
`mock-timeout`, `mock-ratelimit`, and `mock-leak` (returns a synthetic key, for
Phase 4 output tests).
