# Architecture

> Status markers: **[built]** implemented and tested · **[planned]** designed, not yet implemented.
> See [STATUS.md](STATUS.md) for the evidence behind each marker.

## 1. Purpose and scope

The guardrail is a security gateway that sits between a client (developer tool,
script, dashboard or browser extension) and an external AI provider. It prevents
credentials, personal data and confidential material from leaving the
organisation inside AI prompts, inspects model responses, and records a
tamper-evident audit trail.

**What it does not claim.** The gateway only protects traffic that is routed
through it. Employees pasting into a public AI website are only covered once the
browser extension (Phase 6) is installed, and even then only on the supported
sites; network- or endpoint-level enforcement is out of scope.

## 2. Request flow

```
Client ──► FastAPI gateway [built, Phase 3]
             │ auth (JWT) · rate limit · size limit · Pydantic validation
             ▼
           Guardrail.inspect(prompt) [built]
             │ normalise → detect → resolve overlaps → policy → redact
             ▼
           decision ── BLOCK ─────────────► 4xx response, nothing forwarded
             │ ── REQUIRE_APPROVAL ───────► approval queue, nothing forwarded yet
             │ ── REDACT / ALLOW
             ▼
           Provider adapter (mock built; real adapter Phase 4)
             ▼
           Guardrail.inspect(response) + output rules [planned, Phase 4]
             ▼
           Safe response to client
             └──► Audit event (HMAC-SHA256 chain) [built; written before forwarding]
```

## 3. Components

### 3.1 Detection engine — `backend/app/detection/` [built]

| Module | Responsibility |
|---|---|
| `normalize.py` | Offset-preserving normalisation: strips zero-width/bidi characters, folds full-width forms (per-character NFKC). Every normalised character maps back to its original index so redaction hits the original text. |
| `rules.py` | 41 built-in pattern rules: vendor tokens (AWS, GCP, Azure, GitHub, GitLab, Slack, Stripe, SendGrid, npm, PyPI, Hugging Face, OpenAI, Anthropic), JWT, PEM keys, bearer/basic auth, URL credentials, keyword-anchored assignments, CLI password flags, PII (email, card, IBAN, Aadhaar, PAN, SSN, phone), RFC 1918 IPs, classification markers. Each rule has an id, entity type, category, severity, confidence, optional checksum validator, value plausibility check, context-boost and suppress keywords. |
| `validators.py` | Luhn + issuer prefixes, Verhoeff (Aadhaar), ISO 13616 mod-97 (IBAN), SSN ranges, RFC 1918, Shannon entropy. |
| `entropy.py` | High-entropy token heuristic with filters for hashes, UUIDs, identifiers and paths; confidence depends on nearby credential keywords. |
| `engine.py` | Runs detectors, resolves overlaps, propagates repeated secrets, enforces the input-size limit, computes keyed fingerprints. |
| `redaction.py` | Typed numbered placeholders (`[PASSWORD_1]`), consistent per value, collision-safe against user-supplied placeholder text. |

**Overlaps (revised after the independent review).** The scanner only merges
overlapping candidates of the *same entity type* (union span, corroboration).
Findings of different entity types are never dropped, even when they overlap,
because each must reach the policy engine: a card number inside a URL password
still triggers the card's BLOCK. Three later stages handle overlaps safely:

1. *Policy* evaluates every finding, so the request action is never weaker than
   the strictest finding. It then folds a finding into a containing finding of
   the same category for presentation, but only if the folded one's action is
   no stricter and it would still be redacted.
2. *Escalation* counts distinct redacted regions, so overlaps are not
   double-counted.
3. *Redaction* unions overlapping actioned spans into one region labelled by the
   highest-priority finding (`password: 2345 6789 0124` → `password: [PASSWORD_1]`).

Ranking (best first): confidence at or above the policy threshold, severity,
specific rules before the entropy heuristic, confidence, length. All merging is
an O(n log n) sort-and-sweep. Scans stop at 5,000 candidates and the policy then
**fails closed** (BLOCK).

**Repeated secrets.** Every other occurrence of a detected secret value
(≥ 6 characters, up to 200 distinct values) is also redacted, even without
context, and keeps the original rule id so rule-level policy applies.

**Normalisation.** Drops Unicode format/control characters, combining marks,
variation selectors, tag characters and blank fillers; folds Cyrillic/Greek
look-alike letters; applies NFKC with expansions capped at three characters
(bounding normalised length to 3× the input).

### 3.2 Policy engine — `backend/app/policy/` [built]

Policies are YAML files validated by a strict Pydantic schema (unknown keys are
rejected). Lookup order for one finding: `rule_actions` → `entity_actions` →
`category_actions` → `default_action`. Findings under `min_confidence` are
recorded but never act. The request action is the strongest finding action
(`ALLOW < REDACT < REQUIRE_APPROVAL < BLOCK`), then escalation rules apply
(bulk findings → approval/block, optional risk-score block). Every decision
carries human-readable reasons.

Risk score: `100 × (1 − Π(1 − w(severity) × confidence))`.

Administrators can add literal terms and regex rules. Custom regexes are
compiled with **RE2** (`google-re2`), which runs in linear time for every
pattern it accepts, so a policy author cannot introduce ReDoS. RE2 rejects
backreferences and lookaround; patterns matching the empty string are rejected.
(An earlier nested-quantifier heuristic was bypassed in review by
`((a+))+$` and `(?:a|a)+$` and has been removed.)

### 3.3 Guardrail facade — `backend/app/guardrail.py` [built]

`Guardrail.inspect(text) → Inspection` combines the above. `forwardable_text`
is `None` for BLOCK and REQUIRE_APPROVAL. `to_public()` is the only
serialisation path and never includes raw values or the placeholder mapping.

### 3.4 Audit chain — `backend/app/audit/`, `backend/app/db/` [built]

Append-only event log in SQLite (SQLAlchemy 2 async + Alembic). Every event is
authenticated with `HMAC-SHA256(audit_key, domain ‖ canonical(record))`, where the
record includes its `seq` and the previous event's hash. Appends are serialised
(`BEGIN IMMEDIATE` on SQLite, `FOR UPDATE` on the head row for PostgreSQL) and
`UNIQUE(prev_hash)` makes forks impossible. Append-only triggers block
accidental edits. Ed25519-signed checkpoints of the chain head are stored and
exportable; the verifier checks links, MACs, sequence, head and checkpoints and
pinpoints each problem by `seq`. Events are scanned and rejected if they contain
secrets. The audit key is separate from the fingerprint key; dev keys live
outside the repository. Full design, threat model and limits: [AUDIT.md](AUDIT.md).

### 3.5 Token vault [planned — only if required]

Not built. Redaction mappings live only in memory for the request. Restoring
original values into model output is **not** done automatically; if a later
phase needs it, it will be a separate authorised operation using AES-GCM with
unique nonces, keys held outside the database, and expiry.

### 3.6 Gateway - `backend/app/api/`, `auth/`, `approvals/`, `providers/` [built]

FastAPI service (see [API.md](API.md)). A pure-ASGI middleware assigns
server-side request ids, adds security headers and enforces the body-size limit
while the body streams in. Authentication accepts JWT session tokens (HS256,
pinned algorithm, issuer/audience/expiry required) or peppered-HMAC API keys;
the role is always re-read from the database. Per-user and per-IP login token
buckets limit request rates. `/v1/chat/completions` inspects all messages as one
conversation (shared placeholder numbering, conversation-wide escalation),
writes an audit event, and only then forwards redacted text to the provider;
BLOCK and REQUIRE_APPROVAL never reach it. Held requests are stored redacted and
AES-256-GCM-encrypted, decided by a different administrator, executed once by
the requester, and erased afterwards. Validation errors never echo input.

### 3.7 Providers, output inspection, dashboards, extension [planned - Phases 4-6]

A real provider adapter and response inspection (Phase 4), React dashboards
(Phase 5) and a Chrome MV3 extension that talks only to the configured gateway
(Phase 6).

## 4. Key decisions

| Decision | Reason |
|---|---|
| Detection on a normalised copy, redaction on the original | Defeats zero-width / full-width evasion without corrupting user text. |
| Redact only the value, not the key (`db_password=[PASSWORD_1]`) | The model can still help with the code structure. |
| Python sources are ASCII-only (escapes for any other character) | Trojan Source / homoglyph guard, enforced by a test. |
| Keyed HMAC fingerprints instead of plain hashes | Plain SHA-256 of a short password is brute-forceable; an HMAC needs the key. |
| Synthetic tokens assembled at runtime | No secret-shaped literals in the repo; GitHub push protection stays happy. |
| Built-in rules on `re` with bounded patterns + ReDoS tests; admin rules on RE2 | Built-ins are audited and tested against 16 pathological 50k-character inputs; untrusted admin patterns get a linear-time engine. |
| Keep overlapping findings of different types; union at redaction | Dropping a finding to resolve an overlap leaked data and downgraded BLOCK to REDACT (found in review). |
| Separate development and held-out evaluation sets | Prevents reporting numbers from data used for tuning. |

## 5. Configuration

Environment variables prefixed `GUARDRAIL_` (see `backend/.env.example`).
`production` refuses to start without an explicit fingerprint key; development
generates an ephemeral one and warns.
