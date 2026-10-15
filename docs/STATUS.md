# Project Status

_Last updated: 2026-10-15 · Current phase: **Phase 4 complete → Phase 5 next**_

Legend: ✅ implemented and verified by automated tests · 🟡 partial · ⬜ not started

## Phase checklist

| Phase | Scope | State |
|---|---|---|
| 0 | Workspace, git, structure, tooling, CI, docs | ✅ |
| 1 | Detection engine, redaction, policy engine, evaluation | ✅ |
| 2 | Canonical audit events, HMAC chain, verification, checkpoints | ✅ |
| 3 | FastAPI gateway, auth, rate limits, mock provider | ✅ |
| 4 | Real provider adapter, output inspection, streaming | ✅ |
| 5 | Developer portal + admin dashboard (React) | ⬜ |
| 6 | Chrome MV3 extension | ⬜ |
| 7 | Hardening, load and security testing | ⬜ |
| 8 | Academic deliverables (SRS, diagrams, STRIDE, report) | ⬜ |

## Completed features (with evidence)

| Feature | Evidence |
|---|---|
| 41 built-in detection rules (vendor tokens, keys, passwords, PII, financial, infra, markers) | `tests/test_detection.py` — every entity type, 5 random values each, exact span check |
| Checksum validation (Luhn + issuer, Verhoeff, IBAN mod-97, SSN ranges, RFC 1918) | `tests/test_validators.py` |
| Entropy heuristic with hash/UUID/identifier/path filters | `tests/test_detection.py`, evaluation negatives |
| Evasion handling: invisible/format chars, combining marks, variation selectors, tag chars, blank fillers, Cyrillic/Greek homoglyphs, full-width; offset mapping; bounded NFKC expansion | `tests/test_normalize.py`, `test_detection.py::test_invisible_character_inside_key_is_seen_through` (12 code points), `test_cyrillic_homoglyph_prefix_detected` |
| Overlap handling: same-entity merge; different entities kept, policy-folded, unioned at redaction | `test_detection.py::test_same_entity_*`, `test_different_entities_are_never_dropped`; `test_policy.py` review regressions |
| Repeated-secret propagation | `test_repeated_secret_without_context_is_also_found` |
| Typed numbered placeholders, consistent per value, collision-safe | `tests/test_redaction.py` |
| YAML policy with strict schema; ALLOW / REDACT / REQUIRE_APPROVAL / BLOCK; explainable reasons; escalation; risk score | `tests/test_policy.py` |
| Custom terms and custom regex rules; admin regexes compiled with RE2 (linear time) | `test_custom_term_*`, `test_catastrophic_shapes_run_in_linear_time_under_re2`, `test_patterns_re2_cannot_run_are_rejected` |
| Input size limit, type checking, malformed unicode | `test_input_size_limit`, `test_lone_surrogate_does_not_crash`, Hypothesis |
| Raw values never in repr / public output | `test_finding_repr_*`, `test_mapping_not_in_repr`, Hypothesis property |
| ReDoS resistance | `tests/test_redos.py` — 41 rules × 16 pathological 50k-char inputs + full engine |
| Fail-closed candidate cap (5,000) and O(n log n) merging | `test_candidate_cap_sets_truncated`, `test_truncated_scan_fails_closed`, `test_merge_is_fast_for_many_findings` |
| Repository hygiene: no vendor-token literals; no invisible/bidi characters (Trojan Source); ASCII-only Python | `tests/test_repo_hygiene.py` |
| CLI inspector | manual: `python -m app.cli "..."` (output shown in README) |
| Labeled evaluation with development + held-out sets | `evaluation/`, `docs/EVALUATION.md`, `tests/test_evaluation.py` regression floor |
| **Phase 2** — HMAC-SHA256 audit chain over canonical records (seq + prev_hash authenticated) | `tests/test_audit_chain.py::test_mac_covers_every_field`, `test_append_builds_contiguous_linked_chain` |
| Tamper detection located by seq: edit, rehash without key, delete, reorder, forged insert, non-canonical data | `test_audit_chain.py` attack tests |
| Rollback / wipe detection via anchor file outside the DB; honest limitation test without it | `test_rollback_detected_by_anchor_file`, `test_full_wipe_detected_by_anchor`, `test_rollback_undetectable_without_external_anchor` |
| Ed25519 checkpoints bound to the chain; external/exported verification; untrusted, altered and foreign checkpoints rejected | `test_full_rewrite_with_stolen_hmac_key`, `test_checkpoint_*` |
| Concurrency: no forks/duplicates with 4 connection pools and with 4 OS processes on one SQLite file | `tests/test_audit_concurrency.py`; `test_appends_use_begin_immediate` |
| Append-only triggers (UPDATE / DELETE / INSERT OR REPLACE) and UNIQUE(prev_hash) fork guard | `test_triggers_block_*`, `test_insert_or_replace_blocked_by_triggers`, `test_unique_prev_hash_prevents_fork` |
| Key management: separate audit key, rotation with ordering, retired-key rejection, weak-key rejection, dev keys outside repo, verify never generates keys, public-key-only verification | `tests/test_audit_infra.py`, `tests/test_audit_review_regressions.py` |
| Verifier robustness: malformed / oversized rows and checkpoints reported, never raised; issue cap cannot hide rollback | `test_blob_columns_*`, `test_junk_checkpoint_row_reported`, `test_issue_cap_*` |
| Secret scan on audit events over decoded values | `test_event_containing_*`, `test_secret_scan_bypasses_closed` |
| Alembic migration matches models (no drift) and installs triggers; migrated DB works end to end | `test_migration_matches_models_and_installs_triggers`, `test_migrated_database_works_end_to_end` |
| Audit CLI: init-db, verify (exit 1 on issues), checkpoint, export, tamper demo | `tests/test_audit_cli.py`; manual run of `python -m app.audit tamper-demo` |
| **Phase 3** — FastAPI gateway: `/v1/inspect`, OpenAI-compatible `/v1/chat/completions`, approvals, admin API | `tests/test_api_gateway.py` |
| Only redacted text reaches the provider; BLOCK / REQUIRE_APPROVAL never do; audit committed before forwarding or holding (fail closed) | `test_secret_is_redacted_before_reaching_provider`, `test_blocked_prompt_never_reaches_provider`, `test_audit_failure_fails_closed`, `test_approval_not_created_when_audit_fails` |
| Conversation-wide inspection: shared placeholders, all roles, secrets/phrases split across messages, model name | `test_conversation_redacted_consistently_across_messages`, `test_token_split_across_messages_is_redacted`, `test_phrase_split_across_messages_still_needs_approval`, `test_secret_in_model_name_rejected_and_never_stored` |
| Auth: Argon2id (off the event loop), JWT HS256 with pinned algorithm and required claims, peppered-HMAC API keys, DB-sourced roles, logout / deactivation revoke sessions | `tests/test_api_security.py`, `test_api_review_regressions.py` |
| Approval workflow: AES-256-GCM (HKDF, row-bound AAD), single-use execution, release on failure, expiry, separation of duties incl. account-creation links | `test_approval_flow_end_to_end`, `test_held_ciphertext_is_encrypted_and_bound_to_row`, `test_admin_cannot_approve_requests_of_accounts_they_created`, `test_approval_survives_provider_failure` |
| HTTP hardening: body limit (incl. chunked), security headers on every response incl. 500s, server-side request ids, no input echo in errors, CORS allow-list, docs off in production | `tests/test_api_security.py`, `test_unhandled_route_exception_keeps_headers_and_hides_message` |
| Rate limiting: per user, login per IP, bounded memory that fails closed | `test_per_user_rate_limit`, `test_login_rate_limited`, `test_rate_limiter_memory_is_bounded` |
| Provider abstraction + deterministic mock provider (echo, error, timeout, rate-limit, leak modes); failures mapped, audited, never echoed | `tests/test_gateway_units.py`, `test_provider_failures_mapped_and_audited`, `test_unexpected_provider_exception_is_contained` |
| Live run with Uvicorn; official OpenAI Python SDK 3.31 works unmodified (blocks surface as `PermissionDeniedError`) | manual, 2026-10-14 (see Phase 3 review section) |
| **Phase 4** — OpenAI-compatible provider adapter (OpenAI, Gemini, Ollama...): key only in the auth header, no redirects, allow-listed error codes, validated and byte-capped responses, retries only for transient errors, total deadline | `tests/test_openai_adapter.py` (simulated upstream), `test_output_review_regressions.py` |
| Live provider: verified against Google Gemini (`gemini-3.5-flash-lite`) end to end - prompt redaction, answer redaction, streaming, model allow-list | `tests/test_live_provider.py` (opt-in, 5/5 passed 2026-10-15) |
| Output policy: secrets/PII in answers redacted, private keys block the answer, candidate cap fails closed | `tests/test_output_inspection.py`, `test_api_output.py` |
| Leak-safe streaming (`stream=true`, OpenAI SSE format): never releases part of a secret; remembers secrets for later repeats; bounded held text and near-linear cost | Hypothesis properties (stream == batch, no 8-char secret prefix), `test_output_review_regressions.py` performance tests |
| Insecure-code checks: 19 CWE-tagged rules over fenced blocks (backtick and tilde fences, unclosed final blocks); annotate or block mode, incl. while streaming | `test_output_inspection.py` (19 positive, 15 negative cases, ReDoS), regression tests |

## Latest test results

Command: `backend\scripts\check.ps1` (Windows PowerShell)

- ruff lint: pass · ruff format: pass · mypy `--strict`: no issues in 64 files
- pytest: **645 passed, 5 skipped** (the 5 live-provider tests are opt-in and
  passed separately against Gemini). Un-awaited coroutines fail the suite.

## Independent security review (Phase 1)

A separate reviewer agent audited the detection, redaction and policy code
with read-only access and reproduced each issue with concrete inputs. All
confirmed findings were re-reproduced, fixed, and covered by regression tests:

| # | Confirmed issue | Fix |
|---|---|---|
| 1 | A secret whose span was widened during merging leaked in full on its second occurrence | Values restored before repeat search; `test_repeat_of_widened_secret_is_redacted` |
| 2 | A below-threshold entropy hit out-ranked and hid a real email | Different entity types are never dropped; threshold-aware ranking; `test_sub_threshold_entropy_hit_cannot_hide_email` |
| 3 | Cross-category partial overlap leaked 8 of 12 Aadhaar digits / half a phone number | Redaction unions overlapping spans; `test_cross_entity_overlap_redacts_the_union` |
| 4 | Card number inside a URL password was downgraded from BLOCK to REDACT | Policy evaluates every finding before folding; `test_card_inside_url_password_still_blocks`, `test_fold_never_weakens_action` |
| 5 | 11 invisible code points + Cyrillic homoglyphs bypassed normalisation | Category-based stripping + confusables fold; 12 parametrised tests |
| 6 | Admin regex ReDoS heuristic bypassable (`((a+))+$` took 25.7 s) | Admin patterns compiled with RE2; linear-time tests on 200k chars |
| 7 | Quadratic overlap resolution (9.1 s on 100k chars of emails) | Sort-and-sweep merging, 5,000-candidate cap failing closed (now 0.12 s) |
| 8 | Size limit bypass via NFKC expansion (×18) and PEM lazy rescans | NFKC expansion capped at 3 chars; PEM body cannot cross `-----` |

Plausible items: look-alike placeholders are now reserved (fixed); repeats keep
the original rule id (fixed); a placeholder maps normalised-equal values to the
first original text (acceptable — restoration is not implemented); sub-threshold
findings are recorded but not redacted (by design, documented below);
`sanitized_text` is returned for REQUIRE_APPROVAL and must go only to the
submitter (to be enforced in Phase 3).

While reproducing, a further bug was found and fixed: the CLI crashed printing
non-ASCII on Windows consoles (cp1252).

## Independent security review (Phase 2)

A second reviewer agent audited the audit chain (read-only, with reproductions).
All confirmed findings were re-reproduced, fixed, and covered by regression tests
(`tests/test_audit_review_regressions.py` and `test_audit_chain.py`):

| # | Confirmed issue | Fix |
|---|---|---|
| 1 | **Keyless rollback / wipe went undetected** (delete newest events + head + checkpoints). The docs wrongly claimed only a key holder could do this. | Anchor file outside the DB (on by default); docs corrected; honest limitation kept as a test |
| 2 | A retired audit key could still sign new tail events | Keyring rotation order; `retired_key` issue |
| 3 | Verifier crashed on BLOB-typed columns and deeply nested JSON | Type checks, per-row isolation, size cap; reported as `malformed` / `oversized` |
| 4 | One junk checkpoint row (an INSERT the triggers allow) crashed verification | Reported as `checkpoint_malformed`; export skips such rows |
| 5 | `INSERT OR REPLACE` overwrote rows despite the append-only triggers | `BEFORE INSERT` clash triggers + `recursive_triggers`; tested with triggers intact |
| 6 | Secret scan ran on escaped JSON: escaped-quote passwords, key-name secrets and split card numbers got through | Scan decoded keys/values, `key=value` pairs and joined lists, each piece separately |
| 7 | Weak retired keys and an empty dev key file were accepted | Length checks on every key source |

Plausible items addressed: verification with only the public key
(`verify --public-key`, never loads the private key); trusted keys for
signing-key rotation; checkpoints bound to the chain's first event; PostgreSQL
`TRUNCATE` trigger; head/checkpoint findings exempt from the issue cap; planted
oversized rows not parsed. Not changed: dev keys share the per-user data folder
with the database (documented); Windows ignores `0o600` (files inherit the
user-profile ACL); no idempotency key for client retries (Phase 3 request IDs).

Found while fixing: `verify` silently generated a **new** audit key when the key
file was missing, producing only `unknown_key` noise. Verification now never
generates keys and fails with a clear message (exit 2). Also: copying
`.env.example` verbatim produced empty (rejected) keys - empty variables now mean
"unset"; and the repo-hygiene test was extended to catch ASCII control
characters after one slipped into a document.

## Independent security review (Phase 3)

A third reviewer agent probed the running gateway. Every confirmed finding was
first captured as a failing test (`tests/test_api_review_regressions.py`, all 18
failed before the fixes) and then fixed:

| # | Confirmed issue | Fix |
|---|---|---|
| 1 | A raw token in the `model` field was stored unencrypted in a held request and shown to admins; the approval row was written before the audit check | Model name inspected (`400 invalid_model`); audit written before the row is created |
| 2 | One admin could approve their own request via a sock-puppet account they created | Separation of duties extended to account-creation links (`created_by`) |
| 3 | Anyone could lock a known user out of login (per-username bucket spent before the password check) | Login limited per client IP only; rationale documented |
| 4 | Unhandled exceptions bypassed the middleware: no security headers, and the exception message (possibly prompt text) reached the server log | Middleware contains all exceptions; non-`ProviderError` provider failures mapped to 502, audited, message dropped |
| 5 | A secret or phrase split across two messages was not detected | Conversation also scanned joined (no separator / space); boundary-spanning findings mapped back to each message |
| 6 | Argon2 ran on the event loop (~150 ms stall per login) | `asyncio.to_thread` for hashing and verification |
| 7 | A failed execution used up the approval | Claim released on provider or audit failure |

Plausible items fixed: expired requests can no longer be decrypted for review;
approval decisions and user changes are audited *before* they take effect; a
failed post-delivery audit no longer turns a delivered answer into an error
(`audit_incomplete: true`); a full rate-limit table refuses new keys instead of
evicting live ones; logout endpoint and session revocation on deactivation
(survives reactivation); at most 20 API keys per user, prefix collisions
retried; the last active admin cannot be deactivated (checked under a write
lock); unknown field names are not echoed in 422s; the docs CSP exemption
matches exact paths only.

Found while fixing: joining messages without a separator glued unrelated text
together (`...=hunter2hunter` + `Is it strong?` redacted the word "Is"). Cross-
message findings are now dropped when the first message already contains the
whole value as the same entity type.

Manual verification (2026-10-14): the gateway was started with Uvicorn and
exercised over real HTTP (redaction, block, split-token redaction, logout,
admin-route denial, audit verify); the server log contained no prompt text and
no tracebacks. The official `openai` Python SDK (3.31) worked against
`/v1/chat/completions` unmodified.

## Independent security review (Phase 4)

A fourth reviewer agent attacked the output path with synthetic secrets and a
simulated upstream. Each confirmed issue became a failing test first
(`tests/test_output_review_regressions.py`, 16 failing before the fixes):

| # | Confirmed issue | Fix |
|---|---|---|
| 1 | Streaming CPU DoS: once text was held, every chunk triggered a full rescan (20k random chars in 1-char chunks: 512 s; block-mode code: up to 267 s) | Geometric rescan back-off, 16 KiB held-text cap (fail closed), incremental fence parsing: now 0.2-0.8 s |
| 2 | Output path ignored the scan's candidate cap: a card number after 5,100 emails was returned in clear | Answers and streams fail closed when the scan is truncated |
| 3 | A secret repeated far from its context was redacted in full answers but released in streams | Stream remembers every detected secret and redacts later repeats |
| 4 | A very long URL password containing `!` leaked a prefix while streaming | Hold any run of non-whitespace, not only "token" characters |
| 5 | Code block mode bypassable: unclosed final fence, a stray inline ``` shifting pairing, `~~~` fences | CommonMark-style line-anchored fence parser; unclosed blocks checked |
| 6 | Client disconnect skipped the closing audit event and could leave a broken DB connection (next request 500) | Closing audit written in its own task; `chat.stream_aborted` event; provider stream always closed |
| 7 | Adapter read whole bodies before size checks; non-content stream events and single huge lines were unbounded; no total deadline | Byte-capped reads, own line splitter with per-line cap, total deadline |
| 8 | `http://localhost.evil.example` / `http://localhost@evil` counted as "local" (key could go over plain http) | URL parsed; exact loopback host names; credentials in URL rejected |
| 9 | Placeholder collision with model-written `[EMAIL_1]`; arbitrary upstream error codes echoed; upstream `model`/`finish_reason` trusted | Reserve placeholders from streamed text; allow-listed error codes; model and finish reason not trusted |

Also fixed: executing an approval re-checks the model allow-list; the provider
stream is closed even if the response body never starts. Found while fixing:
Starlette ran a bound `aclose` method in a thread, so the stream was never
actually closed (an un-awaited coroutine) - now a real coroutine, and
un-awaited coroutines fail the test suite.

Live provider notes (2026-10-15): the configured OpenAI account returned
`credit_balance_exhausted` (key valid, no credit) - now reported immediately as
`503 provider_quota_exhausted` without retries. Google Gemini works: the
originally suggested model names were retired for new users, so the allowed
models were taken from the key's own model list.

## System health check (2026-10-15)

A full check of the running system before Phase 5 found and fixed:

| Problem | Cause | Fix / evidence |
|---|---|---|
| **GitHub CI failed on every push** (all 4 jobs: Windows/Ubuntu × Python 3.12/3.13) | Current `setuptools` refuses a package README outside the package directory (`readme = "../README.md"`); the local venv predated that rule | `backend/README.md`; reproduced and verified with a fresh clone + fresh venv: install, lint, format, mypy and 645 tests pass |
| Fingerprint key changed on every development restart (start-up warning) | Development used an ephemeral key, so the same secret got a different fingerprint after a restart | Persisted in the per-user keys folder like every other dev key; `test_development_fingerprint_key_is_persisted` |
| `GET /favicon.ico` 404 and `HEAD /` 405 in server logs | Browser/preview probes | Quiet 204 / redirect; `test_favicon_and_head_root_are_quiet` |
| Local tool config could be committed by `git add -A` | `.claude/` not ignored | Added to `.gitignore` |

Verified healthy: the real development database is at migration head with no
schema drift (`alembic check`) and its audit chain verifies; the server starts
with no warnings; an 11-step live walkthrough against Google Gemini passed
(ALLOW, input REDACT, real answer redacted, insecure-code warning, streaming,
BLOCK, approval hold → approve → execute, model allow-list, audit verify, no
secrets in the audit log); the server log contained no errors and no prompt text.

## Detection quality (5 seeds; see `docs/EVALUATION.md`)

| Set | Samples | Entity recall | Finding precision | F1 | Benign-prompt FP rate | Leaked values |
|---|---|---|---|---|---|---|
| Development (used for tuning) | 495 | 1.000 | 1.000 | 1.000 | 0.0% | 0 |
| Held-out, first blind run | 345 | 0.951 | 0.916 | 0.933 | 8.0% | 14 |
| Held-out, after fixing defects it exposed | 345 | 0.951 | 1.000 | 0.975 | 0.0% | 14 |

The development numbers are optimistic by construction. The **blind held-out run
is the honest estimate**; after it, four genuine defects were fixed, so the held-out
set is no longer blind. All 14 remaining leaks fall in three documented known gaps.

## Known limitations

1. **Coverage gaps (measured):** passwords given positionally without a keyword
   (`connect("mailer", "Secret123")`), `user / password` pairs in prose, and
   keyless license-style keys under 32 characters are not detected.
2. Encoded secrets (base64, hex, URL-encoded) are not decoded; they are caught only
   when a credential keyword is nearby.
3. Names and free-text addresses are not detected (no NER yet; Presidio/spaCy is an
   optional future detector behind the same interface).
4. Phone and PAN detection is format-based and India-centric; other national IDs
   are not covered.
5. Public test card numbers (e.g. `4111…`) are blocked like real cards, by design.
6. Homoglyph folding covers common Cyrillic/Greek look-alikes only, not the full
   Unicode confusables table. Visible separators inside a token (space, NBSP,
   hyphen) are not removed, so a deliberately split secret is not detected.
7. Findings below the policy confidence threshold (e.g. a 20–31 character random
   key with no credential keyword) are recorded but not redacted.
   Invalid admin regexes produce RE2 log lines on stderr when a policy is loaded.
8. Fingerprints are 128-bit truncated HMAC-SHA256; if the fingerprint key leaks,
   short passwords could be brute-forced from fingerprints. The key must be managed
   like any other secret.
9. Datasets are synthetic and small; metrics are evidence for this project, not a
   claim of comprehensive real-world detection.
10. Only traffic sent **through the gateway** is protected. Employees using AI
    websites directly are not covered until the browser extension (Phase 6), and
    then only on supported sites.
11. Bulk prompts producing more than 5,000 candidate detections are blocked
    outright (fail closed) rather than inspected.
12. **Audit rollback** is detected only through a checkpoint stored outside the
    database. The default anchor file is on the same machine; protection against a
    full host compromise requires exporting checkpoints to another system.
13. The PostgreSQL path (row lock, triggers) is implemented but untested; only
    SQLite is verified.
14. Verifying event MACs needs the symmetric audit key; only checkpoint
    verification works with a public key alone.
15. Output-path limits: in a **stream**, a value that first appears bare and only
    later becomes recognisable as a secret may already have been released;
    a single unbroken run longer than 16 KiB ends the stream (fail closed).
    Text released before an output block or provider error mid-stream has
    already reached the client (it was checked, but the answer is incomplete).
    Code checks are line-based patterns over fenced blocks - indented code and
    unfenced code are not checked, and a clean result is not a proof of safety.
    Output findings below the 0.6 confidence threshold (e.g. short random
    tokens without a keyword) pass, as for prompts.
16. Rate limits are per process; several workers each enforce their own budget.
    `X-Forwarded-For` is not trusted, so behind a reverse proxy all clients share
    the proxy's login budget until trusted-proxy support is configured.
17. No JWT refresh tokens; sessions last 30 minutes. A logout revokes sessions at
    sub-second precision only.
18. Separation of duties relies on recorded account creators; CLI-bootstrapped
    users have none, and anyone with server or database access is outside it.
19. Live testing covers one real provider (Google Gemini via its OpenAI-compatible
    endpoint); OpenAI itself is untested live (account without credit).
    Free-tier providers may log prompts - the gateway only ever sends redacted text.

## Environment notes (Windows)

- Python 3.13.5 (venv at `backend/.venv`), Node 22.14, Git 2.39 available. Docker is
  not installed (not needed until optional containerisation in Phase 7).
- The project lives under OneDrive; `.venv` and `node_modules` sync slowly. If sync
  causes file locks, exclude those folders from OneDrive or move the repo.
- `gh` CLI is not installed; GitHub operations use plain `git`.

## Next steps (exact)

**Phase 5 — developer portal and administrator dashboard (React + Vite + TypeScript)**

1. Scaffold `frontend/` (Vite, React, TypeScript, Tailwind), API client with the
   gateway's error format, session handling (token in memory, logout).
2. Developer view: prompt playground showing the inspection (findings, risk,
   sanitized text), streamed answers, output findings and code warnings; own
   approval requests and API keys.
3. Administrator view (role-gated in the UI *and* enforced by the API): approval
   queue with review/approve/deny, searchable audit log, chain verification,
   user management, live metrics (entities, actions, risk over time).
4. Accessibility, responsive layout, no secrets in browser storage, strict CSP.
5. Component and end-to-end tests; independent security review.
