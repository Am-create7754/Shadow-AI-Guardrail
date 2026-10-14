# Project Status

_Last updated: 2026-10-14 · Current phase: **Phase 2 complete → Phase 3 next**_

Legend: ✅ implemented and verified by automated tests · 🟡 partial · ⬜ not started

## Phase checklist

| Phase | Scope | State |
|---|---|---|
| 0 | Workspace, git, structure, tooling, CI, docs | ✅ |
| 1 | Detection engine, redaction, policy engine, evaluation | ✅ |
| 2 | Canonical audit events, HMAC chain, verification, checkpoints | ✅ |
| 3 | FastAPI gateway, auth, rate limits, mock provider | ⬜ |
| 4 | Real provider adapter, output inspection, streaming | ⬜ |
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

## Latest test results

Command: `backend\scripts\check.ps1` (Windows PowerShell)

- ruff lint: pass · ruff format: pass · mypy `--strict`: no issues in 33 files
- pytest: **419 passed** (332 Phase 1 + 87 Phase 2; includes slow ReDoS and
  multi-process tests, 3 Hypothesis properties × 150 examples)

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
10. The gateway does not exist yet — nothing is intercepted on the network until Phase 3,
    and nothing writes audit events automatically until the gateway is wired up.
11. Bulk prompts producing more than 5,000 candidate detections are blocked
    outright (fail closed) rather than inspected.
12. **Audit rollback** is detected only through a checkpoint stored outside the
    database. The default anchor file is on the same machine; protection against a
    full host compromise requires exporting checkpoints to another system.
13. The PostgreSQL path (row lock, triggers) is implemented but untested; only
    SQLite is verified.
14. Verifying event MACs needs the symmetric audit key; only checkpoint
    verification works with a public key alone.

## Environment notes (Windows)

- Python 3.13.5 (venv at `backend/.venv`), Node 22.14, Git 2.39 available. Docker is
  not installed (not needed until optional containerisation in Phase 7).
- The project lives under OneDrive; `.venv` and `node_modules` sync slowly. If sync
  causes file locks, exclude those folders from OneDrive or move the repo.
- `gh` CLI is not installed; GitHub operations use plain `git`.

## Next steps (exact)

**Phase 3 — FastAPI gateway**

1. Add FastAPI + Uvicorn; app factory with lifespan creating the engine, the
   `Guardrail`, the `AuditLog` and the provider.
2. Pydantic request/response schemas: `POST /v1/inspect` (scan only) and
   `POST /v1/chat/completions` (OpenAI-compatible subset); request-size limit
   enforced before parsing; request IDs on every response; structured errors
   that never echo input.
3. Authentication: users and API keys stored as Argon2 hashes; JWT for the
   dashboard; roles (`developer`, `admin`) decided server-side only.
4. Rate limiting per principal; safe logging (no prompts, no auth headers).
5. Provider abstraction + deterministic mock provider; integration tests proving
   BLOCK and REQUIRE_APPROVAL requests never reach the provider, and that only
   redacted text does.
6. Approval queue for REQUIRE_APPROVAL (admin approve/deny) and an audit event
   for every decision.
7. Independent security review of the gateway, as for Phases 1-2.
