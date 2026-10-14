# Project Status

_Last updated: 2026-10-14 · Current phase: **Phase 1 complete → Phase 2 next**_

Legend: ✅ implemented and verified by automated tests · 🟡 partial · ⬜ not started

## Phase checklist

| Phase | Scope | State |
|---|---|---|
| 0 | Workspace, git, structure, tooling, CI, docs | ✅ |
| 1 | Detection engine, redaction, policy engine, evaluation | ✅ |
| 2 | Canonical audit events, HMAC chain, verification, checkpoints | ⬜ |
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

## Latest test results

Command: `backend\scripts\check.ps1` (Windows PowerShell)

- ruff lint: pass · ruff format: pass · mypy `--strict`: no issues in 19 files
- pytest: **332 passed** (includes 57 slow ReDoS tests, 3 Hypothesis properties × 150 examples)

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
10. The gateway does not exist yet — nothing is intercepted on the network until Phase 3.
11. Bulk prompts producing more than 5,000 candidate detections are blocked
    outright (fail closed) rather than inspected.

## Environment notes (Windows)

- Python 3.13.5 (venv at `backend/.venv`), Node 22.14, Git 2.39 available. Docker is
  not installed (not needed until optional containerisation in Phase 7).
- The project lives under OneDrive; `.venv` and `node_modules` sync slowly. If sync
  causes file locks, exclude those folders from OneDrive or move the repo.
- `gh` CLI is not installed; GitHub operations use plain `git`.

## Next steps (exact)

1. **Phase 2 — audit chain**
   - Add SQLAlchemy 2 + Alembic (SQLite), `audit_events` table: `seq` (unique,
     monotonically increasing), `ts`, `event_type`, `actor`, `request_id`,
     `payload` (canonical JSON of safe metadata only), `prev_hash`, `hash`.
   - Canonical JSON (sorted keys, no whitespace, UTF-8, ISO-8601 UTC timestamps).
   - `hash = HMAC-SHA256(GUARDRAIL_AUDIT_KEY, prev_hash || canonical_event)`; genesis
     prev_hash = 64 zeros; separate key from the fingerprint key.
   - Single-writer append: transaction + `UNIQUE(seq)` + retry on conflict; test with
     concurrent writers.
   - Verifier that reports the first broken sequence; tests for modification,
     deletion (truncation), reordering, insertion, and wrong-key forgery.
   - Signed checkpoints of the chain head using Ed25519 (`cryptography`), public
     key exportable for independent verification.
2. Phase 3 — FastAPI gateway using `Guardrail.inspect`, with a mock provider and a
   test proving blocked prompts never reach the provider.
