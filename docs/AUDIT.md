# Tamper-Evident Audit Log

The gateway records every security decision (prompt inspected, request blocked,
policy changed, ...) in an append-only log whose integrity can be verified
independently. This document describes the design, the exact guarantees, the
limits, and how to operate it.

## 1. What is recorded

Only **safe metadata**: event type, actor id, request id, timestamps and a small
JSON `data` object (decision, risk score, entity types, placeholders, keyed
fingerprints). Raw prompts, secret values and placeholder→value mappings are
never written. As a defence-in-depth check, `AuditLog.append` runs the detection
engine over every decoded key and string value of each event (plus `key=value`
pairs and joined list items, so escaped quotes or a card split across a list are
still seen) and **rejects** any event containing a secret or payment card number.
The error names the entity type, never the value. Encoded secrets (base64,
reversed) are not decoded — the same limitation as the detection engine.

## 2. Record format

| Column | Meaning |
|---|---|
| `seq` | 1, 2, 3, … contiguous, primary key |
| `event_id` | random 128-bit id |
| `occurred_at`, `recorded_at` | ISO-8601 UTC strings, stored exactly as authenticated |
| `event_type`, `actor`, `request_id` | validated identifiers |
| `data` | canonical JSON text (sorted keys, no whitespace, UTF-8, no NaN) |
| `prev_hash` | `hash` of event `seq − 1` (genesis: 64 zeros); `UNIQUE` |
| `hash` | `HMAC-SHA256(audit_key, "guardrail-audit-chain-v1\n" ‖ canonical(record))` |
| `key_id` | identifier of the HMAC key used (supports rotation) |

`canonical(record)` covers **every** column above except `hash` itself, plus a
format version — so `seq` and `prev_hash` are authenticated too.

## 3. Integrity layers

| Layer | Protects against | Implemented in |
|---|---|---|
| HMAC chain | Any edit, insertion, deletion or reordering of events by someone **without** the HMAC key | `app/audit/chain.py`, `service.py` |
| Chain-head row | Deleting the newest events (truncation) | `audit_chain_head` |
| Serialised appends + `UNIQUE(prev_hash)` | Concurrent writers forking the chain or skipping/duplicating `seq` | `BEGIN IMMEDIATE` (SQLite) / `SELECT … FOR UPDATE` (PostgreSQL) |
| Append-only triggers | `UPDATE`, `DELETE` and `INSERT OR REPLACE` through ordinary SQL (a guard against mistakes — anyone with direct DB access can drop triggers) | migration `0001`, `models.py` |
| Ed25519-signed checkpoints, bound to the chain's first event | Rollback and history rewrites — **only when a checkpoint is kept outside the database** (anchor file or export) | `keys.py`, `service.py` |
| Anchor file (outside the DB) | Rollback / wipe / restoring an old backup by someone who can change the DB but not the anchor file | `GUARDRAIL_AUDIT_ANCHOR_PATH` |
| Key rotation order | A retired (possibly leaked) audit key signing events newer than ones signed by its successor | `AuditKeyring.rank` |

## 4. Verification

`AuditLog.verify()` (or `python -m app.audit verify`) streams events in `seq`
order in batches of 1,000 and reports each problem at the sequence number where
it occurs:

| Issue kind | Meaning |
|---|---|
| `mac` | Event content does not match its MAC (modified or forged) |
| `link` | `prev_hash` does not match the previous event (insertion/deletion/reordering) |
| `gap` | Sequence numbers missing |
| `unknown_key` | Event claims a key id the verifier does not hold |
| `retired_key` | Event signed with a key older than one already used earlier in the chain |
| `malformed` / `oversized` | Row has wrong column types or implausibly large data (reported, never crashes the verifier) |
| `non_canonical` | Stored data is not canonical JSON |
| `head_mismatch` / `head_missing` | Head row disagrees with the end of the chain (truncation) |
| `checkpoint_signature` | Checkpoint not signed by a trusted public key |
| `checkpoint_mismatch` | Event hash at a checkpointed `seq` differs from the signed value (history rewritten) |
| `checkpoint_beyond_chain` | A checkpoint attests events that no longer exist (truncation, wipe, rollback) |
| `checkpoint_foreign` | Checkpoint was signed for a different chain (different first event) |
| `checkpoint_malformed` | A stored checkpoint row is invalid (reported, never crashes the verifier) |
| `anchor_missing` / `anchor_malformed` | The anchor file is gone or corrupt although checkpoints exist |

Per-event issues are capped at 100 in a report; head, checkpoint and anchor
findings are always included, so the cap cannot hide a rollback.

## 5. Threat model and honest limits

| Attacker | Can do | Detected by |
|---|---|---|
| Write access to the DB, **no keys** — edits, inserts, deletes or reorders events in the middle | anything | the HMAC chain — always, located by `seq` |
| Same, **rolls the DB back** (deletes newest events + head + newest checkpoints, wipes everything, or restores an old backup) | leaves only genuine rows | **only** a checkpoint outside the DB: the anchor file or an exported checkpoint |
| Holds a **retired** audit key | sign events after newer-key events | `retired_key` |
| Holds the **current audit key** and DB write access | rebuild a consistent history and head | only a checkpoint outside the DB, verified with the Ed25519 **public** key (the signing key must not be on the same host) |
| Also controls the anchor file and every exported checkpoint | everything | not detectable — the trust anchor is gone |

Consequences, stated plainly:

* **Rollback cannot be detected from inside the database.** Every remaining
  row is genuine. This is why the anchor file exists (on by default, stored
  outside the database) and why checkpoints should also be exported to storage
  the application host cannot modify. Both are tested:
  `test_rollback_detected_by_anchor_file` and
  `test_rollback_undetectable_without_external_anchor`.
* The default anchor lives on the **same machine** (`%LOCALAPPDATA%\guardrail\anchors`).
  It defeats database-level attackers (SQL access, a DBA, a restored backup) but
  not someone with full control of the host. Exported checkpoints on another
  system are the defence for that case.
* Events written **after the newest external checkpoint** can be rewritten by a
  full-key attacker; the checkpoint interval bounds that window.
* Concurrent processes writing checkpoints can briefly leave the anchor one
  checkpoint behind (the write is atomic but not locked); the next checkpoint
  advances it.
* The log is **tamper-evident, not tamper-proof**, and availability (deleting
  the database *and* the anchor) is out of scope — back up both.

## 6. Key management

| Key | Type | Configure with | Notes |
|---|---|---|---|
| Audit key | HMAC-SHA256, ≥ 32 bytes | `GUARDRAIL_AUDIT_KEY` | Must differ from the fingerprint key (enforced). |
| Retired audit keys | same | `GUARDRAIL_AUDIT_PREVIOUS_KEYS` (comma-separated) | Lets old events verify after rotation. |
| Checkpoint signing key | Ed25519 PKCS#8 PEM | `GUARDRAIL_CHECKPOINT_KEY_PATH` | Only the public key is needed to verify. |

* **Production** refuses to start without the audit key and the checkpoint key path.
* **Development** generates both keys once and stores them in
  `%LOCALAPPDATA%\guardrail\keys` (Windows) or `~/.local/share/guardrail/keys` —
  deliberately outside the repository, because the repository may sit in a synced
  folder (OneDrive) that would upload keys to the cloud.
* **Tests** use throw-away in-memory keys.
* Key ids are truncated SHA-256 hashes of the key (HMAC) or public key (Ed25519);
  they identify keys without revealing them.

**Rotation:** set the new key as `GUARDRAIL_AUDIT_KEY` and move the old one to
`GUARDRAIL_AUDIT_PREVIOUS_KEYS` (oldest first). New events use the new key; old
events still verify. Once the new key has signed an event, any later event
signed with an older key is rejected (`retired_key`). Removing an old key makes
its events report `unknown_key`. Retired checkpoint public keys can be kept
trusted with `GUARDRAIL_CHECKPOINT_TRUSTED_KEYS` (comma-separated PEM paths).

**Who needs which key:** appending needs the audit key and (for checkpoints)
the signing key. Verifying needs the audit key — an HMAC cannot be checked
without it — but only the **public** half of the signing key:
`verify --public-key pub.pem` never loads the private key, and `verify` never
generates keys (missing keys are an error, not a reason to invent new ones).
All key-length rules (≥ 32 bytes) apply to current keys, retired keys and key files.

## 7. Operating it (PowerShell, from `backend/`)

```powershell
.venv\Scripts\python -m app.audit init-db                         # migrations + dev keys
.venv\Scripts\python -m app.audit verify                          # exit 1 on any issue
.venv\Scripts\python -m app.audit checkpoint                      # sign current head now
.venv\Scripts\python -m app.audit export-checkpoints cps.json     # copy off-host
.venv\Scripts\python -m app.audit export-public-key pub.pem
.venv\Scripts\python -m app.audit verify --checkpoints cps.json   # verify against export
.venv\Scripts\python -m app.audit verify --public-key pub.pem    # without the private signing key
.venv\Scripts\python -m app.audit tamper-demo                     # self-contained demo
```

## 8. Database portability

Models and the migration are portable SQLAlchemy. The SQLite path is fully
tested (including multi-process writers). The PostgreSQL path (`FOR UPDATE` head
lock, PL/pgSQL row and `TRUNCATE` triggers) is implemented but **not yet tested**
against a PostgreSQL server.
