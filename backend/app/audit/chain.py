"""Canonical encoding and MAC computation for the audit chain (pure functions).

Each stored event is protected by::

    hash_n = HMAC-SHA256(audit_key, DOMAIN || canonical(record_n))

where ``record_n`` contains every stored field of the event *including*
``seq`` and ``prev_hash = hash_{n-1}``. Consequently:

* changing any field of an event changes its MAC              -> "mac" error
* deleting or inserting an event breaks the next link / seq   -> "link"/"gap"
* swapping two events breaks seq order and both links         -> "link"/"mac"
* forging a valid MAC requires the audit key.

Canonical JSON: UTF-8, keys sorted, no insignificant whitespace, no NaN/Infinity.
Timestamps are stored as the exact ISO-8601 strings that were MAC'd, so database
timezone handling can never alter what is verified.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

DOMAIN = b"guardrail-audit-chain-v1\n"
CHECKPOINT_DOMAIN = b"guardrail-audit-checkpoint-v1\n"
GENESIS_HASH = "0" * 64
FORMAT_VERSION = 1


def canonical_json(obj: Any) -> str:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def utc_timestamp(dt: datetime | None = None) -> str:
    """ISO-8601 UTC with microseconds and 'Z' suffix, e.g. 2026-10-14T09:30:00.000000Z."""
    dt = (dt or datetime.now(UTC)).astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def record_payload(
    *,
    seq: int,
    event_id: str,
    occurred_at: str,
    recorded_at: str,
    event_type: str,
    actor: str,
    request_id: str | None,
    data: str,
    prev_hash: str,
    key_id: str,
) -> dict[str, Any]:
    """The exact set of fields covered by an event's MAC."""
    return {
        "v": FORMAT_VERSION,
        "seq": seq,
        "event_id": event_id,
        "occurred_at": occurred_at,
        "recorded_at": recorded_at,
        "event_type": event_type,
        "actor": actor,
        "request_id": request_id,
        "data": data,  # already canonical JSON text
        "prev_hash": prev_hash,
        "key_id": key_id,
    }


def compute_mac(key: bytes, payload: dict[str, Any]) -> str:
    message = DOMAIN + canonical_json(payload).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def macs_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("ascii", "replace"), b.encode("ascii", "replace"))


def checkpoint_message(
    *, seq: int, chain_hash: str, genesis_hash: str, created_at: str, signer_key_id: str
) -> bytes:
    """Signed checkpoint content. ``genesis_hash`` (hash of event 1) binds the
    checkpoint to one specific chain, so it cannot be replayed against another."""
    return CHECKPOINT_DOMAIN + canonical_json(
        {
            "v": FORMAT_VERSION,
            "seq": seq,
            "chain_hash": chain_hash,
            "genesis_hash": genesis_hash,
            "created_at": created_at,
            "signer_key_id": signer_key_id,
        }
    ).encode("utf-8")
