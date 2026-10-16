"""Dashboard metrics computed from audit events (no separate counters to drift).

Only metadata already present in the audit log is used - actions, entity types,
rule ids, risk scores, model names - so metrics can never expose prompt text.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from app.audit.schemas import AuditRecord

# Audit event -> the decision it represents in charts.
_DECISION_EVENTS = {
    "chat.forwarded": None,  # action taken from data["action"] (ALLOW / REDACT)
    "chat.blocked": "BLOCK",
    "chat.approval_required": "REQUIRE_APPROVAL",
}
# Dry runs (/v1/inspect, the playground's "Inspect only") are not requests: a
# prompt inspected and then sent would otherwise be counted twice.
_INSPECTION_EVENT = "prompt.inspected"
_ACTIONS = ("ALLOW", "REDACT", "REQUIRE_APPROVAL", "BLOCK")


def _bucket(ts: str, hours: int) -> str:
    """Hourly buckets for windows up to 2 days, daily buckets beyond."""
    dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    if hours <= 48:
        return dt.strftime("%Y-%m-%dT%H:00Z")
    return dt.strftime("%Y-%m-%d")


def window_start(hours: int, now: datetime | None = None) -> str:
    start = (now or datetime.now(UTC)) - timedelta(hours=hours)
    return start.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def compute_metrics(events: list[AuditRecord], hours: int) -> dict[str, Any]:
    actions: Counter[str] = Counter()
    entities: Counter[str] = Counter()
    output_entities: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    code_rules: Counter[str] = Counter()
    models: Counter[str] = Counter()
    event_types: Counter[str] = Counter()
    risk_bands: Counter[str] = Counter()
    series: dict[str, Counter[str]] = {}
    active_users: set[str] = set()
    sources: Counter[str] = Counter()

    for e in events:
        event_types[e.event_type] += 1
        data = e.data
        if e.event_type == _INSPECTION_EVENT:
            source = data.get("source")
            sources[source if isinstance(source, str) else "api"] += 1
            continue
        if e.event_type == "chat.forwarded" and "approval_id" in data:
            continue  # execution of an approval already counted as REQUIRE_APPROVAL
        if e.event_type in _DECISION_EVENTS:
            action = _DECISION_EVENTS[e.event_type] or str(data.get("action", "ALLOW"))
            if action not in _ACTIONS:
                continue
            actions[action] += 1
            series.setdefault(_bucket(e.recorded_at, hours), Counter())[action] += 1
            active_users.add(e.actor)
            for etype, n in (data.get("entities") or {}).items():
                if isinstance(n, int):
                    entities[str(etype)] += n
            for rule in data.get("rules") or []:
                rules[str(rule)] += 1
            score = data.get("risk_score")
            if isinstance(score, int):
                band = (
                    "none"
                    if score == 0
                    else "low"
                    if score < 30
                    else "medium"
                    if score < 60
                    else "high"
                    if score < 85
                    else "critical"
                )
                risk_bands[band] += 1
            if isinstance(data.get("model"), str):
                models[data["model"]] += 1
        elif e.event_type in ("chat.completed", "chat.output_blocked"):
            for etype, n in (data.get("output_entities") or {}).items():
                if isinstance(n, int):
                    output_entities[str(etype)] += n
            for rule in data.get("code_findings") or []:
                code_rules[str(rule)] += 1

    timeline = [{"bucket": b, **{a: series[b].get(a, 0) for a in _ACTIONS}} for b in sorted(series)]
    total = sum(actions.values())
    protected = actions["REDACT"] + actions["BLOCK"] + actions["REQUIRE_APPROVAL"]
    return {
        "window_hours": hours,
        "events": len(events),
        "requests": total,
        "protected_requests": protected,
        "protection_rate": round(protected / total, 4) if total else 0.0,
        "active_users": len(active_users),
        "actions": {a: actions.get(a, 0) for a in _ACTIONS},
        "timeline": timeline,
        "top_entities": entities.most_common(10),
        "top_rules": rules.most_common(10),
        "output_entities": output_entities.most_common(10),
        "code_findings": code_rules.most_common(10),
        "risk_bands": {
            b: risk_bands.get(b, 0) for b in ("none", "low", "medium", "high", "critical")
        },
        "models": models.most_common(10),
        "event_types": dict(sorted(event_types.items())),
        "provider_errors": event_types.get("chat.provider_error", 0),
        "output_blocked": event_types.get("chat.output_blocked", 0),
        "inspections": event_types.get(_INSPECTION_EVENT, 0),
        # Where inspect-only checks came from: "api" or "extension:<site>".
        "inspection_sources": sources.most_common(10),
        "failed_logins": event_types.get("auth.login_failed", 0),
    }
