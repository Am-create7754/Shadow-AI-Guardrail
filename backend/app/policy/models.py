"""Policy configuration schema (validated with Pydantic, loaded from YAML)."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal

import re2  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.detection.models import ENTITY_TYPE_RE, Category, Severity


class Action(StrEnum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"

    @property
    def rank(self) -> int:
        return _ACTION_RANK[self]


_ACTION_RANK = {
    Action.ALLOW: 0,
    Action.REDACT: 1,
    Action.REQUIRE_APPROVAL: 2,
    Action.BLOCK: 3,
}

RuleId = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9\-]{1,63}$")]
EntityType = Annotated[str, Field(pattern=ENTITY_TYPE_RE.pattern)]


def compile_custom_pattern(pattern: str) -> Any:
    """Compile an administrator-supplied pattern with RE2.

    RE2 runs in time linear in the input for every pattern it accepts, so a
    policy author cannot introduce catastrophic backtracking (ReDoS), however
    the pattern is written. RE2 rejects backreferences and lookaround.
    """
    try:
        return re2.compile(pattern)
    except re2.error as exc:
        raise ValueError(f"invalid or unsupported regex for RE2: {exc}") from exc


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CustomTerm(_Strict):
    """Organisation-specific literal, e.g. a project codename or internal hostname."""

    term: str = Field(min_length=2, max_length=200)
    entity_type: EntityType = "CUSTOM_TERM"
    category: Category = Category.CONFIDENTIAL
    severity: Severity = Severity.MEDIUM
    case_sensitive: bool = False
    redact: bool = True

    @field_validator("severity", mode="before")
    @classmethod
    def _sev(cls, v: object) -> object:
        return Severity[v] if isinstance(v, str) else v


class CustomPattern(_Strict):
    rule_id: RuleId
    pattern: str = Field(min_length=3, max_length=500)
    entity_type: EntityType
    category: Category = Category.CONFIDENTIAL
    severity: Severity = Severity.MEDIUM
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    group: int = Field(default=0, ge=0, le=9)
    description: str = Field(default="", max_length=200)

    @field_validator("severity", mode="before")
    @classmethod
    def _sev(cls, v: object) -> object:
        return Severity[v] if isinstance(v, str) else v

    @field_validator("pattern")
    @classmethod
    def _safe_regex(cls, v: str) -> str:
        compiled = compile_custom_pattern(v)
        if compiled.search("") is not None:
            raise ValueError("pattern must not match the empty string")
        return v

    @model_validator(mode="after")
    def _group_exists(self) -> CustomPattern:
        if self.group > compile_custom_pattern(self.pattern).groups:
            raise ValueError("group index exceeds the number of groups in pattern")
        return self


class EntropySettings(_Strict):
    enabled: bool = True
    min_length: int = Field(default=20, ge=12, le=256)
    min_entropy_base64: float = Field(default=4.0, ge=2.5, le=6.0)
    min_entropy_hex: float = Field(default=3.0, ge=2.0, le=4.0)


class Escalation(_Strict):
    # Many sensitive items in one prompt looks like bulk exfiltration (e.g. a pasted
    # customer table) - escalate regardless of the individual actions.
    block_at_findings: int | None = Field(default=25, ge=1)
    approval_at_findings: int | None = Field(default=10, ge=1)
    block_at_risk_score: int | None = Field(default=None, ge=1, le=100)


class PolicyConfig(_Strict):
    version: Literal[1] = 1
    name: str = Field(default="default", max_length=80)
    description: str = Field(default="", max_length=500)
    default_action: Action = Action.ALLOW
    # Findings below this confidence are recorded (monitor mode) but do not act.
    min_confidence: float = Field(default=0.6, ge=0.0, le=1.0)
    category_actions: dict[Category, Action] = Field(default_factory=dict)
    entity_actions: dict[EntityType, Action] = Field(default_factory=dict)
    rule_actions: dict[RuleId, Action] = Field(default_factory=dict)
    escalation: Escalation = Field(default_factory=Escalation)
    disabled_rules: list[RuleId] = Field(default_factory=list)
    custom_terms: list[CustomTerm] = Field(default_factory=list, max_length=500)
    custom_patterns: list[CustomPattern] = Field(default_factory=list, max_length=100)
    entropy: EntropySettings = Field(default_factory=EntropySettings)

    @model_validator(mode="after")
    def _unique_custom_rule_ids(self) -> PolicyConfig:
        ids = [p.rule_id for p in self.custom_patterns]
        if len(ids) != len(set(ids)):
            raise ValueError("custom_patterns contain duplicate rule_id values")
        return self
