"""Inspection of model output, for complete answers and for streams.

Complete answers (:meth:`OutputInspector.inspect`) are scanned with the same
detection engine as prompts, then handled by the *output* policy: findings are
allowed, redacted (typed placeholders) or cause the answer to be withheld.
Fenced code blocks (including an unclosed final block) are checked for
insecure patterns. If the scan hits its candidate cap, the answer is withheld
(fail closed), exactly as for prompts.

Streams (:class:`StreamGuard`) must reach the client promptly, yet no part of a
secret may be released before the whole secret has arrived and been checked.
Text is released only up to a *cut* that is never

* within the last ``HOLD`` characters received (room for spaced values such as
  card numbers and for patterns that need trailing context),
* inside a run of non-whitespace characters (a key, URL or password may still
  be growing - no length or character-set assumption is needed),
* inside any detection, including an open one at the tail (e.g. a private-key
  block whose END line has not arrived), and
* inside an open fenced code block when code checks may block the answer.

Further guarantees:

* Every secret detected in the stream is remembered; later repeats of it are
  redacted even when the context that identified it was released long ago.
* Held text is bounded (``MAX_HELD``): a run that never ends is withheld rather
  than buffered without limit (fail closed), and rescans happen at
  geometrically growing intervals while text is held, keeping the total work
  close to linear in the answer length.

Known limitation: if a value first appears *bare* and only later becomes
recognisable as a secret (e.g. ``Tr0ub4dor`` ... ``password=Tr0ub4dor``), the
first occurrence may already have been released; avoiding that would require
holding the entire answer. Complete (non-streamed) answers are not affected.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Any

from app.core.config import Settings
from app.detection.engine import DetectionEngine
from app.detection.models import Category, Finding
from app.detection.redaction import PlaceholderAllocator, redact
from app.output.code_checks import CodeBlock, CodeFinding, FenceParser, check_block, check_code
from app.policy.engine import build_detection_engine
from app.policy.models import CodeCheckMode, OutputAction, PolicyConfig

_NON_SPACE = re.compile(r"\S")
MIN_REMEMBERED_LEN = 6
MAX_REMEMBERED = 200


@dataclass
class OutputResult:
    action: OutputAction
    text: str  # what the client may see ("" when blocked)
    entities: dict[str, int] = field(default_factory=dict)
    placeholders: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    code_findings: list[CodeFinding] = field(default_factory=list)
    reason: str | None = None

    def to_public(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "entities": self.entities,
            "placeholders": self.placeholders,
            "code_findings": [f.to_public() for f in self.code_findings],
            "reason": self.reason,
        }

    def audit_summary(self) -> dict[str, Any]:
        return {
            "output_action": self.action.value,
            "output_entities": self.entities,
            "output_rules": self.rules,
            "code_findings": sorted({f.rule_id for f in self.code_findings}),
        }


class OutputInspector:
    def __init__(self, policy: PolicyConfig, settings: Settings) -> None:
        self.policy = policy.output
        self.detector: DetectionEngine = build_detection_engine(
            policy, max_input_chars=settings.provider_max_output_chars
        )
        self.key = settings.fingerprint_key_bytes()

    def allocator(self, reserved_texts: list[str]) -> PlaceholderAllocator:
        """Allocator that never reuses placeholders already present in the prompt."""
        return PlaceholderAllocator(self.key, reserved_texts)

    def action_for(self, f: Finding) -> OutputAction:
        if f.confidence < self.policy.min_confidence or not f.redactable:
            return OutputAction.ALLOW
        if f.entity_type in self.policy.entity_actions:
            return self.policy.entity_actions[f.entity_type]
        return self.policy.category_actions.get(f.category, OutputAction.ALLOW)

    @property
    def code_mode(self) -> CodeCheckMode:
        return self.policy.code.mode

    def code_blocks_answer(self, findings: list[CodeFinding]) -> bool:
        """True if code findings require withholding the answer."""
        if self.code_mode is not CodeCheckMode.BLOCK:
            return False
        return any(f.severity >= self.policy.code.block_at for f in findings)

    def code_findings(self, text: str) -> list[CodeFinding]:
        return [] if self.code_mode is CodeCheckMode.OFF else check_code(text)

    def inspect(self, text: str, allocator: PlaceholderAllocator) -> OutputResult:
        allocator.reserve_from(text)
        scan = self.detector.scan(text)
        acted = [(f, self.action_for(f)) for f in scan.findings]
        entities = _count(f for f, a in acted if a is not OutputAction.ALLOW)
        rules = sorted({f.rule_id for f, a in acted if a is not OutputAction.ALLOW})
        code = self.code_findings(text)
        if scan.truncated:
            return OutputResult(
                OutputAction.BLOCK, "", entities, [], rules, code,
                "too many detections to inspect the answer safely",
            )  # fmt: skip
        blocking = sorted({f.entity_type for f, a in acted if a is OutputAction.BLOCK})
        if blocking:
            return OutputResult(
                OutputAction.BLOCK, "", entities, [], rules, code,
                f"answer contained {', '.join(blocking)}",
            )  # fmt: skip
        if self.code_blocks_answer(code):
            return OutputResult(
                OutputAction.BLOCK, "", entities, [], rules, code,
                "generated code failed security checks",
            )  # fmt: skip
        to_redact = [f for f, a in acted if a is OutputAction.REDACT]
        result = redact(text, to_redact, self.key, allocator)
        action = OutputAction.REDACT if result.replacements else OutputAction.ALLOW
        placeholders = sorted({r.placeholder for r in result.replacements})
        return OutputResult(action, result.text, entities, placeholders, rules, code)


def _count(findings: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.entity_type] = counts.get(f.entity_type, 0) + 1
    return dict(sorted(counts.items()))


class StreamGuard:
    """Incrementally inspect and release a streamed answer (see module docstring)."""

    HOLD = 128  # never release the newest characters
    CONTEXT = 256  # released text kept for context-dependent rules (password=...)
    RESCAN_EVERY = 32  # minimum new characters between rescans
    MAX_HELD = 16_384  # longest text the guard will hold back; beyond it, fail closed

    def __init__(self, inspector: OutputInspector, allocator: PlaceholderAllocator) -> None:
        self.inspector = inspector
        self.allocator = allocator
        self._buf = ""  # received, not yet released (original text)
        self._ctx = ""  # tail of released original text
        self._full: list[str] = []  # whole original answer (annotate-mode code checks)
        self._since_scan = 0
        self._known: dict[str, Finding] = {}  # secret value -> finding that identified it
        self.blocked: str | None = None
        self.entities: dict[str, int] = {}
        self.rules: set[str] = set()
        self.placeholders: set[str] = set()
        self.code_findings: list[CodeFinding] = []
        # Block-mode code tracking (incremental, line by line).
        self._fences = FenceParser()
        self._received = 0  # total characters received
        self._parsed = 0  # characters consumed by the fence parser
        self._pending_line = ""
        self._released_total = 0
        self._block_index = 0

    # ------------------------------------------------------------------ public
    def feed(self, delta: str) -> str:
        if self.blocked:
            return ""
        self._buf += delta
        self._full.append(delta)
        self._received += len(delta)
        self._since_scan += len(delta)
        # Geometric back-off while text is held keeps total rescans ~linear.
        if self._since_scan < max(self.RESCAN_EVERY, len(self._buf) // 4):
            return ""
        self._since_scan = 0
        out = self._release(final=False)
        if not self.blocked and len(self._buf) > self.MAX_HELD:
            self._block(f"answer held back more than {self.MAX_HELD} characters")
            return ""
        return out

    def finish(self) -> str:
        if self.blocked:
            return ""
        out = self._release(final=True)
        if not self.blocked and self.inspector.code_mode is CodeCheckMode.ANNOTATE:
            self.code_findings = self.inspector.code_findings("".join(self._full))
        return out

    @property
    def result(self) -> OutputResult:
        if self.blocked:
            action = OutputAction.BLOCK
        else:
            action = OutputAction.REDACT if self.placeholders else OutputAction.ALLOW
        return OutputResult(
            action, "", dict(sorted(self.entities.items())), sorted(self.placeholders),
            sorted(self.rules), self.code_findings, self.blocked,
        )  # fmt: skip

    # --------------------------------------------------------------- internals
    def _release(self, *, final: bool) -> str:
        text = self._ctx + self._buf
        offset = len(self._ctx)
        scan = self.inspector.detector.scan(text)
        if scan.truncated:
            self._block("too many detections to inspect the answer safely")
            return ""
        findings: list[tuple[Finding, OutputAction]] = []
        for f in scan.findings:
            if f.end <= offset:
                continue  # entirely in already-released context
            local = replace(f, start=max(f.start - offset, 0), end=f.end - offset)
            findings.append((local, self.inspector.action_for(f)))
        findings += self._repeats_of_known_secrets(findings)

        if any(a is OutputAction.BLOCK for _, a in findings):
            types = sorted({f.entity_type for f, a in findings if a is OutputAction.BLOCK})
            self._block(f"answer contained {', '.join(types)}")
            return ""

        cut = len(self._buf) if final else self._safe_cut(findings)
        if self.inspector.code_mode is CodeCheckMode.BLOCK:
            cut = self._code_gate(cut, final)
            if self.blocked:
                return ""
        if cut <= 0:
            return ""

        released = self._buf[:cut]
        inside = [f for f, a in findings if a is OutputAction.REDACT and f.end <= cut]
        for f, a in findings:
            if a is not OutputAction.ALLOW and f.end <= cut:
                self.entities[f.entity_type] = self.entities.get(f.entity_type, 0) + 1
                self.rules.add(f.rule_id)
        for f in inside:
            self._remember(f)
        # Placeholder-shaped text written by the model itself is never reused.
        self.allocator.reserve_from(text)
        result = redact(released, inside, self.inspector.key, self.allocator)
        self.placeholders.update(r.placeholder for r in result.replacements)
        self._ctx = (self._ctx + released)[-self.CONTEXT :]
        self._buf = self._buf[cut:]
        self._released_total += cut
        return result.text

    def _remember(self, f: Finding) -> None:
        if (
            f.category is Category.SECRET
            and len(f.value) >= MIN_REMEMBERED_LEN
            and len(self._known) < MAX_REMEMBERED
        ):
            self._known.setdefault(f.value, f)

    def _repeats_of_known_secrets(
        self, findings: list[tuple[Finding, OutputAction]]
    ) -> list[tuple[Finding, OutputAction]]:
        """Occurrences, in the held buffer, of secrets identified earlier."""
        extra: list[tuple[Finding, OutputAction]] = []
        for value, origin in self._known.items():
            start = self._buf.find(value)
            while start != -1:
                end = start + len(value)
                if not any(f.start < end and start < f.end for f, _ in findings + extra):
                    rep = replace(
                        origin, start=start, end=end,
                        explanation="Repeat of a secret detected earlier in the answer",
                    )  # fmt: skip
                    extra.append((rep, OutputAction.REDACT))
                start = self._buf.find(value, end)
        return extra

    def _safe_cut(self, findings: list[tuple[Finding, OutputAction]]) -> int:
        buf = self._buf
        cut = len(buf) - self.HOLD
        changed = True
        while cut > 0 and changed:
            changed = False
            # Never split a run of non-whitespace (a key or URL may still be growing).
            if _NON_SPACE.match(buf[cut]) and _NON_SPACE.match(buf[cut - 1]):
                while cut > 0 and _NON_SPACE.match(buf[cut - 1]):
                    cut -= 1
                changed = True
            # Never split a detection, including ALLOW ones that may still grow.
            for f, _ in findings:
                if f.start < cut < f.end:
                    cut = f.start
                    changed = True
        return max(cut, 0)

    def _code_gate(self, cut: int, final: bool) -> int:
        """Block mode: parse new complete lines, check each block when it closes,
        and never release past the opening fence of a block that is still open."""
        new = self._pending_line + "".join(self._full)[self._parsed :]
        line_start = self._parsed - len(self._pending_line)
        self._parsed = self._received
        lines = new.split("\n")
        self._pending_line = "" if final else lines.pop()
        for line in lines:
            block = self._fences.line(line.rstrip("\r"), line_start)
            line_start += len(line) + 1
            if block is not None:
                self._check(block)
                if self.blocked:
                    return 0
        if final:
            block = self._fences.end()
            if block is not None:
                self._check(block)
            return 0 if self.blocked else cut
        if self._fences.open is not None:
            cut = min(cut, max(self._fences.open_at - self._released_total, 0))
        elif self._pending_line.lstrip(" ").startswith(("`", "~")):
            # A fence line still being typed (no newline yet) must not be released.
            cut = min(cut, max(line_start - self._released_total, 0))
        return cut

    def _check(self, block: CodeBlock) -> None:
        found = check_block(block, self._block_index)
        self._block_index += 1
        self.code_findings.extend(found)
        if self.inspector.code_blocks_answer(found):
            self._block("generated code failed security checks")

    def _block(self, reason: str) -> None:
        self.blocked = reason
        self._buf = ""
