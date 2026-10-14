from __future__ import annotations

from app.detection.engine import DetectionEngine
from app.detection.models import Category, DetectorKind, Finding, Severity
from app.detection.redaction import redact

KEY = b"k" * 32


def _scan_redact(engine: DetectionEngine, text: str) -> tuple[str, dict[str, str]]:
    result = redact(text, engine.scan(text).redactable, KEY)
    return result.text, result.mapping


def test_typed_numbered_placeholders(engine: DetectionEngine) -> None:
    text = "a@example.com, b@example.org and db_password=hunter2hunter"
    out, mapping = _scan_redact(engine, text)
    assert out == "[EMAIL_1], [EMAIL_2] and db_password=[PASSWORD_1]"
    assert mapping == {
        "[EMAIL_1]": "a@example.com",
        "[EMAIL_2]": "b@example.org",
        "[PASSWORD_1]": "hunter2hunter",
    }


def test_same_value_gets_same_placeholder(engine: DetectionEngine) -> None:
    out, mapping = _scan_redact(engine, "to a@example.com cc a@example.com")
    assert out == "to [EMAIL_1] cc [EMAIL_1]"
    assert len(mapping) == 1


def test_user_supplied_placeholder_text_is_not_reused(engine: DetectionEngine) -> None:
    text = "[PASSWORD_1] is fake but db_password=realSecret99 is real"
    out, mapping = _scan_redact(engine, text)
    assert out.startswith("[PASSWORD_1] is fake")
    assert "[PASSWORD_2]" in out
    assert mapping == {"[PASSWORD_2]": "realSecret99"}


def test_mapping_not_in_repr(engine: DetectionEngine) -> None:
    result = redact(
        "db_password=hunter2hunter", engine.scan("db_password=hunter2hunter").findings, KEY
    )
    assert "hunter2hunter" not in repr(result)


def test_non_redactable_findings_left_in_place(engine: DetectionEngine) -> None:
    text = "STRICTLY CONFIDENTIAL memo"
    out, mapping = _scan_redact(engine, text)
    assert out == text
    assert not mapping


def _fd(s: int, e: int, etype: str, sev: Severity) -> Finding:
    return Finding(
        "r-" + etype.lower(), etype, Category.SECRET, sev, 0.9, DetectorKind.REGEX, s, e, "v"
    )


def test_overlapping_findings_redacted_as_one_union_region() -> None:
    text = "0123456789ABCDEF"
    result = redact(
        text, [_fd(0, 6, "PASSWORD", Severity.HIGH), _fd(4, 12, "CARD", Severity.CRITICAL)], KEY
    )
    assert result.text == "[CARD_1]CDEF"
    assert result.mapping == {"[CARD_1]": "0123456789AB"}


def test_lookalike_placeholders_in_input_are_reserved(engine: DetectionEngine) -> None:
    text = "\uff3bPASSWORD_1\uff3d and [PASSWORD\u200b_2] but db_password=realSecret99"
    out, mapping = _scan_redact(engine, text)
    assert list(mapping) == ["[PASSWORD_3]"]
    assert out.endswith("db_password=[PASSWORD_3]")


def test_zero_width_characters_inside_secret_are_removed_with_it(engine: DetectionEngine) -> None:
    text = "key " + "AK" + "IA\u200bABCDEFGHIJKLMNOP!"  # split prefix: repo hygiene
    out, _ = _scan_redact(engine, text)
    assert out == "key [AWS_ACCESS_KEY_1]!"
