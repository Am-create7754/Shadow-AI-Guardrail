from __future__ import annotations

import pytest

from app.detection.normalize import normalize


def test_ascii_is_identity() -> None:
    nt = normalize("plain ascii text")
    assert nt.text == "plain ascii text"
    assert not nt.changed
    assert nt.to_original_span(6, 11) == (6, 11)


def test_zero_width_removed_and_span_maps_back() -> None:
    original = "key AB\u200bCD end"
    nt = normalize(original)
    assert nt.text == "key ABCD end"
    start = nt.text.index("ABCD")
    o_start, o_end = nt.to_original_span(start, start + 4)
    # The mapped span covers the hidden character too, so redaction removes all of it.
    assert original[o_start:o_end] == "AB\u200bCD"


def test_fullwidth_folded() -> None:
    nt = normalize("\uff21\uff2b\uff29\uff21")
    assert nt.text == "AKIA"
    assert nt.to_original_span(0, 4) == (0, 4)


@pytest.mark.parametrize("ch", ["\u200b", "\u200d", "\u2060", "\ufeff", "\u202e", "\u00ad"])
def test_each_invisible_character_is_stripped(ch: str) -> None:
    assert normalize(f"a{ch}b").text == "ab"


def test_empty_span_rejected() -> None:
    with pytest.raises(ValueError, match="empty span"):
        normalize("abc").to_original_span(1, 1)
