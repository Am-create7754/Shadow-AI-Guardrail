"""Offset-preserving text normalisation.

Attackers (or copy/paste from rich editors) can hide secrets from naive regexes
with invisible characters (``AKIA\\u200bXXXX``), combining marks, variation
selectors, full-width forms (``\\uff21\\uff2b\\uff29\\uff21``) or Cyrillic/Greek
look-alike letters. Detection therefore runs on a normalised copy of the text,
and every normalised character keeps a pointer back to its original index so
that redaction is applied to the *original* text at the correct span.

The normalised text is used ONLY for detection; it is never forwarded.

Rules, applied per character:

1. Drop invisible characters: Unicode categories Cf (format: zero-width, bidi,
   tags), Mn/Me (combining marks, variation selectors), Cc (controls other than
   tab/newline/CR), and blank "filler" letters such as Hangul fillers and the
   blank Braille pattern.
2. Fold look-alike Cyrillic/Greek letters to their Latin counterparts.
3. Apply NFKC (full-width -> ASCII, ligatures). Expansions longer than three
   characters (e.g. U+FDFA -> 18 characters) are not applied, which bounds the
   normalised length to at most 3x the input.

Known limitation: a *visible* separator (space, NBSP after NFKC, hyphen) inside
a token is not removed; a user can always deliberately mangle a secret.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

_DROP_CATEGORIES = frozenset({"Cf", "Mn", "Me", "Cc"})
_KEEP_CONTROLS = frozenset({"\t", "\n", "\r"})
# Letters/symbols that render as blank space but are not in a "format" category.
_BLANK_FILLERS = frozenset(
    {
        "\u115f", "\u1160", "\u3164", "\uffa0",  # Hangul fillers
        "\u2800",  # braille pattern blank
        "\u17b4", "\u17b5",  # Khmer inherent vowels
        "\u180b", "\u180c", "\u180d", "\u180e", "\u180f",  # Mongolian selectors / separator
    }
)  # fmt: skip

# Cyrillic and Greek letters that are visually identical to Latin letters.
_CONFUSABLES = str.maketrans(
    {
        # Cyrillic upper
        "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
        "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
        "\u0425": "X", "\u0406": "I", "\u0408": "J", "\u0405": "S", "\u04ae": "Y",
        # Cyrillic lower
        "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
        "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s",
        "\u04bb": "h", "\u0501": "d", "\u051b": "q", "\u051d": "w",
        # Greek upper
        "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z", "\u0397": "H",
        "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N", "\u039f": "O",
        "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y", "\u03a7": "X",
        # Greek lower
        "\u03bf": "o", "\u03b1": "a", "\u03bd": "v", "\u03b9": "i", "\u03ba": "k",
        "\u03c1": "p", "\u03c5": "u",
    }
)  # fmt: skip

_MAX_EXPANSION = 3
# ASCII text without control characters (other than tab/newline/CR) needs no work.
_ASCII_UNSAFE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(frozen=True, slots=True)
class NormalizedText:
    original: str
    text: str
    # index_map[i] = index in ``original`` of the character that produced text[i]
    index_map: tuple[int, ...]

    @property
    def changed(self) -> bool:
        return self.text != self.original

    def to_original_span(self, start: int, end: int) -> tuple[int, int]:
        """Map a half-open span in normalised text back to the original text.

        The mapped span is widened to cover every original character that
        contributed, including invisible characters sitting *inside* the span.
        """
        if start >= end:
            raise ValueError("empty span")
        o_start = self.index_map[start]
        o_end = self.index_map[end - 1] + 1
        return o_start, o_end


def _fold(ch: str) -> str:
    """Normalised replacement for one non-ASCII (or control) character."""
    if ch in _KEEP_CONTROLS:
        return ch
    if ch in _BLANK_FILLERS or unicodedata.category(ch) in _DROP_CATEGORIES:
        return ""
    ch = ch.translate(_CONFUSABLES)
    if ch.isascii():
        return ch
    folded = unicodedata.normalize("NFKC", ch)
    if len(folded) > _MAX_EXPANSION:
        return ch
    # NFKC can itself produce combining marks (e.g. U+00A8 -> " \u0308"); drop them.
    return "".join(c for c in folded if unicodedata.category(c) not in _DROP_CATEGORIES)


def normalize(text: str) -> NormalizedText:
    if text.isascii() and not _ASCII_UNSAFE.search(text):
        return NormalizedText(text, text, tuple(range(len(text))))

    out: list[str] = []
    index_map: list[int] = []
    for i, ch in enumerate(text):
        folded = ch if " " <= ch < "\x7f" else _fold(ch)
        for f in folded:
            out.append(f)
            index_map.append(i)
    return NormalizedText(text, "".join(out), tuple(index_map))
