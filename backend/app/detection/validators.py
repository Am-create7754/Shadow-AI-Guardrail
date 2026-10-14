"""Checksum and structural validators used to suppress false positives.

A regex alone says "this looks like a card number"; a checksum says "this
could actually be one". Every validator takes the raw matched string and
returns ``True`` if the value is structurally valid.
"""

from __future__ import annotations

import ipaddress
import math
import string
from collections import Counter

_DIGITS = frozenset(string.digits)


def digits_only(value: str) -> str:
    return "".join(ch for ch in value if ch in _DIGITS)


def luhn_valid(value: str) -> bool:
    """Luhn mod-10 check (payment card numbers)."""
    digits = digits_only(value)
    if not 12 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# Major issuer prefixes (IIN ranges) - narrows Luhn-valid noise to plausible cards.
def card_issuer_plausible(value: str) -> bool:
    d = digits_only(value)
    n = len(d)
    if d.startswith("4") and n in (13, 16, 19):  # Visa
        return True
    two, four = int(d[:2]), int(d[:4])
    if (51 <= two <= 55 or 2221 <= four <= 2720) and n == 16:  # Mastercard
        return True
    if two in (34, 37) and n == 15:  # Amex
        return True
    if (d.startswith("6011") or d.startswith("65") or 644 <= int(d[:3]) <= 649) and n in (16, 19):
        return True  # Discover
    if 3528 <= four <= 3589 and 16 <= n <= 19:  # JCB
        return True
    if (d.startswith("60") or d.startswith("65") or d.startswith("81") or d.startswith("82")) and (
        n == 16
    ):
        return True  # RuPay (common ranges)
    return two in (36, 38, 30) and n == 14  # Diners


# --- Verhoeff (Aadhaar) -------------------------------------------------------
_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff_valid(value: str) -> bool:
    digits = digits_only(value)
    if not digits:
        return False
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][ord(ch) - 48]]
    return c == 0


def verhoeff_check_digit(payload: str) -> str:
    """Compute the Verhoeff check digit to append to ``payload`` (used by test generators)."""
    inv = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)
    c = 0
    for i, ch in enumerate(reversed(digits_only(payload))):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][ord(ch) - 48]]
    return str(inv[c])


def aadhaar_valid(value: str) -> bool:
    d = digits_only(value)
    # 12 digits, cannot start with 0 or 1, and not a trivially repeated pattern.
    return len(d) == 12 and d[0] not in "01" and len(set(d)) > 2 and verhoeff_valid(d)


# --- IBAN (ISO 13616 mod-97) --------------------------------------------------
_IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AT": 20, "BE": 16, "BG": 22, "CH": 21, "CY": 28, "CZ": 24,
    "DE": 22, "DK": 18, "EE": 20, "ES": 24, "FI": 18, "FR": 27, "GB": 22, "GR": 27,
    "HR": 21, "HU": 28, "IE": 22, "IS": 26, "IT": 27, "LT": 20, "LU": 20, "LV": 21,
    "MT": 31, "NL": 18, "NO": 15, "PL": 28, "PT": 25, "RO": 24, "SA": 24, "SE": 24,
    "SI": 19, "SK": 24, "TR": 26,
}  # fmt: skip


def iban_valid(value: str) -> bool:
    iban = "".join(value.split()).upper()
    if len(iban) < 15 or not iban.isalnum():
        return False
    expected = _IBAN_LENGTHS.get(iban[:2])
    if expected is None or len(iban) != expected:
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(numeric) % 97 == 1


def iban_check_digits(country: str, bban: str) -> str:
    """Return a full valid IBAN for ``country`` + ``bban`` (used by test generators)."""
    rearranged = bban + country + "00"
    numeric = "".join(str(int(ch, 36)) for ch in rearranged.upper())
    check = 98 - int(numeric) % 97
    return f"{country}{check:02d}{bban}"


# --- Misc ---------------------------------------------------------------------
def ssn_valid(value: str) -> bool:
    d = digits_only(value)
    if len(d) != 9:
        return False
    area, group, serial = d[:3], d[3:5], d[5:]
    return area not in ("000", "666") and area[0] != "9" and group != "00" and serial != "0000"


_RFC1918 = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


def private_ipv4(value: str) -> bool:
    """True only for RFC 1918 ranges.

    ``ipaddress.is_private`` is deliberately not used: it also covers loopback and
    the documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24), which are
    not internal infrastructure.
    """
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return any(ip in net for net in _RFC1918)


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character."""
    if not value:
        return 0.0
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in Counter(value).values())


def char_class_count(value: str) -> int:
    classes = 0
    classes += any(c.islower() for c in value)
    classes += any(c.isupper() for c in value)
    classes += any(c.isdigit() for c in value)
    classes += any(not c.isalnum() for c in value)
    return classes
