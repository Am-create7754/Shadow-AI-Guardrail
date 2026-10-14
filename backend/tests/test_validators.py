from __future__ import annotations

import random

import pytest

from app.detection import validators as v
from evaluation import synth


@pytest.mark.parametrize("seed", range(25))
def test_generated_values_pass_their_validators(seed: int) -> None:
    rng = random.Random(seed)
    assert v.luhn_valid(synth.credit_card(rng))
    assert v.aadhaar_valid(synth.aadhaar(rng))
    assert v.iban_valid(synth.iban(rng))
    assert v.ssn_valid(synth.ssn(rng))


@pytest.mark.parametrize(
    "number",
    ["4111111111111111", "5500 0000 0000 0004", "3400-000000-00009", "4012888888881881"],
)
def test_luhn_accepts_known_test_cards(number: str) -> None:
    assert v.luhn_valid(number)
    assert v.card_issuer_plausible(number)


@pytest.mark.parametrize("number", ["4111111111111112", "1234567890123456", "12345", ""])
def test_luhn_rejects_invalid(number: str) -> None:
    assert not v.luhn_valid(number)


def test_card_issuer_rejects_unknown_prefix() -> None:
    # Luhn-valid but no major issuer starts with 9.
    assert v.luhn_valid("9000000000000001")
    assert not v.card_issuer_plausible("9000000000000001")


def test_verhoeff_roundtrip_and_single_digit_error() -> None:
    payload = "23412341234"
    full = payload + v.verhoeff_check_digit(payload)
    assert v.verhoeff_valid(full)
    corrupted = full[:5] + str((int(full[5]) + 1) % 10) + full[6:]
    assert not v.verhoeff_valid(corrupted)


@pytest.mark.parametrize("value", ["012345678901", "111111111111", "2222 2222 2222"])
def test_aadhaar_rejects_structurally_invalid(value: str) -> None:
    assert not v.aadhaar_valid(value)


def test_iban_known_examples() -> None:
    assert v.iban_valid("GB82 WEST 1234 5698 7654 32")
    assert v.iban_valid("DE89370400440532013000")
    assert not v.iban_valid("DE89370400440532013001")
    assert not v.iban_valid("XX00123")


@pytest.mark.parametrize("value", ["000-12-3456", "666-12-3456", "912-12-3456", "123-00-4567"])
def test_ssn_rejects_reserved_ranges(value: str) -> None:
    assert not v.ssn_valid(value)


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        ("10.1.2.3", True),
        ("172.16.0.1", True),
        ("172.31.255.254", True),
        ("192.168.1.1", True),
        ("172.32.0.1", False),
        ("8.8.8.8", False),
        ("127.0.0.1", False),
        ("203.0.113.10", False),  # documentation range: is_private in stdlib, not RFC 1918
        ("999.1.1.1", False),
    ],
)
def test_private_ipv4_is_rfc1918_only(ip: str, expected: bool) -> None:
    assert v.private_ipv4(ip) is expected


def test_entropy_ordering() -> None:
    assert v.shannon_entropy("") == 0.0
    assert v.shannon_entropy("aaaaaaaa") == 0.0
    assert v.shannon_entropy("abcdefgh") == pytest.approx(3.0)
    assert v.char_class_count("aB3!") == 4
