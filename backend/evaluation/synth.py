"""Deterministic synthetic sensitive-data generators.

No real or real-looking credential literals are stored in this repository:
vendor prefixes are assembled at runtime and every value is random. This keeps
the dataset safe to publish and avoids tripping secret-scanning push protection.
All emails use reserved example domains (RFC 2606).
"""

from __future__ import annotations

import base64
import json
import random
import string
from collections.abc import Callable

from app.detection.validators import iban_check_digits, verhoeff_check_digit

_ALNUM = string.ascii_letters + string.digits
_B64 = _ALNUM + "+/"
_URLSAFE = _ALNUM + "-_"


def _s(rng: random.Random, alphabet: str, n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def _p(*parts: str) -> str:
    """Join prefix fragments (keeps full vendor prefixes out of source text)."""
    return "".join(parts)


def aws_access_key(rng: random.Random) -> str:
    return _p("AK", "IA") + _s(rng, string.ascii_uppercase + "234567", 16)


def aws_secret_key(rng: random.Random) -> str:
    return _s(rng, _ALNUM + "/+", 40)


def gcp_api_key(rng: random.Random) -> str:
    return _p("AI", "za") + _s(rng, _URLSAFE, 35)


def github_token(rng: random.Random) -> str:
    return _p("gh", "p_") + _s(rng, _ALNUM, 36)


def gitlab_token(rng: random.Random) -> str:
    return _p("glp", "at-") + _s(rng, _ALNUM, 20)


def slack_token(rng: random.Random) -> str:
    return _p("xo", "xb-") + _s(rng, string.digits, 12) + "-" + _s(rng, _ALNUM, 24)


def stripe_key(rng: random.Random) -> str:
    return _p("sk", "_", "li", "ve_") + _s(rng, _ALNUM, 24)


def sendgrid_key(rng: random.Random) -> str:
    return _p("S", "G.") + _s(rng, _URLSAFE, 22) + "." + _s(rng, _URLSAFE, 43)


def npm_token(rng: random.Random) -> str:
    return _p("np", "m_") + _s(rng, _ALNUM, 36)


def openai_key(rng: random.Random) -> str:
    return _p("sk-", "proj-") + _s(rng, _URLSAFE, 24) + _p("T3Blbk", "FJ") + _s(rng, _URLSAFE, 24)


def anthropic_key(rng: random.Random) -> str:
    return _p("sk-", "ant-", "api03-") + _s(rng, _URLSAFE, 93) + "AA"


def jwt(rng: random.Random) -> str:
    def enc(obj: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    header = enc({"alg": "HS256", "typ": "JWT"})
    payload = enc({"sub": str(rng.randint(1000, 99999)), "role": "admin", "iat": 1700000000})
    return f"{header}.{payload}.{_s(rng, _URLSAFE, 43)}"


def private_key(rng: random.Random) -> str:
    lines = [_s(rng, _B64, 64) for _ in range(rng.randint(3, 6))]
    kind = rng.choice(["RSA ", "EC ", "OPENSSH ", ""])
    return "\n".join(
        [f"-----BEGIN {kind}PRIVATE KEY-----", *lines, f"-----END {kind}PRIVATE KEY-----"]
    )


_WORDS = ["river", "falcon", "copper", "maple", "orbit", "velvet", "summit", "ember", "quartz"]


def password(rng: random.Random) -> str:
    style = rng.randint(0, 2)
    if style == 0:
        return rng.choice(_WORDS).capitalize() + rng.choice("!@#$%") + str(rng.randint(10, 9999))
    if style == 1:
        return f"{rng.choice(_WORDS)}_{rng.choice(_WORDS)}_{rng.randint(100, 999)}"
    return _s(rng, _ALNUM + "!@#%^&*", rng.randint(10, 18))


def random_secret(rng: random.Random) -> str:
    """Homegrown high-entropy key with no vendor prefix."""
    return _s(rng, _ALNUM, rng.choice([24, 32, 40]))


def email(rng: random.Random) -> str:
    first = rng.choice(["asha", "rahul", "jane", "omar", "li", "maria", "dev", "priya"])
    last = rng.choice(["sharma", "doe", "khan", "chen", "garcia", "iyer", "smith"])
    dom = rng.choice(["example.com", "example.org", "example.net", "corp.example.com"])
    return f"{first}.{last}{rng.randint(1, 99)}@{dom}"


def credit_card(rng: random.Random) -> str:
    prefix = rng.choice(["4", "51", "52", "55", "2221"])
    body = prefix + "".join(rng.choice(string.digits) for _ in range(15 - len(prefix)))
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            d = d - 9 if d > 9 else d
        total += d
    digits = body + str((10 - total % 10) % 10)
    if rng.random() < 0.5:
        return " ".join(digits[i : i + 4] for i in range(0, 16, 4))
    return digits


def aadhaar(rng: random.Random) -> str:
    while True:
        payload = str(rng.randint(2, 9)) + "".join(rng.choice(string.digits) for _ in range(10))
        if len(set(payload)) > 3:
            break
    full = payload + verhoeff_check_digit(payload)
    return f"{full[:4]} {full[4:8]} {full[8:]}" if rng.random() < 0.6 else full


def pan(rng: random.Random) -> str:
    up = string.ascii_uppercase
    return (
        _s(rng, up, 3)
        + rng.choice("PCHFT")
        + rng.choice(up)
        + _s(rng, string.digits, 4)
        + rng.choice(up)
    )


def ssn(rng: random.Random) -> str:
    return f"{rng.randint(100, 665):03d}-{rng.randint(1, 99):02d}-{rng.randint(1, 9999):04d}"


def iban(rng: random.Random) -> str:
    return iban_check_digits("DE", "".join(rng.choice(string.digits) for _ in range(18)))


def phone_in(rng: random.Random) -> str:
    n = str(rng.randint(6, 9)) + "".join(rng.choice(string.digits) for _ in range(9))
    return rng.choice([f"+91 {n[:5]} {n[5:]}", f"+91-{n}", n, f"{n[:5]} {n[5:]}"])


def private_ip(rng: random.Random) -> str:
    return rng.choice(
        [
            f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
            f"192.168.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
            f"172.{rng.randint(16, 31)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
        ]
    )


def employee_id(rng: random.Random) -> str:
    return f"EMP-{rng.randint(100000, 999999)}"


Generator = Callable[[random.Random], str]

# name -> (generator, entity types that count as a correct classification)
GENERATORS: dict[str, tuple[Generator, frozenset[str]]] = {
    "AWS_ACCESS_KEY": (aws_access_key, frozenset({"AWS_ACCESS_KEY"})),
    "AWS_SECRET_KEY": (aws_secret_key, frozenset({"AWS_SECRET_KEY", "HIGH_ENTROPY_SECRET"})),
    "GCP_API_KEY": (gcp_api_key, frozenset({"GCP_API_KEY"})),
    "GITHUB_TOKEN": (github_token, frozenset({"GITHUB_TOKEN"})),
    "GITLAB_TOKEN": (gitlab_token, frozenset({"GITLAB_TOKEN"})),
    "SLACK_TOKEN": (slack_token, frozenset({"SLACK_TOKEN"})),
    "STRIPE_KEY": (stripe_key, frozenset({"STRIPE_KEY"})),
    "SENDGRID_KEY": (sendgrid_key, frozenset({"SENDGRID_KEY"})),
    "NPM_TOKEN": (npm_token, frozenset({"NPM_TOKEN"})),
    "OPENAI_KEY": (openai_key, frozenset({"OPENAI_KEY"})),
    "ANTHROPIC_KEY": (anthropic_key, frozenset({"ANTHROPIC_KEY"})),
    "JWT": (jwt, frozenset({"JWT", "BEARER_TOKEN"})),
    "PRIVATE_KEY": (private_key, frozenset({"PRIVATE_KEY"})),
    "PASSWORD": (password, frozenset({"PASSWORD", "CONNECTION_PASSWORD", "SECRET_VALUE"})),
    "RANDOM_SECRET": (
        random_secret,
        frozenset({"HIGH_ENTROPY_SECRET", "SECRET_VALUE", "PASSWORD", "BEARER_TOKEN"}),
    ),
    "EMAIL": (email, frozenset({"EMAIL"})),
    "CREDIT_CARD": (credit_card, frozenset({"CREDIT_CARD"})),
    "AADHAAR": (aadhaar, frozenset({"AADHAAR"})),
    "PAN": (pan, frozenset({"PAN"})),
    "SSN": (ssn, frozenset({"SSN"})),
    "IBAN": (iban, frozenset({"IBAN"})),
    "PHONE": (phone_in, frozenset({"PHONE"})),
    "INTERNAL_IP": (private_ip, frozenset({"INTERNAL_IP"})),
    "EMPLOYEE_ID": (employee_id, frozenset({"EMPLOYEE_ID"})),
}
