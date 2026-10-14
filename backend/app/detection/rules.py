"""Built-in pattern rules.

Design notes
------------
* Every pattern is linear-time friendly: quantifiers are bounded, there are no
  nested quantifiers, and alternations are anchored by literal prefixes. A
  ReDoS regression test (``tests/test_redos.py``) runs every rule against
  pathological inputs.
* ``group`` selects the sensitive part of a match. For ``db_password=hunter2``
  only ``hunter2`` is redacted, so the AI still sees the structure of the code.
* Rules never embed real credentials. Test values are generated at runtime.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol

from app.detection import validators as v
from app.detection.models import Category, DetectorKind, Severity


class MatchLike(Protocol):
    def span(self, group: Any = 0, /) -> tuple[int, int]: ...


class CompiledPattern(Protocol):
    """What the engine needs from a compiled regex.

    Satisfied by ``re.Pattern`` (built-in rules, audited and ReDoS-tested) and by
    ``re2`` patterns (administrator-supplied rules, linear time by construction).
    """

    @property
    def pattern(self) -> str: ...

    def finditer(self, text: str, /) -> Iterator[MatchLike]: ...


Validator = Callable[[str], bool]
# (value, text_after_value) -> keep?  Used to reject code references like os.getenv(...)
ValueCheck = Callable[[str, str], bool]

# Values that are references, types or placeholders rather than literal secrets.
_REFERENCE_RE = re.compile(
    r"(?i)^(?:os\.environ|os\.getenv|getenv|environ|process\.env|env\.|config\.|settings\.|"
    r"self\.|this\.|request\.|req\.|args\.|params\.|props\.|vault\.|secrets\.|"
    r"none|null|nil|true|false|undefined|string|str|int|bool|bytes|optional|any|"
    r"required|input|prompt|getpass|readline|"
    r"await|async|new|yield|return|function|lambda|typeof|hash|bcrypt|argon2)\b"
)
_PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%[A-Za-z_][A-Za-z0-9_]*%|\{\{.*\}\}|"
    r"<[^>]*>|\[[A-Z0-9_]+\]|\*+|x+|\.+|-+|#+|"
    r"(?:your|my|the|some|enter|insert)[_-]?\w*|example\w*|placeholder\w*|"
    r"redacted\w*|dummy\w*|sample\w*|test|testing|todo|fixme|tbd|n/?a)$"
)


def _not_reference(value: str, after: str) -> bool:
    """Reject values that are clearly code references or placeholders, not literals."""
    if after[:1] in ("(", "."):  # function call / attribute chain: tokenizer(...), cfg.x.y
        return False
    if _REFERENCE_RE.match(value) or _PLACEHOLDER_RE.match(value):
        return False
    return len(set(value)) > 2  # "aaaa", "1111"


def _plausible_secret(value: str, after: str) -> bool:
    """Stricter check for generic *secret/token* keys: needs some character diversity."""
    if not _not_reference(value, after):
        return False
    return v.char_class_count(value) >= 2 or len(value) >= 24


@dataclass(frozen=True, slots=True)
class PatternRule:
    rule_id: str
    entity_type: str
    category: Category
    severity: Severity
    pattern: CompiledPattern
    confidence: float
    detector: DetectorKind = DetectorKind.REGEX
    group: int | str = 0
    validator: Validator | None = None
    value_check: ValueCheck | None = None
    # Words that, when found near the match, raise confidence.
    context_keywords: tuple[str, ...] = ()
    context_boost: float = 0.0
    # Words immediately before the match that mean "not sensitive" (e.g. "version 10.2.3.4").
    suppress_keywords: tuple[str, ...] = ()
    redactable: bool = True
    description: str = ""
    tags: tuple[str, ...] = field(default=())


def _rx(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


# Characters that terminate a "bare" secret value in assignments.
_VALUE = r"[^\s\"'`,;<>(){}\[\]]"

BUILTIN_RULES: tuple[PatternRule, ...] = (
    # ------------------------------------------------------------------ cloud
    PatternRule(
        rule_id="aws-access-key-id",
        entity_type="AWS_ACCESS_KEY",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        pattern=_rx(r"(?<![A-Z0-9])((?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})(?![A-Z0-9])"),
        group=1,
        confidence=0.95,
        description="AWS access key ID",
    ),
    PatternRule(
        rule_id="aws-secret-access-key",
        entity_type="AWS_SECRET_KEY",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        pattern=_rx(
            r"(?i)aws_?secret_?(?:access_?)?key[\"']?\s{0,5}(?:=|:|=>)\s{0,5}[\"']?"
            r"([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"
        ),
        group=1,
        confidence=0.95,
        detector=DetectorKind.CONTEXT,
        description="AWS secret access key assignment",
    ),
    PatternRule(
        rule_id="gcp-api-key",
        entity_type="GCP_API_KEY",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_rx(r"(?<![A-Za-z0-9_-])(AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9_-])"),
        group=1,
        confidence=0.9,
        description="Google Cloud / Firebase API key",
    ),
    PatternRule(
        rule_id="gcp-service-account-key",
        entity_type="GCP_SERVICE_ACCOUNT_KEY",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        pattern=_rx(r"\"private_key_id\"\s{0,5}:\s{0,5}\"([a-f0-9]{40})\""),
        group=1,
        confidence=0.9,
        detector=DetectorKind.CONTEXT,
        description="GCP service-account JSON private_key_id",
    ),
    PatternRule(
        rule_id="azure-storage-key",
        entity_type="AZURE_STORAGE_KEY",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        pattern=_rx(r"(?i)AccountKey=([A-Za-z0-9+/]{86}==)"),
        group=1,
        confidence=0.95,
        detector=DetectorKind.CONTEXT,
        description="Azure storage account key in a connection string",
    ),
    # ------------------------------------------------------ source control / SaaS
    PatternRule(
        rule_id="github-token",
        entity_type="GITHUB_TOKEN",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        pattern=_rx(r"(?<![A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9]{36,255})(?![A-Za-z0-9_])"),
        group=1,
        confidence=0.97,
        description="GitHub personal/OAuth/app token",
    ),
    PatternRule(
        rule_id="github-fine-grained-pat",
        entity_type="GITHUB_TOKEN",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        pattern=_rx(r"(?<![A-Za-z0-9_])(github_pat_[A-Za-z0-9_]{80,90})(?![A-Za-z0-9_])"),
        group=1,
        confidence=0.97,
        description="GitHub fine-grained personal access token",
    ),
    PatternRule(
        rule_id="gitlab-token",
        entity_type="GITLAB_TOKEN",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        pattern=_rx(r"(?<![A-Za-z0-9_-])(glpat-[A-Za-z0-9_-]{20,64})(?![A-Za-z0-9_-])"),
        group=1,
        confidence=0.95,
        description="GitLab personal access token",
    ),
    PatternRule(
        rule_id="slack-token",
        entity_type="SLACK_TOKEN",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_rx(r"(?<![A-Za-z0-9-])(xox[abposr]-[0-9A-Za-z-]{10,250})(?![A-Za-z0-9-])"),
        group=1,
        confidence=0.93,
        description="Slack bot/user/app token",
    ),
    PatternRule(
        rule_id="slack-webhook",
        entity_type="SLACK_WEBHOOK",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_rx(
            r"(https://hooks\.slack\.com/services/T[A-Z0-9]{6,12}/B[A-Z0-9]{6,12}/[A-Za-z0-9]{20,32})"
        ),
        group=1,
        confidence=0.95,
        description="Slack incoming webhook URL",
    ),
    PatternRule(
        rule_id="discord-webhook",
        entity_type="DISCORD_WEBHOOK",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_rx(
            r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/"
            r"[A-Za-z0-9_-]{60,70})"
        ),
        group=1,
        confidence=0.95,
        description="Discord webhook URL",
    ),
    PatternRule(
        rule_id="stripe-key",
        entity_type="STRIPE_KEY",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        pattern=_rx(
            r"(?<![A-Za-z0-9_])((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,99})(?![A-Za-z0-9])"
        ),
        group=1,
        confidence=0.95,
        description="Stripe secret / restricted key",
    ),
    PatternRule(
        rule_id="sendgrid-key",
        entity_type="SENDGRID_KEY",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_rx(r"(?<![A-Za-z0-9])(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])"),
        group=1,
        confidence=0.95,
        description="SendGrid API key",
    ),
    PatternRule(
        rule_id="twilio-key",
        entity_type="TWILIO_KEY",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_rx(r"(?<![A-Za-z0-9])(SK[0-9a-f]{32})(?![A-Za-z0-9])"),
        group=1,
        confidence=0.8,
        context_keywords=("twilio",),
        context_boost=0.15,
        description="Twilio API key SID",
    ),
    PatternRule(
        rule_id="npm-token",
        entity_type="NPM_TOKEN",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_rx(r"(?<![A-Za-z0-9_])(npm_[A-Za-z0-9]{36})(?![A-Za-z0-9])"),
        group=1,
        confidence=0.95,
        description="npm access token",
    ),
    PatternRule(
        rule_id="pypi-token",
        entity_type="PYPI_TOKEN",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_rx(r"(?<![A-Za-z0-9_-])(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,250})"),
        group=1,
        confidence=0.97,
        description="PyPI upload token",
    ),
    PatternRule(
        rule_id="huggingface-token",
        entity_type="HUGGINGFACE_TOKEN",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_rx(r"(?<![A-Za-z0-9_])(hf_[A-Za-z]{34})(?![A-Za-z0-9])"),
        group=1,
        confidence=0.9,
        description="Hugging Face access token",
    ),
    # --------------------------------------------------------------- AI vendors
    PatternRule(
        rule_id="anthropic-key",
        entity_type="ANTHROPIC_KEY",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        pattern=_rx(r"(?<![A-Za-z0-9_-])(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,120})"),
        group=1,
        confidence=0.98,
        description="Anthropic API key",
    ),
    PatternRule(
        rule_id="openai-key",
        entity_type="OPENAI_KEY",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        pattern=_rx(
            r"(?<![A-Za-z0-9_-])(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,200}"
            r"T3BlbkFJ[A-Za-z0-9_-]{20,200})(?![A-Za-z0-9_-])"
        ),
        group=1,
        confidence=0.98,
        description="OpenAI API key (contains the T3BlbkFJ marker)",
    ),
    PatternRule(
        rule_id="openai-project-key",
        entity_type="OPENAI_KEY",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        pattern=_rx(r"(?<![A-Za-z0-9_-])(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,250})"),
        group=1,
        confidence=0.9,
        description="OpenAI project / service-account key",
    ),
    # --------------------------------------------------------- generic credentials
    PatternRule(
        rule_id="private-key-block",
        entity_type="PRIVATE_KEY",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        pattern=_rx(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
            # Body may contain '-' (Proc-Type / DEK-Info headers) but never "-----", so
            # the lazy scan stops at the next dashes run instead of reading 16k chars
            # past every unterminated BEGIN line.
            r"(?:[A-Za-z0-9+/=\s:,.]|-(?!----)){16,16384}?"
            r"-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
        ),
        confidence=0.99,
        description="PEM / OpenSSH / PGP private key block",
    ),
    PatternRule(
        rule_id="private-key-header",
        entity_type="PRIVATE_KEY",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        # Truncated paste: header present but no END line. Redact header + body lines.
        pattern=_rx(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
            r"[A-Za-z0-9+/=\s]{0,16384}"
        ),
        confidence=0.95,
        description="Private key header without matching footer (truncated paste)",
    ),
    PatternRule(
        rule_id="jwt",
        entity_type="JWT",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_rx(
            r"(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{8,4096}\.eyJ[A-Za-z0-9_-]{8,8192}"
            r"\.[A-Za-z0-9_-]{16,1024})(?![A-Za-z0-9_-])"
        ),
        group=1,
        confidence=0.9,
        description="JSON Web Token (header.payload.signature)",
    ),
    PatternRule(
        rule_id="bearer-token",
        entity_type="BEARER_TOKEN",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_rx(r"(?i)\bbearer\s{1,5}([A-Za-z0-9\-._~+/]{20,2048}=*)(?![A-Za-z0-9\-._~+/=])"),
        group=1,
        value_check=_plausible_secret,
        confidence=0.85,
        detector=DetectorKind.CONTEXT,
        description="Bearer token in an Authorization header",
    ),
    PatternRule(
        rule_id="basic-auth-header",
        entity_type="BASIC_AUTH",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_rx(r"(?i)\bauthorization:\s{0,5}basic\s{1,5}([A-Za-z0-9+/]{8,1024}={0,2})"),
        group=1,
        confidence=0.9,
        detector=DetectorKind.CONTEXT,
        description="HTTP Basic credentials (base64 user:password)",
    ),
    PatternRule(
        rule_id="url-credentials",
        entity_type="CONNECTION_PASSWORD",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        # scheme://user:PASSWORD@host - redact the password only. The password part is
        # greedy up to the LAST '@' so a raw (un-encoded) '@' inside it is still covered.
        pattern=_rx(
            r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s:/@\"']{1,128}:([^\s/\"']{1,256})@"
            r"[A-Za-z0-9.\-\[\]]{1,253}"
        ),
        group=1,
        confidence=0.93,
        detector=DetectorKind.CONTEXT,
        description="Password embedded in a connection URL",
    ),
    PatternRule(
        rule_id="password-assignment",
        entity_type="PASSWORD",
        category=Category.SECRET,
        severity=Severity.HIGH,
        # db_password=admin_pass_123 / "password": "x" / PASSWORD := 'x' / pwd => x
        pattern=_rx(
            r"(?i)(?<![A-Za-z0-9])(?P<key>[A-Za-z0-9_.\-]{0,40}"
            # "pass" counts only as a whole key component: SMTP_PASS, db.pass, pass - not
            # compass / bypass / passenger.
            r"(?:password|passwd|passphrase|pwd|(?<![A-Za-z0-9])pass(?![a-z]))"
            r"[A-Za-z0-9_.\-]{0,20})"
            # Separators may not cross a newline (avoids "password:\n    raise ...").
            r"[\"']?[ \t]{0,5}(?::=|=>|==|=|:)[ \t]{0,5}[\"']?(?P<val>" + _VALUE + r"{4,256})"
        ),
        group="val",
        value_check=_not_reference,
        confidence=0.85,
        detector=DetectorKind.CONTEXT,
        description="Password value assigned to a password-like key",
    ),
    PatternRule(
        rule_id="secret-assignment",
        entity_type="SECRET_VALUE",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_rx(
            r"(?i)(?<![A-Za-z0-9])(?P<key>[A-Za-z0-9_.\-]{0,40}"
            r"(?:secret|api_?key|apikey|access_?key|private_?key|auth_?token|access_?token|"
            # Connection-string keys are intentionally absent: their value is "k=v;k=v"
            # and the password inside is caught by password-assignment.
            r"refresh_?token|client_?secret|token|credentials?)"
            r"[A-Za-z0-9_.\-]{0,20})"
            r"[\"']?[ \t]{0,5}(?::=|=>|=|:)[ \t]{0,5}[\"']?(?P<val>" + _VALUE + r"{8,512})"
        ),
        group="val",
        value_check=_plausible_secret,
        confidence=0.75,
        detector=DetectorKind.CONTEXT,
        description="Secret-like value assigned to a key/token/secret variable",
    ),
    PatternRule(
        rule_id="password-natural-language",
        entity_type="PASSWORD",
        category=Category.SECRET,
        severity=Severity.HIGH,
        # "the root password is Tr0ub4dor" / "pwd was: hunter22"
        pattern=_rx(
            r"(?i)\b(?:password|passcode|passphrase|pwd|pin)[ \t]{1,3}(?:is|was|=|:)[ \t]{0,3}:?"
            r"[ \t]{0,3}[\"'`]?(?P<val>[^\s\"'`]{4,128})"
        ),
        group="val",
        value_check=_not_reference,
        confidence=0.7,
        detector=DetectorKind.CONTEXT,
        description="Password stated in natural language",
    ),
    PatternRule(
        rule_id="cli-password-flag",
        entity_type="PASSWORD",
        category=Category.SECRET,
        severity=Severity.HIGH,
        # mysql -u root -p'secret' / mysqldump -psecret / sshpass -p secret / redis-cli -a secret
        pattern=_rx(
            # Case-sensitive flags on purpose: mysql's -P is the port, -p the password.
            r"\b(?:(?i:mysql|mysqldump|mysqladmin|mariadb)\b[^\n]{0,200}?[ \t]-p"
            r"|(?i:sshpass)[ \t]{1,5}-p[ \t]{0,5}|(?i:redis-cli)\b[^\n]{0,200}?[ \t]-a[ \t]{1,5})"
            r"[\"']?(?P<val>[^\s\"']{3,128})"
        ),
        group="val",
        value_check=_not_reference,
        confidence=0.85,
        detector=DetectorKind.CONTEXT,
        description="Password passed as a command-line flag",
    ),
    # ------------------------------------------------------------------- PII
    PatternRule(
        rule_id="email",
        entity_type="EMAIL",
        category=Category.PII,
        severity=Severity.LOW,
        pattern=_rx(
            r"(?<![A-Za-z0-9._%+\-])([A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}"
            r"(?:\.[A-Za-z0-9\-]{1,63}){0,8}\.[A-Za-z]{2,24})(?![A-Za-z0-9\-])"
        ),
        group=1,
        confidence=0.9,
        # user@host after ssh/scp is a login target, and git@host is a git remote.
        validator=lambda s: not s.lower().startswith("git@"),
        suppress_keywords=("ssh", "scp", "sftp", "rsync", "mosh"),
        description="Email address",
    ),
    PatternRule(
        rule_id="credit-card",
        entity_type="CREDIT_CARD",
        category=Category.FINANCIAL,
        severity=Severity.CRITICAL,
        pattern=_rx(r"(?<![0-9-])((?:\d[ -]?){12,18}\d)(?![0-9])"),
        group=1,
        confidence=0.9,
        detector=DetectorKind.CHECKSUM,
        validator=lambda s: v.luhn_valid(s) and v.card_issuer_plausible(s),
        context_keywords=("card", "visa", "mastercard", "amex", "cvv", "payment", "rupay"),
        context_boost=0.08,
        description="Payment card number (Luhn + issuer prefix validated)",
    ),
    PatternRule(
        rule_id="iban",
        entity_type="IBAN",
        category=Category.FINANCIAL,
        severity=Severity.HIGH,
        pattern=_rx(r"\b([A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?)\b"),
        group=1,
        confidence=0.92,
        detector=DetectorKind.CHECKSUM,
        validator=v.iban_valid,
        description="IBAN (ISO 13616 mod-97 validated)",
    ),
    PatternRule(
        rule_id="aadhaar",
        entity_type="AADHAAR",
        category=Category.PII,
        severity=Severity.HIGH,
        pattern=_rx(r"(?<![0-9A-Za-z\-])([2-9]\d{3}[ -]?\d{4}[ -]?\d{4})(?![0-9A-Za-z\-])"),
        group=1,
        confidence=0.7,
        detector=DetectorKind.CHECKSUM,
        validator=v.aadhaar_valid,
        context_keywords=("aadhaar", "aadhar", "uid", "uidai"),
        context_boost=0.25,
        description="Indian Aadhaar number (Verhoeff validated)",
    ),
    PatternRule(
        rule_id="india-pan",
        entity_type="PAN",
        category=Category.PII,
        severity=Severity.HIGH,
        pattern=_rx(r"(?<![A-Za-z0-9])([A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z])(?![A-Za-z0-9])"),
        group=1,
        confidence=0.8,
        context_keywords=("pan", "income tax", "permanent account"),
        context_boost=0.15,
        description="Indian Permanent Account Number",
    ),
    PatternRule(
        rule_id="us-ssn",
        entity_type="SSN",
        category=Category.PII,
        severity=Severity.HIGH,
        pattern=_rx(r"(?<![0-9-])(\d{3}-\d{2}-\d{4})(?![0-9-])"),
        group=1,
        confidence=0.8,
        detector=DetectorKind.CHECKSUM,
        validator=v.ssn_valid,
        context_keywords=("ssn", "social security"),
        context_boost=0.15,
        description="US Social Security Number (dashed form, area/group/serial validated)",
    ),
    PatternRule(
        rule_id="india-phone",
        entity_type="PHONE",
        category=Category.PII,
        severity=Severity.MEDIUM,
        pattern=_rx(r"(?<![0-9+])((?:\+91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5})(?![0-9])"),
        group=1,
        confidence=0.65,
        context_keywords=("phone", "mobile", "call", "contact", "whatsapp", "tel"),
        context_boost=0.25,
        description="Indian mobile number",
    ),
    PatternRule(
        rule_id="intl-phone",
        entity_type="PHONE",
        category=Category.PII,
        severity=Severity.MEDIUM,
        pattern=_rx(
            r"(?<![0-9+])(\+[1-9]\d{0,2}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4})(?![0-9])"
        ),
        group=1,
        confidence=0.7,
        context_keywords=("phone", "mobile", "call", "contact", "tel"),
        context_boost=0.2,
        description="International phone number in +CC form",
    ),
    # --------------------------------------------------------- infrastructure
    PatternRule(
        rule_id="private-ipv4",
        entity_type="INTERNAL_IP",
        category=Category.INFRASTRUCTURE,
        severity=Severity.LOW,
        pattern=_rx(r"(?<![0-9.])((?:\d{1,3}\.){3}\d{1,3})(?![0-9]|\.\d)"),
        group=1,
        confidence=0.85,
        validator=v.private_ipv4,
        suppress_keywords=("version", "ver", "v", "release", "build", "sdk", "oid", "firmware"),
        description="RFC 1918 private IPv4 address",
    ),
    # ----------------------------------------------------------- confidential
    PatternRule(
        rule_id="classification-marker",
        entity_type="CLASSIFICATION_MARKER",
        category=Category.CONFIDENTIAL,
        severity=Severity.MEDIUM,
        pattern=_rx(
            r"(?i)\b(strictly confidential|company confidential|confidential and proprietary|"
            r"proprietary and confidential|internal use only|for internal use|"
            r"do not (?:distribute|share|forward)|not for (?:external )?distribution|"
            r"trade secret|under nda|confidential - internal)\b"
        ),
        group=1,
        confidence=0.85,
        detector=DetectorKind.KEYWORD,
        redactable=False,  # the marker describes the document; redacting the word is pointless
        description="Explicit document classification marker",
    ),
    PatternRule(
        rule_id="classification-marker-weak",
        entity_type="CLASSIFICATION_MARKER",
        category=Category.CONFIDENTIAL,
        severity=Severity.LOW,
        pattern=_rx(r"\b(CONFIDENTIAL|Confidential|RESTRICTED|PROPRIETARY)\b"),
        group=1,
        confidence=0.45,
        detector=DetectorKind.KEYWORD,
        redactable=False,
        description="Weak classification word (monitored, below default action threshold)",
    ),
)
