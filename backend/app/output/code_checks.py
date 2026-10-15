"""Static checks for insecure patterns in AI-generated code.

Scope and honesty
-----------------
These are *lightweight, line-based* checks over fenced code blocks in a model
answer - closer to a linter than to a full static analyser (no data flow, no
type information). They flag well-known dangerous constructs so a developer
sees a warning next to generated code; they do not prove code is safe, and a
clean result means only that none of these patterns matched.

* Only fenced blocks (```lang ... ```) are checked, to avoid flagging prose.
* Each rule is scoped to languages; an unlabelled block is checked against all.
* Comment-only lines are skipped (``#``, ``//``, ``--``) to cut false positives.
* Patterns are bounded and anchored on literal tokens (ReDoS-tested).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.detection.models import Severity

# A fence opens/closes a block only at the start of a line (CommonMark): up to
# three spaces, then 3+ backticks or tildes. Inline ``` in prose is not a fence.
_FENCE_LINE = re.compile(r"^ {0,3}(`{3,}|~{3,})[ \t]*([A-Za-z0-9_+#.\-]{0,20})")

_LANG_ALIASES = {
    "py": "python",
    "python3": "python",
    "python": "python",
    "js": "javascript",
    "javascript": "javascript",
    "node": "javascript",
    "jsx": "javascript",
    "ts": "javascript",
    "typescript": "javascript",
    "tsx": "javascript",
    "sh": "shell",
    "bash": "shell",
    "shell": "shell",
    "zsh": "shell",
    "powershell": "shell",
    "ps1": "shell",
    "console": "shell",
    "sql": "sql",
    "java": "java",
    "php": "php",
    "go": "go",
    "csharp": "csharp",
    "cs": "csharp",
    "yaml": "yaml",
    "yml": "yaml",
    "dockerfile": "dockerfile",
    "docker": "dockerfile",
}
ALL = frozenset(
    {
        "python",
        "javascript",
        "shell",
        "sql",
        "java",
        "php",
        "go",
        "csharp",
        "yaml",
        "dockerfile",
        "unknown",
    }
)


@dataclass(frozen=True)
class CodeRule:
    rule_id: str
    cwe: str
    severity: Severity
    languages: frozenset[str]
    pattern: re.Pattern[str]
    message: str


@dataclass(frozen=True)
class CodeFinding:
    rule_id: str
    cwe: str
    severity: Severity
    language: str
    block: int  # index of the fenced block in the answer
    line: int  # 1-based line within the block
    message: str

    def to_public(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "severity": self.severity.name,
            "language": self.language,
            "block": self.block,
            "line": self.line,
            "message": self.message,
        }


def _r(p: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(p, flags)


PY = frozenset({"python", "unknown"})
JS = frozenset({"javascript", "unknown"})
SH = frozenset({"shell", "dockerfile", "unknown"})

CODE_RULES: tuple[CodeRule, ...] = (
    # ------------------------------------------------------------- injection
    CodeRule(
        "py-eval-exec",
        "CWE-95",
        Severity.HIGH,
        PY,
        _r(r"(?<![\w.])(?:eval|exec)\s{0,3}\("),
        "eval()/exec() executes arbitrary code; parse input explicitly instead",
    ),
    CodeRule(
        "py-subprocess-shell",
        "CWE-78",
        Severity.HIGH,
        PY,
        _r(r"\bsubprocess\.\w{1,20}\([^\n]{0,300}shell\s{0,3}=\s{0,3}True"),
        "shell=True enables shell injection; pass an argument list instead",
    ),
    CodeRule(
        "py-os-system",
        "CWE-78",
        Severity.HIGH,
        PY,
        _r(r"\bos\.(?:system|popen)\s{0,3}\("),
        "os.system/os.popen run a shell command; use subprocess with a list",
    ),
    CodeRule(
        "py-pickle-load",
        "CWE-502",
        Severity.HIGH,
        PY,
        _r(r"\b(?:pickle|cPickle|dill|shelve)\.loads?\s{0,3}\("),
        "unpickling untrusted data executes code",
    ),
    CodeRule(
        "py-yaml-unsafe",
        "CWE-502",
        Severity.HIGH,
        PY,
        _r(
            r"\byaml\.(?:load|load_all)\s{0,3}\((?![^\n)]{0,200}Loader\s{0,3}=\s{0,3}"
            r"(?:yaml\.)?(?:Safe|CSafe)Loader)[^\n]{0,200}\)"
        ),
        "yaml.load without SafeLoader can construct arbitrary objects; use safe_load",
    ),
    CodeRule(
        "sql-string-building",
        "CWE-89",
        Severity.HIGH,
        ALL,
        _r(
            r"(?i)\b(?:execute|executemany|raw|query|exec)\s{0,3}\(\s{0,3}"
            r"(?:f[\"']|[\"'][^\"'\n]{0,200}(?:select|insert|update|delete)\b[^\"'\n]{0,200}"
            r"[\"']\s{0,3}(?:%|\+|\.format\())"
        ),
        "SQL built from strings is injectable; use parameterised queries",
    ),
    CodeRule(
        "sql-fstring-query",
        "CWE-89",
        Severity.HIGH,
        PY,
        _r(
            r"(?i)\bf[\"'][^\"'\n]{0,200}\b(?:select\s[^\"'\n]{0,200}\bfrom|insert\s+into|"
            r"update\s+\w{1,64}\s+set|delete\s+from)\b[^\"'\n]{0,200}\{"
        ),
        "SQL in an f-string is injectable; use parameterised queries",
    ),
    CodeRule(
        "js-eval",
        "CWE-95",
        Severity.HIGH,
        JS,
        _r(r"(?<![\w.])(?:eval|Function)\s{0,3}\(|setTimeout\s{0,3}\(\s{0,3}[\"'`]"),
        "eval/new Function/string timers execute arbitrary code",
    ),
    CodeRule(
        "js-child-process-exec",
        "CWE-78",
        Severity.HIGH,
        JS,
        _r(
            r"\b(?:child_process\.)?exec(?:Sync)?\s{0,3}\(\s{0,3}(?:`[^`\n]{0,300}\$\{|"
            r"[\"'][^\"'\n]{0,300}[\"']\s{0,3}\+)"
        ),
        "shell command built from strings; use execFile/spawn with an argument array",
    ),
    CodeRule(
        "js-dom-xss",
        "CWE-79",
        Severity.MEDIUM,
        JS,
        _r(
            r"\.(?:innerHTML|outerHTML)\s{0,3}=|document\.write\s{0,3}\(|"
            r"dangerouslySetInnerHTML|insertAdjacentHTML\s{0,3}\("
        ),
        "writing HTML from data enables XSS; use textContent or sanitise",
    ),
    CodeRule(
        "shell-pipe-to-shell",
        "CWE-494",
        Severity.HIGH,
        SH,
        _r(r"\b(?:curl|wget)\b[^\n|]{0,300}\|\s{0,3}(?:sudo\s{1,3})?(?:ba|z)?sh\b"),
        "piping a download into a shell runs unverified code",
    ),
    CodeRule(
        "shell-chmod-777",
        "CWE-732",
        Severity.MEDIUM,
        SH,
        _r(r"\bchmod\s{1,3}(?:-R\s{1,3})?0?777\b"),
        "world-writable permissions",
    ),
    # ---------------------------------------------------------------- crypto / TLS
    CodeRule(
        "tls-verify-disabled",
        "CWE-295",
        Severity.HIGH,
        ALL,
        _r(
            r"verify\s{0,3}=\s{0,3}False|rejectUnauthorized\s{0,3}:\s{0,3}false|"
            r"NODE_TLS_REJECT_UNAUTHORIZED\s{0,3}=\s{0,3}[\"']?0|"
            r"InsecureSkipVerify\s{0,3}:\s{0,3}true|curl\s[^\n]{0,200}\s(?:-k|--insecure)\b|"
            r"CERT_NONE|_create_unverified_context"
        ),
        "TLS certificate verification is disabled (man-in-the-middle risk)",
    ),
    CodeRule(
        "weak-hash-for-secrets",
        "CWE-328",
        Severity.MEDIUM,
        ALL,
        _r(
            r"(?i)\b(?:hashlib\.)?(?:md5|sha1)\s{0,3}\([^\n]{0,120}"
            r"(?:pass|pwd|secret|token)"
        ),
        "MD5/SHA-1 for passwords or secrets; use Argon2/bcrypt/scrypt",
    ),
    CodeRule(
        "insecure-random-token",
        "CWE-338",
        Severity.MEDIUM,
        PY,
        _r(
            r"(?i)\b(?:token|secret|password|otp|nonce|salt|session)\w{0,20}\s{0,3}=\s{0,3}"
            r"[^\n]{0,80}\brandom\.(?:random|randint|choice|choices|getrandbits)\b"
        ),
        "random is predictable; use the secrets module for security tokens",
    ),
    CodeRule(
        "js-insecure-random-token",
        "CWE-338",
        Severity.MEDIUM,
        JS,
        _r(
            r"(?i)\b(?:token|secret|password|otp|nonce|salt|session)\w{0,20}\s{0,3}=\s{0,3}"
            r"[^\n]{0,80}Math\.random\s{0,3}\("
        ),
        "Math.random is predictable; use crypto.randomUUID / getRandomValues",
    ),
    # ----------------------------------------------------------- configuration
    CodeRule(
        "flask-debug",
        "CWE-489",
        Severity.MEDIUM,
        PY,
        _r(r"\.run\([^\n)]{0,200}debug\s{0,3}=\s{0,3}True"),
        "debug mode exposes an interactive debugger; never enable in production",
    ),
    CodeRule(
        "cors-wildcard-credentials",
        "CWE-942",
        Severity.MEDIUM,
        ALL,
        _r(
            r"(?i)allow_origins\s{0,3}=\s{0,3}\[\s{0,3}[\"']\*[\"'][^\n]{0,200}"
            r"allow_credentials\s{0,3}=\s{0,3}True|"
            r"Access-Control-Allow-Origin[\"']?\s{0,3}[:,]\s{0,3}[\"']\*"
        ),
        "wildcard CORS origin (with credentials) exposes the API to any site",
    ),
    CodeRule(
        "hardcoded-credential",
        "CWE-798",
        Severity.HIGH,
        ALL,
        _r(
            r"(?i)\b\w{0,30}(?:password|passwd|secret|api_?key|token)\w{0,20}\s{0,3}"
            r"[:=]\s{0,3}[\"'](?![\"'])(?!\s)(?![^\"'\n]{0,64}(?:\{|\$|<|your|example|"
            r"changeme|xxx|\*\*\*))[^\"'\n]{6,128}[\"']"
        ),
        "credential hard-coded in source; load it from the environment or a vault",
    ),
)


def _language(label: str) -> str:
    return _LANG_ALIASES.get(label.lower(), "unknown") if label else "unknown"


def _is_comment(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith(("#", "//", "--", "/*", "*", "REM "))


@dataclass
class CodeBlock:
    language: str
    lines: list[str]
    closed: bool


class FenceParser:
    """Incremental, line-based fenced-block parser.

    Feed complete lines in order; :meth:`line` returns a block when it closes.
    An unclosed block at the end of the answer is returned by :meth:`end` so it
    is checked too (models are cut off mid-block, and attackers can omit the
    closing fence on purpose).
    """

    def __init__(self) -> None:
        self.open: CodeBlock | None = None
        self._fence = ""
        self.open_at = -1  # caller-defined offset of the opening fence line

    def line(self, text: str, offset: int = -1) -> CodeBlock | None:
        m = _FENCE_LINE.match(text)
        if self.open is None:
            if m:
                self.open = CodeBlock(_language(m.group(2)), [], closed=False)
                self._fence = m.group(1)
                self.open_at = offset
            return None
        if (
            m
            and m.group(1)[0] == self._fence[0]
            and len(m.group(1)) >= len(self._fence)
            and not m.group(2)
            and not text[m.end() :].strip()
        ):
            block, self.open = self.open, None
            block.closed = True
            return block
        self.open.lines.append(text)
        return None

    def end(self) -> CodeBlock | None:
        block, self.open = self.open, None
        return block


def code_blocks(text: str) -> list[CodeBlock]:
    parser = FenceParser()
    blocks = []
    for line in text.split("\n"):
        if (b := parser.line(line.rstrip("\r"))) is not None:
            blocks.append(b)
    if (b := parser.end()) is not None:
        blocks.append(b)
    return blocks


def check_block(block: CodeBlock, index: int) -> list[CodeFinding]:
    findings: list[CodeFinding] = []
    for line_no, line in enumerate(block.lines, 1):
        if len(line) > 2_000 or _is_comment(line):
            continue
        for rule in CODE_RULES:
            if block.language in rule.languages and rule.pattern.search(line):
                findings.append(
                    CodeFinding(
                        rule.rule_id,
                        rule.cwe,
                        rule.severity,
                        block.language,
                        index,
                        line_no,
                        rule.message,
                    )
                )
    return findings


def check_code(text: str) -> list[CodeFinding]:
    findings: list[CodeFinding] = []
    for index, block in enumerate(code_blocks(text)):
        findings.extend(check_block(block, index))
    return findings
