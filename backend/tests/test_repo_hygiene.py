"""Dog-fooding: the repository itself must not contain vendor-token-shaped literals.

Synthetic tokens are assembled at runtime (see evaluation/synth.py) so that the
source tree never carries anything that looks like a live credential.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from app.detection.engine import DetectionEngine
from app.detection.models import DetectorKind, Severity
from app.detection.rules import BUILTIN_RULES

REPO = Path(__file__).resolve().parents[2]
SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".mypy_cache", ".ruff_cache",
             ".pytest_cache", ".hypothesis", "dist", "build"}  # fmt: skip
TEXT_SUFFIXES = {".py", ".md", ".yaml", ".yml", ".toml", ".json", ".ps1", ".txt", ".example",
                 ".ts", ".tsx", ".js", ".html", ".css"}  # fmt: skip

# Only prefix-anchored vendor formats and key blocks: these are what secret
# scanners (and GitHub push protection) flag. Keyword rules would fire on docs
# that intentionally show "db_password=..." examples.
VENDOR_RULES = tuple(
    r
    for r in BUILTIN_RULES
    if r.detector is DetectorKind.REGEX and r.severity >= Severity.HIGH and r.rule_id != "jwt"
)


def _candidates() -> list[Path]:
    """Files that are, or would be, committed: tracked files plus untracked files
    that .gitignore does not exclude. Ignored local files (backend/.env with a
    real provider key, databases) are deliberately out of scope - they never
    reach the repository."""
    try:
        listed = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],  # noqa: S607
            cwd=REPO,
            capture_output=True,
            check=True,
            timeout=60,
        ).stdout.decode("utf-8", "replace")
        return [REPO / name for name in listed.split("\0") if name]
    except (OSError, subprocess.SubprocessError):
        # No git available: walk the tree, never reading real .env files.
        return [
            p
            for p in REPO.rglob("*")
            if not (p.name.startswith(".env") and p.name != ".env.example")
        ]


def _files() -> list[Path]:
    out = []
    for p in _candidates():
        if any(part in SKIP_DIRS for part in p.parts) or not p.is_file():
            continue
        if p.suffix in TEXT_SUFFIXES or p.name == ".env.example":
            out.append(p)
    return out


def test_no_vendor_secrets_in_repository() -> None:
    engine = DetectionEngine(VENDOR_RULES, disabled_rules=["high-entropy-string"],
                             max_input_chars=5_000_000)  # fmt: skip
    offenders = []
    files = _files()
    assert files, "repository scan found no files"
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for f in engine.scan(text).findings:
            offenders.append(f"{path.relative_to(REPO)}:{f.rule_id}")
    assert not offenders, offenders


def test_no_real_env_file_committed() -> None:
    assert not (REPO / "backend" / ".env").exists() or ".env" in (REPO / ".gitignore").read_text()


def test_no_invisible_or_bidi_characters_in_source() -> None:
    """Trojan Source guard (CVE-2021-42574): invisible/bidi characters must be escaped."""
    import unicodedata

    offenders = []
    for path in _files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            # Any format char, and any control char except tab / carriage return
            # (also catches ASCII controls such as a stray \x07 from a bad escape).
            if any(
                unicodedata.category(c) == "Cf"
                or (unicodedata.category(c) == "Cc" and c not in "\t\r")
                for c in line
            ):
                offenders.append(f"{path.relative_to(REPO)}:{lineno}")
    assert not offenders, offenders


def test_python_sources_are_ascii_only() -> None:
    """Homoglyph guard: non-ASCII in code must be written as backslash-u escapes.

    A Cyrillic 'a' in a rule or confusables table is indistinguishable from a
    Latin one when reviewing; escapes make every such character explicit.
    """
    offenders = [
        str(p.relative_to(REPO))
        for p in _files()
        if p.suffix == ".py" and not p.read_text(encoding="utf-8").isascii()
    ]
    assert not offenders, offenders
