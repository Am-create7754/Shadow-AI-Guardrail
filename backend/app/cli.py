"""Command-line inspector - demo/debug tool for the detection + policy engine.

PowerShell examples (from backend/)::

    .venv\\Scripts\\python -m app.cli "Fix this connection string: db_password=admin_pass_123"
    Get-Content prompt.txt | .venv\\Scripts\\python -m app.cli -

Output is the same safe JSON summary the API will return: raw values and the
placeholder mapping are never printed.
"""

from __future__ import annotations

import argparse
import json
import sys

from app.detection.engine import InputTooLargeError
from app.guardrail import Guardrail


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__.splitlines()[0])
    parser.add_argument("text", help="prompt text to inspect, or '-' to read stdin")
    args = parser.parse_args(argv)
    # Windows consoles default to cp1252, which cannot print most Unicode.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    text = sys.stdin.read() if args.text == "-" else args.text
    guard = Guardrail.from_settings()
    try:
        inspection = guard.inspect(text)
    except InputTooLargeError as exc:
        print(json.dumps({"error": "input_too_large", "detail": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(inspection.to_public(), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
