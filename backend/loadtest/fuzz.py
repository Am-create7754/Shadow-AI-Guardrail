"""API fuzzing: Schemathesis against an isolated gateway (see docs/SECURITY-TESTING.md).

    .venv\\Scripts\\python -m loadtest.fuzz                 # default 100 examples per operation
    .venv\\Scripts\\python -m loadtest.fuzz --max-examples 300

Generates valid and malformed requests from the OpenAPI schema for every
operation, once as a developer and once as an administrator, and fails on any
server error (5xx) - the gateway must answer every input with a controlled 4xx.
Exit code 0 only if both runs pass.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

BACKEND = Path(__file__).resolve().parents[1]
SCHEMATHESIS = Path(sys.executable).with_name("st.exe" if os.name == "nt" else "st")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-examples", type=int, default=100)
    ap.add_argument("--port", type=int, default=8766)
    ap.add_argument("--report-dir", type=Path)
    args = ap.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="guardrail-fuzz-"))
    env = {k: v for k, v in os.environ.items() if not k.startswith("GUARDRAIL_")}
    server_log = (workdir / "server.log").open("w", encoding="utf-8")
    proc = subprocess.Popen(  # noqa: S603 - our own module, fixed arguments
        [sys.executable, "-m", "loadtest.server", "--dir", str(workdir), "--port", str(args.port)],
        cwd=BACKEND,
        env=env,
        stdout=subprocess.PIPE,
        stderr=server_log,
        text=True,
    )
    failed = False
    try:
        if proc.stdout is None:
            raise SystemExit("server output not captured")
        keys = dict(proc.stdout.readline().strip().split(" ", 1) for _ in range(2))
        base = f"http://127.0.0.1:{args.port}"
        for _ in range(100):
            try:
                if httpx.get(base + "/health", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.2)
        for role, key in (("developer", keys["KEY"]), ("admin", keys["ADMIN_KEY"])):
            print(f"\n=== fuzzing as {role} ===", flush=True)
            cmd = [
                str(SCHEMATHESIS), "run", f"{base}/openapi.json",
                "--checks", "not_a_server_error",
                "--header", f"Authorization: Bearer {key}",
                "--max-examples", str(args.max_examples),
                "--workers", "4",
            ]  # fmt: skip
            if args.report_dir:
                args.report_dir.mkdir(parents=True, exist_ok=True)
                cmd += [
                    "--report",
                    "junit",
                    "--report-junit-path",
                    str(args.report_dir / f"fuzz-{role}.xml"),
                ]
            # UTF-8 mode: Schemathesis prints Unicode, which a Windows cp1252 console cannot.
            utf8 = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
            result = subprocess.run(cmd, cwd=BACKEND, env=utf8, check=False)  # noqa: S603
            failed |= result.returncode != 0
    finally:
        proc.terminate()
        proc.wait(timeout=30)
        server_log.close()
    errors = [
        line.strip()
        for line in (workdir / "server.log").read_text(encoding="utf-8").splitlines()
        if "ERROR" in line or "Traceback" in line
    ]
    for line in errors[:20]:
        print("server:", line)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
