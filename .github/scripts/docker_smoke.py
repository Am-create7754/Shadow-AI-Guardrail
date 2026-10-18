# CI script: runs the docker CLI with fixed arguments and a container-side /tmp.
# ruff: noqa: S603, S607, S108, E501
"""Smoke-test the Docker image the way docs/DEPLOYMENT.md describes it.

Run by .github/workflows/docker.yml after `docker build -t guardrail .`:
production mode, secrets from an env file, read-only root filesystem, data
volume, unprivileged user. Results are printed and emitted as annotations.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

IMAGE = "guardrail"
NAME = "guardrail-smoke"
BASE = "http://127.0.0.1:8000"
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + (f" - {detail}" if detail else ""), flush=True)
    if not ok:
        clean = detail.replace("\n", " ").replace("%", " ")[:300]
        print(
            f"::error title=Docker {name.replace(':', ' ').replace(',', ' ')}::{clean}", flush=True
        )


def docker(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], input=stdin, capture_output=True, text=True, check=False
    )


def http(
    method: str, path: str, body: Any = None, token: str | None = None
) -> tuple[int, dict[str, str], str]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)  # noqa: S310 - fixed local URL
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def main() -> int:
    data = Path(tempfile.mkdtemp(prefix="guardrail-docker-"))
    (data / "keys").mkdir()
    os.chmod(data, 0o777)  # noqa: S103 - throwaway CI directory, written by uid 10001
    os.chmod(data / "keys", 0o777)  # noqa: S103

    # Checkpoint signing key, generated inside the image (it has `cryptography`).
    gen = docker("run", "--rm", "-v", f"{data}:/data", "--entrypoint", "python", IMAGE, "-c",
                 "from cryptography.hazmat.primitives.asymmetric import ed25519;"
                 "from cryptography.hazmat.primitives import serialization as s;"
                 "k=ed25519.Ed25519PrivateKey.generate();"
                 "open('/data/keys/checkpoint.pem','wb').write(k.private_bytes(s.Encoding.PEM,"
                 "s.PrivateFormat.PKCS8,s.NoEncryption()))")  # fmt: skip
    check("checkpoint key generated in the image", gen.returncode == 0, gen.stderr[-300:])

    env = data.parent / f"{data.name}.env"
    keys = ["AUDIT_KEY", "FINGERPRINT_KEY", "JWT_SECRET", "API_KEY_PEPPER", "DATA_KEY"]
    env.write_text(
        "".join(f"GUARDRAIL_{k}={secrets.token_urlsafe(48)}\n" for k in keys)
        + "GUARDRAIL_CHECKPOINT_KEY_PATH=/data/keys/checkpoint.pem\n"
        + "GUARDRAIL_CORS_ORIGINS=\n",
        encoding="utf-8",
    )
    run = docker("run", "-d", "--name", NAME, "--read-only", "--tmpfs", "/tmp", "-p", "127.0.0.1:8000:8000",
                 "-v", f"{data}:/data", "--env-file", str(env), IMAGE)  # fmt: skip
    check("container started (production, read-only root)", run.returncode == 0, run.stderr[-300:])

    try:
        ready = False
        for _ in range(60):
            try:
                ready = http("GET", "/ready")[0] == 200
            except OSError:
                ready = False
            if ready:
                break
            time.sleep(1)
        check("/ready answers 200 (migrations applied)", ready, docker("logs", NAME).stderr[-500:])

        status, headers, body = http("GET", "/app/")
        csp = headers.get("Content-Security-Policy", "")
        check(
            "dashboard served with strict CSP",
            status == 200 and "trusted-types 'none'" in csp,
            csp[:120],
        )
        check("API docs disabled in production", http("GET", "/docs")[0] == 404)
        check("no server header", "server" not in {k.lower() for k in headers})

        uid = docker("exec", NAME, "id", "-u").stdout.strip()
        check("runs as unprivileged user", uid == "10001", uid)
        ro = docker("exec", NAME, "sh", "-c", "touch /app/x 2>&1; echo $?").stdout.strip()
        check("root filesystem is read-only", ro.endswith("1"), ro)

        password = secrets.token_urlsafe(18)
        created = docker("exec", "-i", NAME, "python", "-m", "app.api.manage", "create-user", "admin",
                         "--role", "admin", "--password-stdin", stdin=password + "\n")  # fmt: skip
        check("admin created with the CLI", created.returncode == 0, created.stderr[-300:])
        status, _, body = http(
            "POST", "/v1/auth/login", {"username": "admin", "password": password}
        )
        token = json.loads(body).get("access_token") if status == 200 else None
        check("admin can log in", bool(token), str(status))

        secret = "db_" + "password=" + secrets.token_urlsafe(12)
        status, _, body = http("POST", "/v1/inspect", {"text": f"fix {secret}"}, token)
        insp = json.loads(body)
        check(
            "inspection redacts",
            status == 200
            and insp.get("action") == "REDACT"
            and secret not in insp.get("sanitized_text", ""),
            str(insp.get("action")),
        )
        status, _, body = http("GET", "/v1/admin/audit/verify", None, token)
        check(
            "audit chain verifies (API)",
            status == 200 and json.loads(body).get("ok") is True,
            body[:200],
        )
        verify = docker("exec", NAME, "python", "-m", "app.audit", "verify")
        check(
            "audit chain verifies (CLI in the container)",
            verify.returncode == 0,
            verify.stdout[-300:],
        )
        logs = docker("logs", NAME)
        check("no secret in the container logs", secret not in logs.stdout + logs.stderr)
    finally:
        docker("rm", "-f", NAME)

    failed_names = [name for name, ok, _ in results if not ok]
    summary = f"{len(results) - len(failed_names)}/{len(results)} checks passed"
    if failed_names:
        summary += "; failed: " + "; ".join(failed_names)
    print(f"::notice title=Docker image::{summary}", flush=True)
    return 1 if failed_names else 0


if __name__ == "__main__":
    sys.exit(main())
