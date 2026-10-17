"""Load test: start an isolated gateway process and drive it with concurrent clients.

    .venv\\Scripts\\python -m loadtest.run                      # print results
    .venv\\Scripts\\python -m loadtest.run --report ..\\docs\\PERFORMANCE.md

Scenarios (mock provider, so the numbers are the gateway's own cost):
inspect a short prompt with a secret, inspect a 20k-character source file,
chat (redacted, forwarded, answer inspected), streamed chat, blocked prompt.
Also times the detection engine alone on growing inputs.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import platform
import random
import statistics
import string
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

BACKEND = Path(__file__).resolve().parents[1]


def _secret(rng: random.Random) -> str:
    # Built at runtime: the repository never contains credential-shaped literals.
    return "db_" + "password=" + "".join(rng.choices(string.ascii_letters + string.digits, k=14))


def _source_file(rng: random.Random, chars: int) -> str:
    lines: list[str] = []
    size = 0
    while size < chars:
        n = rng.randint(0, 9999)
        for line in (
            f"def handler_{n}(request):",
            f"    value = compute(request.args.get('q{n}'))",
            "    return value",
        ):
            lines.append(line)
            size += len(line) + 1
    lines.insert(len(lines) // 2, _secret(rng))
    return "\n".join(lines)[:chars]


@dataclass
class Result:
    name: str
    latencies: list[float] = field(default_factory=list)
    errors: int = 0
    statuses: dict[int, int] = field(default_factory=dict)
    error_types: dict[str, int] = field(default_factory=dict)
    elapsed: float = 0.0

    def row(self) -> list[str]:
        lat = sorted(self.latencies)

        def q(p: float) -> str:
            return f"{lat[min(len(lat) - 1, int(p * len(lat)))] * 1000:.0f}" if lat else "-"

        rps = len(lat) / self.elapsed if self.elapsed else 0.0
        codes = ", ".join(f"{k}x{v}" for k, v in sorted(self.statuses.items()))
        if self.error_types:
            codes += " (" + ", ".join(f"{k}x{v}" for k, v in sorted(self.error_types.items())) + ")"
        return [self.name, str(len(lat)), f"{rps:.0f}", q(0.5), q(0.95), q(0.99),
                str(self.errors), codes]  # fmt: skip


async def _scenario(
    client: httpx.AsyncClient, name: str, make: Any, requests: int, concurrency: int, expect: int
) -> Result:
    res = Result(name)
    queue: asyncio.Queue[int] = asyncio.Queue()
    for i in range(requests):
        queue.put_nowait(i)

    async def worker() -> None:
        while True:
            try:
                i = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            method, path, body, stream = make(i)
            t0 = time.perf_counter()
            try:
                if stream:
                    async with client.stream(method, path, json=body) as r:
                        async for _ in r.aiter_bytes():
                            pass
                        status = r.status_code
                else:
                    resp = await client.request(method, path, json=body)
                    status = resp.status_code
                    if status != expect:
                        try:
                            kind = str(resp.json()["error"]["type"])
                        except (ValueError, KeyError, TypeError):
                            kind = "unparsed"
                        res.error_types[kind] = res.error_types.get(kind, 0) + 1
            except httpx.HTTPError:
                res.errors += 1
                continue
            res.latencies.append(time.perf_counter() - t0)
            res.statuses[status] = res.statuses.get(status, 0) + 1
            if status != expect:
                res.errors += 1

    t0 = time.perf_counter()
    await asyncio.gather(*(worker() for _ in range(concurrency)))
    res.elapsed = time.perf_counter() - t0
    return res


async def drive(base_url: str, key: str, requests: int, concurrency: int) -> list[Result]:
    rng = random.Random(7)
    short = [f"Fix this connection string: {_secret(rng)} please" for _ in range(50)]
    big = [_source_file(rng, 20_000) for _ in range(5)]
    card = "Why was card 4" + "1" * 15 + " declined?"

    def msg(text: str) -> dict[str, Any]:
        return {"model": "mock-echo", "messages": [{"role": "user", "content": text}]}

    chat = "/v1/chat/completions"
    scenarios = [
        ("inspect, short prompt with a secret",
         lambda i: ("POST", "/v1/inspect", {"text": short[i % 50]}, False), 200),
        ("inspect, 20k-char source file",
         lambda i: ("POST", "/v1/inspect", {"text": big[i % 5]}, False), 200),
        ("chat, redacted + forwarded + answer inspected",
         lambda i: ("POST", chat, msg(short[i % 50]), False), 200),
        ("chat, streamed",
         lambda i: ("POST", chat, {**msg(short[i % 50]), "stream": True}, True), 200),
        ("chat, blocked (card number)",
         lambda i: ("POST", chat, msg(card), False), 403),
    ]  # fmt: skip
    headers = {"Authorization": f"Bearer {key}"}
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    async with httpx.AsyncClient(
        base_url=base_url, headers=headers, timeout=60, limits=limits
    ) as client:
        for _ in range(20):  # warm-up
            await client.post("/v1/inspect", json={"text": "warm up"})
        return [await _scenario(client, n, m, requests, concurrency, e) for n, m, e in scenarios]


def engine_benchmark() -> list[list[str]]:
    from app.core.config import Environment, Settings

    Settings.model_config["env_file"] = None
    from app.guardrail import Guardrail

    guard = Guardrail.from_settings(Settings(environment=Environment.TEST))
    rng = random.Random(11)
    rows = []
    for size in (1_000, 10_000, 50_000, 100_000):
        text = _source_file(rng, size)
        guard.inspect(text)  # warm caches
        times = []
        for _ in range(7):
            t0 = time.perf_counter()
            guard.inspect(text)
            times.append(time.perf_counter() - t0)
        med = statistics.median(times)
        rows.append([f"{size:,}", f"{med * 1000:.1f}", f"{size / med / 1e6:.2f}"])
    return rows


def _table(header: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", type=int, default=400, help="requests per scenario")
    ap.add_argument("--concurrency", type=int, default=16)
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--report", type=Path)
    args = ap.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="guardrail-load-"))
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
    try:
        if proc.stdout is None:
            raise SystemExit("server output not captured")
        line = proc.stdout.readline().strip()
        if not line.startswith("KEY "):
            raise SystemExit(f"server failed to start: {line!r}")
        key = line[4:]
        base = f"http://127.0.0.1:{args.port}"
        for _ in range(100):
            try:
                if httpx.get(base + "/health", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.2)
        results = asyncio.run(drive(base, key, args.requests, args.concurrency))
    finally:
        proc.terminate()
        proc.wait(timeout=30)
        server_log.close()
    problems = [
        line.strip()
        for line in (workdir / "server.log").read_text(encoding="utf-8").splitlines()
        if "ERROR" in line or "WARNING" in line or "failed" in line
    ]
    for line in problems[:20]:
        print("server:", line)

    header = [
        "Scenario",
        "Requests",
        "Req/s",
        "p50 ms",
        "p95 ms",
        "p99 ms",
        "Errors",
        "Status codes",
    ]
    load_table = _table(header, [r.row() for r in results])
    engine_table = _table(["Input chars", "Median ms", "MB/s"], engine_benchmark())
    print(load_table)
    print()
    print(engine_table)
    if args.report:
        cpu = platform.processor() or platform.machine()
        machine = (
            f"{platform.system()} {platform.release()}, {cpu}, Python {platform.python_version()}"
        )
        args.report.write_text(
            REPORT.format(
                date=datetime.now(UTC).strftime("%Y-%m-%d"),
                machine=machine,
                cpus=os.cpu_count(),
                requests=args.requests,
                concurrency=args.concurrency,
                load=load_table,
                engine=engine_table,
            ),
            encoding="utf-8",
        )
        print(f"\nreport written to {args.report}")
    return 1 if any(r.errors for r in results) else 0


REPORT = """# Performance

_Generated by `python -m loadtest.run --report` on {date}._

Machine: {machine}, {cpus} logical CPUs. One Uvicorn worker, SQLite audit log,
mock provider (no network), {requests} requests per scenario, {concurrency}
concurrent clients on the same machine (client and server compete for CPU, so
these are conservative). Every request writes at least one audit event; chat
requests write two (forwarded + completed).

## Gateway under load

{load}

## Detection engine alone (median of 7 runs, source-code-like text with a secret)

{engine}

## Reading the numbers

* The audit log is the deliberate bottleneck: every decision is committed (HMAC
  chain, `BEGIN IMMEDIATE`) before anything is forwarded, so writes are
  serialised. That is the fail-closed design, not an accident.
* Scaling: more Uvicorn workers help detection (CPU-bound) but not audit writes
  on SQLite; PostgreSQL (row lock on the chain head) is the path for higher
  write rates (implemented, not load-tested here).
* With a real provider, model latency (hundreds of ms to seconds) dominates;
  the gateway adds the inspection and audit time measured above.
"""

if __name__ == "__main__":
    sys.exit(main())
