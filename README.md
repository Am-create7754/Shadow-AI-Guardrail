# Autonomous AppSec Guardrail for Shadow AI Deployments

A security gateway that inspects AI prompts **before** they leave the
organisation. It detects credentials, personal data and confidential material,
applies a configurable policy (allow / redact / require approval / block),
replaces sensitive values with typed placeholders, and, in later phases, inspects
model output and writes a tamper-evident audit trail.

```
"Fix this connection string: db_password=admin_pass_123"
                         │
                         ▼   action REDACT · risk 55 · rule password-assignment
"Fix this connection string: db_password=[PASSWORD_1]"
```

> **Current phase:** Phase 1 (detection + policy engine) is complete.
> The HTTP gateway, audit chain, dashboards and browser extension are planned.
> See [docs/STATUS.md](docs/STATUS.md) for exactly what works and how it was verified.

## Repository layout

```
backend/
  app/
    core/config.py          settings (GUARDRAIL_* env vars)
    detection/              normaliser, rules, validators, entropy, engine, redaction
    policy/                 policy schema, evaluation, default_policy.yaml
    guardrail.py            inspect(text) -> decision + sanitized text
    cli.py                  command-line inspector
  evaluation/               synthetic generators, labeled datasets, metrics script
  tests/                    pytest + Hypothesis + ReDoS suites
  scripts/check.ps1         all quality gates
docs/                       architecture, status, evaluation report
```

## Quick start (Windows PowerShell)

Requires Python 3.12+ (developed on 3.13).

```powershell
cd backend
py -3.13 -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
Copy-Item .env.example .env          # optional in development
```

Inspect a prompt:

```powershell
.venv\Scripts\python -m app.cli "Fix this connection string: db_password=admin_pass_123"
```

Run all checks (lint, format, strict type-check, tests):

```powershell
.\scripts\check.ps1
```

Detection-quality report:

```powershell
.venv\Scripts\python -m evaluation.evaluate --seeds 5 --report ..\docs\EVALUATION.md
```

## Security notes

- Every credential-like value in this repository is synthetic and generated at
  runtime; no real keys are stored in code, tests or datasets.
- Raw detected values never appear in `repr()`, logs or public output.
- Detection is heuristic. See the known gaps in [docs/EVALUATION.md](docs/EVALUATION.md)
  and [docs/STATUS.md](docs/STATUS.md); it is not a guarantee that every secret is caught.
