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

> **Current phase:** Phases 1-3 are complete: detection + policy engine,
> tamper-evident audit log, and the HTTP gateway (auth, approvals, mock provider,
> OpenAI-compatible endpoint). Output inspection, dashboards and the browser
> extension are planned.
> See [docs/STATUS.md](docs/STATUS.md) for exactly what works and how it was verified.

## Repository layout

```
backend/
  app/
    core/config.py          settings (GUARDRAIL_* env vars)
    detection/              normaliser, rules, validators, entropy, engine, redaction
    policy/                 policy schema, evaluation, default_policy.yaml
    api/                    FastAPI gateway: routes, auth deps, middleware, rate limits
    auth/                   users, Argon2 passwords, API keys, JWT sessions
    approvals/              approval workflow (AES-GCM encrypted held prompts)
    providers/              provider interface + deterministic mock provider
    audit/                  HMAC-chained audit log, signed checkpoints, verifier, CLI
    db/                     async SQLAlchemy engine (SQLite hardening)
    migrations/             Alembic migrations
    guardrail.py            inspect(text) -> decision + sanitized text
    cli.py                  command-line inspector
  evaluation/               synthetic generators, labeled datasets, metrics script
  tests/                    pytest + Hypothesis + ReDoS suites
  scripts/check.ps1         all quality gates
docs/                       architecture, status, API, evaluation report, audit design
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

Run the gateway (see [docs/API.md](docs/API.md)):

```powershell
.venv\Scripts\python -m app.audit init-db
.venv\Scripts\python -m app.api.manage create-user admin --role admin
.venv\Scripts\uvicorn --factory app.api.app:create_app --host 127.0.0.1 --port 8000
```

Audit log (see [docs/AUDIT.md](docs/AUDIT.md)):

```powershell
.venv\Scripts\python -m app.audit init-db        # create the database
.venv\Scripts\python -m app.audit tamper-demo    # tamper with a demo chain and detect it
.venv\Scripts\python -m app.audit verify
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
