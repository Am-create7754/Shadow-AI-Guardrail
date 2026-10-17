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

> **Current phase:** Phases 1-5 are complete: detection + policy engine,
> tamper-evident audit log, the HTTP gateway (auth, approvals, OpenAI-compatible
> endpoint), output security (real OpenAI-compatible provider, answer
> redaction, insecure-code checks, leak-safe streaming) and the web dashboard
> (developer playground, approvals, API keys; admin overview, approval queue,
> audit log with verification, users, policy) and a Chrome MV3 extension that
> checks prompts typed into ChatGPT, Claude, Gemini and Copilot before they are sent.
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
    providers/              provider interface, OpenAI-compatible adapter, mock provider
    output/                 answer inspection, leak-safe stream guard, insecure-code checks
    audit/                  HMAC-chained audit log, signed checkpoints, verifier, CLI
    db/                     async SQLAlchemy engine (SQLite hardening)
    migrations/             Alembic migrations
    guardrail.py            inspect(text) -> decision + sanitized text
    cli.py                  command-line inspector
  evaluation/               synthetic generators, labeled datasets, metrics script
  tests/                    pytest + Hypothesis + ReDoS suites
  scripts/check.ps1         all quality gates
frontend/                   React 19 + TypeScript + Vite dashboard (served by the gateway at /app)
  src/api/                  typed API client (token in memory only, SSE parser)
  src/pages/                playground, approvals, API keys; admin/* pages
  src/components/           UI primitives, guardrail visualisations (text-only rendering)
extension/                  Chrome MV3 extension (see extension/README.md)
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

Dashboard (requires Node.js 20.19+ or 22.12+), from the repository root:

```powershell
cd frontend
npm ci
npm run build        # the gateway now serves it at http://127.0.0.1:8000/app/
npm test             # Vitest component and client tests
```

For live development, run `npm run dev` (http://localhost:5173/app/) next to the
gateway; API calls are proxied to it. The session token is held in memory only,
so reloading the page signs you out.

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
