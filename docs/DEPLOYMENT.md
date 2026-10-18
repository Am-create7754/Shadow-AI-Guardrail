# Production deployment checklist

The gateway refuses to start in production (`GUARDRAIL_ENVIRONMENT=production`)
without explicit keys; development conveniences (generated keys, `/docs`) are off.

## 1. Secrets

| Setting | Purpose | Notes |
|---|---|---|
| `GUARDRAIL_AUDIT_KEY` | HMAC key of the audit chain | ≥ 32 bytes; rotate with `GUARDRAIL_AUDIT_PREVIOUS_KEYS` (old keys verify, never sign) |
| `GUARDRAIL_CHECKPOINT_KEY_PATH` | Ed25519 private key file for signed checkpoints | File readable by the service only; export the **public** key (`python -m app.audit export-public-key`) to the verifiers |
| `GUARDRAIL_FINGERPRINT_KEY` | HMAC key for value fingerprints | Leak lets short passwords be brute-forced from fingerprints |
| `GUARDRAIL_JWT_SECRET`, `GUARDRAIL_API_KEY_PEPPER`, `GUARDRAIL_DATA_KEY` | Sessions, API-key hashes, AES-GCM for held prompts | All distinct (enforced) |
| `GUARDRAIL_PROVIDER_API_KEY` | Upstream AI provider | Never sent to clients or logged |

Load them from a secret store (Azure Key Vault, AWS Secrets Manager, Vault,
Kubernetes secrets) into environment variables; never bake them into an image or
commit them. Generate with `python -c "import secrets; print(secrets.token_urlsafe(48))"`.

## 2. Network

* **TLS:** terminate HTTPS at a reverse proxy; the gateway listens on localhost or
  a private network only. Example (Caddy):

  ```
  guardrail.example.com {
      reverse_proxy 127.0.0.1:8000
  }
  ```

* **Client IP for the login rate limit:** run Uvicorn with `--proxy-headers
  --forwarded-allow-ips <proxy address>` so `X-Forwarded-For` is trusted only from
  that proxy (the Dockerfile does this via `FORWARDED_ALLOW_IPS`). Without it,
  all clients share the proxy's login budget; with `*` an attacker could choose
  their apparent IP.
* **Egress:** only the gateway host may reach provider APIs
  (`deploy/ai-domains.json`, `docs/SECURITY-ARCHITECTURE.md`).
* `GUARDRAIL_CORS_ORIGINS`: empty or the dashboard origin only (the built
  dashboard is served by the gateway itself, so it needs no CORS).

## 3. Process and files

* One Uvicorn worker per SQLite database (rate limits and the audit group commit
  are per process; several workers are safe for the chain but each has its own
  limits). For more load, PostgreSQL (`GUARDRAIL_DATABASE_URL=postgresql+asyncpg://...`
  after `pip install asyncpg`, which is not a default dependency; the row-lock code
  path is implemented but untested - see the known limitations).
* Run as an unprivileged user with a read-only root filesystem; only the data
  directory (database, anchor) is writable. The `Dockerfile` is built and
  smoke-tested in CI on every relevant push (`.github/workflows/docker.yml`:
  production mode, read-only root, uid 10001, login, inspection, audit verify).
* Keep the database **outside** synced folders (OneDrive/Dropbox) - sync tools can
  corrupt SQLite's WAL files.
* Build the dashboard (`frontend: npm ci && npm run build`); the gateway serves it
  at `/app` with a strict CSP and Trusted Types.

## 4. Audit evidence

* **Anchor off-host:** checkpoints are signed every `GUARDRAIL_CHECKPOINT_INTERVAL`
  events and written to `GUARDRAIL_AUDIT_ANCHOR_PATH`. Copy exported checkpoints
  regularly to a system the gateway cannot write to (a WORM bucket, another
  team's server):

  ```powershell
  .venv\Scripts\python -m app.audit checkpoint
  .venv\Scripts\python -m app.audit export-checkpoints D:\evidence\checkpoints-2026-10-18.json
  ```

* **Verify** regularly and alert on a non-zero exit code:
  `python -m app.audit verify --checkpoints <exported.json> --public-key <pub.pem>`.

## 5. Backup and restore

Backup (safe while the gateway runs; uses SQLite's online backup API, verifies
the copy's chain and writes a SHA-256 file next to it; never overwrites):

```powershell
.venv\Scripts\python -m app.audit backup --out D:\backups\guardrail-2026-10-18.db
```

Store backups encrypted and off-host. The database holds AES-GCM-encrypted held
prompts and hashed API keys, but also user names and audit metadata.

Restore:

1. Stop the gateway. Check the checksum:
   `(Get-FileHash D:\backups\guardrail-2026-10-18.db).Hash` against the `.sha256` file.
2. Copy the backup to the database path (keep the damaged file for analysis).
3. Run `python -m app.audit verify`. If events were written after the backup, the
   anchor (newer than the backup) reports a **rollback** - correct: those events
   are lost, and the report is the evidence. Record the incident, move the old
   anchor file aside (keep it), then `python -m app.audit checkpoint` to anchor the
   restored chain.
4. Start the gateway.

## 6. Operations

* `GET /health` (liveness) and `GET /ready` (database) for the orchestrator.
* Logs contain request ids, decisions and exception types - never prompt text,
  keys or answers. Audit write failures are logged as
  `audit write failed (<type>)`; they mean requests are being refused (fail closed).
* Users: bootstrap the first admin with `python -m app.api.manage create-user`;
  later accounts from the dashboard (creator recorded for separation of duties).
* Browser extension and policies: `deploy/chrome-policy/README.md`.
