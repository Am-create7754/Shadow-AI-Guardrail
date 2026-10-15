# Guardrail dashboard

React 19 + TypeScript + Vite web UI for the Shadow AI Guardrail gateway.

- **Developers:** prompt playground (decision, findings, the exact text sent to
  the model, streamed answer with output findings and code warnings), their own
  approval requests, API keys.
- **Administrators:** security overview (metrics from the audit log), approval
  queue (redacted text only), audit log with chain verification, users, active
  policy.

```powershell
npm ci
npm run build            # served by the gateway at http://127.0.0.1:8000/app/
npm run dev              # dev server at http://localhost:5173/app/, API proxied to :8000
.\scripts\check.ps1      # lint, typecheck, tests, build
```

Set `GUARDRAIL_GATEWAY_URL` to proxy the dev server to a gateway other than
`http://127.0.0.1:8000`.

Security properties (see `docs/ARCHITECTURE.md` §3.8): the session token is kept
in memory only, every server-provided string is rendered as text, and admin
screens are hidden from developers while the API enforces the same rule.
