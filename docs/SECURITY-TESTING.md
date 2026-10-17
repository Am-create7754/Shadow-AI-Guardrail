# Security testing

What is tested automatically, how to run it, and the latest results.

## In CI on every push

| Check | Tool | Where | Fails the build when |
|---|---|---|---|
| Unit, integration, property and regression tests | pytest + Hypothesis | `backend` (Windows/Ubuntu x Python 3.12/3.13) | any test fails |
| Dependency vulnerabilities (Python) | `pip-audit --strict` | `backend` | a known vulnerability, or a package that cannot be audited |
| API fuzzing | Schemathesis (`python -m loadtest.fuzz`) | `backend`, Ubuntu / 3.13 | any generated request causes a 5xx |
| Dependency vulnerabilities (JS) | `npm audit` | `frontend`, `extension` | high or critical advisories |
| Static checks | ruff (incl. bandit rules `S`), mypy `--strict`, tsc strict, oxlint | all | any finding |
| Repository hygiene | `tests/test_repo_hygiene.py` | `backend` | credential-shaped literals, invisible/bidi characters, non-ASCII Python |
| Supply chain of CI itself | GitHub Actions pinned to commit SHAs (`actions/checkout`, `setup-python`, `setup-node` v7), `persist-credentials: false`, `permissions: contents: read` | all workflows | - (a tag cannot be moved under us) |

## API fuzzing (2026-10-18)

`python -m loadtest.fuzz --max-examples 50` starts an isolated gateway (temp DB,
mock provider, `backend/.env` ignored) and runs Schemathesis against its OpenAPI
schema twice: as a developer and as an administrator. Phases: coverage (boundary
values), fuzzing (random valid/invalid inputs), stateful (sequences linking
operations).

| Run | Operations | Generated requests | Server errors |
|---|---|---|---|
| Developer API key | 24 / 24 | 1,569 | **0** |
| Administrator API key | 24 / 24 | 1,543 | **0** |

Coverage limits reported by Schemathesis (honest): approval and API-key ids
cannot be discovered from the schema, so `/v1/admin/approvals/{id}...` and
`DELETE /v1/me/api-keys/{id}` were mostly exercised with unknown ids (404);
`POST /v1/admin/users` and `POST /v1/approvals/{id}/execute` reject most
generated bodies (stricter validation than the schema expresses). These paths
are covered by the targeted tests in `tests/test_api_*.py`.

## Dependency audits (2026-10-18)

* `pip-audit --strict`: no known vulnerabilities (backend runtime and dev tools).
* `npm audit`: 0 vulnerabilities in `frontend/` and `extension/`.

## Browser hardening of the dashboard

Content-Security-Policy: `default-src 'none'; script-src 'self'; style-src 'self';
... frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'`
plus `Permissions-Policy`, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`.
Trusted Types was verified in Chromium: every page (including lazily loaded admin
pages and charts) works, and an `innerHTML` string assignment is refused
("This document requires 'TrustedHTML' assignment").

## Other targeted security tests (see `docs/STATUS.md` for the full list)

ReDoS (41 rules x 16 pathological inputs), Hypothesis properties (redaction never
leaks, stream equals batch), audit tampering (edit, delete, reorder, forge,
rollback, key theft), authentication (JWT algorithm pinning, revocation, API
key hashing), path traversal and UNC paths on the static route, separation of
duties, fail-closed behaviour on audit and provider failures, and the browser
extension's trust boundaries (`extension/src/**/*.test.ts`).

## Not done (and why)

* **OWASP ZAP baseline scan:** needs Docker or a Java install, neither available
  on the development machine; the headers and CSP it would check are asserted by
  tests instead (`tests/test_api_dashboard_static.py`, `tests/test_api_security.py`).
* **Penetration test by a third party:** out of scope for this project.
