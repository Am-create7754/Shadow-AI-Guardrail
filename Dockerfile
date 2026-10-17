# Shadow AI Guardrail gateway + dashboard.
#
# NOT BUILT OR TESTED in this project's environment (Docker was not available
# on the development machine). It follows the deployment checklist in
# docs/DEPLOYMENT.md; build and test it before relying on it:
#
#   docker build -t guardrail .
#   docker run --read-only --tmpfs /tmp -p 8000:8000 \
#     -v guardrail-data:/data --env-file guardrail.env guardrail

# --- 1. dashboard ---------------------------------------------------------------
FROM node:22.14-bookworm-slim AS dashboard
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# --- 2. runtime -----------------------------------------------------------------
FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    GUARDRAIL_ENVIRONMENT=production \
    GUARDRAIL_DATABASE_URL=sqlite+aiosqlite:////data/guardrail.db \
    GUARDRAIL_KEYS_DIR=/data/keys \
    GUARDRAIL_AUDIT_ANCHOR_PATH=/data/anchors/audit_anchor.json
WORKDIR /app
COPY backend/pyproject.toml backend/README.md backend/
COPY backend/app backend/app
COPY backend/alembic.ini backend/
# Editable install: the app locates alembic.ini, migrations and ../frontend/dist
# relative to its source directory (BACKEND_DIR).
RUN pip install -e ./backend && useradd --system --uid 10001 --home-dir /nonexistent guardrail \
    && mkdir -p /data && chown guardrail /data
COPY --from=dashboard /src/frontend/dist frontend/dist

USER guardrail
WORKDIR /app/backend
EXPOSE 8000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=2).status != 200)"
# Behind a reverse proxy, set FORWARDED_ALLOW_IPS to the proxy's address so the
# client IP (used by the login rate limit) is taken from X-Forwarded-For only
# when the request really comes from that proxy.
CMD ["sh", "-c", "exec uvicorn --factory app.api.app:create_app --host 0.0.0.0 --port 8000 --workers 1 --proxy-headers --forwarded-allow-ips \"${FORWARDED_ALLOW_IPS:-127.0.0.1}\" --no-server-header"]
