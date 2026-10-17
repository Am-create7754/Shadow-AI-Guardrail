"""Start an isolated gateway for load testing.

Fresh database, anchor and keys in ``--dir``, mock provider, the developer's
``backend/.env`` ignored (it may hold a real provider key: load tests must never
call a paid API). Prints ``KEY <api key>`` for a throwaway user, then serves.

    .venv\\Scripts\\python -m loadtest.server --dir %TEMP%\\gr-load --port 8765
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
from pathlib import Path

import uvicorn
from pydantic import SecretStr

from app.core.config import Environment, Settings

Settings.model_config["env_file"] = None  # never read backend/.env here

from app.api.app import create_app, migrate  # noqa: E402
from app.auth.models import Role  # noqa: E402
from app.auth.service import AuthService  # noqa: E402
from app.core.secrets import resolve_key  # noqa: E402
from app.db.engine import create_engine  # noqa: E402


def settings_for(base: Path) -> Settings:
    # One random set of keys per run, shared by the bootstrap and the server
    # (in test mode each component would otherwise generate its own).
    def key() -> SecretStr:
        return SecretStr(secrets.token_urlsafe(48))

    return Settings(
        fingerprint_key=key(),
        audit_key=key(),
        jwt_secret=key(),
        api_key_pepper=key(),
        data_key=key(),
        environment=Environment.TEST,
        database_url="sqlite+aiosqlite:///" + (base / "load.db").as_posix(),
        audit_anchor_path=base / "anchor.json",
        keys_dir=base / "keys",
        provider="mock",
        rate_limit_per_minute=100_000,  # maximum allowed: measure the gateway, not the limiter
        dashboard_dir=None,
        checkpoint_interval=1_000,
    )


async def _bootstrap(settings: Settings) -> str:
    await asyncio.to_thread(migrate, settings.database_url)
    engine = create_engine(settings.database_url)
    try:
        auth = AuthService(
            engine,
            jwt_key=resolve_key(settings, settings.jwt_secret, "jwt_secret"),
            pepper=resolve_key(settings, settings.api_key_pepper, "api_key_pepper"),
            token_ttl_minutes=settings.jwt_ttl_minutes,
        )
        user = await auth.create_user("loadtest", "load-test-password-not-secret", Role.DEVELOPER)
        return (await auth.create_api_key(user.id, "loadtest")).key
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    args.dir.mkdir(parents=True, exist_ok=True)
    settings = settings_for(args.dir)  # one instance: same keys for both
    key = asyncio.run(_bootstrap(settings))
    print(f"KEY {key}", flush=True)
    app = create_app(settings)
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning", access_log=False)


if __name__ == "__main__":
    main()
