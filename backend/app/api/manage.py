"""Gateway administration CLI (bootstrap users and API keys).

PowerShell examples (from backend/)::

    .venv\\Scripts\\python -m app.api.manage create-user admin --role admin
    .venv\\Scripts\\python -m app.api.manage create-api-key admin --name laptop

Passwords are read from a hidden prompt (or stdin with ``--password-stdin``),
never from command-line arguments, which end up in shell history and process
listings.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys

from app.api.app import migrate
from app.auth.models import Role
from app.auth.service import AuthError, AuthService
from app.core.config import get_settings
from app.core.secrets import resolve_key
from app.db.engine import create_engine


def _auth(engine: object) -> AuthService:
    s = get_settings()
    return AuthService(
        engine,  # type: ignore[arg-type]
        jwt_key=resolve_key(s, s.jwt_secret, "jwt_secret"),
        pepper=resolve_key(s, s.api_key_pepper, "api_key_pepper"),
        token_ttl_minutes=s.jwt_ttl_minutes,
    )


async def _create_user(username: str, password: str, role: Role) -> int:
    engine = create_engine(get_settings().database_url)
    try:
        user = await _auth(engine).create_user(username, password, role)
    except AuthError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        await engine.dispose()
    print(f"created {user.role.value} '{user.username}' (id {user.id})")
    return 0


async def _create_key(username: str, name: str) -> int:
    engine = create_engine(get_settings().database_url)
    try:
        auth = _auth(engine)
        user = next((u for u in await auth.list_users() if u.username == username.lower()), None)
        if user is None:
            print(f"error: no user '{username}'", file=sys.stderr)
            return 1
        created = await auth.create_api_key(user.id, name)
    finally:
        await engine.dispose()
    print(created.key)
    print("store this key now; it cannot be shown again", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.api.manage")
    sub = parser.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("create-user")
    u.add_argument("username")
    u.add_argument("--role", choices=[r.value for r in Role], default=Role.DEVELOPER.value)
    u.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    k = sub.add_parser("create-api-key")
    k.add_argument("username")
    k.add_argument("--name", default="cli")
    args = parser.parse_args(argv)

    migrate(get_settings().database_url)
    if args.cmd == "create-user":
        if args.password_stdin:
            password = sys.stdin.readline().rstrip("\r\n")
        else:
            password = getpass.getpass("Password: ")
            if getpass.getpass("Repeat password: ") != password:
                print("error: passwords do not match", file=sys.stderr)
                return 1
        return asyncio.run(_create_user(args.username, password, Role(args.role)))
    return asyncio.run(_create_key(args.username, args.name))


if __name__ == "__main__":
    sys.exit(main())
