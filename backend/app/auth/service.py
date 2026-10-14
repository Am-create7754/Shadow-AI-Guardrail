"""Authentication: passwords (Argon2id), API keys (peppered HMAC), JWT sessions.

Security properties
-------------------
* Passwords are hashed with Argon2id (argon2-cffi defaults, RFC 9106 low-memory
  profile) and transparently re-hashed when parameters change.
* Unknown usernames still run one Argon2 verification against a dummy hash, so
  response time does not reveal which usernames exist.
* API keys are 256-bit random values. Being high-entropy, they are stored as
  HMAC-SHA256(pepper, key) - a slow hash adds nothing and would make every
  request slow. Lookup uses a non-secret prefix; comparison is constant-time.
* JWTs carry only the user id. On every request the user is re-loaded from the
  database and the *database* role and active flag are used, so a demoted or
  disabled user loses access immediately and a token cannot grant a role.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import Table, func, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.audit.chain import utc_timestamp
from app.auth.models import ApiKeyRow, Role, UserRow

USERS = cast(Table, UserRow.__table__)
API_KEYS = cast(Table, ApiKeyRow.__table__)

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-]{2,63}$")
MIN_PASSWORD_LENGTH = 12
API_KEY_PREFIX = "grk_"
JWT_ISSUER = "guardrail"
JWT_AUDIENCE = "guardrail-api"
JWT_ALGORITHM = "HS256"
MAX_API_KEYS_PER_USER = 20
# A tiny deny-list of the most common choices; length is the main defence.
_COMMON_PASSWORDS = frozenset(
    {
        "password1234",
        "123456789012",
        "qwertyuiop12",
        "administrator",
        "letmein12345",
        "welcome12345",
        "changeme1234",
        "passwordpassword",
        "iloveyou1234",
    }
)


class AuthError(ValueError):
    """Invalid input to an auth operation (message is safe to show)."""


@dataclass(frozen=True)
class User:
    id: str
    username: str
    role: Role
    is_active: bool
    created_by: str | None = None

    @property
    def is_admin(self) -> bool:
        return self.role is Role.ADMIN


@dataclass(frozen=True)
class CreatedApiKey:
    id: str
    name: str
    prefix: str
    key: str  # plaintext, returned exactly once

    def __repr__(self) -> str:
        return f"CreatedApiKey(id={self.id!r}, name={self.name!r}, prefix={self.prefix!r})"


def check_password_policy(username: str, password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AuthError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > 256:
        raise AuthError("password must be at most 256 characters")
    lowered = password.lower()
    if lowered in _COMMON_PASSWORDS or username.lower() in lowered:
        raise AuthError("password is too easy to guess")


def _row_to_user(row: object) -> User:
    return User(
        id=row.id,  # type: ignore[attr-defined]
        username=row.username,  # type: ignore[attr-defined]
        role=Role(row.role),  # type: ignore[attr-defined]
        is_active=bool(row.is_active),  # type: ignore[attr-defined]
        created_by=row.created_by,  # type: ignore[attr-defined]
    )


def _ts_seconds(ts: str) -> float:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC).timestamp()


class AuthService:
    def __init__(
        self, engine: AsyncEngine, *, jwt_key: bytes, pepper: bytes, token_ttl_minutes: int
    ) -> None:
        self.engine = engine
        self._jwt_key = jwt_key
        self._pepper = pepper
        self._ttl = timedelta(minutes=token_ttl_minutes)
        self._hasher = PasswordHasher()
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(16))

    def __repr__(self) -> str:
        return "AuthService()"

    # ------------------------------------------------------------------ users
    async def create_user(
        self,
        username: str,
        password: str,
        role: Role,
        *,
        created_by: str | None = None,
        user_id: str | None = None,
    ) -> User:
        username = username.strip().lower()
        if not USERNAME_RE.match(username):
            raise AuthError("username must be 3-64 chars: lowercase letters, digits, . _ -")
        check_password_policy(username, password)
        user = User(user_id or uuid.uuid4().hex, username, role, True, created_by)
        # Argon2 is deliberately slow (~0.1 s): never run it on the event loop.
        password_hash = await asyncio.to_thread(self._hasher.hash, password)
        async with self.engine.begin() as conn:
            exists = (
                await conn.execute(select(USERS.c.id).where(USERS.c.username == username))
            ).first()
            if exists:
                raise AuthError("username already exists")
            await conn.execute(
                insert(USERS).values(
                    id=user.id,
                    username=username,
                    password_hash=password_hash,
                    role=role.value,
                    is_active=True,
                    created_at=utc_timestamp(),
                    created_by=created_by,
                    sessions_valid_after=None,
                )
            )
        return user

    async def get_user(self, user_id: str) -> User | None:
        async with self.engine.connect() as conn:
            row = (await conn.execute(select(USERS).where(USERS.c.id == user_id))).first()
        return _row_to_user(row) if row else None

    async def list_users(self) -> list[User]:
        async with self.engine.connect() as conn:
            rows = (await conn.execute(select(USERS).order_by(USERS.c.username))).all()
        return [_row_to_user(r) for r in rows]

    async def set_active(self, user_id: str, active: bool) -> bool:
        """Activate/deactivate. Deactivation also revokes the user's sessions.

        Raises AuthError rather than leaving the system without an active
        administrator (checked under the write lock, so two admins deactivating
        each other concurrently cannot both succeed).
        """
        async with self.engine.connect() as raw:
            conn = await raw.execution_options(sqlite_begin="IMMEDIATE")
            async with conn.begin():
                row = (
                    await conn.execute(select(USERS).where(USERS.c.id == user_id).with_for_update())
                ).first()
                if row is None:
                    return False
                values: dict[str, object] = {"is_active": active}
                if not active:
                    if row.role == Role.ADMIN.value and row.is_active:
                        others = (
                            await conn.execute(
                                select(func.count())
                                .select_from(USERS)
                                .where(
                                    USERS.c.role == Role.ADMIN.value,
                                    USERS.c.is_active.is_(True),
                                    USERS.c.id != user_id,
                                )
                            )
                        ).scalar_one()
                        if others == 0:
                            raise AuthError("cannot deactivate the last active administrator")
                    values["sessions_valid_after"] = utc_timestamp()
                await conn.execute(update(USERS).where(USERS.c.id == user_id).values(**values))
        return True

    async def revoke_sessions(self, user_id: str) -> None:
        """Invalidate every session token issued to the user so far (logout)."""
        async with self.engine.begin() as conn:
            await conn.execute(
                update(USERS)
                .where(USERS.c.id == user_id)
                .values(sessions_valid_after=utc_timestamp())
            )

    async def authenticate(self, username: str, password: str) -> User | None:
        """Return the user for valid credentials, else None (timing-uniform)."""
        username = username.strip().lower()
        async with self.engine.connect() as conn:
            row = (await conn.execute(select(USERS).where(USERS.c.username == username))).first()
        stored = row.password_hash if row else self._dummy_hash
        try:
            await asyncio.to_thread(self._hasher.verify, stored, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return None
        if row is None or not row.is_active:
            return None
        if self._hasher.check_needs_rehash(stored):
            async with self.engine.begin() as conn:
                await conn.execute(
                    update(USERS)
                    .where(USERS.c.id == row.id)
                    .values(password_hash=await asyncio.to_thread(self._hasher.hash, password))
                )
        return _row_to_user(row)

    # --------------------------------------------------------------- api keys
    def _hash_key(self, key: str) -> str:
        return hmac.new(self._pepper, key.encode(), hashlib.sha256).hexdigest()

    async def create_api_key(self, user_id: str, name: str) -> CreatedApiKey:
        name = name.strip()
        if not 1 <= len(name) <= 64:
            raise AuthError("key name must be 1-64 characters")
        async with self.engine.connect() as conn:
            active = (
                await conn.execute(
                    select(func.count())
                    .select_from(API_KEYS)
                    .where(API_KEYS.c.user_id == user_id, API_KEYS.c.revoked_at.is_(None))
                )
            ).scalar_one()
        if active >= MAX_API_KEYS_PER_USER:
            raise AuthError(f"at most {MAX_API_KEYS_PER_USER} active API keys per user")
        for _ in range(3):  # a 48-bit prefix collision is unlikely, but handled
            prefix = secrets.token_hex(6)  # 12 hex chars, non-secret lookup handle
            key = f"{API_KEY_PREFIX}{prefix}_{secrets.token_urlsafe(32)}"
            # Dashed UUID: recognisable as an identifier (hex blobs near the word "key"
            # look like secrets to the audit log's own secret scan, and are rejected).
            created = CreatedApiKey(str(uuid.uuid4()), name, prefix, key)
            try:
                async with self.engine.begin() as conn:
                    await conn.execute(
                        insert(API_KEYS).values(
                            id=created.id,
                            user_id=user_id,
                            name=name,
                            prefix=prefix,
                            key_hash=self._hash_key(key),
                            created_at=utc_timestamp(),
                            last_used_at=None,
                            revoked_at=None,
                        )
                    )
            except IntegrityError:
                continue
            return created
        raise AuthError("could not allocate an API key; try again")

    async def list_api_keys(self, user_id: str) -> list[dict[str, object]]:
        async with self.engine.connect() as conn:
            rows = (
                (
                    await conn.execute(
                        select(
                            API_KEYS.c.id,
                            API_KEYS.c.name,
                            API_KEYS.c.prefix,
                            API_KEYS.c.created_at,
                            API_KEYS.c.last_used_at,
                            API_KEYS.c.revoked_at,
                        )
                        .where(API_KEYS.c.user_id == user_id)
                        .order_by(API_KEYS.c.created_at)
                    )
                )
                .mappings()
                .all()
            )
        return [dict(r) for r in rows]

    async def revoke_api_key(self, user_id: str, key_id: str) -> bool:
        async with self.engine.begin() as conn:
            res = await conn.execute(
                update(API_KEYS)
                .where(
                    API_KEYS.c.id == key_id,
                    API_KEYS.c.user_id == user_id,
                    API_KEYS.c.revoked_at.is_(None),
                )
                .values(revoked_at=utc_timestamp())
            )
        return res.rowcount == 1

    async def resolve_api_key(self, key: str) -> User | None:
        m = re.fullmatch(rf"{API_KEY_PREFIX}([0-9a-f]{{12}})_[A-Za-z0-9_\-]{{40,64}}", key)
        if not m:
            return None
        async with self.engine.connect() as conn:
            row = (
                await conn.execute(
                    select(
                        API_KEYS.c.id.label("key_id"),
                        API_KEYS.c.key_hash,
                        API_KEYS.c.revoked_at,
                        USERS,
                    )
                    .join(USERS, USERS.c.id == API_KEYS.c.user_id)
                    .where(API_KEYS.c.prefix == m.group(1))
                )
            ).first()
        if row is None or not hmac.compare_digest(row.key_hash, self._hash_key(key)):
            return None
        if row.revoked_at is not None or not row.is_active:
            return None
        async with self.engine.begin() as conn:
            await conn.execute(
                update(API_KEYS)
                .where(API_KEYS.c.id == row.key_id)
                .values(last_used_at=utc_timestamp())
            )
        return _row_to_user(row)

    # ----------------------------------------------------------------- tokens
    def issue_token(self, user: User) -> tuple[str, int]:
        now = datetime.now(UTC)
        claims = {
            "sub": user.id,
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            # Sub-second iat so a session revoked a moment ago does not also kill a
            # login made just after it (revocation compares against this value).
            "iat": now.timestamp(),
            "nbf": int(now.timestamp()),
            "exp": now + self._ttl,
            "jti": uuid.uuid4().hex,
            "typ": "access",
        }
        return jwt.encode(claims, self._jwt_key, algorithm=JWT_ALGORITHM), int(
            self._ttl.total_seconds()
        )

    async def resolve_token(self, token: str) -> User | None:
        try:
            claims = jwt.decode(
                token,
                self._jwt_key,
                algorithms=[JWT_ALGORITHM],  # pinned: rejects "none" and algorithm confusion
                audience=JWT_AUDIENCE,
                issuer=JWT_ISSUER,
                options={"require": ["exp", "iat", "nbf", "sub", "iss", "aud", "jti"]},
            )
        except jwt.PyJWTError:
            return None
        if claims.get("typ") != "access" or not isinstance(claims.get("sub"), str):
            return None
        async with self.engine.connect() as conn:
            row = (await conn.execute(select(USERS).where(USERS.c.id == claims["sub"]))).first()
        if row is None or not row.is_active:
            return None
        if row.sessions_valid_after is not None and float(claims["iat"]) <= _ts_seconds(
            row.sessions_valid_after
        ):
            return None  # issued before logout / deactivation
        return _row_to_user(row)
