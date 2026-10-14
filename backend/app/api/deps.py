"""Shared services and request dependencies (authentication, roles, rate limits)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.api.errors import ApiError, request_id
from app.api.ratelimit import RateLimiter, retry_after_header
from app.approvals.service import ApprovalService
from app.audit.schemas import AuditEventIn
from app.audit.service import AuditLog
from app.auth.service import API_KEY_PREFIX, AuthService, User
from app.core.config import Settings
from app.guardrail import Guardrail
from app.providers.base import Provider


@dataclass
class Services:
    settings: Settings
    guard: Guardrail
    audit: AuditLog
    auth: AuthService
    approvals: ApprovalService
    provider: Provider
    limiter: RateLimiter
    login_limiter: RateLimiter

    async def record(
        self,
        request: Request,
        event_type: str,
        actor: str,
        data: dict[str, Any],
    ) -> None:
        """Append an audit event tied to this request (raises on failure: callers
        that must fail closed rely on that)."""
        await self.audit.append(
            AuditEventIn(
                event_type=event_type,
                actor=actor,
                request_id=request_id(request),
                data=data,
            )
        )


def get_services(request: Request) -> Services:
    services: Services = request.app.state.services
    return services


ServicesDep = Annotated[Services, Depends(get_services)]

_UNAUTHORIZED = {"WWW-Authenticate": "Bearer"}


# Declares the scheme in the OpenAPI document (adds the "Authorize" button to
# /docs). auto_error=False: the header is still parsed and validated below.
_bearer_scheme = HTTPBearer(
    auto_error=False,
    description="Session token from /v1/auth/login, or an API key (grk_...)",
)


async def current_user(
    request: Request,
    services: ServicesDep,
    _doc: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)] = None,
) -> User:
    """Authenticate via ``Authorization: Bearer <JWT or API key>``.

    The role used for authorisation always comes from the database row, never
    from the token or the request.
    """
    header = request.headers.get("authorization", "")
    scheme, _, credential = header.partition(" ")
    if scheme.lower() != "bearer" or not credential:
        raise ApiError(401, "unauthorized", "missing bearer credentials", headers=_UNAUTHORIZED)
    credential = credential.strip()
    if credential.startswith(API_KEY_PREFIX):
        user = await services.auth.resolve_api_key(credential)
    else:
        user = await services.auth.resolve_token(credential)
    if user is None:
        raise ApiError(401, "unauthorized", "invalid or expired credentials", headers=_UNAUTHORIZED)
    wait = services.limiter.hit(f"user:{user.id}")
    if wait:
        raise ApiError(429, "rate_limited", "too many requests",
                       headers={"Retry-After": retry_after_header(wait)})  # fmt: skip
    request.state.user = user
    return user


CurrentUser = Annotated[User, Depends(current_user)]


async def require_admin(user: CurrentUser) -> User:
    if not user.is_admin:
        raise ApiError(403, "forbidden", "administrator role required")
    return user


AdminUser = Annotated[User, Depends(require_admin)]
