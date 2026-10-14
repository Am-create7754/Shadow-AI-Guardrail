"""Login, current-user info and self-service API keys."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from app.api.deps import CurrentUser, ServicesDep
from app.api.errors import ApiError
from app.api.ratelimit import retry_after_header
from app.api.schemas import CreateApiKeyRequest, LoginRequest, TokenResponse, UserOut
from app.auth.service import AuthError

router = APIRouter(prefix="/v1", tags=["auth"])


def _client_ip(request: Request) -> str:
    # X-Forwarded-For is deliberately NOT trusted: without a known reverse proxy
    # in front, any client could set it to dodge the login rate limit.
    return request.client.host if request.client else "unknown"


@router.post("/auth/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request, services: ServicesDep) -> TokenResponse:
    ip = _client_ip(request)
    # Limited per client address only. A per-username budget would let anyone lock
    # a known user (e.g. an admin) out by spamming wrong passwords; online guessing
    # is instead bounded by this limit, Argon2 cost and the password policy.
    wait = services.login_limiter.hit(f"login-ip:{ip}")
    if wait:
        raise ApiError(
            429,
            "rate_limited",
            "too many login attempts",
            headers={"Retry-After": retry_after_header(wait)},
        )
    user = await services.auth.authenticate(body.username, body.password)
    if user is None:
        # The attempted username is not logged: users sometimes type a password there.
        await services.record(request, "auth.login_failed", "anonymous", {"client": ip})
        raise ApiError(401, "invalid_credentials", "invalid username or password")
    await services.record(request, "auth.login_succeeded", user.id, {"client": ip})
    token, ttl = services.auth.issue_token(user)
    return TokenResponse(access_token=token, expires_in=ttl)


@router.post("/auth/logout", status_code=204)
async def logout(request: Request, user: CurrentUser, services: ServicesDep) -> None:
    """Revoke every session token of the current user (API keys are unaffected)."""
    await services.auth.revoke_sessions(user.id)
    await services.record(request, "auth.logout", user.id, {})


@router.get("/me", response_model=UserOut)
async def me(user: CurrentUser) -> UserOut:
    return UserOut.from_user(user)


@router.get("/me/api-keys")
async def list_my_keys(user: CurrentUser, services: ServicesDep) -> list[dict[str, Any]]:
    return await services.auth.list_api_keys(user.id)


@router.post("/me/api-keys", status_code=201)
async def create_my_key(
    body: CreateApiKeyRequest, request: Request, user: CurrentUser, services: ServicesDep
) -> dict[str, Any]:
    try:
        created = await services.auth.create_api_key(user.id, body.name)
    except AuthError as exc:
        raise ApiError(400, "invalid_request", str(exc)) from exc
    await services.record(
        request, "api_key.created", user.id, {"key_id": created.id, "prefix": created.prefix}
    )
    return {
        "id": created.id,
        "name": created.name,
        "prefix": created.prefix,
        "key": created.key,
        "note": "store this key now; it cannot be shown again",
    }


@router.delete("/me/api-keys/{key_id}", status_code=204)
async def revoke_my_key(
    key_id: str, request: Request, user: CurrentUser, services: ServicesDep
) -> None:
    if not await services.auth.revoke_api_key(user.id, key_id):
        raise ApiError(404, "not_found", "API key not found")
    await services.record(request, "api_key.revoked", user.id, {"key_id": key_id})
