"""Administrator endpoints: approvals, audit log, users. All require the admin role."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Query, Request

from app.api.deps import AdminUser, ServicesDep
from app.api.errors import ApiError
from app.api.metrics import compute_metrics, window_start
from app.api.schemas import CreateUserRequest, DecisionRequest, UpdateUserRequest, UserOut
from app.approvals.models import ApprovalStatus
from app.approvals.service import ApprovalError
from app.auth.service import AuthError, User

router = APIRouter(prefix="/v1/admin", tags=["admin"])


# ------------------------------------------------------------------ approvals
@router.get("/approvals")
async def list_approvals(
    admin: AdminUser, services: ServicesDep, status: ApprovalStatus | None = None
) -> list[dict[str, Any]]:
    return [a.to_public() for a in await services.approvals.list_requests(status=status)]


@router.get("/approvals/{approval_id}")
async def get_approval(
    approval_id: str, request: Request, admin: AdminUser, services: ServicesDep
) -> dict[str, Any]:
    await services.approvals.expire_stale()
    approval = await services.approvals.get(approval_id)
    if approval is None:
        raise ApiError(404, "not_found", "approval request not found")
    messages = await services.approvals.review_messages(approval_id)
    await services.record(request, "approval.reviewed", admin.id, {"approval_id": approval_id})
    return {**approval.to_public(), "messages": messages}


async def _decide(
    approval_id: str,
    approve: bool,
    body: DecisionRequest | None,
    request: Request,
    admin: AdminUser,
    services: ServicesDep,
) -> dict[str, Any]:
    current = await services.approvals.get(approval_id)
    if current is None:
        raise ApiError(404, "not_found", "approval request not found")
    requester = await services.auth.get_user(current.requester_id)
    if requester is None or not _independent(admin, requester):
        raise ApiError(
            403,
            "forbidden",
            "separation of duties: you cannot decide requests of yourself, of accounts you "
            "created, of the account that created you, or of accounts created by the same "
            "administrator as you",
        )
    event = "approval.approved" if approve else "approval.denied"
    # Audit first (fail closed), then change state; record a failed attempt too.
    try:
        await services.record(request, event, admin.id, {"approval_id": approval_id})
    except Exception as exc:
        raise ApiError(503, "audit_unavailable", "audit log unavailable; nothing changed") from exc
    try:
        approval = await services.approvals.decide(
            approval_id, admin_id=admin.id, approve=approve, note=body.note if body else None
        )
    except ApprovalError as exc:
        await services.record(
            request, "approval.decision_failed", admin.id, {"approval_id": approval_id}
        )
        raise ApiError(409, "approval_not_pending", str(exc)) from exc
    return approval.to_public()


def _independent(approver: User, requester: User) -> bool:
    """Separation of duties for approvals.

    An administrator may not decide a request when they are the requester, when
    they created the requester's account, when the requester created theirs, or
    when both accounts were created by the same administrator - each of these
    would let one person approve their own request through a second account.
    Accounts created from the CLI have no creator and are not linked this way;
    an administrator with direct server access is outside this control.
    """
    if approver.id == requester.id:
        return False
    if requester.created_by is not None and requester.created_by == approver.id:
        return False
    if approver.created_by is not None and approver.created_by == requester.id:
        return False
    return not (approver.created_by is not None and approver.created_by == requester.created_by)


@router.post("/approvals/{approval_id}/approve")
async def approve(
    approval_id: str,
    request: Request,
    admin: AdminUser,
    services: ServicesDep,
    body: DecisionRequest | None = None,
) -> dict[str, Any]:
    return await _decide(approval_id, True, body, request, admin, services)


@router.post("/approvals/{approval_id}/deny")
async def deny(
    approval_id: str,
    request: Request,
    admin: AdminUser,
    services: ServicesDep,
    body: DecisionRequest | None = None,
) -> dict[str, Any]:
    return await _decide(approval_id, False, body, request, admin, services)


# ----------------------------------------------------------------------- audit
@router.get("/audit/events")
async def audit_events(
    admin: AdminUser,
    services: ServicesDep,
    limit: int = Query(default=50, ge=1, le=500),
    before_seq: int | None = Query(default=None, ge=1),
    event_type: str | None = Query(default=None, max_length=64),
    actor: str | None = Query(default=None, max_length=128),
) -> list[dict[str, Any]]:
    events = await services.audit.list_events(
        limit=limit, before_seq=before_seq, event_type=event_type, actor=actor
    )
    return [e.model_dump() for e in events]


@router.get("/audit/verify")
async def audit_verify(request: Request, admin: AdminUser, services: ServicesDep) -> dict[str, Any]:
    report = await services.audit.verify()
    await services.record(
        request,
        "audit.verified",
        admin.id,
        {"ok": report.ok, "events_checked": report.events_checked},
    )
    return report.to_public()


# ------------------------------------------------------------ metrics / policy
@router.get("/metrics")
async def metrics(
    admin: AdminUser, services: ServicesDep, hours: int = Query(default=168, ge=1, le=24 * 90)
) -> dict[str, Any]:
    """Aggregates over the audit log for the dashboard (metadata only)."""
    events, truncated = await services.audit.events_since(window_start(hours))
    return compute_metrics(events, hours) | {"truncated": truncated}


@router.get("/policy")
async def policy(admin: AdminUser, services: ServicesDep) -> dict[str, Any]:
    """The active policy (read-only)."""
    return services.guard.policy.model_dump(mode="json")


# ----------------------------------------------------------------------- users
@router.get("/users", response_model=list[UserOut])
async def list_users(admin: AdminUser, services: ServicesDep) -> list[UserOut]:
    return [UserOut.from_user(u) for u in await services.auth.list_users()]


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    body: CreateUserRequest, request: Request, admin: AdminUser, services: ServicesDep
) -> UserOut:
    user_id = uuid.uuid4().hex
    try:
        await services.record(
            request, "user.created", admin.id, {"user_id": user_id, "role": body.role.value}
        )
    except Exception as exc:
        raise ApiError(503, "audit_unavailable", "audit log unavailable; nothing changed") from exc
    try:
        user = await services.auth.create_user(
            body.username, body.password, body.role, created_by=admin.id, user_id=user_id
        )
    except AuthError as exc:
        await services.record(request, "user.create_failed", admin.id, {"user_id": user_id})
        raise ApiError(400, "invalid_request", str(exc)) from exc
    return UserOut.from_user(user)


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: str, body: UpdateUserRequest, request: Request, admin: AdminUser, services: ServicesDep
) -> UserOut:
    if user_id == admin.id and not body.is_active:
        raise ApiError(400, "invalid_request", "administrators cannot deactivate themselves")
    if await services.auth.get_user(user_id) is None:
        raise ApiError(404, "not_found", "user not found")
    try:
        await services.record(
            request, "user.updated", admin.id, {"user_id": user_id, "is_active": body.is_active}
        )
    except Exception as exc:
        raise ApiError(503, "audit_unavailable", "audit log unavailable; nothing changed") from exc
    try:
        changed = await services.auth.set_active(user_id, body.is_active)
    except AuthError as exc:
        raise ApiError(400, "invalid_request", str(exc)) from exc
    if not changed:
        raise ApiError(404, "not_found", "user not found")
    user = await services.auth.get_user(user_id)
    assert user is not None  # noqa: S101 - updated above
    return UserOut.from_user(user)
