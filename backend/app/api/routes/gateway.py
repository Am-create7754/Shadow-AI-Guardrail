"""Prompt inspection, the OpenAI-compatible chat proxy, and approval execution.

Invariants (each covered by integration tests):

1. The provider is called only with text produced by ``Guardrail`` redaction.
2. BLOCK and REQUIRE_APPROVAL never call the provider.
3. An audit event is committed *before* anything is forwarded or held; if that
   write fails the request fails and nothing is forwarded or stored.
4. Responses, audit events, approval rows and logs never contain raw secrets:
   only placeholders, entity types, counts and fingerprints. Every client-chosen
   string that is stored (prompt text, model name) is inspected first.
5. Provider failures of any kind are contained: mapped to 502/503/504, audited,
   and never echoed (an exception message may quote the prompt).
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from fastapi import APIRouter, Request

from app.api.deps import CurrentUser, Services, ServicesDep
from app.api.errors import ApiError, request_id
from app.api.schemas import ChatCompletionRequest, InspectRequest
from app.approvals.service import ApprovalError
from app.auth.service import User
from app.guardrail import ConversationInspection
from app.policy.models import Action
from app.providers.base import ChatMessage, ProviderError, ProviderRequest, ProviderResponse

router = APIRouter(prefix="/v1", tags=["gateway"])
logger = logging.getLogger("guardrail.api")


def _summary(insp: ConversationInspection, model: str | None = None) -> dict[str, Any]:
    """Audit/approval-safe description of an inspection (no text)."""
    rules = sorted(
        {d.finding.rule_id for d in insp.decision.findings if d.action is not Action.ALLOW}
    )
    data: dict[str, Any] = {
        "action": insp.action.value,
        "risk_score": insp.decision.risk_score,
        "entities": insp.entity_counts,
        "rules": rules,
        "placeholders": insp.placeholders,
        "messages": len(insp.messages),
        "reasons": list(insp.decision.reasons)[:5],
    }
    if model is not None:
        data["model"] = model
    return data


async def _audit_or_fail(
    services: Services, request: Request, event: str, user: User, data: dict[str, Any]
) -> None:
    try:
        await services.record(request, event, user.id, data)
    except Exception as exc:
        # Fail closed: without an audit record, nothing may be forwarded or held.
        raise ApiError(
            503, "audit_unavailable", "audit log unavailable; request not forwarded"
        ) from exc


async def _audit_best_effort(
    services: Services, request: Request, event: str, user: User, data: dict[str, Any]
) -> bool:
    """For events after the prompt has already left: a failed audit write must
    not turn a delivered answer into an error (the pre-forward event exists)."""
    try:
        await services.record(request, event, user.id, data)
    except Exception as exc:
        logger.error(
            "audit write failed for %s (request %s): %s",
            event,
            request_id(request),
            type(exc).__name__,
        )
        return False
    return True


def _check_model_name(services: Services, model: str) -> None:
    """The model name is client-chosen text that is stored and logged; refuse one
    that looks sensitive instead of storing it (never echo it back)."""
    insp = services.guard.inspect(model)
    if insp.action is not Action.ALLOW:
        raise ApiError(400, "invalid_model", "model name contains sensitive-looking content")


def _completion_body(
    request: Request, resp: ProviderResponse, guardrail: dict[str, Any]
) -> dict[str, Any]:
    return {
        "id": f"chatcmpl-{request_id(request)}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": resp.model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": resp.content},
                "finish_reason": resp.finish_reason,
            }
        ],
        "usage": {
            "prompt_tokens": resp.usage.prompt_tokens,
            "completion_tokens": resp.usage.completion_tokens,
            "total_tokens": resp.usage.prompt_tokens + resp.usage.completion_tokens,
        },
        # Extra field; OpenAI clients ignore unknown keys.
        "guardrail": guardrail,
    }


async def _forward(
    services: Services,
    request: Request,
    user: User,
    provider_request: ProviderRequest,
    audit_data: dict[str, Any],
) -> tuple[ProviderResponse, bool]:
    """Audit, then call the provider. Returns (response, completion_audited)."""
    await _audit_or_fail(services, request, "chat.forwarded", user, audit_data)
    started = time.perf_counter()
    try:
        resp = await services.provider.chat(provider_request)
    except ProviderError as exc:
        await _audit_best_effort(
            services,
            request,
            "chat.provider_error",
            user,
            {"kind": exc.kind, "model": provider_request.model},
        )
        raise
    except Exception as exc:
        # Unknown failure inside a provider adapter: never propagate its message.
        await _audit_best_effort(
            services,
            request,
            "chat.provider_error",
            user,
            {"kind": "unexpected", "error": type(exc).__name__, "model": provider_request.model},
        )
        raise ProviderError("bad_response", "upstream provider failed") from None
    audited = await _audit_best_effort(
        services,
        request,
        "chat.completed",
        user,
        {
            "model": resp.model,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            "completion_tokens": resp.usage.completion_tokens,
            "output_inspected": False,
        },
    )
    return resp, audited


@router.post("/inspect")
async def inspect(
    body: InspectRequest, request: Request, user: CurrentUser, services: ServicesDep
) -> dict[str, Any]:
    """Scan text without contacting any AI provider."""
    insp = services.guard.inspect_conversation([body.text])
    await _audit_or_fail(services, request, "prompt.inspected", user, _summary(insp))
    public = insp.messages[0].to_public()
    public["action"] = insp.action.value  # conversation-level decision
    public["sanitized_text"] = insp.sanitized_texts[0] if insp.action is not Action.BLOCK else None
    public["request_id"] = request_id(request)
    return public


@router.post("/chat/completions")
async def chat_completions(
    body: ChatCompletionRequest, request: Request, user: CurrentUser, services: ServicesDep
) -> dict[str, Any]:
    if body.stream:
        raise ApiError(
            400, "streaming_not_supported", "stream=true is not supported yet; send stream=false"
        )
    _check_model_name(services, body.model)
    insp = services.guard.inspect_conversation([m.content for m in body.messages])
    summary = _summary(insp, body.model)
    guardrail = {
        "request_id": request_id(request),
        "action": insp.action.value,
        "risk_score": insp.decision.risk_score,
        "placeholders": insp.placeholders,
        "reasons": list(insp.decision.reasons),
    }

    if insp.action is Action.BLOCK:
        await _audit_or_fail(services, request, "chat.blocked", user, summary)
        raise ApiError(
            403,
            "policy_blocked",
            "request blocked by security policy",
            details={**guardrail, "entities": insp.entity_counts},
        )

    if insp.action is Action.REQUIRE_APPROVAL:
        approval_id = uuid.uuid4().hex
        # Audit first: if it fails, nothing is stored.
        await _audit_or_fail(
            services,
            request,
            "chat.approval_required",
            user,
            {**summary, "approval_id": approval_id},
        )
        held = [
            {"role": m.role, "content": text}
            for m, text in zip(body.messages, insp.sanitized_texts, strict=True)
        ]
        approval = await services.approvals.create(
            requester_id=user.id,
            request_id=request_id(request),
            model=body.model,
            risk_score=insp.decision.risk_score,
            summary=summary,
            messages=held,
            approval_id=approval_id,
        )
        raise ApiError(
            403,
            "approval_required",
            "request held for administrator approval",
            details={**guardrail, "approval_id": approval.id, "expires_at": approval.expires_at},
        )

    texts = insp.forwardable_texts
    if texts is None:  # pragma: no cover - excluded by the branches above
        raise ApiError(500, "internal_error", "inconsistent policy decision")
    provider_request = ProviderRequest(
        model=body.model,
        messages=tuple(ChatMessage(m.role, t) for m, t in zip(body.messages, texts, strict=True)),
        temperature=body.temperature,
        max_tokens=body.max_tokens,
    )
    resp, audited = await _forward(services, request, user, provider_request, summary)
    guardrail["output_inspected"] = False  # output inspection arrives in Phase 4
    if not audited:
        guardrail["audit_incomplete"] = True
    return _completion_body(request, resp, guardrail)


@router.get("/approvals")
async def my_approvals(user: CurrentUser, services: ServicesDep) -> list[dict[str, Any]]:
    return [a.to_public() for a in await services.approvals.list_requests(requester_id=user.id)]


@router.post("/approvals/{approval_id}/execute")
async def execute_approval(
    approval_id: str, request: Request, user: CurrentUser, services: ServicesDep
) -> dict[str, Any]:
    """Send an approved request to the provider - once, by its original requester.
    If forwarding fails, the approval is released so the requester can retry."""
    try:
        approval, messages = await services.approvals.claim_for_execution(
            approval_id, requester_id=user.id
        )
    except ApprovalError as exc:
        raise ApiError(409, "approval_not_executable", str(exc)) from exc
    provider_request = ProviderRequest(
        model=approval.model,
        messages=tuple(ChatMessage(m["role"], m["content"]) for m in messages),  # type: ignore[arg-type]
    )
    audit_data = {
        **approval.summary,
        "approval_id": approval.id,
        "approved_by": approval.decided_by,
    }
    try:
        resp, audited = await _forward(services, request, user, provider_request, audit_data)
    except (ProviderError, ApiError):
        await services.approvals.release(approval_id, messages)
        raise
    guardrail: dict[str, Any] = {
        "request_id": request_id(request),
        "action": "APPROVED",
        "approval_id": approval.id,
        "placeholders": approval.summary.get("placeholders", []),
        "output_inspected": False,
    }
    if not audited:
        guardrail["audit_incomplete"] = True
    return _completion_body(request, resp, guardrail)
