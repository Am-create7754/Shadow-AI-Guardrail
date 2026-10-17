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
6. Every answer - complete or streamed - passes the output inspector before the
   client sees it: secrets/PII are redacted or the answer withheld, generated
   code is checked, and a stream never releases part of a secret.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

from app.api.deps import CurrentUser, Services, ServicesDep
from app.api.errors import ApiError, request_id
from app.api.schemas import ChatCompletionRequest, InspectRequest
from app.approvals.service import ApprovalError
from app.auth.service import User
from app.guardrail import ConversationInspection
from app.output.inspector import OutputResult, StreamGuard
from app.policy.models import Action, OutputAction
from app.providers.base import ChatMessage, ProviderError, ProviderRequest, ProviderResponse

router = APIRouter(prefix="/v1", tags=["gateway"])
# Strong references to fire-and-forget audit tasks (asyncio keeps only weak ones).
_BACKGROUND_TASKS: set[asyncio.Task[bool]] = set()


async def drain_background_tasks(timeout: float = 10.0) -> None:
    """Let pending audit writes finish before shutdown (called by the lifespan)."""
    if _BACKGROUND_TASKS:
        await asyncio.wait(set(_BACKGROUND_TASKS), timeout=timeout)


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
        # Logged by type only (the message could contain data).
        logger.error(
            "audit write failed (%s): %s refused (request %s)",
            type(exc).__name__,
            event,
            request_id(request),
        )
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
    request: Request, resp: ProviderResponse, content: str, guardrail: dict[str, Any]
) -> dict[str, Any]:
    return {
        "id": f"chatcmpl-{request_id(request)}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": resp.model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
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


def _check_model_allowed(services: Services, model: str) -> None:
    """Real providers only serve configured models (cost control, and the model
    name is then a known value rather than free client text)."""
    settings = services.settings
    if services.provider.name != "mock" and model not in settings.provider_model_list:
        raise ApiError(
            400,
            "model_not_allowed",
            f"model not allowed; choose one of: {', '.join(settings.provider_model_list)}",
        )


async def _call_provider(
    services: Services, request: Request, user: User, provider_request: ProviderRequest
) -> ProviderResponse:
    try:
        return await services.provider.chat(provider_request)
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


async def _forward(
    services: Services,
    request: Request,
    user: User,
    provider_request: ProviderRequest,
    audit_data: dict[str, Any],
    reserved: list[str],
) -> tuple[ProviderResponse, OutputResult, bool]:
    """Audit, call the provider, inspect the answer.

    Returns (response, inspected output, completion_audited). Raises 502
    ``output_blocked`` if the output policy withholds the answer.
    """
    await _audit_or_fail(services, request, "chat.forwarded", user, audit_data)
    started = time.perf_counter()
    resp = await _call_provider(services, request, user, provider_request)
    out = services.output.inspect(resp.content, services.output.allocator(reserved))
    if out.action is OutputAction.BLOCK:
        await _audit_best_effort(
            services,
            request,
            "chat.output_blocked",
            user,
            {"model": resp.model, **out.audit_summary()},
        )
        raise ApiError(
            502,
            "output_blocked",
            "the model's answer was withheld by the output policy",
            details={"request_id": request_id(request), **out.to_public()},
        )
    audited = await _audit_best_effort(
        services,
        request,
        "chat.completed",
        user,
        {
            "model": resp.model,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            "completion_tokens": resp.usage.completion_tokens,
            "output_inspected": True,
            **out.audit_summary(),
        },
    )
    return resp, out, audited


def _sse(obj: dict[str, Any]) -> bytes:
    return f"data: {json.dumps(obj, separators=(',', ':'))}\n\n".encode()


async def _stream(
    services: Services,
    request: Request,
    user: User,
    provider_request: ProviderRequest,
    audit_data: dict[str, Any],
    reserved: list[str],
    guardrail: dict[str, Any],
) -> StreamingResponse:
    """OpenAI-style SSE stream; every delta passes through :class:`StreamGuard`.

    The first provider chunk is awaited before the response starts, so errors
    such as bad credentials or quota still produce a normal HTTP error status.
    Later problems are sent as an ``error`` event (the status is already 200).
    """
    await _audit_or_fail(services, request, "chat.forwarded", user, audit_data)
    started = time.perf_counter()
    agen = services.provider.stream(provider_request)
    try:
        first: str | None = await agen.__anext__()
    except StopAsyncIteration:
        first = None
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
        await _audit_best_effort(
            services,
            request,
            "chat.provider_error",
            user,
            {"kind": "unexpected", "error": type(exc).__name__, "model": provider_request.model},
        )
        raise ProviderError("bad_response", "upstream provider failed") from None

    guard = StreamGuard(services.output, services.output.allocator(reserved))
    rid = request_id(request)
    base = {
        "id": f"chatcmpl-{rid}",
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": provider_request.model,
    }

    def chunk(delta: dict[str, Any], finish: str | None = None) -> bytes:
        return _sse({**base, "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]})

    audited = False

    def schedule_audit(event: str, error: ProviderError | None = None) -> asyncio.Task[bool] | None:
        """Write the closing audit event in its own task: if the client hangs up,
        Starlette cancels this generator, and a cancellation landing inside a
        database write would both lose the record and break the connection."""
        nonlocal audited
        if audited:
            return None
        audited = True
        data = {
            "model": provider_request.model,
            "stream": True,
            "output_inspected": True,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            **({"kind": error.kind} if error else {}),
            **guard.result.audit_summary(),
        }
        task = asyncio.create_task(_audit_best_effort(services, request, event, user, data))
        _BACKGROUND_TASKS.add(task)
        task.add_done_callback(_BACKGROUND_TASKS.discard)
        return task

    async def settle(task: asyncio.Task[bool] | None) -> None:
        """Wait for the closing audit record before the final events, so the
        stream never ends before its record exists (the earlier fire-and-forget
        version let clients finish first - visible as flaky CI). Shielded: a
        disconnect cancels only this wait, never the write."""
        if task is not None:
            await asyncio.shield(task)

    async def body() -> AsyncIterator[bytes]:
        error: ProviderError | None = None
        try:
            yield chunk({"role": "assistant"})
            try:
                if first is not None:
                    if out := guard.feed(first):
                        yield chunk({"content": out})
                    async for delta in agen:
                        out = guard.feed(delta)
                        if guard.blocked:
                            break
                        if out:
                            yield chunk({"content": out})
                if not guard.blocked and (out := guard.finish()):
                    yield chunk({"content": out})
            except ProviderError as exc:
                error = exc
            except Exception as exc:
                logger.error("stream failed: %s (request %s)", type(exc).__name__, rid)
                error = ProviderError("bad_response", "upstream provider failed")
            finally:
                await agen.aclose()

            result = guard.result
            if guard.blocked:
                await settle(schedule_audit("chat.output_blocked"))
                yield _sse({"error": {
                    "type": "output_blocked", "request_id": rid,
                    "message": "the rest of the answer was withheld by the output policy",
                    **result.to_public(),
                }})  # fmt: skip
            elif error is not None:
                await settle(schedule_audit("chat.provider_error", error))
                yield _sse({"error": {"type": f"provider_{error.kind}", "message": error.detail,
                                      "request_id": rid}})  # fmt: skip
            else:
                await settle(schedule_audit("chat.completed"))
                yield _sse({
                    **base,
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                    "guardrail": {**guardrail, "output_inspected": True,
                                  "output": result.to_public()},
                })  # fmt: skip
            yield b"data: [DONE]\n\n"
        finally:
            # Client disconnected (or the server is shutting down) mid-stream.
            schedule_audit("chat.stream_aborted")
            with contextlib.suppress(Exception):
                await agen.aclose()

    async def close_provider_stream() -> None:
        # A real coroutine function: Starlette would run a bound ``aclose`` in a
        # thread, creating a coroutine that is never awaited.
        with contextlib.suppress(Exception):
            await agen.aclose()

    return StreamingResponse(
        body(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        # Closes the provider stream even if the response body is never iterated.
        background=BackgroundTask(close_provider_stream),
    )


MOCK_MODELS = ("mock-echo", "mock-leak", "mock-code", "mock-error", "mock-timeout",
               "mock-ratelimit")  # fmt: skip


@router.get("/models")
async def list_models(user: CurrentUser, services: ServicesDep) -> dict[str, Any]:
    """OpenAI-compatible model list: the models this gateway lets clients use."""
    names = (
        MOCK_MODELS
        if services.provider.name == "mock"
        else tuple(services.settings.provider_model_list)
    )
    return {
        "object": "list",
        "data": [{"id": n, "object": "model", "owned_by": services.provider.name} for n in names],
    }


@router.post("/inspect")
async def inspect(
    body: InspectRequest, request: Request, user: CurrentUser, services: ServicesDep
) -> dict[str, Any]:
    """Scan text without contacting any AI provider."""
    if body.source is not None and services.guard.inspect(body.source).action is not Action.ALLOW:
        # Client-chosen and stored: refuse a label that looks sensitive (never echo it).
        raise ApiError(400, "invalid_source", "source contains sensitive-looking content")
    insp = services.guard.inspect_conversation([body.text])
    summary = _summary(insp)
    if body.source is not None:
        summary["source"] = body.source
    await _audit_or_fail(services, request, "prompt.inspected", user, summary)
    public = insp.messages[0].to_public()
    public["action"] = insp.action.value  # conversation-level decision
    public["sanitized_text"] = insp.sanitized_texts[0] if insp.action is not Action.BLOCK else None
    public["request_id"] = request_id(request)
    return public


@router.post("/chat/completions", response_model=None)
async def chat_completions(
    body: ChatCompletionRequest, request: Request, user: CurrentUser, services: ServicesDep
) -> dict[str, Any] | StreamingResponse:
    _check_model_name(services, body.model)
    _check_model_allowed(services, body.model)
    insp = services.guard.inspect_conversation([m.content for m in body.messages])
    summary = _summary(insp, body.model)
    guardrail: dict[str, Any] = {
        "request_id": request_id(request),
        "action": insp.action.value,
        "risk_score": insp.decision.risk_score,
        "placeholders": insp.placeholders,
        "reasons": list(insp.decision.reasons),
        # Detection metadata only (types, rules, confidence) - never values.
        "findings": [
            {k: v for k, v in d.to_public().items() if k not in ("start", "end", "length")}
            for d in insp.decision.findings
        ],
    }
    if insp.action is not Action.BLOCK:
        # The caller's own prompt as it was (or would be) forwarded: their text
        # minus the secrets. Lets developers see exactly what left the gateway.
        guardrail["sanitized_messages"] = insp.sanitized_texts

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
    reserved = list(insp.sanitized_texts)
    if body.stream:
        return await _stream(
            services, request, user, provider_request, summary, reserved, guardrail
        )
    resp, out, audited = await _forward(
        services, request, user, provider_request, summary, reserved
    )
    guardrail["output_inspected"] = True
    guardrail["output"] = out.to_public()
    if not audited:
        guardrail["audit_incomplete"] = True
    return _completion_body(request, resp, out.text, guardrail)


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
    try:
        # The allow-list may have changed since the request was held.
        _check_model_allowed(services, approval.model)
    except ApiError:
        await services.approvals.release(approval_id, messages)
        raise
    provider_request = ProviderRequest(
        model=approval.model,
        messages=tuple(ChatMessage(m["role"], m["content"]) for m in messages),  # type: ignore[arg-type]
    )
    audit_data = {
        **approval.summary,
        "approval_id": approval.id,
        "approved_by": approval.decided_by,
    }
    reserved = [m["content"] for m in messages]
    try:
        resp, out, audited = await _forward(
            services, request, user, provider_request, audit_data, reserved
        )
    except ProviderError:
        await services.approvals.release(approval_id, messages)
        raise
    except ApiError as exc:
        if exc.kind == "audit_unavailable":  # nothing was sent: allow a retry
            await services.approvals.release(approval_id, messages)
        raise
    guardrail: dict[str, Any] = {
        "request_id": request_id(request),
        "action": "APPROVED",
        "approval_id": approval.id,
        "placeholders": approval.summary.get("placeholders", []),
        "output_inspected": True,
        "output": out.to_public(),
    }
    if not audited:
        guardrail["audit_incomplete"] = True
    return _completion_body(request, resp, out.text, guardrail)
