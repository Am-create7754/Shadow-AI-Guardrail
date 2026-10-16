"""HTTP request/response schemas (strict: unknown fields rejected unless noted)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.auth.models import Role

MAX_MESSAGES = 100
MAX_MESSAGE_CHARS = 100_000


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class InspectRequest(_Strict):
    text: str = Field(max_length=MAX_MESSAGE_CHARS)
    # Where the text came from, e.g. "extension:chatgpt.com" (browser extension).
    # Stored in the audit log, so it is restricted to a hostname-like shape.
    source: str | None = Field(
        default=None, pattern=r"^[a-z][a-z0-9-]{0,31}(:[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?)?$"
    )


class ChatMessageIn(_Strict):
    role: Literal["system", "user", "assistant"]
    content: str = Field(max_length=MAX_MESSAGE_CHARS)


class ChatCompletionRequest(BaseModel):
    """OpenAI-compatible subset. Unknown OpenAI fields are ignored (not
    forwarded) so standard clients work; nothing unvalidated reaches a provider."""

    model_config = ConfigDict(extra="ignore")

    model: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:/\-]+$")
    messages: list[ChatMessageIn] = Field(min_length=1, max_length=MAX_MESSAGES)
    temperature: float | None = Field(default=None, ge=0, le=2)
    max_tokens: int | None = Field(default=None, ge=1, le=32_768)
    stream: bool = False


class LoginRequest(_Strict):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - OAuth token type name
    expires_in: int


class CreateUserRequest(_Strict):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    role: Role = Role.DEVELOPER


class UpdateUserRequest(_Strict):
    is_active: bool


class CreateApiKeyRequest(_Strict):
    name: str = Field(min_length=1, max_length=64)


class DecisionRequest(_Strict):
    note: str | None = Field(default=None, max_length=500)


class UserOut(BaseModel):
    id: str
    username: str
    role: Role
    is_active: bool
    created_by: str | None = None

    @classmethod
    def from_user(cls, user: Any) -> UserOut:
        return cls(id=user.id, username=user.username, role=user.role,
                   is_active=user.is_active, created_by=user.created_by)  # fmt: skip


class ErrorBody(BaseModel):
    type: str
    message: str
    request_id: str
    details: Any | None = None


class ErrorResponse(BaseModel):
    error: ErrorBody
