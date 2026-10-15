"""Gateway test harness: a fresh app + database per test, with seeded users."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app
from app.api.deps import Services
from app.auth.models import Role
from app.core.config import Environment, Settings
from app.providers.mock import MockProvider

PASSWORD = "correct horse battery staple"  # test-only credential
USERS = {"dev1": Role.DEVELOPER, "dev2": Role.DEVELOPER, "admin": Role.ADMIN, "admin2": Role.ADMIN}


@dataclass
class Gateway:
    client: TestClient
    services: Services
    provider: MockProvider
    user_ids: dict[str, str] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)

    def h(self, who: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.tokens[who]}"}

    def chat(
        self, who: str, content: str | list[dict[str, str]], model: str = "mock-echo", **extra: Any
    ) -> Any:
        messages = [{"role": "user", "content": content}] if isinstance(content, str) else content
        return self.client.post(
            "/v1/chat/completions",
            headers=self.h(who),
            json={"model": model, "messages": messages, **extra},
        )

    def call(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Run an async service method on the app's event loop."""
        return self.client.portal.call(lambda: fn(*args, **kwargs))  # type: ignore[union-attr]


@contextmanager
def gateway(tmp_path: Path, **overrides: Any) -> Iterator[Gateway]:
    # Independent of whether frontend/dist happens to be built on this machine.
    overrides.setdefault("dashboard_dir", None)
    settings = Settings(
        environment=Environment.TEST,
        database_url="sqlite+aiosqlite:///" + (tmp_path / "gw.db").as_posix(),
        audit_anchor_path=tmp_path / "anchor.json",
        **overrides,
    )
    provider = MockProvider()
    app = create_app(settings, provider=provider)
    with TestClient(app, base_url="http://testserver") as client:
        gw = Gateway(client, app.state.services, provider)
        for name, role in USERS.items():
            user = gw.call(gw.services.auth.create_user, name, PASSWORD, role)
            gw.user_ids[name] = user.id
            gw.tokens[name] = gw.services.auth.issue_token(user)[0]
        yield gw


@pytest.fixture
def gw(tmp_path: Path) -> Iterator[Gateway]:
    with gateway(tmp_path) as g:
        yield g
