"""The gateway serving the built dashboard at /app."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.api_helpers import Gateway, gateway

INDEX = "<!doctype html><title>Shadow AI Guardrail</title><div id=root></div>"


@pytest.fixture
def dist(tmp_path: Path) -> Path:
    root = tmp_path / "dist"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text(INDEX, encoding="utf-8")
    (root / "assets" / "index-abc123.js").write_text("console.log(1)", encoding="utf-8")
    (root / "assets" / "index-abc123.css").write_text("body{}", encoding="utf-8")
    (root / "favicon.svg").write_text("<svg/>", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("outside the build dir", encoding="utf-8")
    # Allow-listed extension outside the build: only containment can stop these.
    (tmp_path / "secret.js").write_text("outside the build dir", encoding="utf-8")
    (root / "assets" / "nested").mkdir()
    (root / "assets" / "nested" / "x.js").write_text("nested ok", encoding="utf-8")
    (root / "notes.py").write_text("print('not an asset type')", encoding="utf-8")
    return root


@pytest.fixture
def app_gw(tmp_path: Path, dist: Path) -> Iterator[Gateway]:
    with gateway(tmp_path, dashboard_dir=dist) as g:
        yield g


def test_index_and_spa_routes_get_the_shell_with_strict_csp(app_gw: Gateway) -> None:
    for path in ("/app/", "/app/admin/audit", "/app/keys"):
        r = app_gw.client.get(path)
        assert r.status_code == 200, path
        assert r.text == INDEX
        assert r.headers["content-type"].startswith("text/html")
        csp = r.headers["content-security-policy"]
        assert "script-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "require-trusted-types-for 'script'" in csp
        assert "trusted-types 'none'" in csp
        assert "unsafe-inline" not in csp
        assert "unsafe-eval" not in csp
        assert r.headers["cache-control"] == "no-store"
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["x-content-type-options"] == "nosniff"


def test_assets_have_correct_types_and_long_cache(app_gw: Gateway) -> None:
    js = app_gw.client.get("/app/assets/index-abc123.js")
    assert js.status_code == 200
    assert js.headers["content-type"].startswith("text/javascript")
    assert "immutable" in js.headers["cache-control"]
    css = app_gw.client.get("/app/assets/index-abc123.css")
    assert css.headers["content-type"].startswith("text/css")
    icon = app_gw.client.get("/app/favicon.svg")
    assert icon.headers["content-type"].startswith("image/svg+xml")
    assert icon.headers["cache-control"] == "no-cache"


def test_missing_assets_are_404_not_the_shell(app_gw: Gateway) -> None:
    assert app_gw.client.get("/app/assets/gone.js").status_code == 404
    assert app_gw.client.get("/app/assets/whatever").status_code == 404
    assert app_gw.client.get("/app/missing.css").status_code == 404


@pytest.mark.parametrize(
    "path",
    [
        "/app/../secret.txt",
        "/app/%2e%2e/secret.txt",
        "/app/..%2fsecret.txt",
        "/app/assets/..%2f..%2fsecret.txt",
        "/app/%2e%2e%5csecret.txt",
    ],
)
def test_path_traversal_never_leaves_the_build_dir(app_gw: Gateway, path: str) -> None:
    r = app_gw.client.get(path)
    assert "outside the build dir" not in r.text


def test_only_allow_listed_file_types_are_served(app_gw: Gateway) -> None:
    r = app_gw.client.get("/app/notes.py")
    assert "not an asset type" not in r.text


def test_root_redirects_to_dashboard_when_built(app_gw: Gateway) -> None:
    r = app_gw.client.get("/", follow_redirects=False)
    assert r.status_code == 307
    assert r.headers["location"] == "/app/"
    assert app_gw.client.get("/app", follow_redirects=False).headers["location"] == "/app/"


def test_api_csp_is_unchanged(app_gw: Gateway) -> None:
    r = app_gw.client.get("/health")
    assert r.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"


def test_disabled_or_unbuilt_dashboard(tmp_path: Path) -> None:
    with gateway(tmp_path) as g:  # dashboard_dir=None
        assert g.client.get("/app/").status_code == 404
        assert g.client.get("/", follow_redirects=False).headers["location"] == "/docs"
    with gateway(tmp_path / "b", dashboard_dir=tmp_path / "nothing") as g:
        r = g.client.get("/app/")
        assert r.status_code == 404
        assert r.json()["error"]["type"] == "dashboard_not_built"


@pytest.mark.parametrize(
    "path",
    [
        "/app/../secret.js",
        "/app/%2e%2e/secret.js",
        "/app/..%2fsecret.js",
        "/app/assets/..%2f..%2fsecret.js",
        "/app/%2e%2e%5csecret.js",
        "/app/assets/%2e%2e/%2e%2e/secret.js",
    ],
)
def test_traversal_to_allow_listed_type_is_refused(app_gw: Gateway, path: str) -> None:
    r = app_gw.client.get(path)
    assert "outside the build dir" not in r.text


def test_nested_build_files_are_served(app_gw: Gateway) -> None:
    assert app_gw.client.get("/app/assets/nested/x.js").text == "nested ok"


@pytest.mark.parametrize(
    "path",
    [
        "/app///evil.example/share/x.js",
        "/app/%5c%5cevil.example%5cshare%5cx.js",
        "/app//%5cevil.example/share/x.js",
        "/app///./pipe/evil.js",
        "/app/C:/evil.example/x.js",
        "/app/C:%5cevil.example%5cx.js",
        "/app/assets/evil.example::$DATA.js",
        "/app/assets/evil.example%00.js",
    ],
)
def test_request_path_never_reaches_the_filesystem(
    app_gw: Gateway, path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression (Phase 5 review): resolving the user path before the containment
    check made Windows open UNC paths (SMB to an attacker host, NTLM hash leak)."""
    import os
    import pathlib

    seen: list[str] = []
    for name in ("resolve", "stat", "is_file", "exists", "open"):
        original = getattr(pathlib.Path, name)

        def spy(self: pathlib.Path, *a: object, _orig: object = original, **k: object) -> object:
            seen.append(os.fspath(self))
            return _orig(self, *a, **k)  # type: ignore[operator]

        monkeypatch.setattr(pathlib.Path, name, spy)
    r = app_gw.client.get(path)
    assert r.status_code in (404, 200)
    assert "outside the build dir" not in r.text
    assert not [p for p in seen if "evil" in p], seen


def test_rebuilt_dashboard_is_picked_up(app_gw: Gateway, dist: Path) -> None:
    import os

    assert app_gw.client.get("/app/assets/index-new999.js").status_code == 404
    (dist / "assets" / "index-new999.js").write_text("new build", encoding="utf-8")
    index = dist / "index.html"
    st = index.stat()
    os.utime(index, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
    assert app_gw.client.get("/app/assets/index-new999.js").text == "new build"


def test_dashboard_has_permissions_policy(app_gw: Gateway) -> None:
    assert "camera=()" in app_gw.client.get("/app/").headers["permissions-policy"]
