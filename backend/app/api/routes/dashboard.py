"""Serves the built React dashboard (frontend/dist) under /app.

The request path is never handed to the filesystem. The build directory is
scanned into a manifest {relative path: file} (rescanned only when index.html
changes), and a request is served only on an exact manifest match. A URL like
``/app///host/share/x.js`` therefore cannot make Windows open a UNC path (SMB
connection, NTLM hash leak) or touch devices and absolute paths - the earlier
resolve-then-check design did exactly that before rejecting the request.

Only allow-listed extensions are listed; every other path under /app returns
index.html so client-side routes (/app/admin/audit, ...) survive a reload. The
dashboard gets its own strict Content-Security-Policy: scripts, styles and API
calls from this origin only, no inline script, no framing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, RedirectResponse, Response

from app.api.deps import ServicesDep
from app.api.errors import ApiError

router = APIRouter(include_in_schema=False)

DASHBOARD_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'; object-src 'none'; "
    # Trusted Types: DOM XSS sinks (innerHTML, script src...) refuse plain
    # strings, and no policy may be created to bypass that. The dashboard
    # renders text only, so it needs none.
    "require-trusted-types-for 'script'; trusted-types 'none'"
)
PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
# Explicit types: on Windows, mimetypes reads the registry and may say text/plain
# for .js, which browsers refuse to execute as a module under nosniff.
_TYPES = {
    ".js": "text/javascript",
    ".css": "text/css",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".json": "application/json",
}
_IMMUTABLE = "public, max-age=31536000, immutable"  # Vite fingerprints asset names
_SEGMENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}")
_MAX_FILES = 5_000


@dataclass(frozen=True)
class _Build:
    stamp: int  # index.html mtime (ns) the manifest was built for
    files: dict[str, Path]


_builds: dict[Path, _Build] = {}


def _scan(root: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    real_root = root.resolve()
    for p in root.rglob("*"):
        if len(files) >= _MAX_FILES:
            break
        rel = p.relative_to(root)
        if p.suffix.lower() not in _TYPES or not all(_SEGMENT.fullmatch(s) for s in rel.parts):
            continue
        # Our own build output: skip links/junctions that lead outside it.
        if p.is_file() and p.resolve().is_relative_to(real_root):
            files[rel.as_posix()] = p
    return files


def _manifest(root: Path) -> dict[str, Path] | None:
    """Files of the current build, or None when it is not built."""
    try:
        stamp = (root / "index.html").stat().st_mtime_ns
    except OSError:
        return None
    build = _builds.get(root)
    if build is None or build.stamp != stamp:
        build = _Build(stamp, _scan(root))
        _builds[root] = build
    return build.files


def _headers(cache: str) -> dict[str, str]:
    return {
        "Content-Security-Policy": DASHBOARD_CSP,
        "Permissions-Policy": PERMISSIONS_POLICY,
        "Cache-Control": cache,
    }


@router.get("/app")
async def dashboard_root() -> Response:
    return RedirectResponse("/app/")


@router.api_route("/app/{path:path}", methods=["GET", "HEAD"])
async def dashboard(path: str, services: ServicesDep) -> Response:
    root = services.settings.dashboard_dir
    if root is None:
        raise ApiError(404, "not_found", "dashboard disabled")
    files = _manifest(root)
    if files is None:
        raise ApiError(404, "dashboard_not_built", "dashboard is not built (npm run build)")
    file = files.get(path)
    if file is not None:
        cache = _IMMUTABLE if path.startswith("assets/") else "no-cache"
        return FileResponse(file, media_type=_TYPES[file.suffix.lower()], headers=_headers(cache))
    last = path.rsplit("/", 1)[-1]
    if path.startswith("assets/") or "." in last:
        # A missing file is a real 404, not the SPA shell (avoids serving HTML
        # where the browser expects a script).
        raise ApiError(404, "not_found", "not found")
    return FileResponse(
        root / "index.html", media_type="text/html; charset=utf-8", headers=_headers("no-store")
    )


def dashboard_available(request: Request) -> bool:
    root = request.app.state.services.settings.dashboard_dir
    return root is not None and _manifest(root) is not None
