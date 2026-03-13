"""
src/gateway/middleware.py
──────────────────────────
Starlette middleware for the LegionForge gateway.

Phase 14 adds two middlewares:

  RequestIDMiddleware
    Reads ``X-Request-ID`` from the incoming request.  If absent, generates a
    UUID4.  Echoes the ID back on every response so clients can correlate
    requests with log entries and SSE streams.

    The ID is also stored on ``request.state.request_id`` so route handlers
    and downstream code can read it without re-parsing headers.

  MetricsMiddleware
    Increments ``legionforge_http_requests_total`` for every response, keyed
    by HTTP method, normalised path, and status code.  SSE stream endpoints
    are counted on first response (when the 200 header is sent) — the long-
    lived connection does not distort duration measurements.

  SubmissionRateLimitMiddleware
    Sliding-window rate limit on POST /tasks and POST /tasks/batch.
    Per authenticated user (keyed on Bearer token prefix) or per IP for
    unauthenticated requests.  Limit and window are read from
    ``settings.gateway.submission_rate_limit_per_minute``.  Set to 0 to
    disable.  In-memory only — resets on gateway restart; suitable for
    single-instance deployments.  For multi-instance, replace ``_windows``
    with a Redis ZADD/ZCOUNT counter.

All middlewares are registered in ``src/gateway/app.py``.

Usage (app.py)::

    from src.gateway.middleware import (
        MetricsMiddleware,
        RequestIDMiddleware,
        SubmissionRateLimitMiddleware,
    )
    app.add_middleware(SubmissionRateLimitMiddleware)
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(RequestIDMiddleware)
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import defaultdict
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from src.gateway.metrics import inc_counter

# ── Path normalisation for Prometheus labels ──────────────────────────────────
# Recording raw request paths as Prometheus label values creates one label series
# per unique path.  With UUID or numeric IDs in paths (/tasks/abc-123-...) this
# explodes cardinality unboundedly and will OOM the in-process label store.
# This regex replaces high-cardinality path segments with placeholders so that
# /tasks/abc-123/notes/42 → /tasks/{id}/notes/{id} — a single stable series.
_HIGH_CARDINALITY_RE = re.compile(
    r"(?<=/)"  # must follow a slash (don't mangle the leading /)
    r"("
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # UUID v4
    r"|[0-9]{4,}"  # numeric ID ≥ 4 digits
    r")",
    re.IGNORECASE,
)


def _normalize_path(path: str) -> str:
    """Replace UUIDs and long numeric IDs in a URL path with ``{id}``."""
    return _HIGH_CARDINALITY_RE.sub("{id}", path)


logger = logging.getLogger(__name__)

# Rate-limited paths and the settings key that provides their per-minute limit.
# Each path uses its own per-user sliding window (key is "path:user_bucket")
# so task submissions and memory ingests don't share a budget.
#
# _TASK_PATHS   — reads submission_rate_limit_per_minute
# _MEMORY_PATHS — reads memory_rate_limit_per_minute (Ollama embedding calls)
_TASK_PATHS = frozenset({"/tasks", "/tasks/batch"})
_MEMORY_PATHS = frozenset({"/memory/ingest", "/memory/search"})
_RATE_LIMITED_PATHS = _TASK_PATHS | _MEMORY_PATHS

# Paths that are SSE streams — we skip timing these since the connection
# can stay open for minutes and the duration is not meaningful as a latency.
_SSE_PATH_FRAGMENTS = ("/stream",)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Propagate or generate a ``X-Request-ID`` header.

    Clients that supply their own ``X-Request-ID`` will see it echoed back
    unchanged, enabling end-to-end correlation from browser to logs to SSE.
    Clients that do not supply one get a freshly-generated UUID4.

    The ID is stored on ``request.state.request_id`` for use in route handlers.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("x-request-id") or str(uuid4())
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        return response


class MetricsMiddleware(BaseHTTPMiddleware):
    """
    Count HTTP requests by method, path, and response status.

    Increments the ``legionforge_http_requests_total`` counter after each
    response.  Path is recorded as-is (no parameter stripping) so
    ``/tasks/abc-123`` and ``/tasks/def-456`` appear as separate label values.
    For high-cardinality environments, normalise paths before recording.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        inc_counter(
            "legionforge_http_requests_total",
            {
                "method": request.method,
                "path": _normalize_path(request.url.path),
                "status": str(response.status_code),
            },
        )
        return response


class SubmissionRateLimitMiddleware(BaseHTTPMiddleware):
    """
    Sliding-window rate limit for POST /tasks and POST /tasks/batch.

    Each authenticated user gets at most ``limit`` submissions per
    ``_WINDOW_SECONDS`` seconds.  The key is the first 20 characters of the
    Bearer token (never logged or stored in full).  Unauthenticated requests
    (no Bearer header) are keyed by client IP.

    Limits are read from ``settings.gateway.submission_rate_limit_per_minute``
    at dispatch time so a settings reload takes effect without restarting.
    Set the value to 0 to disable the limiter entirely.

    The in-memory ``_windows`` dict never grows unboundedly: entries older than
    the sliding window are evicted on each check, and the dict key disappears
    once the list empties.
    """

    _WINDOW_SECONDS = 60

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        # {key: [monotonic timestamps of recent requests within the window]}
        self._windows: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    def _rate_limit(self, path: str) -> int:
        """Return the configured limit for this path (live read — YAML reload takes effect)."""
        try:
            from config.settings import settings

            if path in _MEMORY_PATHS:
                return settings.gateway.memory_rate_limit_per_minute
            return settings.gateway.submission_rate_limit_per_minute
        except Exception:
            return 10  # safe default if settings unavailable

    def _key(self, request: Request, path: str) -> str:
        """Derive a rate-limit bucket key scoped to (path, user).

        Including the path in the key gives each endpoint its own per-user
        window so task submissions and memory ingests don't share a budget.
        """
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            # Use a fixed-length prefix — enough to distinguish users, never
            # long enough to reconstruct the full token.
            return f"{path}:token:{auth[7:27]}"
        return f"{path}:ip:{request.client.host if request.client else 'unknown'}"

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path.rstrip("/")
        if request.method == "POST" and path in _RATE_LIMITED_PATHS:
            limit = self._rate_limit(path)
            if limit > 0:
                key = self._key(request, path)
                now = time.monotonic()
                async with self._lock:
                    # Evict timestamps outside the sliding window
                    self._windows[key] = [
                        t for t in self._windows[key] if now - t < self._WINDOW_SECONDS
                    ]
                    # Clean up empty buckets immediately after eviction — this is the
                    # correct placement.  Checking after append() is dead code because
                    # the list is never empty after an append.  Without this, stale
                    # empty buckets from churned users accumulate in the dict.
                    if not self._windows[key]:
                        del self._windows[key]
                    if len(self._windows.get(key, [])) >= limit:
                        logger.warning(
                            "[rate-limit] Submission rate limit hit key=%s path=%s",
                            key[:20],
                            path,
                        )
                        inc_counter(
                            "legionforge_rate_limit_rejections_total",
                            {"path": path},
                        )
                        return JSONResponse(
                            {
                                "detail": (
                                    f"Rate limit exceeded — max {limit} task "
                                    f"submissions per {self._WINDOW_SECONDS}s. "
                                    "Retry after the window resets."
                                )
                            },
                            status_code=429,
                            headers={"Retry-After": str(self._WINDOW_SECONDS)},
                        )
                    self._windows[key].append(now)

        return await call_next(request)
