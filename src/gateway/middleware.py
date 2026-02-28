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

Both middlewares are registered in ``src/gateway/app.py``.

Usage (app.py)::

    from src.gateway.middleware import RequestIDMiddleware, MetricsMiddleware
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(RequestIDMiddleware)
"""

from __future__ import annotations

import logging
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from src.gateway.metrics import inc_counter

logger = logging.getLogger(__name__)

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
                "path": request.url.path,
                "status": str(response.status_code),
            },
        )
        return response
