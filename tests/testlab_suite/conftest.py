"""
tests/testlab_suite/conftest.py
────────────────────────────────
Shared fixtures for testlab_suite API tests.

Dual-mode:
  - Default: starts a TestlabMockGateway (no services required)
  - Real gateway: set TESTLAB_GATEWAY_URL=http://localhost:8080

Fixtures:
  gateway_server   (session-scope, sync): mock or real gateway wrapper
  api_client       (session-scope, async): authenticated httpx.AsyncClient
  anon_client      (session-scope, async): unauthenticated httpx.AsyncClient
  admin_headers    (session-scope, sync): Authorization headers for primary user
  second_user_headers (session-scope, sync): headers for second test user
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import threading
import uuid
from typing import Any

import httpx
import pytest
import pytest_asyncio
import uvicorn
from fastapi import FastAPI, Request, Response
from sse_starlette.sse import EventSourceResponse

# ── Auth constants ────────────────────────────────────────────────────────────
VALID_API_KEY = "test-api-key"
SECOND_API_KEY = "test-api-key-2"

# Injection patterns the mock gateway blocks (mirrors real gateway's detection)
_INJECTION_PATTERNS = [
    re.compile(r"(?i)(union\s+select|drop\s+table|or\s+1=1|;\s*delete)", re.IGNORECASE),
    re.compile(r"(?i)(exec\s*\(|system\s*\(|subprocess|os\.system)", re.IGNORECASE),
    re.compile(r"\x00"),  # null byte
    re.compile(r"[\x01-\x08\x0b\x0c\x0e-\x1f]"),  # control chars (not tab/lf/cr)
    re.compile(r"(?i)\{\{.*?\}\}"),  # template injection
    re.compile(r"(?i)<script[\s>]"),  # XSS
    re.compile(
        r"(?i)(ignore\s+previous\s+instructions?|disregard\s+prior|forget\s+your\s+instructions?)",
    ),  # prompt injection
]

_DANGEROUS_HEADERS = {
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
}

_MAX_TASK_LEN = 50_000


def _is_injection(text: str) -> bool:
    """Return True if text contains injection payload."""
    for p in _INJECTION_PATTERNS:
        if p.search(text):
            return True
    return False


class TestlabMockGateway:
    """
    Extended mock gateway for testlab API tests.
    Implements auth, per-user task isolation, injection detection,
    and all endpoints needed for the full test suite.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self._requested_port = port
        self.port: int = 0
        self._app = self._build_app()
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._tasks: dict[str, dict] = {}
        self._sse_queues: dict[str, asyncio.Queue] = {}

    # ── Lifecycle ─────────────────────────────────────────────────

    def start(self) -> None:
        config = uvicorn.Config(
            self._app,
            host=self.host,
            port=self._requested_port,
            log_level="error",
            limit_concurrency=200,
        )
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=10.0)

    def stop(self) -> None:
        if self._server:
            self._server.should_exit = True
        if self._thread:
            self._thread.join(timeout=5.0)

    def reset(self) -> None:
        """Clear per-test state."""
        self._tasks.clear()
        if self._loop:
            asyncio.run_coroutine_threadsafe(self._drain_queues(), self._loop)

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        original_startup = self._server.startup  # type: ignore[union-attr]

        async def patched_startup(sockets=None):
            await original_startup(sockets)
            for s in self._server.servers:  # type: ignore[union-attr]
                for sock in s.sockets:
                    self.port = sock.getsockname()[1]
                    break
            self._ready.set()

        self._server.startup = patched_startup  # type: ignore[union-attr]
        loop.run_until_complete(self._server.serve())  # type: ignore[union-attr]

    async def _drain_queues(self) -> None:
        for q in list(self._sse_queues.values()):
            await q.put(None)
        self._sse_queues.clear()

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    # ── Auth helper ───────────────────────────────────────────────

    def _check_auth(self, request: Request) -> tuple[bool, str]:
        """Return (valid, api_key). Only accepts Bearer scheme."""
        auth = request.headers.get("Authorization", "")
        # Reject if multiple Authorization headers
        raw_headers = [(k.lower(), v) for k, v in request.headers.raw]
        auth_count = sum(1 for k, _ in raw_headers if k == b"authorization")
        if auth_count > 1:
            return False, ""
        if not auth.startswith("Bearer "):
            return False, ""
        token = auth[7:].strip()
        if not token:
            return False, ""
        return token in (VALID_API_KEY, SECOND_API_KEY), token

    # ── FastAPI app ───────────────────────────────────────────────

    def _build_app(self) -> FastAPI:  # noqa: C901
        app = FastAPI()
        mock = self

        def _json_401(msg: str = "Not authenticated") -> Response:
            return Response(
                content=json.dumps({"detail": msg}),
                status_code=401,
                media_type="application/json",
            )

        def _json_400(msg: str = "Bad request") -> Response:
            return Response(
                content=json.dumps({"detail": msg}),
                status_code=400,
                media_type="application/json",
            )

        # Security headers for all responses
        @app.middleware("http")
        async def security_headers(request: Request, call_next):
            # Block dangerous method-override headers
            for h in _DANGEROUS_HEADERS:
                if request.headers.get(h):
                    return _json_400("Method override not permitted")
            response = await call_next(request)
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-Request-ID"] = request.headers.get(
                "X-Request-ID", str(uuid.uuid4())
            )
            response.headers["Access-Control-Allow-Origin"] = "*"
            return response

        @app.get("/health")
        async def health():
            return {"status": "ok", "service": "gateway"}

        @app.post("/tasks")
        async def create_task(request: Request):
            ok, token = mock._check_auth(request)
            if not ok:
                return _json_401()

            # Body size limit
            body_bytes = await request.body()
            if len(body_bytes) > 1_048_576:  # 1MB
                return Response(
                    content=json.dumps({"detail": "Request body too large"}),
                    status_code=413,
                    media_type="application/json",
                )

            try:
                body: dict = json.loads(body_bytes)
            except Exception:
                return Response(
                    content=json.dumps({"detail": "Invalid JSON"}),
                    status_code=422,
                    media_type="application/json",
                )

            if not isinstance(body, dict):
                return Response(
                    content=json.dumps({"detail": "Expected JSON object"}),
                    status_code=422,
                    media_type="application/json",
                )

            task_text = body.get("task", "")
            if not task_text or not isinstance(task_text, str):
                return Response(
                    content=json.dumps({"detail": "task field required"}),
                    status_code=422,
                    media_type="application/json",
                )

            if len(task_text) > _MAX_TASK_LEN:
                return Response(
                    content=json.dumps({"detail": "Task text too long"}),
                    status_code=413,
                    media_type="application/json",
                )

            # Injection detection
            if _is_injection(task_text):
                return Response(
                    content=json.dumps({"detail": "Task blocked: prohibited content"}),
                    status_code=400,
                    media_type="application/json",
                )

            task_id = str(uuid.uuid4())
            stream_token = "st-" + task_id
            mock._tasks[task_id] = {
                "task_id": task_id,
                "status": "queued",
                "owner_key": token,
                "estimated_tokens": 100,
            }
            if mock._loop:
                mock._sse_queues[task_id] = asyncio.Queue()

            return Response(
                content=json.dumps(
                    {
                        "task_id": task_id,
                        "status": "queued",
                        "stream_token": stream_token,
                    }
                ),
                status_code=202,
                media_type="application/json",
            )

        @app.get("/tasks")
        async def list_tasks(request: Request):
            ok, token = mock._check_auth(request)
            if not ok:
                return _json_401()
            user_tasks = [
                v for v in mock._tasks.values() if v.get("owner_key") == token
            ]
            page = int(request.query_params.get("page", "1"))
            limit = min(int(request.query_params.get("limit", "20")), 100)
            return {
                "tasks": user_tasks[:limit],
                "total": len(user_tasks),
                "page": page,
                "limit": limit,
            }

        @app.get("/tasks/{task_id}")
        async def get_task(task_id: str, request: Request):
            ok, token = mock._check_auth(request)
            if not ok:
                return _json_401()
            t = mock._tasks.get(task_id)
            if not t or t.get("owner_key") != token:
                return Response(
                    content=json.dumps({"detail": "Not found"}),
                    status_code=404,
                    media_type="application/json",
                )
            return t

        @app.get("/tasks/{task_id}/stream")
        async def stream_task(task_id: str, request: Request):
            token = request.query_params.get("token", "")
            expected_token = "st-" + task_id
            if token != expected_token:
                return Response(
                    content=json.dumps({"detail": "Invalid stream token"}),
                    status_code=401,
                    media_type="application/json",
                )

            async def gen():
                if task_id not in mock._sse_queues:
                    mock._sse_queues[task_id] = asyncio.Queue()
                q = mock._sse_queues[task_id]
                yield {
                    "event": "task_start",
                    "data": json.dumps({"task_id": task_id}),
                }
                yield {
                    "event": "output",
                    "data": json.dumps({"chunk": "Working on task..."}),
                }
                yield {
                    "event": "task_complete",
                    "data": json.dumps(
                        {"task_id": task_id, "status": "complete", "result": "done"}
                    ),
                }

            return EventSourceResponse(gen())

        @app.delete("/tasks/{task_id}")
        async def cancel_task(task_id: str, request: Request):
            ok, token = mock._check_auth(request)
            if not ok:
                return _json_401()
            t = mock._tasks.get(task_id)
            if t and t.get("owner_key") == token:
                t["status"] = "cancelled"
            return {"task_id": task_id, "status": "cancelled"}

        @app.get("/usage/me")
        async def usage_me(request: Request):
            ok, _ = mock._check_auth(request)
            if not ok:
                return _json_401()
            return {
                "daily_token_limit": 100_000,
                "tokens_used_today": 0,
                "remaining": 100_000,
            }

        @app.get("/a2a/agent-card")
        async def agent_card():
            return {
                "name": "LegionForge",
                "version": "1.0.1",
                "capabilities": ["research", "orchestrate", "analyze"],
            }

        @app.get("/mcp/tools")
        async def mcp_tools():
            return {
                "tools": [
                    {"name": "web_search", "description": "Search the web"},
                    {"name": "read_file", "description": "Read a file"},
                ]
            }

        return app


# ── Real gateway wrapper ───────────────────────────────────────────────────────


class _RealGatewayRef:
    """Thin wrapper so fixtures can treat real and mock gateways uniformly."""

    def __init__(self, url: str, api_key: str = VALID_API_KEY):
        self.base_url = url.rstrip("/")
        self._api_key = api_key

    def reset(self) -> None:
        pass  # no-op for real gateway


# ── Session-scoped fixtures ────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def gateway_server():
    """
    Start mock gateway (or wrap real gateway if TESTLAB_GATEWAY_URL is set).
    Session-scoped: started once, reused for all tests.
    """
    real_url = os.environ.get("TESTLAB_GATEWAY_URL", "").strip()
    if real_url:
        yield _RealGatewayRef(real_url)
    else:
        server = TestlabMockGateway(port=0)
        server.start()
        yield server
        server.stop()


@pytest.fixture(scope="session")
def admin_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {VALID_API_KEY}",
        "Content-Type": "application/json",
    }


@pytest.fixture(scope="session")
def second_user_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {SECOND_API_KEY}",
        "Content-Type": "application/json",
    }


@pytest_asyncio.fixture(scope="session")
async def api_client(gateway_server) -> httpx.AsyncClient:
    """Authenticated async HTTP client (primary user)."""
    async with httpx.AsyncClient(
        base_url=gateway_server.base_url,
        timeout=httpx.Timeout(30.0, connect=5.0),
    ) as client:
        yield client


@pytest_asyncio.fixture(scope="session")
async def anon_client(gateway_server) -> httpx.AsyncClient:
    """Unauthenticated async HTTP client."""
    async with httpx.AsyncClient(
        base_url=gateway_server.base_url,
        timeout=httpx.Timeout(30.0, connect=5.0),
    ) as client:
        yield client
