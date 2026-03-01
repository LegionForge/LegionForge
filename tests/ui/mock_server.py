"""
tests/ui/mock_server.py
───────────────────────
A lightweight mock gateway that Playwright UI tests talk to.

Serves the real index.html from src/gateway/static/ so the tests run against
the actual production HTML/JS.  All API endpoints are mocked:

  GET  /health          → {"status": "ok"}
  GET  /ui              → redirect to /
  GET  /                → index.html
  POST /tasks           → {"task_id": ..., "stream_token": ...}
  GET  /tasks/{id}      → task row  (configurable by test)
  GET  /tasks/{id}/stream → SSE stream  (test-controlled via emit())
  DELETE /tasks/{id}    → {"status": "cancelled"}
  GET  /usage/me        → {"daily_token_limit": 100000, "tokens_used_today": 0}

Usage in tests (see conftest.py):

    server.configure(task_result={"status": "complete", ...})
    server.emit("task-001", "task_start",  {"task_id": "task-001"})
    server.emit("task-001", "task_complete", {"task_id": "task-001", "status": "complete"})
    task_id = server.wait_for_submission(timeout=5.0)
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, HTMLResponse
from sse_starlette.sse import EventSourceResponse

_STATIC_DIR = Path(__file__).parent.parent.parent / "src" / "gateway" / "static"
_INDEX_HTML = _STATIC_DIR / "index.html"


class MockGateway:
    """Thread-safe mock gateway server used by Playwright tests."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self._requested_port = port
        self.port: int = 0  # assigned after bind
        self._app = self._build_app()
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()

        # Test-controlled state
        self._task_results: dict[str, dict] = {}
        self._sse_queues: dict[str, asyncio.Queue] = {}
        self._submitted_task_ids: list[str] = []
        self._submission_event = threading.Event()
        self._next_task_id: str | None = None
        self._api_key: str = "test-api-key"
        self._loop: asyncio.AbstractEventLoop | None = None

    # ── Public control API used by tests ──────────────────────────

    def configure(
        self,
        *,
        api_key: str = "test-api-key",
        next_task_id: str | None = None,
        task_result: dict | None = None,
    ) -> None:
        """Configure mock responses before a test action."""
        self._api_key = api_key
        self._next_task_id = next_task_id
        if task_result and next_task_id:
            self._task_results[next_task_id] = task_result

    def emit(self, task_id: str, event: str, data: dict) -> None:
        """Push an SSE event to the active stream for task_id."""
        if self._loop is None:
            raise RuntimeError("Server not started")
        asyncio.run_coroutine_threadsafe(
            self._async_emit(task_id, event, data), self._loop
        )

    def close_stream(self, task_id: str) -> None:
        """Signal end-of-stream for task_id (puts sentinel None)."""
        if self._loop is None:
            return
        asyncio.run_coroutine_threadsafe(self._async_close_stream(task_id), self._loop)

    def wait_for_submission(self, timeout: float = 5.0) -> str:
        """Block until POST /tasks is called; return the task_id.

        NOTE: do NOT clear _submission_event here — reset() is responsible
        for that.  Clearing here creates a race where the browser POSTs
        before wait_for_submission runs, and we clear the signal.
        """
        ok = self._submission_event.wait(timeout=timeout)
        if not ok:
            raise TimeoutError("No task submitted within timeout")
        return self._submitted_task_ids[-1]

    def reset(self) -> None:
        """Clear all state between tests."""
        self._task_results.clear()
        self._submitted_task_ids.clear()
        self._submission_event.clear()
        self._next_task_id = None
        self._api_key = "test-api-key"
        # Drain existing SSE queues
        if self._loop:
            asyncio.run_coroutine_threadsafe(self._async_drain_queues(), self._loop)

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    # ── Lifecycle ─────────────────────────────────────────────────

    def start(self) -> None:
        """Start the server in a background thread and wait until ready."""
        config = uvicorn.Config(
            self._app,
            host=self.host,
            port=self._requested_port,  # 0 = OS picks a free port
            log_level="warning",
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

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop

        # Patch server to signal readiness after bind
        original_startup = self._server.startup

        async def patched_startup(sockets=None):
            await original_startup(sockets)
            # Extract actual port from server's sockets
            for s in self._server.servers:
                for sock in s.sockets:
                    self.port = sock.getsockname()[1]
                    break
            self._ready.set()

        self._server.startup = patched_startup
        loop.run_until_complete(self._server.serve())

    # ── Async helpers ─────────────────────────────────────────────

    async def _async_emit(self, task_id: str, event: str, data: dict) -> None:
        q = self._sse_queues.get(task_id)
        if q is None:
            # Queue not yet created — wait briefly for subscriber
            for _ in range(20):
                await asyncio.sleep(0.05)
                q = self._sse_queues.get(task_id)
                if q:
                    break
            if q is None:
                return
        await q.put({"event": event, "data": json.dumps(data)})

    async def _async_close_stream(self, task_id: str) -> None:
        q = self._sse_queues.get(task_id)
        if q:
            await q.put(None)  # sentinel

    async def _async_drain_queues(self) -> None:
        for task_id in list(self._sse_queues.keys()):
            q = self._sse_queues[task_id]
            await q.put(None)
        self._sse_queues.clear()

    # ── FastAPI app ───────────────────────────────────────────────

    def _build_app(self) -> FastAPI:
        app = FastAPI()
        mock = self  # closure reference

        @app.get("/health")
        async def health():
            return {"status": "ok"}

        @app.get("/ui")
        async def ui_redirect():
            return Response(status_code=302, headers={"Location": "/"})

        @app.get("/")
        async def index():
            return FileResponse(str(_INDEX_HTML), media_type="text/html")

        @app.post("/tasks")
        async def create_task(request: Request):
            # Auth check
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return Response(
                    content=json.dumps({"detail": "Not authenticated"}),
                    status_code=401,
                    media_type="application/json",
                )
            token = auth[7:]
            if token != mock._api_key:
                return Response(
                    content=json.dumps({"detail": "Invalid API key"}),
                    status_code=401,
                    media_type="application/json",
                )

            task_id = mock._next_task_id or str(uuid.uuid4())
            stream_token = "st-" + task_id
            mock._submitted_task_ids.append(task_id)
            mock._submission_event.set()

            # Pre-create SSE queue
            mock._sse_queues[task_id] = asyncio.Queue()

            return {
                "task_id": task_id,
                "status": "queued",
                "stream_token": stream_token,
            }

        @app.get("/tasks/{task_id}")
        async def get_task(task_id: str, request: Request):
            result = mock._task_results.get(
                task_id,
                {"task_id": task_id, "status": "complete", "estimated_tokens": 42},
            )
            return result

        @app.get("/tasks/{task_id}/stream")
        async def stream_task(task_id: str, request: Request):
            async def event_generator():
                # Create queue if not already present
                if task_id not in mock._sse_queues:
                    mock._sse_queues[task_id] = asyncio.Queue()
                q = mock._sse_queues[task_id]
                while True:
                    try:
                        item = await asyncio.wait_for(q.get(), timeout=30.0)
                    except asyncio.TimeoutError:
                        yield {"event": "heartbeat", "data": "{}"}
                        continue
                    if item is None:
                        break
                    yield item

            return EventSourceResponse(event_generator())

        @app.delete("/tasks/{task_id}")
        async def cancel_task(task_id: str):
            # Signal stream to close
            q = mock._sse_queues.get(task_id)
            if q:
                await q.put(
                    {
                        "event": "task_cancelled",
                        "data": json.dumps({"task_id": task_id, "status": "cancelled"}),
                    }
                )
                await q.put(None)
            return {"task_id": task_id, "status": "cancelled"}

        @app.get("/usage/me")
        async def usage_me(request: Request):
            return {"daily_token_limit": 100000, "tokens_used_today": 0}

        return app
