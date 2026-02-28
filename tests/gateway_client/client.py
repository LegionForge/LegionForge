"""
tests/gateway_client/client.py
────────────────────────────────
Thin async HTTP wrapper around httpx for gateway testing.

Provides:
  GatewayClient — async context manager; all methods return (status, body_dict)
  timed()       — decorator that records wall-clock duration in ms
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from tests.gateway_client import config


class GatewayClient:
    """
    Async HTTP client for the LegionForge gateway.

    All methods return a tuple of (status_code: int, body: dict | str).
    The body is the parsed JSON dict, or the raw text if JSON decode fails.
    Timeout is 30 s — generous enough for a loaded gateway without hanging tests.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._api_key = api_key or config.GATEWAY_API_KEY
        self._base_url = (base_url or config.GATEWAY_URL).rstrip("/")
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "GatewayClient":
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=self._timeout,
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._client:
            await self._client.aclose()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _auth_header(self, api_key: str | None = None) -> dict[str, str]:
        key = api_key or self._api_key
        return {"Authorization": f"Bearer {key}"} if key else {}

    def _parse(self, resp: httpx.Response) -> tuple[int, Any]:
        try:
            return resp.status_code, resp.json()
        except Exception:
            return resp.status_code, resp.text

    # ── Public methods ────────────────────────────────────────────────────────

    async def get(
        self,
        path: str,
        api_key: str | None = None,
        auth: bool = True,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        raw: bool = False,
    ) -> tuple[int, Any]:
        assert self._client
        h = {**(self._auth_header(api_key) if auth else {}), **(headers or {})}
        resp = await self._client.get(path, headers=h, params=params)
        if raw:
            return resp.status_code, resp.content
        return self._parse(resp)

    async def post(
        self,
        path: str,
        body: dict | str | bytes | None = None,
        api_key: str | None = None,
        auth: bool = True,
        headers: dict[str, str] | None = None,
        content_type: str = "application/json",
    ) -> tuple[int, Any]:
        assert self._client
        h = {
            **(self._auth_header(api_key) if auth else {}),
            "Content-Type": content_type,
            **(headers or {}),
        }
        if isinstance(body, dict):
            resp = await self._client.post(path, json=body, headers=h)
        elif isinstance(body, (str, bytes)):
            resp = await self._client.post(path, content=body, headers=h)
        else:
            resp = await self._client.post(path, headers=h)
        return self._parse(resp)

    async def delete(
        self,
        path: str,
        api_key: str | None = None,
        auth: bool = True,
    ) -> tuple[int, Any]:
        assert self._client
        h = self._auth_header(api_key) if auth else {}
        resp = await self._client.delete(path, headers=h)
        try:
            return resp.status_code, resp.json()
        except Exception:
            return resp.status_code, resp.text

    async def options(
        self, path: str, headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, str]]:
        assert self._client
        resp = await self._client.options(path, headers=headers or {})
        return resp.status_code, dict(resp.headers)

    # ── Convenience wrappers ──────────────────────────────────────────────────

    async def submit_task(
        self,
        task: str = "Say hello.",
        agent_type: str = "orchestrator",
        api_key: str | None = None,
    ) -> tuple[int, Any]:
        return await self.post(
            "/tasks",
            body={"task": task, "agent_type": agent_type},
            api_key=api_key,
        )

    async def health(self) -> tuple[int, Any]:
        return await self.get("/health", auth=False)


# ── Timing helper ─────────────────────────────────────────────────────────────


class Timer:
    """Context manager that records elapsed wall-clock time in milliseconds."""

    def __init__(self) -> None:
        self.elapsed_ms: float = 0.0
        self._start: float = 0.0

    def __enter__(self) -> "Timer":
        self._start = time.monotonic()
        return self

    def __exit__(self, *_: Any) -> None:
        self.elapsed_ms = (time.monotonic() - self._start) * 1000
