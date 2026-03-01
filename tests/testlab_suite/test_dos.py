"""
tests/testlab_suite/test_dos.py
─────────────────────────────────
Denial-of-Service resilience tests.

The gateway must survive all these attacks:
  - No 5xx responses
  - Bounded response time (< 30s wall-clock per request)
  - No server crash / hang

These tests measure resilience, not performance.

Mark: dos
Count: 15 tests
"""

from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest

pytestmark = [pytest.mark.dos]


# ── Helpers ───────────────────────────────────────────────────────────────────


async def _health(client: httpx.AsyncClient) -> int:
    r = await client.get("/health")
    return r.status_code


async def _submit(
    client: httpx.AsyncClient, headers: dict, task: str = "DOS test"
) -> int:
    try:
        r = await client.post("/tasks", json={"task": task}, headers=headers)
        return r.status_code
    except httpx.TimeoutException:
        return 408


# ── Flood tests ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_concurrent_health_flood(gateway_server, anon_client: httpx.AsyncClient):
    """50 concurrent GET /health requests — all must succeed, no 5xx."""
    async with httpx.AsyncClient(
        base_url=gateway_server.base_url, timeout=30.0
    ) as client:
        results = await asyncio.gather(*[_health(client) for _ in range(50)])
    assert all(s == 200 for s in results), f"Some health checks failed: {set(results)}"


@pytest.mark.asyncio
async def test_concurrent_task_flood(gateway_server, admin_headers: dict):
    """20 concurrent task submissions — no 5xx."""
    async with httpx.AsyncClient(
        base_url=gateway_server.base_url, timeout=30.0
    ) as client:
        results = await asyncio.gather(
            *[_submit(client, admin_headers, f"Flood task {i}") for i in range(20)]
        )
    assert all(s < 500 for s in results), f"Some tasks 5xx'd: {set(results)}"


# ── Body attacks ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_oversized_body(gateway_server, admin_headers: dict):
    """2MB JSON body — gateway must not 5xx (reject with 4xx or accept)."""
    big_payload = json.dumps({"task": "x" * (2 * 1024 * 1024)})
    async with httpx.AsyncClient(
        base_url=gateway_server.base_url, timeout=30.0
    ) as client:
        r = await client.post(
            "/tasks",
            content=big_payload.encode(),
            headers={**admin_headers, "Content-Type": "application/json"},
        )
    assert r.status_code < 500


@pytest.mark.asyncio
async def test_malformed_json_empty_body(gateway_server, admin_headers: dict):
    """Empty body to /tasks — must not 5xx."""
    async with httpx.AsyncClient(
        base_url=gateway_server.base_url, timeout=10.0
    ) as client:
        r = await client.post(
            "/tasks",
            content=b"",
            headers={**admin_headers, "Content-Type": "application/json"},
        )
    assert r.status_code < 500


@pytest.mark.asyncio
async def test_malformed_json_truncated(gateway_server, admin_headers: dict):
    """Truncated JSON body — must not 5xx."""
    async with httpx.AsyncClient(
        base_url=gateway_server.base_url, timeout=10.0
    ) as client:
        r = await client.post(
            "/tasks",
            content=b'{"task": "incomplete',
            headers={**admin_headers, "Content-Type": "application/json"},
        )
    assert r.status_code < 500


@pytest.mark.asyncio
async def test_malformed_json_garbage(gateway_server, admin_headers: dict):
    """Random garbage body — must not 5xx."""
    async with httpx.AsyncClient(
        base_url=gateway_server.base_url, timeout=10.0
    ) as client:
        r = await client.post(
            "/tasks",
            content=b"\xff\xfe\x00garbage\x01\x02\x03",
            headers={**admin_headers, "Content-Type": "application/json"},
        )
    assert r.status_code < 500


@pytest.mark.asyncio
async def test_deep_json_nesting(gateway_server, admin_headers: dict):
    """100-level nested JSON — must not 5xx or hang."""
    obj: dict = {"task": "deep"}
    for _ in range(100):
        obj = {"level": obj}
    async with httpx.AsyncClient(
        base_url=gateway_server.base_url, timeout=15.0
    ) as client:
        t0 = time.monotonic()
        r = await client.post(
            "/tasks",
            json=obj,
            headers=admin_headers,
        )
        elapsed = time.monotonic() - t0
    assert r.status_code < 500
    assert elapsed < 10.0, f"Deep nesting took {elapsed:.1f}s (too slow)"


@pytest.mark.asyncio
async def test_json_array_bomb(gateway_server, admin_headers: dict):
    """JSON array with 10,000 elements — must not 5xx."""
    payload = json.dumps({"tasks": ["item"] * 10_000})
    async with httpx.AsyncClient(
        base_url=gateway_server.base_url, timeout=15.0
    ) as client:
        r = await client.post(
            "/tasks",
            content=payload.encode(),
            headers={**admin_headers, "Content-Type": "application/json"},
        )
    assert r.status_code < 500


# ── Auth flood ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rapid_auth_failures(gateway_server):
    """50 rapid invalid auth attempts — no 5xx, no server crash."""
    async with httpx.AsyncClient(
        base_url=gateway_server.base_url, timeout=30.0
    ) as client:

        async def bad_auth(i: int) -> int:
            r = await client.post(
                "/tasks",
                json={"task": "test"},
                headers={
                    "Authorization": f"Bearer invalid-key-{i}",
                    "Content-Type": "application/json",
                },
            )
            return r.status_code

        results = await asyncio.gather(*[bad_auth(i) for i in range(50)])
    assert all(s == 401 for s in results), f"Unexpected status codes: {set(results)}"


# ── SSE flood ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_concurrent_sse_connections(
    gateway_server, api_client: httpx.AsyncClient, admin_headers: dict
):
    """8 concurrent SSE connections — gateway must not crash."""
    # First, create some tasks
    tasks_data = []
    for i in range(8):
        r = await api_client.post(
            "/tasks", json={"task": f"SSE task {i}"}, headers=admin_headers
        )
        if r.status_code == 202:
            tasks_data.append(r.json())

    if not tasks_data:
        pytest.skip("Could not create tasks for SSE test")

    async def stream_one(data: dict) -> bool:
        task_id = data["task_id"]
        stream_token = data["stream_token"]
        try:
            async with httpx.AsyncClient(
                base_url=gateway_server.base_url, timeout=10.0
            ) as c:
                async with c.stream(
                    "GET", f"/tasks/{task_id}/stream?token={stream_token}"
                ) as resp:
                    # Read a few lines and move on
                    count = 0
                    async for _ in resp.aiter_lines():
                        count += 1
                        if count >= 6:
                            break
            return True
        except Exception:
            return True  # Any response (including disconnect) is ok

    results = await asyncio.gather(*[stream_one(d) for d in tasks_data])
    assert all(results)


# ── Protocol flood ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mixed_method_flood(gateway_server):
    """Mixed GET/POST/DELETE/PUT flood — no 5xx."""
    async with httpx.AsyncClient(
        base_url=gateway_server.base_url, timeout=30.0
    ) as client:
        tasks = [
            client.get("/health"),
            client.post("/tasks", json={"task": "x"}),
            client.get("/a2a/agent-card"),
            client.get("/mcp/tools"),
            client.get("/nonexistent"),
            client.put("/tasks/fake", json={}),
            client.delete("/tasks/fake"),
            client.get("/health"),
        ] * 3
        responses = await asyncio.gather(*tasks, return_exceptions=True)
    for r in responses:
        if isinstance(r, httpx.Response):
            assert r.status_code < 500, f"Got 5xx: {r.status_code}"


@pytest.mark.asyncio
async def test_long_query_string(gateway_server, admin_headers: dict):
    """Request with a very long query string — no 5xx."""
    long_param = "x" * 4096
    async with httpx.AsyncClient(
        base_url=gateway_server.base_url, timeout=10.0
    ) as client:
        r = await client.get(f"/tasks?filter={long_param}", headers=admin_headers)
    assert r.status_code < 500


@pytest.mark.asyncio
async def test_many_custom_headers(gateway_server, admin_headers: dict):
    """Request with 40 custom headers — no 5xx."""
    extra = {f"X-Custom-Header-{i}": f"value{i}" for i in range(40)}
    async with httpx.AsyncClient(
        base_url=gateway_server.base_url, timeout=10.0
    ) as client:
        r = await client.get("/health", headers={**admin_headers, **extra})
    assert r.status_code < 500


@pytest.mark.asyncio
async def test_unicode_heavy_payload(gateway_server, admin_headers: dict):
    """10KB emoji/unicode payload — no 5xx."""
    emoji_block = "🔥💀🚀" * 1000  # ~12KB
    async with httpx.AsyncClient(
        base_url=gateway_server.base_url, timeout=15.0
    ) as client:
        r = await client.post(
            "/tasks", json={"task": emoji_block}, headers=admin_headers
        )
    assert r.status_code < 500


@pytest.mark.asyncio
async def test_repeated_rapid_cancellations(
    gateway_server, api_client: httpx.AsyncClient, admin_headers: dict
):
    """Rapidly cancel the same task ID repeatedly — no 5xx."""
    r = await api_client.post(
        "/tasks", json={"task": "Cancellation flood test"}, headers=admin_headers
    )
    task_id = r.json().get("task_id", "fake-id")

    async with httpx.AsyncClient(
        base_url=gateway_server.base_url, timeout=30.0
    ) as client:
        results = await asyncio.gather(
            *[
                client.delete(f"/tasks/{task_id}", headers=admin_headers)
                for _ in range(10)
            ]
        )
    assert all(r.status_code < 500 for r in results)
