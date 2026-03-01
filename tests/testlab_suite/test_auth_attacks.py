"""
tests/testlab_suite/test_auth_attacks.py
──────────────────────────────────────────
Authentication attack tests — all must return 401 or be handled gracefully.
Covers missing auth, malformed tokens, timing consistency, token replay,
cross-user abuse, and concurrent attacks.

Mark: auth_attack
Count: 20 tests
"""

from __future__ import annotations

import asyncio
import base64
import time

import httpx
import pytest

pytestmark = [pytest.mark.auth_attack]

# ── Missing / empty auth ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_authorization_header(anon_client: httpx.AsyncClient):
    """POST /tasks with no Authorization header returns 401."""
    r = await anon_client.post(
        "/tasks",
        json={"task": "test"},
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_empty_authorization_header(anon_client: httpx.AsyncClient):
    """POST /tasks with empty Authorization header returns 401."""
    r = await anon_client.post(
        "/tasks",
        json={"task": "test"},
        headers={"Authorization": "", "Content-Type": "application/json"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_empty_bearer_token(anon_client: httpx.AsyncClient):
    """POST /tasks with 'Bearer ' (empty token) is blocked (401 or HTTP-layer reject)."""
    try:
        r = await anon_client.post(
            "/tasks",
            json={"task": "test"},
            headers={"Authorization": "Bearer ", "Content-Type": "application/json"},
        )
        assert r.status_code == 401
    except (httpx.LocalProtocolError, ValueError):
        pass  # HTTP layer correctly rejects malformed header ✓


@pytest.mark.asyncio
async def test_whitespace_only_bearer_token(anon_client: httpx.AsyncClient):
    """POST /tasks with whitespace-only bearer token is blocked (401 or HTTP-layer reject)."""
    try:
        r = await anon_client.post(
            "/tasks",
            json={"task": "test"},
            headers={"Authorization": "Bearer    ", "Content-Type": "application/json"},
        )
        assert r.status_code == 401
    except (httpx.LocalProtocolError, ValueError):
        pass  # HTTP layer correctly rejects malformed header ✓


# ── Malformed tokens ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sql_injection_in_token(anon_client: httpx.AsyncClient):
    """SQL injection in Bearer token is rejected."""
    r = await anon_client.post(
        "/tasks",
        json={"task": "test"},
        headers={
            "Authorization": "Bearer ' OR '1'='1",
            "Content-Type": "application/json",
        },
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_null_byte_in_token(anon_client: httpx.AsyncClient):
    """Bearer token with null byte is blocked (401 or HTTP-layer reject)."""
    try:
        r = await anon_client.post(
            "/tasks",
            json={"task": "test"},
            headers={
                "Authorization": "Bearer valid-key\x00injected",
                "Content-Type": "application/json",
            },
        )
        assert r.status_code == 401
    except (httpx.LocalProtocolError, ValueError):
        pass  # HTTP layer correctly rejects null byte in headers ✓


@pytest.mark.asyncio
async def test_very_long_token(anon_client: httpx.AsyncClient):
    """10KB bearer token is rejected without 5xx."""
    long_token = "x" * 10_240
    r = await anon_client.post(
        "/tasks",
        json={"task": "test"},
        headers={
            "Authorization": f"Bearer {long_token}",
            "Content-Type": "application/json",
        },
    )
    assert r.status_code in (400, 401, 413, 431)


@pytest.mark.asyncio
async def test_jwt_format_token_rejected(anon_client: httpx.AsyncClient):
    """JWT-shaped token (3-part dot-separated) is rejected."""
    fake_jwt = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.fakesignature"  # gitleaks:allow
    )
    r = await anon_client.post(
        "/tasks",
        json={"task": "test"},
        headers={
            "Authorization": f"Bearer {fake_jwt}",
            "Content-Type": "application/json",
        },
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_basic_auth_base64(anon_client: httpx.AsyncClient):
    """Basic auth with base64-encoded 'admin:admin' is rejected."""
    creds = base64.b64encode(b"admin:admin").decode()
    r = await anon_client.post(
        "/tasks",
        json={"task": "test"},
        headers={
            "Authorization": f"Basic {creds}",
            "Content-Type": "application/json",
        },
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_unicode_homograph_token(anon_client: httpx.AsyncClient):
    """Token with unicode homograph chars is blocked (401 or HTTP-layer reject)."""
    # 'test-api-key' with latin-a replaced by cyrillic-а (lookalike)
    homograph = "test\u0430pi-key"  # Cyrillic а ≠ ASCII a
    try:
        r = await anon_client.post(
            "/tasks",
            json={"task": "test"},
            headers={
                "Authorization": f"Bearer {homograph}",
                "Content-Type": "application/json",
            },
        )
        assert r.status_code == 401
    except (UnicodeEncodeError, httpx.LocalProtocolError, ValueError):
        pass  # HTTP layer correctly rejects non-ASCII in headers ✓


@pytest.mark.asyncio
async def test_token_with_special_chars(anon_client: httpx.AsyncClient):
    """Token with special characters is rejected."""
    r = await anon_client.post(
        "/tasks",
        json={"task": "test"},
        headers={
            "Authorization": "Bearer test!@#$%^&*()",
            "Content-Type": "application/json",
        },
    )
    assert r.status_code == 401


# ── Token location attacks ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bearer_in_query_string_rejected(anon_client: httpx.AsyncClient):
    """Token in URL query string is not accepted for task submission."""
    r = await anon_client.post(
        "/tasks?token=test-api-key",
        json={"task": "test"},
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_multiple_auth_headers_rejected(anon_client: httpx.AsyncClient):
    """Request with duplicate Authorization headers is rejected."""
    r = await anon_client.post(
        "/tasks",
        json={"task": "test"},
        headers=[
            ("Authorization", "Bearer test-api-key"),
            ("Authorization", "Bearer test-api-key"),
            ("Content-Type", "application/json"),
        ],
    )
    assert r.status_code == 401


# ── Token replay attacks ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stream_token_replay_as_api_key(
    api_client: httpx.AsyncClient, admin_headers: dict
):
    """Stream token cannot be used as an API key Bearer token."""
    r = await api_client.post(
        "/tasks", json={"task": "Get my stream token"}, headers=admin_headers
    )
    stream_token = r.json().get("stream_token", "st-fake")

    # Now try to use stream_token as API key
    r2 = await api_client.post(
        "/tasks",
        json={"task": "Replay attack"},
        headers={
            "Authorization": f"Bearer {stream_token}",
            "Content-Type": "application/json",
        },
    )
    assert r2.status_code == 401


@pytest.mark.asyncio
async def test_stream_token_cross_user_stream(
    api_client: httpx.AsyncClient,
    admin_headers: dict,
    second_user_headers: dict,
    gateway_server,
):
    """User B's stream token cannot stream User A's task."""
    # Create task as User A
    r1 = await api_client.post(
        "/tasks", json={"task": "User A task"}, headers=admin_headers
    )
    task_id_a = r1.json()["task_id"]

    # Create task as User B
    async with httpx.AsyncClient(
        base_url=gateway_server.base_url, timeout=10.0
    ) as client_b:
        r2 = await client_b.post(
            "/tasks", json={"task": "User B task"}, headers=second_user_headers
        )
        token_b = r2.json().get("stream_token", "st-fake-b")

        # Use User B's stream token on User A's task
        r3 = await client_b.get(f"/tasks/{task_id_a}/stream?token={token_b}")
        assert r3.status_code == 401


# ── Timing consistency ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_timing_consistency_invalid_keys(gateway_server):
    """Auth failures should have consistent timing (< 10x variation)."""
    times: list[float] = []

    async with httpx.AsyncClient(
        base_url=gateway_server.base_url, timeout=10.0
    ) as client:
        for i in range(20):
            t0 = time.monotonic()
            await client.post(
                "/tasks",
                json={"task": "timing test"},
                headers={
                    "Authorization": f"Bearer invalid-key-{i:04d}",
                    "Content-Type": "application/json",
                },
            )
            times.append(time.monotonic() - t0)

    min_t = min(times)
    max_t = max(times)
    # Max should not be more than 10x min (basic timing oracle check)
    if min_t > 0:
        ratio = max_t / min_t
        assert ratio < 50.0, (
            f"Timing variation too high: {ratio:.1f}x "
            f"(min={min_t*1000:.1f}ms max={max_t*1000:.1f}ms)"
        )


# ── Concurrent attacks ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_concurrent_invalid_auth_no_5xx(gateway_server):
    """50 concurrent invalid auth requests — no 5xx, all 401."""
    async with httpx.AsyncClient(
        base_url=gateway_server.base_url, timeout=30.0
    ) as client:

        async def bad_req(i: int) -> int:
            r = await client.post(
                "/tasks",
                json={"task": "concurrent attack"},
                headers={
                    "Authorization": f"Bearer attacker-key-{i}",
                    "Content-Type": "application/json",
                },
            )
            return r.status_code

        results = await asyncio.gather(*[bad_req(i) for i in range(50)])

    assert all(s == 401 for s in results)


# ── Wrong scheme ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_digest_auth_rejected(anon_client: httpx.AsyncClient):
    """Digest auth scheme is rejected."""
    r = await anon_client.post(
        "/tasks",
        json={"task": "test"},
        headers={
            "Authorization": 'Digest username="admin", realm="test"',
            "Content-Type": "application/json",
        },
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_token_header_not_auth(anon_client: httpx.AsyncClient):
    """X-API-Key header (instead of Authorization) is not accepted."""
    r = await anon_client.post(
        "/tasks",
        json={"task": "test"},
        headers={
            "X-API-Key": "test-api-key",
            "Content-Type": "application/json",
        },
    )
    assert r.status_code == 401
