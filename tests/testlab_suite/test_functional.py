"""
tests/testlab_suite/test_functional.py
────────────────────────────────────────
Standard usage patterns — verifies that all gateway endpoints respond correctly
to valid requests. All tests run against MockGateway (no external services).

Mark: functional
Count: 25 tests
"""

from __future__ import annotations

import pytest
import httpx

pytestmark = [pytest.mark.functional]

# ── Health ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health_returns_ok(api_client: httpx.AsyncClient):
    """GET /health returns 200 with status=ok."""
    r = await api_client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data.get("status") == "ok"


@pytest.mark.asyncio
async def test_health_no_auth_required(anon_client: httpx.AsyncClient):
    """GET /health is public — no Authorization header needed."""
    r = await anon_client.get("/health")
    assert r.status_code == 200


# ── Task submission ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_task_submission_returns_202(
    api_client: httpx.AsyncClient, admin_headers: dict
):
    """POST /tasks returns 202 Accepted."""
    r = await api_client.post(
        "/tasks", json={"task": "Research quantum computing"}, headers=admin_headers
    )
    assert r.status_code == 202


@pytest.mark.asyncio
async def test_task_submission_response_schema(
    api_client: httpx.AsyncClient, admin_headers: dict
):
    """POST /tasks response contains task_id, status, and stream_token."""
    r = await api_client.post(
        "/tasks", json={"task": "Summarize this document"}, headers=admin_headers
    )
    assert r.status_code == 202
    data = r.json()
    assert "task_id" in data
    assert "stream_token" in data
    assert data.get("status") == "queued"
    assert isinstance(data["task_id"], str) and len(data["task_id"]) > 0
    assert isinstance(data["stream_token"], str) and len(data["stream_token"]) > 0


@pytest.mark.asyncio
async def test_stream_token_format(api_client: httpx.AsyncClient, admin_headers: dict):
    """stream_token starts with 'st-' followed by the task_id."""
    r = await api_client.post(
        "/tasks", json={"task": "Check stream token format"}, headers=admin_headers
    )
    assert r.status_code == 202
    data = r.json()
    assert data["stream_token"].startswith("st-")
    assert data["task_id"] in data["stream_token"]


# ── Task retrieval ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_task_retrieval(api_client: httpx.AsyncClient, admin_headers: dict):
    """GET /tasks/{id} returns task with matching task_id."""
    r = await api_client.post(
        "/tasks", json={"task": "Retrieve this task"}, headers=admin_headers
    )
    task_id = r.json()["task_id"]
    r2 = await api_client.get(f"/tasks/{task_id}", headers=admin_headers)
    assert r2.status_code == 200
    assert r2.json()["task_id"] == task_id


@pytest.mark.asyncio
async def test_task_not_found(api_client: httpx.AsyncClient, admin_headers: dict):
    """GET /tasks/{nonexistent_id} returns 404."""
    r = await api_client.get(
        "/tasks/nonexistent-task-id-00000000", headers=admin_headers
    )
    assert r.status_code == 404


# ── Task cancellation ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_task_cancel(api_client: httpx.AsyncClient, admin_headers: dict):
    """DELETE /tasks/{id} returns status=cancelled."""
    r = await api_client.post(
        "/tasks", json={"task": "Task to be cancelled"}, headers=admin_headers
    )
    task_id = r.json()["task_id"]
    r2 = await api_client.delete(f"/tasks/{task_id}", headers=admin_headers)
    assert r2.status_code == 200
    data = r2.json()
    assert data.get("status") == "cancelled"
    assert data.get("task_id") == task_id


@pytest.mark.asyncio
async def test_cancel_nonexistent_task(
    api_client: httpx.AsyncClient, admin_headers: dict
):
    """DELETE /tasks/{nonexistent} handles gracefully (200 or 404 — no 5xx)."""
    r = await api_client.delete(
        "/tasks/nonexistent-cancel-00000000", headers=admin_headers
    )
    assert r.status_code < 500


# ── Task listing ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_tasks_schema(api_client: httpx.AsyncClient, admin_headers: dict):
    """GET /tasks returns tasks list with total count."""
    r = await api_client.get("/tasks", headers=admin_headers)
    assert r.status_code == 200
    data = r.json()
    assert "tasks" in data
    assert "total" in data
    assert isinstance(data["tasks"], list)
    assert isinstance(data["total"], int)


@pytest.mark.asyncio
async def test_list_tasks_after_submission(
    api_client: httpx.AsyncClient, admin_headers: dict
):
    """Task appears in list after submission."""
    # Submit a task
    r = await api_client.post(
        "/tasks", json={"task": "Task for listing test"}, headers=admin_headers
    )
    task_id = r.json()["task_id"]
    # List tasks with a high limit to ensure our task is included
    r2 = await api_client.get("/tasks?limit=100", headers=admin_headers)
    task_ids = [t["task_id"] for t in r2.json()["tasks"]]
    assert task_id in task_ids


@pytest.mark.asyncio
async def test_pagination_params(api_client: httpx.AsyncClient, admin_headers: dict):
    """GET /tasks?page=1&limit=5 is accepted without error."""
    r = await api_client.get("/tasks?page=1&limit=5", headers=admin_headers)
    assert r.status_code == 200
    data = r.json()
    assert "tasks" in data


# ── Usage ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_usage_quota_schema(api_client: httpx.AsyncClient, admin_headers: dict):
    """GET /usage/me returns daily_token_limit and tokens_used_today."""
    r = await api_client.get("/usage/me", headers=admin_headers)
    assert r.status_code == 200
    data = r.json()
    assert "daily_token_limit" in data
    assert "tokens_used_today" in data
    assert isinstance(data["daily_token_limit"], int)
    assert isinstance(data["tokens_used_today"], int)


@pytest.mark.asyncio
async def test_usage_remaining_field(
    api_client: httpx.AsyncClient, admin_headers: dict
):
    """GET /usage/me includes remaining tokens."""
    r = await api_client.get("/usage/me", headers=admin_headers)
    assert r.status_code == 200
    data = r.json()
    assert "remaining" in data


# ── A2A & MCP (public) ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a2a_card_public(anon_client: httpx.AsyncClient):
    """GET /a2a/agent-card is public and returns agent metadata."""
    r = await anon_client.get("/a2a/agent-card")
    assert r.status_code == 200
    data = r.json()
    assert "name" in data
    assert "version" in data


@pytest.mark.asyncio
async def test_mcp_tools_public(anon_client: httpx.AsyncClient):
    """GET /mcp/tools is public and returns tools list."""
    r = await anon_client.get("/mcp/tools")
    assert r.status_code == 200
    data = r.json()
    assert "tools" in data
    assert isinstance(data["tools"], list)


# ── Headers ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cors_headers(anon_client: httpx.AsyncClient):
    """Responses include CORS header."""
    r = await anon_client.get("/health")
    assert r.status_code == 200
    assert "access-control-allow-origin" in {k.lower() for k in r.headers}


@pytest.mark.asyncio
async def test_x_request_id_echoed(api_client: httpx.AsyncClient, admin_headers: dict):
    """X-Request-ID sent in request is echoed in response."""
    req_id = "test-req-id-12345"
    r = await api_client.get(
        "/health", headers={**admin_headers, "X-Request-ID": req_id}
    )
    assert r.status_code == 200
    assert r.headers.get("x-request-id") == req_id


# ── Task content edge cases ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unicode_task_text(api_client: httpx.AsyncClient, admin_headers: dict):
    """Task with unicode content (Japanese, emoji) is accepted."""
    r = await api_client.post(
        "/tasks",
        json={"task": "分析してください 🔬 — analyze the security posture"},
        headers=admin_headers,
    )
    assert r.status_code == 202


@pytest.mark.asyncio
async def test_long_but_valid_task_text(
    api_client: httpx.AsyncClient, admin_headers: dict
):
    """Task text up to the limit is accepted."""
    task_text = "Analyze the following text: " + "A" * 5000
    r = await api_client.post("/tasks", json={"task": task_text}, headers=admin_headers)
    assert r.status_code == 202


@pytest.mark.asyncio
async def test_auth_required_for_tasks_list(anon_client: httpx.AsyncClient):
    """GET /tasks without auth returns 401."""
    r = await anon_client.get("/tasks")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_auth_required_for_task_submission(anon_client: httpx.AsyncClient):
    """POST /tasks without auth returns 401."""
    r = await anon_client.post("/tasks", json={"task": "Test"})
    assert r.status_code == 401


# ── Stream ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stream_event_format(api_client: httpx.AsyncClient, admin_headers: dict):
    """GET /tasks/{id}/stream with valid token yields SSE events."""
    r = await api_client.post(
        "/tasks", json={"task": "Stream test task"}, headers=admin_headers
    )
    data = r.json()
    task_id = data["task_id"]
    stream_token = data["stream_token"]

    events: list[str] = []
    async with api_client.stream(
        "GET", f"/tasks/{task_id}/stream?token={stream_token}"
    ) as resp:
        assert resp.status_code == 200
        async for line in resp.aiter_lines():
            if line.startswith("event:"):
                events.append(line.split(":", 1)[1].strip())
            if "task_complete" in events:
                break

    assert "task_start" in events or "task_complete" in events


@pytest.mark.asyncio
async def test_stream_invalid_token_rejected(anon_client: httpx.AsyncClient):
    """GET /tasks/{id}/stream with wrong token returns 401."""
    r = await anon_client.get("/tasks/fake-task-id/stream?token=wrong-token")
    assert r.status_code == 401


# ── Multiple consecutive runs ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_consecutive_task_submissions(
    api_client: httpx.AsyncClient, admin_headers: dict
):
    """Multiple sequential task submissions all succeed."""
    for i in range(3):
        r = await api_client.post(
            "/tasks",
            json={"task": f"Consecutive task {i}"},
            headers=admin_headers,
        )
        assert r.status_code == 202
        assert "task_id" in r.json()
