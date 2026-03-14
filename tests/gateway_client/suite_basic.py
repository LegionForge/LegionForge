"""
tests/gateway_client/suite_basic.py
──────────────────────────────────────
Suite 1 — Functional correctness.

Verifies that the gateway handles the golden path correctly:
auth, task lifecycle, usage, A2A/MCP endpoints, response schemas.

All tests run sequentially (shared task_id state across tests).
"""

from __future__ import annotations

import asyncio
import time

from tests.gateway_client import config
from tests.gateway_client.client import GatewayClient, Timer
from tests.gateway_client.report import SuiteResult, TestResult, Status

NAME = "basic"

# Required keys in a task submission response
_TASK_SUBMIT_KEYS = {"task_id", "status", "created_at", "stream_url", "stream_token"}

# Required keys in a task detail response
_TASK_DETAIL_KEYS = {"task_id", "status", "created_at", "input_text"}


async def _run(suite: SuiteResult, key: str) -> str | None:
    """
    Run the full basic suite.  Returns the task_id of a submitted task so
    later tests can reuse it, or None if task submission was skipped.
    """
    task_id: str | None = None
    stream_token: str | None = None

    async with GatewayClient(api_key=key) as c:

        # ── 1. Health endpoint (public) ────────────────────────────────────────
        with Timer() as t:
            status_code, body = await c.health()
        name = "health_endpoint_returns_200"
        if status_code == 200 and isinstance(body, dict) and body.get("status") == "ok":
            suite.results.append(TestResult.passed(name, t.elapsed_ms))
        else:
            suite.results.append(
                TestResult.failed(
                    name,
                    f"Expected 200 + {{status:ok}}, got {status_code}: {body}",
                    t.elapsed_ms,
                )
            )

        # ── 2. No auth header → 401 ────────────────────────────────────────────
        with Timer() as t:
            status_code, _ = await c.get("/tasks", auth=False)
        name = "no_auth_header_returns_401"
        if status_code == 401:
            suite.results.append(TestResult.passed(name, t.elapsed_ms))
        else:
            suite.results.append(
                TestResult.failed(
                    name, f"Expected 401, got {status_code}", t.elapsed_ms
                )
            )

        # ── 3. Invalid API key → 401 ───────────────────────────────────────────
        with Timer() as t:
            status_code, _ = await c.get("/tasks", api_key=config.BAD_API_KEY)
        name = "invalid_api_key_returns_401"
        if status_code == 401:
            suite.results.append(TestResult.passed(name, t.elapsed_ms))
        else:
            suite.results.append(
                TestResult.failed(
                    name, f"Expected 401, got {status_code}", t.elapsed_ms
                )
            )

        # ── 4. Valid key → 200 on task list ───────────────────────────────────
        with Timer() as t:
            status_code, body = await c.get("/tasks")
        name = "valid_api_key_returns_200"
        if status_code == 200:
            suite.results.append(TestResult.passed(name, t.elapsed_ms))
        else:
            suite.results.append(
                TestResult.failed(
                    name, f"Expected 200, got {status_code}: {body}", t.elapsed_ms
                )
            )

        # ── 5. POST /tasks → 202 with correct schema ───────────────────────────
        with Timer() as t:
            status_code, body = await c.submit_task(
                "Summarize the LegionForge project."
            )
        name = "submit_task_returns_202_with_schema"
        if status_code == 202 and isinstance(body, dict):
            missing = _TASK_SUBMIT_KEYS - body.keys()
            if missing:
                suite.results.append(
                    TestResult.failed(
                        name, f"Response missing keys: {missing}", t.elapsed_ms
                    )
                )
            else:
                task_id = body["task_id"]
                stream_token = body.get("stream_token")
                suite.results.append(
                    TestResult.passed(name, t.elapsed_ms, task_id=task_id)
                )
        else:
            suite.results.append(
                TestResult.failed(
                    name, f"Expected 202, got {status_code}: {body}", t.elapsed_ms
                )
            )

        # ── 6. GET /tasks → list with tasks key or items ──────────────────────
        with Timer() as t:
            status_code, body = await c.get("/tasks")
        name = "list_tasks_returns_200_with_list"
        if status_code == 200 and isinstance(body, dict):
            has_data = (
                "tasks" in body or "items" in body or isinstance(body.get("data"), list)
            )
            # Some implementations return the list directly; accept dict with any iterable value
            if has_data or any(isinstance(v, list) for v in body.values()):
                suite.results.append(TestResult.passed(name, t.elapsed_ms))
            else:
                suite.results.append(
                    TestResult.failed(
                        name,
                        f"Response schema unexpected: {list(body.keys())}",
                        t.elapsed_ms,
                    )
                )
        else:
            suite.results.append(
                TestResult.failed(
                    name, f"Expected 200, got {status_code}", t.elapsed_ms
                )
            )

        # ── 7. GET /tasks/{id} → task detail ─────────────────────────────────
        name = "get_task_by_id_returns_detail"
        if task_id:
            with Timer() as t:
                status_code, body = await c.get(f"/tasks/{task_id}")
            if status_code == 200 and isinstance(body, dict):
                missing = _TASK_DETAIL_KEYS - body.keys()
                if missing:
                    suite.results.append(
                        TestResult.failed(
                            name, f"Response missing keys: {missing}", t.elapsed_ms
                        )
                    )
                else:
                    suite.results.append(TestResult.passed(name, t.elapsed_ms))
            else:
                suite.results.append(
                    TestResult.failed(
                        name, f"Expected 200, got {status_code}: {body}", t.elapsed_ms
                    )
                )
        else:
            suite.results.append(TestResult.skipped(name, "task submission failed"))

        # ── 8. GET /tasks/{unknown_id} → 404 ─────────────────────────────────
        with Timer() as t:
            status_code, _ = await c.get("/tasks/00000000-0000-0000-0000-000000000000")
        name = "unknown_task_id_returns_404"
        if status_code == 404:
            suite.results.append(TestResult.passed(name, t.elapsed_ms))
        else:
            suite.results.append(
                TestResult.failed(
                    name, f"Expected 404, got {status_code}", t.elapsed_ms
                )
            )

        # ── 9. DELETE /tasks/{id} → 204 (cancel queued task) ─────────────────
        name = "cancel_task_returns_204"
        if task_id:
            # Submit a fresh task to cancel (the first one may already be running)
            _, fresh = await c.submit_task("Cancel me immediately.")
            fresh_id = fresh.get("task_id") if isinstance(fresh, dict) else None
            if fresh_id:
                with Timer() as t:
                    status_code, _ = await c.delete(f"/tasks/{fresh_id}")
                # 204 = cancelled; 404 = already picked up by worker (timing race — OK)
                if status_code in (204, 404):
                    suite.results.append(
                        TestResult.passed(
                            name,
                            t.elapsed_ms,
                            note="404 means worker already picked it up — acceptable",
                        )
                    )
                else:
                    suite.results.append(
                        TestResult.failed(
                            name,
                            f"Expected 204 or 404, got {status_code}",
                            t.elapsed_ms,
                        )
                    )
            else:
                suite.results.append(
                    TestResult.skipped(name, "second task submission failed")
                )
        else:
            suite.results.append(TestResult.skipped(name, "task submission failed"))

        # ── 10. GET /usage/me → correct schema ────────────────────────────────
        with Timer() as t:
            status_code, body = await c.get("/usage/me")
        name = "usage_me_returns_correct_schema"
        expected_keys = {"user_id", "username", "daily_limit", "today"}
        if status_code == 200 and isinstance(body, dict):
            missing = expected_keys - body.keys()
            if missing:
                suite.results.append(
                    TestResult.failed(
                        name, f"Response missing keys: {missing}", t.elapsed_ms
                    )
                )
            elif not isinstance(body.get("today"), dict):
                suite.results.append(
                    TestResult.failed(name, "today field is not a dict", t.elapsed_ms)
                )
            else:
                suite.results.append(TestResult.passed(name, t.elapsed_ms))
        else:
            suite.results.append(
                TestResult.failed(
                    name, f"Expected 200, got {status_code}: {body}", t.elapsed_ms
                )
            )

        # ── 11. GET /.well-known/agent.json → A2A agent card ─────────────────
        with Timer() as t:
            status_code, body = await c.get("/.well-known/agent.json", auth=False)
        name = "a2a_agent_card_returns_200"
        if status_code == 200 and isinstance(body, dict):
            suite.results.append(TestResult.passed(name, t.elapsed_ms))
        else:
            suite.results.append(
                TestResult.failed(
                    name,
                    f"Expected 200 + JSON, got {status_code}: {str(body)[:80]}",
                    t.elapsed_ms,
                )
            )

        # ── 12. GET /mcp/tools → MCP tool list ────────────────────────────────
        with Timer() as t:
            status_code, body = await c.get("/mcp/tools", auth=False)
        name = "mcp_tools_returns_200"
        if status_code == 200:
            suite.results.append(TestResult.passed(name, t.elapsed_ms))
        else:
            suite.results.append(
                TestResult.failed(
                    name, f"Expected 200, got {status_code}", t.elapsed_ms
                )
            )

        # ── 13. Blank task body → 422 validation error ─────────────────────────
        with Timer() as t:
            status_code, body = await c.post(
                "/tasks",
                body={"task": "   ", "agent_type": "orchestrator"},
            )
        name = "blank_task_text_returns_422"
        if status_code == 422:
            suite.results.append(TestResult.passed(name, t.elapsed_ms))
        else:
            suite.results.append(
                TestResult.failed(
                    name,
                    f"Expected 422, got {status_code}: {str(body)[:120]}",
                    t.elapsed_ms,
                )
            )

        # ── 14. Invalid agent_type → 422 ──────────────────────────────────────
        with Timer() as t:
            status_code, body = await c.post(
                "/tasks",
                body={"task": "Hello.", "agent_type": "not_a_real_agent"},
            )
        name = "invalid_agent_type_returns_422"
        if status_code == 422:
            suite.results.append(TestResult.passed(name, t.elapsed_ms))
        else:
            suite.results.append(
                TestResult.failed(
                    name,
                    f"Expected 422, got {status_code}: {str(body)[:120]}",
                    t.elapsed_ms,
                )
            )

    return task_id


async def run() -> SuiteResult:
    """Run Suite 1 — Basic functionality."""
    suite = SuiteResult(name=NAME)

    if not config.GATEWAY_API_KEY:
        suite.results.append(
            TestResult.skipped(
                "all_basic_tests", "GATEWAY_API_KEY not set — skipping suite"
            )
        )
        return suite

    try:
        await _run(suite, config.GATEWAY_API_KEY)
    except Exception as exc:
        suite.results.append(TestResult.error("suite_basic_unexpected", exc))

    return suite
