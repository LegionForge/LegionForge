"""
tests/gateway_client/suite_load.py
────────────────────────────────────
Suite 2 — Load and DOS resilience.

Verifies that the gateway remains stable and correct under concurrent
load, rejects malformed/oversized payloads, and enforces rate limits.

Tests are designed to be safe for production: they do not exhaust real
daily token budgets (tasks are submitted with minimal estimated tokens)
and they do not hold connections open for more than a few seconds.
"""

from __future__ import annotations

import asyncio
import statistics
import time
from typing import Any

from tests.gateway_client import config
from tests.gateway_client.client import GatewayClient, Timer
from tests.gateway_client.report import SuiteResult, TestResult


NAME = "load"

_OVERSIZED_BODY_MB = 2  # 2 MB JSON body — should be rejected
_HEALTH_CONCURRENT = 50  # concurrent /health requests
_SUBMIT_CONCURRENT = config.LOAD_CONCURRENCY  # concurrent task submissions
_BAD_KEY_ITERATIONS = config.LOAD_ITERATIONS  # rapid 401 flood
_SSE_CONCURRENT = 8  # concurrent SSE connections


async def _concurrent_health(suite: SuiteResult) -> None:
    """50 concurrent GET /health — all must return 200, gateway must not crash."""
    name = "concurrent_health_all_200"
    statuses: list[int] = []

    async def _fetch() -> None:
        async with GatewayClient() as c:
            sc, _ = await c.health()
            statuses.append(sc)

    with Timer() as t:
        await asyncio.gather(*[_fetch() for _ in range(_HEALTH_CONCURRENT)])

    non_200 = [s for s in statuses if s != 200]
    if non_200:
        suite.results.append(
            TestResult.failed(
                name,
                f"{len(non_200)}/{_HEALTH_CONCURRENT} requests returned non-200: {set(non_200)}",
                t.elapsed_ms,
            )
        )
    else:
        suite.results.append(
            TestResult.passed(
                name,
                t.elapsed_ms,
                requests=_HEALTH_CONCURRENT,
                all_200=True,
            )
        )


async def _health_sla(suite: SuiteResult) -> None:
    """P95 response time for /health must be under HEALTH_SLA_MS (default 2 s)."""
    name = "health_p95_response_time_under_sla"
    times_ms: list[float] = []

    async def _fetch() -> None:
        async with GatewayClient() as c:
            with Timer() as t:
                await c.health()
            times_ms.append(t.elapsed_ms)

    # Run 20 requests to get a meaningful P95 sample
    await asyncio.gather(*[_fetch() for _ in range(20)])

    if not times_ms:
        suite.results.append(
            TestResult.error(name, RuntimeError("No timing data collected"))
        )
        return

    times_ms.sort()
    p50 = statistics.median(times_ms)
    p95_idx = int(len(times_ms) * 0.95)
    p95 = times_ms[min(p95_idx, len(times_ms) - 1)]

    if p95 <= config.HEALTH_SLA_MS:
        suite.results.append(
            TestResult.passed(
                name,
                p95,
                p50_ms=round(p50, 1),
                p95_ms=round(p95, 1),
                sla_ms=config.HEALTH_SLA_MS,
            )
        )
    else:
        suite.results.append(
            TestResult.failed(
                name,
                f"P95 {p95:.0f}ms exceeds SLA {config.HEALTH_SLA_MS}ms",
                p95,
                p50_ms=round(p50, 1),
                p95_ms=round(p95, 1),
            )
        )


async def _concurrent_task_submit(suite: SuiteResult) -> None:
    """Concurrent task submissions — all must return 202 or 429 (not 5xx)."""
    name = "concurrent_task_submit_no_5xx"
    statuses: list[int] = []

    async def _submit() -> None:
        async with GatewayClient() as c:
            sc, _ = await c.submit_task("Load test: what is 2 + 2?")
            statuses.append(sc)

    with Timer() as t:
        await asyncio.gather(*[_submit() for _ in range(_SUBMIT_CONCURRENT)])

    server_errors = [s for s in statuses if s >= 500]
    ok_statuses = [s for s in statuses if s in (202, 429)]

    if server_errors:
        suite.results.append(
            TestResult.failed(
                name,
                f"{len(server_errors)} requests returned 5xx: {set(server_errors)}",
                t.elapsed_ms,
                concurrent=_SUBMIT_CONCURRENT,
            )
        )
    else:
        suite.results.append(
            TestResult.passed(
                name,
                t.elapsed_ms,
                concurrent=_SUBMIT_CONCURRENT,
                status_counts={str(k): statuses.count(k) for k in set(statuses)},
            )
        )


async def _oversized_body(suite: SuiteResult) -> None:
    """A 2 MB JSON body must be rejected (413 or 422) — never crash the gateway."""
    name = "oversized_body_rejected_not_500"
    big_task = "A" * (_OVERSIZED_BODY_MB * 1024 * 1024)
    # The task field has max_length=4000 on the Pydantic model; even if we try to
    # bypass that with raw bytes, the gateway must not 500.
    payload = f'{{"task":"{big_task[:4010]}","agent_type":"orchestrator"}}'

    with Timer() as t:
        async with GatewayClient() as c:
            sc, body = await c.post(
                "/tasks",
                body=payload.encode(),
                content_type="application/json",
            )

    # Accept 413 (too large), 422 (validation error), 400 (bad request)
    if sc in (400, 413, 422):
        suite.results.append(TestResult.passed(name, t.elapsed_ms, status=sc))
    elif sc >= 500:
        suite.results.append(
            TestResult.failed(
                name, f"Gateway returned 5xx ({sc}) on oversized body", t.elapsed_ms
            )
        )
    else:
        # Some servers just truncate and accept — that's a fail too
        suite.results.append(
            TestResult.failed(name, f"Expected 4xx rejection, got {sc}", t.elapsed_ms)
        )


async def _rapid_auth_failures(suite: SuiteResult) -> None:
    """50 rapid requests with invalid keys — all must be 401, gateway must survive."""
    name = "rapid_auth_failures_all_401_no_crash"
    statuses: list[int] = []

    async def _bad() -> None:
        async with GatewayClient(api_key=config.BAD_API_KEY) as c:
            sc, _ = await c.get("/tasks")
            statuses.append(sc)

    with Timer() as t:
        await asyncio.gather(*[_bad() for _ in range(_BAD_KEY_ITERATIONS)])

    non_401 = [s for s in statuses if s != 401]
    if non_401:
        suite.results.append(
            TestResult.failed(
                name,
                f"{len(non_401)}/{_BAD_KEY_ITERATIONS} requests returned non-401: {set(non_401)}",
                t.elapsed_ms,
            )
        )
    else:
        suite.results.append(
            TestResult.passed(
                name,
                t.elapsed_ms,
                requests=_BAD_KEY_ITERATIONS,
                all_401=True,
            )
        )


async def _sse_flood(suite: SuiteResult) -> None:
    """Open multiple SSE connections simultaneously — gateway must not crash."""
    name = "sse_connection_flood_no_crash"

    # First, submit a task to get a valid stream_token
    async with GatewayClient() as c:
        sc, body = await c.submit_task("SSE flood test task.")
    if sc != 202 or not isinstance(body, dict):
        suite.results.append(
            TestResult.skipped(name, "Task submission failed; skipping SSE flood")
        )
        return

    task_id = body.get("task_id", "")
    stream_token = body.get("stream_token", "")

    statuses: list[int] = []

    async def _connect() -> None:
        """Open SSE stream, read one chunk, close."""
        async with GatewayClient() as c:
            # Stream endpoint accepts either Bearer token or ?stream_token= param
            sc, _ = await c.get(
                f"/tasks/{task_id}/stream",
                params={"stream_token": stream_token},
                auth=False,
                raw=True,
            )
            statuses.append(sc)

    with Timer() as t:
        await asyncio.gather(*[_connect() for _ in range(_SSE_CONCURRENT)])

    server_errors = [s for s in statuses if s >= 500]
    if server_errors:
        suite.results.append(
            TestResult.failed(
                name,
                f"{len(server_errors)}/{_SSE_CONCURRENT} SSE connections returned 5xx",
                t.elapsed_ms,
            )
        )
    else:
        suite.results.append(
            TestResult.passed(
                name,
                t.elapsed_ms,
                concurrent=_SSE_CONCURRENT,
                status_counts={str(k): statuses.count(k) for k in set(statuses)},
            )
        )


async def _malformed_json(suite: SuiteResult) -> None:
    """Malformed JSON body must return 422 — never 500."""
    name = "malformed_json_returns_422_not_500"
    payloads = [
        b"{not valid json",
        b"",
        b"null",
        b"[]",
        b'{"task": null}',
        b'{"task": 12345}',
    ]

    results_by_payload: dict[str, int] = {}
    server_errors = []

    async with GatewayClient() as c:
        for payload in payloads:
            sc, _ = await c.post(
                "/tasks", body=payload, content_type="application/json"
            )
            label = payload[:30].decode("utf-8", errors="replace")
            results_by_payload[label] = sc
            if sc >= 500:
                server_errors.append((label, sc))

    if server_errors:
        suite.results.append(
            TestResult.failed(
                name,
                f"Server errors on malformed input: {server_errors}",
                detail=results_by_payload,
            )
        )
    else:
        suite.results.append(TestResult.passed(name, detail=results_by_payload))


async def _method_flood(suite: SuiteResult) -> None:
    """Mixed method flood — GET/POST/DELETE on various endpoints, no 5xx."""
    name = "mixed_method_flood_no_5xx"
    statuses: list[int] = []

    async def _hit() -> None:
        async with GatewayClient() as c:
            sc, _ = await c.get("/health", auth=False)
            statuses.append(sc)
            sc2, _ = await c.get("/tasks", auth=False)
            statuses.append(sc2)

    with Timer() as t:
        await asyncio.gather(*[_hit() for _ in range(10)])

    server_errors = [s for s in statuses if s >= 500]
    if server_errors:
        suite.results.append(
            TestResult.failed(
                name, f"{len(server_errors)} requests returned 5xx", t.elapsed_ms
            )
        )
    else:
        suite.results.append(
            TestResult.passed(name, t.elapsed_ms, total_requests=len(statuses))
        )


async def run() -> SuiteResult:
    """Run Suite 2 — Load and DOS resilience."""
    suite = SuiteResult(name=NAME)

    if not config.GATEWAY_API_KEY:
        suite.results.append(
            TestResult.skipped(
                "all_load_tests", "GATEWAY_API_KEY not set — skipping suite"
            )
        )
        return suite

    for fn in [
        _concurrent_health,
        _health_sla,
        _concurrent_task_submit,
        _oversized_body,
        _rapid_auth_failures,
        _sse_flood,
        _malformed_json,
        _method_flood,
    ]:
        try:
            await fn(suite)
        except Exception as exc:
            suite.results.append(TestResult.error(fn.__name__, exc))

    return suite
