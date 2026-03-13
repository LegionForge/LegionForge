"""
tests/gateway_client/suite_agent_quality.py
─────────────────────────────────────────────
Suite: agent — Phase 1 live agent query runner.

Submits real queries through the gateway, polls until complete, captures the
full event transcript, runs structural assertions, and saves a JSON transcript
to tests/agent_quality_transcripts/ so you can inspect failures without
re-running the query manually.

What "structural" means here:
  - Did the task reach status=complete (not failed/timeout)?
  - Is the result field non-empty and meaningful (>10 chars)?
  - Did the agent call every tool in expected_tools?
  - Did the agent avoid hitting the recursion/step limit?
  - (Phase 2 preview) Do any expected keywords appear in the result?

What is NOT checked here (Phase 2/3 work):
  - Whether the answer is factually correct
  - Whether sources cited are real / reachable
  - LLM-as-judge quality scoring

Requires:
  - Gateway running at GATEWAY_URL (default: http://localhost:8080)
  - GATEWAY_API_KEY set to a valid user API key
  - Ollama running with the configured primary model

Query corpus: tests/agent_queries.yaml

Run:
  python -m tests.gateway_client --suite agent
  make test-agent
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from tests.gateway_client import config
from tests.gateway_client.client import GatewayClient, Timer
from tests.gateway_client.report import SuiteResult, TestResult

NAME = "agent"

# ── Paths ─────────────────────────────────────────────────────────────────────

_CORPUS_FILE = Path(__file__).parent.parent / "agent_queries.yaml"

_TRANSCRIPT_DIR = Path(
    os.environ.get(
        "AGENT_TRANSCRIPT_DIR",
        str(Path(__file__).parent.parent / "agent_quality_transcripts"),
    )
)

# ── Tuning ────────────────────────────────────────────────────────────────────

_POLL_INTERVAL_S: float = 3.0
_DEFAULT_TIMEOUT_S: float = 120.0

# ── Helpers ───────────────────────────────────────────────────────────────────


def _load_corpus() -> list[dict]:
    """Load query definitions from agent_queries.yaml."""
    if not _CORPUS_FILE.exists():
        return []
    with _CORPUS_FILE.open() as f:
        return yaml.safe_load(f) or []


def _extract_tools_called(stream_events: list[dict]) -> list[str]:
    """Return tool names from every tool_start event in the stream (in order)."""
    return [
        evt["data"]["tool"]
        for evt in stream_events
        if evt.get("event") == "tool_start" and evt.get("data", {}).get("tool")
    ]


def _step_limit_hit(stream_events: list[dict]) -> bool:
    """Return True if any task_failed event mentions the step/recursion limit."""
    for evt in stream_events:
        if evt.get("event") != "task_failed":
            continue
        data = evt.get("data") or {}
        reason = str(data.get("reason") or data.get("error") or "").lower()
        if any(tok in reason for tok in ("step", "limit", "recursion")):
            return True
    return False


def _save_transcript(transcript: dict) -> Path:
    """Persist a transcript as JSON. Returns the file path."""
    _TRANSCRIPT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    fname = f"{ts}_{transcript['query_id']}.json"
    path = _TRANSCRIPT_DIR / fname
    with path.open("w") as f:
        json.dump(transcript, f, indent=2, default=str)
    return path


async def _poll_until_done(
    client: GatewayClient,
    task_id: str,
    timeout_s: float,
) -> dict | None:
    """
    Poll GET /tasks/{task_id} every _POLL_INTERVAL_S seconds.
    Returns the task row when status is terminal, or None on timeout.
    """
    _TERMINAL = {"complete", "failed", "cancelled"}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status_code, body = await client.get(f"/tasks/{task_id}")
        if status_code == 200 and isinstance(body, dict):
            if body.get("status") in _TERMINAL:
                return body
        await asyncio.sleep(_POLL_INTERVAL_S)
    return None


# ── Per-query runner ──────────────────────────────────────────────────────────


async def _run_query(
    suite: SuiteResult,
    client: GatewayClient,
    qdef: dict,
) -> dict:
    """
    Execute one query end-to-end and append TestResults to suite.
    Returns a transcript dict ready for _save_transcript().
    """
    qid: str = qdef["id"]
    query: str = qdef["query"]
    agent_type: str = qdef.get("agent_type", "orchestrator")
    timeout_s: float = float(qdef.get("timeout_s", _DEFAULT_TIMEOUT_S))
    expected_tools: list[str] = qdef.get("expected_tools", [])
    expect_completed: bool = qdef.get("expect_completed", True)
    expect_result: bool = qdef.get("expect_result", True)
    keywords: list[str] = qdef.get("keywords", [])

    transcript: dict[str, Any] = {
        "query_id": qid,
        "query": query,
        "agent_type": agent_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "path": "gateway",
        "task_id": None,
        "status": None,
        "result": None,
        "steps": None,
        "tokens": None,
        "tools_called": [],
        "stream_events": [],
        "duration_s": 0.0,
        "assertions": {
            "completed": False,
            "result_non_empty": False,
            "expected_tools_fired": None,  # None = not checked (no expected_tools)
            "missing_tools": [],
            "step_limit_hit": False,
            "keywords_present": None,  # None = not checked (no keywords)
        },
    }

    t0 = time.monotonic()

    # ── 1. Submit ──────────────────────────────────────────────────────────────
    name_submit = f"{qid}::submitted"
    with Timer() as t:
        sc, body = await client.submit_task(query, agent_type=agent_type)

    if sc not in (200, 202) or not isinstance(body, dict) or "task_id" not in body:
        suite.results.append(
            TestResult.failed(
                name_submit,
                f"HTTP {sc} — {str(body)[:120]}",
                t.elapsed_ms,
            )
        )
        transcript["status"] = "submit_failed"
        return transcript

    task_id: str = body["task_id"]
    transcript["task_id"] = task_id
    suite.results.append(TestResult.passed(name_submit, t.elapsed_ms, task_id=task_id))

    # ── 2. Poll until terminal ─────────────────────────────────────────────────
    name_complete = f"{qid}::completed"
    task_row = await _poll_until_done(client, task_id, timeout_s)
    transcript["duration_s"] = round(time.monotonic() - t0, 1)

    if task_row is None:
        suite.results.append(
            TestResult.failed(
                name_complete,
                f"Timed out after {timeout_s}s — still not terminal",
                transcript["duration_s"] * 1000,
            )
        )
        transcript["status"] = "timeout"
        return transcript

    # ── 3. Unpack task row ────────────────────────────────────────────────────
    task_status: str = task_row.get("status", "")
    transcript["status"] = task_status
    transcript["result"] = task_row.get("result") or ""
    transcript["steps"] = task_row.get("steps")
    transcript["tokens"] = task_row.get("tokens")

    raw_events = task_row.get("stream_events") or []
    if isinstance(raw_events, str):
        try:
            raw_events = json.loads(raw_events)
        except Exception:
            raw_events = []
    transcript["stream_events"] = raw_events

    tools_called = _extract_tools_called(raw_events)
    transcript["tools_called"] = tools_called

    step_limit = _step_limit_hit(raw_events)
    transcript["assertions"]["step_limit_hit"] = step_limit

    # ── 4. Completed assertion ────────────────────────────────────────────────
    if expect_completed:
        if task_status == "complete":
            suite.results.append(
                TestResult.passed(
                    name_complete,
                    transcript["duration_s"] * 1000,
                    steps=transcript["steps"],
                )
            )
            transcript["assertions"]["completed"] = True
        else:
            reason = " (step limit hit)" if step_limit else ""
            suite.results.append(
                TestResult.failed(
                    name_complete,
                    f"status={task_status!r} after {transcript['duration_s']}s{reason}",
                    transcript["duration_s"] * 1000,
                )
            )

    # ── 5. Result non-empty ───────────────────────────────────────────────────
    if expect_result:
        name_result = f"{qid}::result_non_empty"
        result_text: str = transcript["result"]
        if result_text and len(result_text.strip()) > 10:
            suite.results.append(TestResult.passed(name_result))
            transcript["assertions"]["result_non_empty"] = True
        else:
            suite.results.append(
                TestResult.failed(
                    name_result,
                    f"Result empty or too short: {result_text!r:.80}",
                )
            )

    # ── 6. Step limit guard ───────────────────────────────────────────────────
    name_steplimit = f"{qid}::no_step_limit_hit"
    if not step_limit:
        suite.results.append(TestResult.passed(name_steplimit))
    else:
        suite.results.append(
            TestResult.failed(name_steplimit, "Agent hit the recursion/step limit")
        )
    transcript["assertions"]["step_limit_hit"] = step_limit

    # ── 7. Expected tools ─────────────────────────────────────────────────────
    if expected_tools:
        name_tools = f"{qid}::expected_tools_fired"
        missing = [tool for tool in expected_tools if tool not in tools_called]
        transcript["assertions"]["missing_tools"] = missing
        if not missing:
            suite.results.append(
                TestResult.passed(name_tools, tools_called=tools_called)
            )
            transcript["assertions"]["expected_tools_fired"] = True
        else:
            suite.results.append(
                TestResult.failed(
                    name_tools,
                    f"Expected {expected_tools} — missing: {missing} — called: {tools_called}",
                )
            )
            transcript["assertions"]["expected_tools_fired"] = False

    # ── 8. Keyword presence (Phase 2 preview) ─────────────────────────────────
    if keywords:
        name_kw = f"{qid}::keywords_present"
        result_lower = (transcript["result"] or "").lower()
        found = [kw for kw in keywords if kw.lower() in result_lower]
        if found:
            suite.results.append(TestResult.passed(name_kw, found=found))
            transcript["assertions"]["keywords_present"] = True
        else:
            suite.results.append(
                TestResult.failed(
                    name_kw,
                    f"None of {keywords!r} found in result",
                )
            )
            transcript["assertions"]["keywords_present"] = False

    return transcript


# ── Suite entry point ─────────────────────────────────────────────────────────


async def run() -> SuiteResult:
    """Run the agent_quality suite against the live gateway."""
    suite = SuiteResult(name=NAME)

    # Guard: corpus exists
    corpus = _load_corpus()
    if not corpus:
        suite.results.append(
            TestResult.skipped(
                "corpus_load",
                f"No queries in {_CORPUS_FILE} — create agent_queries.yaml to use this suite",
            )
        )
        return suite

    # Guard: API key set
    if not config.GATEWAY_API_KEY:
        suite.results.append(
            TestResult.skipped(
                "auth_check",
                "GATEWAY_API_KEY not set — export it before running: make test-agent",
            )
        )
        return suite

    # Use a generous client timeout — queries can take 2-3 minutes with Ollama
    async with GatewayClient(timeout=300.0) as client:

        # Quick gateway health gate — no point running expensive queries
        # against a dead gateway
        sc, body = await client.health()
        if sc != 200:
            suite.results.append(
                TestResult.error(
                    "gateway_health_gate",
                    RuntimeError(f"Gateway not healthy: HTTP {sc} — {body}"),
                )
            )
            return suite

        # Queries run sequentially — Ollama queues inference anyway, so
        # parallel submission just creates a long queue without saving time.
        for qdef in corpus:
            transcript = await _run_query(suite, client, qdef)
            path = _save_transcript(transcript)
            # Print the path inline so the user can open it immediately.
            # This output appears between suite test rows in the terminal.
            _STATUS = transcript.get("status", "?")
            _DUR = transcript.get("duration_s", 0)
            print(f"\n     [{_STATUS} in {_DUR}s] transcript → {path}")

    return suite
