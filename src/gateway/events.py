"""
src/gateway/events.py
─────────────────────
SSE event builders and the in-process pub/sub channel used to bridge the
task worker (which runs the agent and produces LangGraph events) to the SSE
stream endpoint (which delivers them to the client).

Event flow — task SSE:
    worker.run_task()
        ↓  graph.astream_events()
        ↓  build_sse_event(lg_event) → dict | None
        ↓  publish_event(task_id, sse_event)
                ↓
           _channels[task_id] → asyncio.Queue
                ↓
    stream.py  subscribe_task_events(task_id) → AsyncGenerator[dict, None]
                ↓
    EventSourceResponse → browser

Event flow — pipeline SSE (Phase 30):
    pipeline_runner.execute_pipeline()
        ↓  after each step
        ↓  publish_pipeline_event(run_id, step_event)
                ↓
           _pipeline_channels[run_id] → asyncio.Queue
                ↓
    pipelines.py  subscribe_pipeline_events(run_id) → AsyncGenerator[dict, None]
                ↓
    EventSourceResponse → browser

In-memory queues are sufficient at household scale (single process).
"""

from __future__ import annotations

import asyncio
import logging
from collections import OrderedDict
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Maximum number of terminal events to cache in memory.
# Each entry is ~300–400 bytes (UUID + event dict).  2 000 entries ≈ 800 KB.
# Oldest entries are evicted FIFO when the limit is reached.  The cache
# exists only to close the late-subscriber race (subscriber arrives after
# the channel is torn down but within the same request cycle, typically <1 s).
_TERMINAL_CACHE_MAXSIZE = 2_000

# ── SSE event builder ─────────────────────────────────────────────────────────

_TERMINAL_EVENTS = {"task_complete", "task_error", "task_cancelled", "hitl_required"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_sse_event(lg_event: dict) -> dict | None:
    """
    Map a single LangGraph astream_events (v2) event to an SSE event dict.

    Returns None for internal events that should not be forwarded to clients.

    Security: tool_start/tool_end events do NOT include raw tool args or output —
    only the tool name.  Full data is available in GET /tasks/{id} to auth'd users.
    """
    kind = lg_event.get("event", "")
    name = lg_event.get("name", "")
    ts = _now()

    if kind == "on_chain_start":
        return {"event": "chain_start", "data": {"node": name, "timestamp": ts}}

    if kind == "on_chain_end":
        return {"event": "chain_end", "data": {"node": name, "timestamp": ts}}

    if kind == "on_chat_model_stream":
        chunk = lg_event.get("data", {}).get("chunk")
        delta = chunk.content if chunk is not None else ""
        return {"event": "token", "data": {"delta": delta, "timestamp": ts}}

    if kind == "on_tool_start":
        # Include a sanitized one-line hint of what the tool was called with,
        # so the UI can show it as a tooltip.  Raw args are NOT forwarded —
        # only the primary identifying argument (query text or URL).
        args = lg_event.get("data", {}).get("input") or {}
        if isinstance(args, dict):
            hint = (
                str(args.get("query") or args.get("url") or args.get("focus") or "")
            )[:120]
        else:
            hint = ""
        return {
            "event": "tool_start",
            "data": {"tool": name, "hint": hint, "timestamp": ts},
        }

    if kind == "on_tool_end":
        return {"event": "tool_end", "data": {"tool": name, "timestamp": ts}}

    # on_chat_model_start, on_chat_model_end, on_retry, etc. — not client-relevant
    return None


def build_task_start_event(task_id: str, agent_type: str) -> dict:
    return {
        "event": "task_start",
        "data": {"task_id": task_id, "agent_type": agent_type, "timestamp": _now()},
    }


def build_task_complete_event(
    task_id: str,
    result: str = "",
    tokens: dict | None = None,
    charts: list[dict] | None = None,
) -> dict:
    """
    Build a task_complete SSE event.

    Phase 69: ``result`` and ``tokens`` are included inline so the browser
    can render the final answer immediately without an extra REST round-trip.
    Both fields remain optional for backward-compat with callers that don't
    have the result yet (e.g. the fast-path DB read in stream.py already
    populates them directly from task_row).

    ``charts`` carries chart payloads extracted by code_execute — each entry
    is {"type": "svg"|"png"|"plotly", "data": "<raw>"}. Charts are ephemeral:
    they are NOT stored in the DB and will NOT appear on stream reconnect.
    """
    data: dict = {
        "task_id": task_id,
        "status": "complete",
        "result_url": f"/tasks/{task_id}",
        "timestamp": _now(),
    }
    if result:
        data["result"] = result
    if tokens:
        data["tokens"] = tokens
    if charts:
        data["charts"] = charts
    return {"event": "task_complete", "data": data}


_TASK_ERROR_TRANSLATIONS: list[tuple[str, str]] = [
    (
        "connection refused",
        "Could not reach the AI model. Make sure Ollama is running: `brew services start ollama`",
    ),
    (
        "connecterror",
        "Could not reach the AI model. Make sure Ollama is running: `brew services start ollama`",
    ),
    (
        "timeout",
        "The AI model took too long to respond. It may still be loading — try again in a moment.",
    ),
    (
        "timed out",
        "The AI model took too long to respond. It may still be loading — try again in a moment.",
    ),
    (
        "model not found",
        "The requested model is not available. Run `ollama pull <model>` to download it.",
    ),
    (
        "daily budget",
        "Daily token budget exceeded. Try again tomorrow or ask an admin to raise your quota.",
    ),
    (
        "preflight budget",
        "This request exceeds your remaining token budget for today.",
    ),
    (
        "injection detected",
        "The request was blocked: a security pattern was detected in the input.",
    ),
    (
        "security halt",
        "The task was stopped by the security system. Check the audit log for details.",
    ),
    (
        "recursionerror",
        "The agent hit its maximum step limit. Try a more specific query.",
    ),
]


def _friendly_task_error(error: str) -> str:
    """Translate a raw exception/error string into a user-facing message."""
    lowered = error.lower()
    for key, msg in _TASK_ERROR_TRANSLATIONS:
        if key in lowered:
            return msg
    return "An unexpected error occurred. The task could not be completed."


def build_task_error_event(task_id: str, error: str) -> dict:
    return {
        "event": "task_error",
        "data": {
            "task_id": task_id,
            "status": "failed",
            "error": error,
            "user_message": _friendly_task_error(error),
            "timestamp": _now(),
        },
    }


def build_task_cancelled_event(task_id: str) -> dict:
    return {
        "event": "task_cancelled",
        "data": {"task_id": task_id, "status": "cancelled", "timestamp": _now()},
    }


def build_hitl_required_event(task_id: str, request_id: str | None = None) -> dict:
    """
    Terminal SSE event published when the agent is paused awaiting HITL approval.

    Closes the SSE stream from the client's perspective (hitl_required is in
    _TERMINAL_EVENTS).  The task row is set to 'paused' by the worker; the
    operator resolves the request via POST /hitl/{request_id}/approve|reject,
    after which the graph resumes and the task returns to 'running'.

    ``request_id`` is the hitl_pending row UUID — included so the UI can
    navigate directly to the approval modal without a polling round-trip.
    """
    data: dict = {
        "task_id": task_id,
        "status": "paused",
        "message": "Task paused — operator approval required before the agent can continue.",
        "timestamp": _now(),
    }
    if request_id:
        data["request_id"] = request_id
    return {"event": "hitl_required", "data": data}


def build_heartbeat_event() -> dict:
    return {"event": "heartbeat", "data": {}}


# Reason codes → user-visible labels.
# Kept vague enough not to reveal attack-surface internals.
_BLOCK_REASON_LABELS: dict[str, str] = {
    "registry_check_failed": (
        "Security registry check failed — tool integrity could not be verified. "
        "Run: make verify-tool-registry"
    ),
    "sandbox_sequence_violation": (
        "Tool call sequence was not in approved patterns — "
        "model will retry with a different approach"
    ),
    "capability_boundary_violation": (
        "Tool capability boundary exceeded — this action is not permitted"
    ),
    "action_loop_detected": (
        "Repeated action detected — the same tool was called too many times in a row"
    ),
    "acl_token_violation": "Tool is not in the authorized scope for this task",
    "ssrf_protection": "URL was blocked (private network address protection)",
    "hitl_required": "This action requires human approval before it can proceed",
    "injection_detected": "Security pattern detected in tool arguments — run halted",
    "toctou_violation": "Tool call tampering detected — run halted for safety",
    "canary_triggered": "Canary tool invoked — possible probe or hallucination; run halted",
}


def build_tool_blocked_event(tool_name: str, reason: str) -> dict:
    """
    Published by the worker when SecureToolNode dispatches a 'tool_blocked'
    custom LangChain event.  ``reason`` is a short machine-readable code;
    ``description`` is the human-readable label shown as a UI tooltip.
    Sensitive internal details are intentionally omitted.
    """
    return {
        "event": "tool_blocked",
        "data": {
            "tool": tool_name,
            "reason": reason,
            "description": _BLOCK_REASON_LABELS.get(
                reason, "Tool call was blocked by the security system"
            ),
            "timestamp": _now(),
        },
    }


# ── In-process pub/sub channel ────────────────────────────────────────────────
# Maps task_id → list of subscriber queues.  Multiple SSE clients can subscribe
# to the same task (e.g. browser tab + Discord connector).

_channels: dict[str, list[asyncio.Queue]] = {}
_SENTINEL = object()  # signals end-of-stream to subscribers

# Cache of terminal events keyed by task_id.  Populated by publish_event() when
# a terminal event fires; consumed by subscribe_task_events() if a subscriber
# arrives after the channel has already been torn down.  This closes the race:
#
#   1. Client fetches task_row  → status = "running"
#   2. Worker completes, publishes terminal event, deletes _channels[task_id]
#   3. Client calls subscribe_task_events() — channel is gone
#
# Without this cache step 3 creates a new empty channel that never receives
# anything and the client hangs on heartbeats forever.  With the cache the
# late subscriber finds the terminal event immediately and returns it.
#
# Bounded at _TERMINAL_CACHE_MAXSIZE (2 000) via OrderedDict FIFO eviction
# to prevent unbounded growth on long-running servers.
_terminal_events: OrderedDict[str, dict] = OrderedDict()


def _get_or_create_channel(task_id: str) -> list[asyncio.Queue]:
    if task_id not in _channels:
        _channels[task_id] = []
    return _channels[task_id]


async def publish_event(task_id: str, event: dict) -> None:
    """Push an SSE event to all subscribers of task_id."""
    queues = _channels.get(task_id, [])
    is_terminal = event.get("event") in _TERMINAL_EVENTS
    if is_terminal:
        # Cache before notifying subscribers so any subscriber that calls
        # subscribe_task_events() immediately after this returns will find it.
        # Evict oldest entry if the bounded cache is full.
        if len(_terminal_events) >= _TERMINAL_CACHE_MAXSIZE:
            _terminal_events.popitem(last=False)
        _terminal_events[task_id] = event
    for q in queues:
        await q.put(event)
        if is_terminal:
            await q.put(_SENTINEL)
    if is_terminal and task_id in _channels:
        del _channels[task_id]


async def subscribe_task_events(task_id: str) -> asyncio.AsyncGenerator[dict, None]:
    """
    Async generator that yields SSE event dicts as the worker publishes them.
    Yields a heartbeat every 15 s while waiting.  Closes on terminal event.

    Race safety: if the task completed between the caller's DB fetch and this
    call, the terminal event will be in _terminal_events and is returned
    immediately without creating a subscriber queue.
    """
    # Fast-path: task already done (race: completed between task_row fetch and here)
    if task_id in _terminal_events:
        yield _terminal_events[task_id]
        return

    q: asyncio.Queue = asyncio.Queue()
    channel = _get_or_create_channel(task_id)
    channel.append(q)

    try:
        while True:
            try:
                item = await asyncio.wait_for(q.get(), timeout=15.0)
            except asyncio.TimeoutError:
                yield build_heartbeat_event()
                continue

            if item is _SENTINEL:
                break
            yield item
    finally:
        try:
            channel.remove(q)
        except ValueError:
            pass


# ── Pipeline SSE pub/sub (Phase 30) ───────────────────────────────────────────
# Separate channel map keyed by str(run_id).  Pipeline events are step-level;
# terminal events are pipeline_complete / pipeline_failed.

_PIPELINE_TERMINAL_EVENTS = {"pipeline_complete", "pipeline_failed"}

_pipeline_channels: dict[str, list[asyncio.Queue]] = {}
_pipeline_terminal_events: OrderedDict[str, dict] = OrderedDict()


def build_pipeline_start_event(run_id: int, pipeline_id: int, total_steps: int) -> dict:
    return {
        "event": "pipeline_start",
        "data": {
            "run_id": run_id,
            "pipeline_id": pipeline_id,
            "total_steps": total_steps,
            "timestamp": _now(),
        },
    }


def build_pipeline_step_start_event(
    run_id: int, step_index: int, step_name: str, task_id: str
) -> dict:
    return {
        "event": "pipeline_step_start",
        "data": {
            "run_id": run_id,
            "step": step_index,
            "name": step_name,
            "task_id": task_id,
            "timestamp": _now(),
        },
    }


def build_pipeline_step_complete_event(
    run_id: int, step_index: int, step_name: str, task_id: str, result: str
) -> dict:
    return {
        "event": "pipeline_step_complete",
        "data": {
            "run_id": run_id,
            "step": step_index,
            "name": step_name,
            "task_id": task_id,
            "result": result,
            "timestamp": _now(),
        },
    }


def build_pipeline_complete_event(run_id: int, total_steps: int) -> dict:
    return {
        "event": "pipeline_complete",
        "data": {
            "run_id": run_id,
            "total_steps": total_steps,
            "status": "complete",
            "timestamp": _now(),
        },
    }


def build_pipeline_failed_event(run_id: int, error: str) -> dict:
    return {
        "event": "pipeline_failed",
        "data": {
            "run_id": run_id,
            "status": "failed",
            "error": error,
            "timestamp": _now(),
        },
    }


async def publish_pipeline_event(run_id: int, event: dict) -> None:
    """Push a pipeline SSE event to all subscribers of run_id."""
    key = str(run_id)
    queues = _pipeline_channels.get(key, [])
    is_terminal = event.get("event") in _PIPELINE_TERMINAL_EVENTS
    if is_terminal:
        if len(_pipeline_terminal_events) >= _TERMINAL_CACHE_MAXSIZE:
            _pipeline_terminal_events.popitem(last=False)
        _pipeline_terminal_events[key] = event
    for q in queues:
        await q.put(event)
        if is_terminal:
            await q.put(_SENTINEL)
    if is_terminal and key in _pipeline_channels:
        del _pipeline_channels[key]


async def subscribe_pipeline_events(
    run_id: int,
) -> asyncio.AsyncGenerator[dict, None]:
    """
    Async generator that yields pipeline SSE events as the runner publishes them.
    Yields heartbeats every 15 s.  Closes on pipeline_complete / pipeline_failed.

    Race safety: mirrors subscribe_task_events() — checks _pipeline_terminal_events
    first in case the run finished before the client subscribed.
    """
    key = str(run_id)
    if key in _pipeline_terminal_events:
        yield _pipeline_terminal_events[key]
        return

    q: asyncio.Queue = asyncio.Queue()
    if key not in _pipeline_channels:
        _pipeline_channels[key] = []
    _pipeline_channels[key].append(q)

    try:
        while True:
            try:
                item = await asyncio.wait_for(q.get(), timeout=15.0)
            except asyncio.TimeoutError:
                yield build_heartbeat_event()
                continue

            if item is _SENTINEL:
                break
            yield item
    finally:
        try:
            _pipeline_channels.get(key, []).remove(q)
        except ValueError:
            pass
