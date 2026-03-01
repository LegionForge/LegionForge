"""
src/gateway/events.py
─────────────────────
SSE event builders and the in-process pub/sub channel used to bridge the
task worker (which runs the agent and produces LangGraph events) to the SSE
stream endpoint (which delivers them to the client).

Event flow:
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

In-memory queues are sufficient at household scale (single process).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── SSE event builder ─────────────────────────────────────────────────────────

_TERMINAL_EVENTS = {"task_complete", "task_error", "task_cancelled"}


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
        return {"event": "tool_start", "data": {"tool": name, "timestamp": ts}}

    if kind == "on_tool_end":
        return {"event": "tool_end", "data": {"tool": name, "timestamp": ts}}

    # on_chat_model_start, on_chat_model_end, on_retry, etc. — not client-relevant
    return None


def build_task_start_event(task_id: str, agent_type: str) -> dict:
    return {
        "event": "task_start",
        "data": {"task_id": task_id, "agent_type": agent_type, "timestamp": _now()},
    }


def build_task_complete_event(task_id: str) -> dict:
    return {
        "event": "task_complete",
        "data": {
            "task_id": task_id,
            "status": "complete",
            "result_url": f"/tasks/{task_id}",
            "timestamp": _now(),
        },
    }


def build_task_error_event(task_id: str, error: str) -> dict:
    return {
        "event": "task_error",
        "data": {
            "task_id": task_id,
            "status": "failed",
            "error": error,
            "timestamp": _now(),
        },
    }


def build_task_cancelled_event(task_id: str) -> dict:
    return {
        "event": "task_cancelled",
        "data": {"task_id": task_id, "status": "cancelled", "timestamp": _now()},
    }


def build_heartbeat_event() -> dict:
    return {"event": "heartbeat", "data": {}}


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
# The dict is unbounded but small (one entry per completed task per process
# lifetime — typically a few hundred bytes each).
_terminal_events: dict[str, dict] = {}


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
