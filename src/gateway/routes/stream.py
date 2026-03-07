"""
src/gateway/routes/stream.py
─────────────────────────────
SSE streaming endpoint:

    GET /tasks/{task_id}/stream

Browser clients pass their stream_token as a query param (EventSource cannot
set headers).  API clients can use either the Bearer token or stream_token.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sse_starlette.sse import EventSourceResponse

from src.database import get_task
from src.gateway.auth import (
    authenticate,
    extract_bearer_token,
    require_user,
    resolve_stream_token,
)
from src.gateway.events import subscribe_task_events

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Per-user SSE stream slot tracking ─────────────────────────────────────────
# Tracks the number of open SSE connections per user_id. Prevents a single
# user from holding an unlimited number of open asyncio queues.
# asyncio is single-threaded so dict operations are safe without a lock;
# the Lock is kept for clarity and future thread-safety if the model changes.

_active_streams: dict[str, int] = defaultdict(int)
_streams_lock = asyncio.Lock()


async def _acquire_stream_slot(user_id: str) -> None:
    """
    Reserve an SSE stream slot for user_id, or raise HTTP 429 if the limit is reached.

    Reads ``settings.gateway.max_sse_streams_per_user`` live so YAML changes
    take effect on gateway restart. Set to 0 to disable the cap entirely.
    """
    try:
        from config.settings import settings

        limit = settings.gateway.max_sse_streams_per_user
    except Exception:
        limit = 10  # safe default

    if limit <= 0:
        return

    async with _streams_lock:
        current = _active_streams.get(user_id, 0)
        if current >= limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Too many open streams — you already have {current} SSE "
                    f"connection(s) open (max {limit}). "
                    "Close an existing stream before opening a new one."
                ),
                headers={"Retry-After": "30"},
            )
        _active_streams[user_id] = current + 1


async def _release_stream_slot(user_id: str) -> None:
    """Decrement the open-stream counter for user_id."""
    async with _streams_lock:
        count = _active_streams.get(user_id, 0)
        if count <= 1:
            _active_streams.pop(user_id, None)
        else:
            _active_streams[user_id] = count - 1


async def _resolve_user_for_stream(
    task_id: str,
    request: Request,
    stream_token: str | None,
) -> dict:
    """
    Authenticate the SSE request.  Accepts:
      1. stream_token query param  (issued by POST /tasks)
      2. Authorization: Bearer header  (API clients)

    Returns user dict or raises 401/404.
    """
    # ── stream_token path ──────────────────────────────────────────────────
    if stream_token:
        resolved = await resolve_stream_token(stream_token)
        if resolved is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired stream token",
            )
        resolved_task_id, user_id = resolved
        if resolved_task_id != task_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Stream token does not match task",
            )
        return {"user_id": user_id, "username": "stream_token_user"}

    # ── Bearer header path ─────────────────────────────────────────────────
    raw_key = extract_bearer_token(request.headers.get("authorization"))
    if not raw_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header or stream_token param",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = await authenticate(raw_key)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


@router.get("/{task_id}/stream")
async def stream_task(
    task_id: str,
    request: Request,
    stream_token: str | None = Query(default=None),
) -> EventSourceResponse:
    """
    Subscribe to the SSE event stream for a task.

    Events are forwarded from the task worker via in-process pub/sub queues.
    A heartbeat is emitted every 15 s to keep the connection alive through proxies.
    The stream closes on task_complete, task_error, or task_cancelled.
    """
    user = await _resolve_user_for_stream(task_id, request, stream_token)
    user_id = user.get("user_id", "")

    # DOS guard: reject if the user already has too many open SSE connections.
    # Must happen before EventSourceResponse so the 429 is sent as a normal
    # HTTP response, not wrapped in the SSE stream.
    await _acquire_stream_slot(user_id)

    # Verify the task belongs to this user (404 semantics)
    task_row = await get_task(task_id, user_id=user_id)
    if task_row is None:
        await _release_stream_slot(user_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Task not found"
        )

    async def event_generator():
        try:
            # Fast-path: if the task already completed before the browser connected
            # (common for short tasks — the agent finishes before EventSource handshake),
            # emit the terminal event immediately so the UI doesn't hang waiting for a
            # queue that was already deleted when the task finished.
            task_status = task_row.get("status", "")
            if task_status == "complete":
                yield {
                    "event": "task_complete",
                    "data": json.dumps(
                        {
                            "task_id": task_id,
                            "status": "complete",
                            "result_url": f"/tasks/{task_id}",
                            "result": task_row.get("result", ""),
                            "tokens": task_row.get("tokens"),
                        }
                    ),
                }
                return
            if task_status == "failed":
                yield {
                    "event": "task_error",
                    "data": json.dumps(
                        {
                            "task_id": task_id,
                            "status": "failed",
                            "error": task_row.get("error", "Unknown error"),
                        }
                    ),
                }
                return
            if task_status == "cancelled":
                yield {
                    "event": "task_cancelled",
                    "data": json.dumps({"task_id": task_id, "status": "cancelled"}),
                }
                return

            # Task still running — subscribe to the live event queue.
            async for event in subscribe_task_events(task_id):
                if await request.is_disconnected():
                    logger.debug(
                        "[gateway/stream] Client disconnected task_id=%s", task_id
                    )
                    break
                yield {
                    "event": event["event"],
                    "data": json.dumps(event["data"]),
                }
        finally:
            # Always release the stream slot — fired on normal completion,
            # client disconnect, or generator garbage collection.
            await _release_stream_slot(user_id)

    return EventSourceResponse(event_generator())
