"""
src/gateway/routes/stream.py
─────────────────────────────
SSE streaming endpoint:

    GET /tasks/{task_id}/stream

Browser clients pass their stream_token as a query param (EventSource cannot
set headers).  API clients can use either the Bearer token or stream_token.
"""

from __future__ import annotations

import json
import logging

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

    # Verify the task belongs to this user (404 semantics)
    task_row = await get_task(task_id, user_id=user.get("user_id"))
    if task_row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Task not found"
        )

    async def event_generator():
        async for event in subscribe_task_events(task_id):
            if await request.is_disconnected():
                logger.debug(f"[gateway/stream] Client disconnected task_id={task_id}")
                break
            yield {
                "event": event["event"],
                "data": json.dumps(event["data"]),
            }

    return EventSourceResponse(event_generator())
