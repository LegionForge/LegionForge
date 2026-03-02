"""
src/gateway/routes/sessions.py
──────────────────────────────
Conversation session management — multi-turn LangGraph interactions.

Each session has a unique thread_id that persists across task submissions.
When a task is submitted via POST /sessions/{id}/turn, the worker uses the
session's thread_id so the LangGraph checkpointer can resume prior context.

Endpoints:
    POST   /sessions                    — create a session
    GET    /sessions                    — list sessions
    GET    /sessions/{session_id}       — get session + turn history
    DELETE /sessions/{session_id}       — delete session
    GET    /sessions/{session_id}/tasks — list tasks within a session

Phase 54 — Conversation Sessions.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from src.database import (
    create_session,
    delete_session,
    get_session,
    get_session_tasks,
    list_sessions,
    VALID_AGENT_TYPES,
)
from src.gateway.auth import require_user

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Request models ─────────────────────────────────────────────────────────────


class CreateSessionRequest(BaseModel):
    name: str = Field(default="", max_length=128)
    agent_type: str = Field(default="orchestrator")

    model_config = {"extra": "forbid"}


# ── Endpoints ──────────────────────────────────────────────────────────────────


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_session_endpoint(
    body: CreateSessionRequest,
    user: dict = Depends(require_user),
) -> dict:
    """
    Create a new conversation session.

    Sessions share a LangGraph thread_id across multiple task submissions,
    allowing the agent to maintain context between turns.

    Phase 54 — Conversation Sessions.
    """
    if body.agent_type not in VALID_AGENT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"agent_type must be one of {sorted(VALID_AGENT_TYPES)}",
        )
    try:
        session = await create_session(
            user_id=user["user_id"],
            name=body.name,
            agent_type=body.agent_type,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return session


@router.get("")
async def list_sessions_endpoint(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    user: dict = Depends(require_user),
) -> dict:
    """
    List conversation sessions for the authenticated user, newest first.

    Phase 54 — Conversation Sessions.
    """
    return await list_sessions(user["user_id"], limit=limit, offset=offset)


@router.get("/{session_id}")
async def get_session_endpoint(
    session_id: str,
    user: dict = Depends(require_user),
) -> dict:
    """
    Get a session by ID, including basic metadata.

    Phase 54 — Conversation Sessions.
    """
    session = await get_session(session_id, user["user_id"])
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id!r} not found",
        )
    return session


@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_session_endpoint(
    session_id: str,
    user: dict = Depends(require_user),
) -> None:
    """
    Delete a session.

    Tasks linked to the session have their session_id set to NULL
    (ON DELETE SET NULL) — they are not deleted.

    Phase 54 — Conversation Sessions.
    """
    deleted = await delete_session(session_id, user["user_id"])
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id!r} not found",
        )


@router.get("/{session_id}/tasks")
async def get_session_tasks_endpoint(
    session_id: str,
    user: dict = Depends(require_user),
) -> dict:
    """
    Return all tasks within a session, ordered oldest-first (conversation order).

    Phase 54 — Conversation Sessions.
    """
    session = await get_session(session_id, user["user_id"])
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id!r} not found",
        )
    try:
        tasks = await get_session_tasks(session_id, user["user_id"])
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    return {
        "session_id": session_id,
        "turn_count": session.get("turn_count", 0),
        "tasks": tasks,
    }
