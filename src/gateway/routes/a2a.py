"""
src/gateway/routes/a2a.py
──────────────────────────
A2A (Agent-to-Agent) protocol interoperability endpoints:

    GET  /.well-known/agent.json          — A2A Agent Card (public)
    POST /a2a/tasks                       — submit a task (A2A schema)
    GET  /a2a/tasks/{task_id}             — A2A task status
    GET  /a2a/tasks/{task_id}/stream      — A2A SSE stream

The A2A endpoints are thin adapters over the internal task queue.
Same auth, same worker, same Guardian pipeline.

Full A2A conformance: docs/A2A_CONFORMANCE.md
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from src.database import (
    create_task,
    get_task,
)
from src.gateway.auth import create_stream_token, require_user
from src.security.core import sanitize_text

logger = logging.getLogger(__name__)

router = APIRouter()

# ── A2A → internal status mapping ─────────────────────────────────────────────

INTERNAL_TO_A2A_STATUS: dict[str, str] = {
    "queued": "submitted",
    "running": "working",
    "complete": "completed",
    "failed": "failed",
    "cancelled": "canceled",
}


# ── Agent Card ─────────────────────────────────────────────────────────────────


def build_agent_card(host: str = "localhost:8080") -> dict:
    """
    Build the A2A Agent Card (/.well-known/agent.json).
    The 'url' field is populated from the request host at serve time.
    """
    return {
        "name": "LegionForge",
        "description": (
            "Security-native multi-agent framework. "
            "Supports web research, threat analysis, and task orchestration."
        ),
        "url": f"http://{host}",
        "version": "0.7.1-alpha",
        "provider": {
            "organization": "LegionForge",
            "url": "https://github.com/jp-cruz/LegionForge",
        },
        "capabilities": {
            "streaming": True,
            "pushNotifications": False,
            "stateTransitionHistory": True,
        },
        "authentication": {
            "schemes": ["Bearer"],
        },
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain", "application/json"],
        "skills": [
            {
                "id": "web-research",
                "name": "Web Research",
                "description": (
                    "Search the web and synthesize findings from multiple sources."
                ),
                "inputModes": ["text/plain"],
                "outputModes": ["text/plain"],
            },
            {
                "id": "orchestrated-task",
                "name": "Orchestrated Task",
                "description": (
                    "Break a complex task into sub-tasks and delegate to "
                    "specialized agents."
                ),
                "inputModes": ["text/plain"],
                "outputModes": ["text/plain"],
            },
        ],
    }


@router.get("/.well-known/agent.json", include_in_schema=False)
async def agent_card(request: Request) -> dict:
    """Public endpoint — no auth required for agent discovery."""
    host = request.headers.get("host", "localhost:8080")
    return build_agent_card(host=host)


# ── A2A task submission ────────────────────────────────────────────────────────


class A2ATaskRequest(BaseModel):
    """Minimal A2A-conformant task submission schema."""

    id: str | None = None  # caller-supplied idempotency key (ignored in Phase 8)
    message: dict = Field(...)  # A2A message object; we extract text/plain parts


def _extract_text_from_a2a_message(message: dict) -> str:
    """
    Extract a plain-text task string from an A2A message object.
    A2A messages look like: {"role": "user", "parts": [{"type": "text", "text": "..."}]}
    """
    parts = message.get("parts", [])
    text_parts = [p.get("text", "") for p in parts if p.get("type") == "text"]
    return " ".join(text_parts).strip()


@router.post("/a2a/tasks", status_code=status.HTTP_202_ACCEPTED)
async def a2a_submit_task(
    body: A2ATaskRequest,
    user: dict = Depends(require_user),
) -> dict:
    """A2A-conformant task submission. Delegates to the internal task queue."""
    task_text = _extract_text_from_a2a_message(body.message)
    if not task_text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A2A message contains no text/plain parts",
        )
    if len(task_text) > 4000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Task text exceeds 4000-character limit",
        )

    sanitized, injection_meta = sanitize_text(task_text, check_injection=True)
    if injection_meta.get("injection_detected"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Task rejected: invalid input",
        )

    row = await create_task(
        user_id=user["user_id"],
        input_text=sanitized,
        agent_type="orchestrator",
    )
    task_id = row["task_id"]
    stream_token = create_stream_token(task_id, user["user_id"])

    return {
        "id": task_id,
        "status": INTERNAL_TO_A2A_STATUS["queued"],
        "stream_url": f"/a2a/tasks/{task_id}/stream",
        "stream_token": stream_token,
    }


@router.get("/a2a/tasks/{task_id}")
async def a2a_get_task(
    task_id: str,
    user: dict = Depends(require_user),
) -> dict:
    """A2A-conformant task status endpoint."""
    row = await get_task(task_id, user_id=user["user_id"])
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Task not found"
        )

    a2a_status = INTERNAL_TO_A2A_STATUS.get(row["status"], row["status"])
    result_text = row.get("result") or ""

    return {
        "id": task_id,
        "status": a2a_status,
        "artifacts": ([{"type": "text", "text": result_text}] if result_text else []),
        "error": row.get("error"),
    }
