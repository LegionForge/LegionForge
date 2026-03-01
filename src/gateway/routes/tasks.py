"""
src/gateway/routes/tasks.py
────────────────────────────
Core task API:

    POST   /tasks               — submit a task
    POST   /tasks/batch         — submit up to 20 tasks at once (Phase 28)
    GET    /tasks               — list tasks (authenticated user's own)
    GET    /tasks/{task_id}     — get a single task result
    DELETE /tasks/{task_id}     — cancel a queued task
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from src.database import (
    create_task,
    get_task,
    list_tasks,
    lookup_cached_task,
    mark_task_cancelled,
    VALID_AGENT_TYPES,
    VALID_TASK_STATUSES,
)
from src.gateway.auth import create_stream_token, require_user
from src.gateway.metrics import inc_counter
from src.rate_limiter import per_user_budget_check
from src.security.core import sanitize_text

# Maps agent_type → LLM provider (used for per-user budget tracking).
# All current agents run on Ollama; update this if cloud agents are added.
_AGENT_TYPE_TO_PROVIDER: dict[str, str] = {
    "orchestrator": "ollama",
    "researcher": "ollama",
    "base_agent": "ollama",
}

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Request / response models ──────────────────────────────────────────────────


class TaskConfig(BaseModel):
    tracing_enabled: bool = True
    max_steps: int | None = None


class TaskRequest(BaseModel):
    task: str = Field(..., min_length=1, max_length=4000)
    agent_type: str = Field(default="orchestrator")
    config: TaskConfig = Field(default_factory=TaskConfig)
    priority: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Task priority: 1=low, 5=normal (default), 10=high. "
        "Higher-priority tasks are picked up by the worker first.",
    )
    use_cache: bool = Field(
        default=True,
        description=(
            "Return a cached result if an identical task (same agent_type + text) "
            "completed within cache_ttl seconds.  Set to false to force a fresh run."
        ),
    )
    cache_ttl: int = Field(
        default=3600,
        ge=0,
        le=86400,
        description="Cache validity in seconds (0 disables, max 86400 = 24h).  "
        "Ignored when use_cache=false.",
    )
    callback_url: str | None = Field(
        default=None,
        max_length=2048,
        description=(
            "Optional HTTP(S) URL to POST the task result to when the task "
            "completes (success or failure).  Phase 26 completion webhooks."
        ),
    )

    @field_validator("task")
    @classmethod
    def task_must_not_be_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("task must not be blank")
        return v

    @field_validator("agent_type")
    @classmethod
    def agent_type_must_be_valid(cls, v: str) -> str:
        if v not in VALID_AGENT_TYPES:
            raise ValueError(f"agent_type must be one of {sorted(VALID_AGENT_TYPES)}")
        return v

    @field_validator("callback_url")
    @classmethod
    def callback_url_must_be_http(cls, v: str | None) -> str | None:
        if v is None:
            return v
        from urllib.parse import urlparse

        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("callback_url must be an http:// or https:// URL")
        return v


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def submit_task(
    body: TaskRequest,
    user: dict = Depends(require_user),
) -> dict:
    """
    Submit a task to the agent queue.

    The task text is sanitized through sanitize_text() before storage.
    Injection detected → 400 (not 401 — don't leak that detection happened).
    """
    # Sanitize input at the gateway boundary
    sanitized, injection_meta = sanitize_text(body.task, check_injection=True)

    if injection_meta.get("injection_detected"):
        logger.warning(
            "[gateway] Injection detected in task submission "
            f"user={user['username']} pattern_count={injection_meta.get('pattern_count', 0)}"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Task rejected: invalid input",
        )

    # Phase 29: always compute content_hash (stored on the task for future lookups)
    from src.task_cache import compute_task_hash

    content_hash = compute_task_hash(body.agent_type, sanitized)

    # Cache lookup: skip queue if an identical completed task exists within TTL
    if body.use_cache and body.cache_ttl > 0:
        hit = await lookup_cached_task(content_hash, max_age_seconds=body.cache_ttl)
        if hit:
            logger.info(
                "[gateway] Cache hit task_id=%s user=%s",
                hit["task_id"],
                user["username"],
            )
            return {
                "task_id": hit["task_id"],
                "status": "complete",
                "result": hit["result"],
                "cached": True,
                "cached_at": hit["completed_at"],
            }

    # Estimate token cost for budget check (conservative: word count × 1.3 + 500
    # for system prompt / response overhead).  Actual usage replaces this on
    # task completion via api_usage with user_id set.
    estimated_tokens = int(len(sanitized.split()) * 1.3 + 500)
    provider = _AGENT_TYPE_TO_PROVIDER.get(body.agent_type, "ollama")
    daily_limit = user.get("daily_token_limit", 100000)

    try:
        await per_user_budget_check(
            user_id=user["user_id"],
            provider=provider,
            estimated_tokens=estimated_tokens,
            daily_limit=daily_limit,
        )
    except RuntimeError as budget_err:
        logger.warning(
            f"[gateway] Per-user budget exceeded: user={user['username']} "
            f"estimated={estimated_tokens} limit={daily_limit}"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Daily token budget exceeded. Try again tomorrow.",
        ) from budget_err

    row = await create_task(
        user_id=user["user_id"],
        input_text=sanitized,
        agent_type=body.agent_type,
        config=body.config.model_dump(),
        estimated_tokens=estimated_tokens,
        callback_url=body.callback_url,
        priority=body.priority,
        content_hash=content_hash,
    )

    task_id = row["task_id"]
    stream_token = await create_stream_token(task_id, user["user_id"])

    inc_counter("legionforge_tasks_submitted_total")

    logger.info(
        f"[gateway] Task queued task_id={task_id} "
        f"agent={body.agent_type} user={user['username']}"
    )

    return {
        "task_id": task_id,
        "status": "queued",
        "priority": row.get("priority", 5),
        "created_at": row["created_at"],
        "stream_url": f"/tasks/{task_id}/stream",
        "stream_token": stream_token,
    }


# ── Batch submission (Phase 28) ────────────────────────────────────────────────


class BatchTaskRequest(BaseModel):
    tasks: list[TaskRequest] = Field(
        ...,
        min_length=1,
        max_length=20,
        description="List of 1–20 task requests to submit atomically.",
    )


@router.post("/batch", status_code=status.HTTP_202_ACCEPTED)
async def submit_tasks_batch(
    body: BatchTaskRequest,
    user: dict = Depends(require_user),
) -> dict:
    """
    Submit up to 20 tasks at once.

    Each task is validated and sanitized individually.  The entire batch fails
    fast if any task fails validation or budget checks.  Returns a list of
    ``task_id`` + ``stream_token`` pairs in the same order as the input.

    Phase 28 — batch submission.
    """
    results = []
    daily_limit = user.get("daily_token_limit", 100000)

    for idx, req in enumerate(body.tasks):
        # Sanitize + injection check
        sanitized, injection_meta = sanitize_text(req.task, check_injection=True)
        if injection_meta.get("injection_detected"):
            logger.warning(
                "[gateway/batch] Injection detected task %d user=%s",
                idx,
                user["username"],
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Task {idx}: rejected — invalid input",
            )

        estimated_tokens = int(len(sanitized.split()) * 1.3 + 500)
        provider = _AGENT_TYPE_TO_PROVIDER.get(req.agent_type, "ollama")

        try:
            await per_user_budget_check(
                user_id=user["user_id"],
                provider=provider,
                estimated_tokens=estimated_tokens,
                daily_limit=daily_limit,
            )
        except RuntimeError as budget_err:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Task {idx}: daily token budget exceeded",
            ) from budget_err

        row = await create_task(
            user_id=user["user_id"],
            input_text=sanitized,
            agent_type=req.agent_type,
            config=req.config.model_dump(),
            estimated_tokens=estimated_tokens,
            callback_url=req.callback_url,
            priority=req.priority,
        )
        task_id = row["task_id"]
        stream_token = await create_stream_token(task_id, user["user_id"])
        inc_counter("legionforge_tasks_submitted_total")

        results.append(
            {
                "task_id": task_id,
                "status": "queued",
                "priority": row.get("priority", 5),
                "created_at": row["created_at"],
                "stream_url": f"/tasks/{task_id}/stream",
                "stream_token": stream_token,
            }
        )

    logger.info(
        "[gateway/batch] Queued %d tasks user=%s", len(results), user["username"]
    )
    return {"count": len(results), "tasks": results}


@router.get("")
async def list_user_tasks(
    user: dict = Depends(require_user),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status_filter: str | None = Query(default=None, alias="status"),
) -> dict:
    """Return paginated task history for the authenticated user."""
    if status_filter and status_filter not in VALID_TASK_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"status must be one of {sorted(VALID_TASK_STATUSES)}",
        )

    return await list_tasks(
        user_id=user["user_id"],
        limit=limit,
        offset=offset,
        status=status_filter,
    )


@router.get("/{task_id}")
async def get_task_result(
    task_id: str,
    user: dict = Depends(require_user),
) -> dict:
    """
    Return a task's full result.
    Returns 404 for unknown task_id OR task belonging to a different user
    (do not confirm existence to unauthorized callers).
    """
    row = await get_task(task_id, user_id=user["user_id"])
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Task not found"
        )
    return row


@router.delete("/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_task(
    task_id: str,
    user: dict = Depends(require_user),
) -> None:
    """
    Cancel a queued task.  Only queued tasks can be cancelled — running tasks
    cannot be interrupted in Phase 8.
    """
    cancelled = await mark_task_cancelled(task_id, user["user_id"])
    if not cancelled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found, not queued, or not owned by this user",
        )
