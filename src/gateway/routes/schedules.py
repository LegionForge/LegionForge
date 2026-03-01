"""
src/gateway/routes/schedules.py
────────────────────────────────
Gateway endpoints for cron-style scheduled tasks (Phase 23).

Endpoints:
    POST   /schedules            — create a new scheduled task
    GET    /schedules            — list user's scheduled tasks
    GET    /schedules/{id}       — get a single scheduled task
    PUT    /schedules/{id}       — update (name, task_text, cron_expr, enabled)
    DELETE /schedules/{id}       — delete a scheduled task

All endpoints are user-scoped: users can only see and manage their own schedules.

Cron expressions:
    5-field cron:  "*/15 * * * *", "0 9 * * 1-5"
    Shortcuts:     @hourly  @daily  @weekly  @monthly  @yearly
    Intervals:     @every 5m   @every 2h   @every 1d
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from src.gateway.auth import require_user

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Request models ─────────────────────────────────────────────────────────────


class CreateScheduleRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200, description="Human label.")
    task_text: str = Field(..., min_length=1, max_length=4000)
    cron_expr: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description=(
            "5-field cron, @shortcut, or @every interval. "
            "Examples: '*/15 * * * *', '@daily', '@every 2h'."
        ),
    )
    agent_type: str = Field(default="orchestrator")

    @field_validator("agent_type")
    @classmethod
    def _valid_agent(cls, v: str) -> str:
        from src.database import VALID_AGENT_TYPES

        if v not in VALID_AGENT_TYPES:
            raise ValueError(f"agent_type must be one of {VALID_AGENT_TYPES}")
        return v

    @field_validator("cron_expr")
    @classmethod
    def _valid_cron(cls, v: str) -> str:
        from src.scheduler import validate_cron_expr

        try:
            validate_cron_expr(v)
        except (ValueError, RuntimeError) as exc:
            raise ValueError(str(exc)) from exc
        return v


class UpdateScheduleRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    task_text: Optional[str] = Field(default=None, min_length=1, max_length=4000)
    cron_expr: Optional[str] = Field(default=None, min_length=1, max_length=200)
    agent_type: Optional[str] = Field(default=None)
    enabled: Optional[bool] = Field(default=None)

    @field_validator("agent_type")
    @classmethod
    def _valid_agent(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        from src.database import VALID_AGENT_TYPES

        if v not in VALID_AGENT_TYPES:
            raise ValueError(f"agent_type must be one of {VALID_AGENT_TYPES}")
        return v

    @field_validator("cron_expr")
    @classmethod
    def _valid_cron(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        from src.scheduler import validate_cron_expr

        try:
            validate_cron_expr(v)
        except (ValueError, RuntimeError) as exc:
            raise ValueError(str(exc)) from exc
        return v


# ── Endpoints ──────────────────────────────────────────────────────────────────


@router.post("", status_code=201)
async def create_schedule(
    req: CreateScheduleRequest,
    user: dict = Depends(require_user),
):
    """
    Create a new scheduled task.

    The ``cron_expr`` controls when the task fires.  At each fire time a normal
    gateway task is created and queued for the authenticated user.

    Example::

        POST /schedules
        {
            "name": "Daily digest",
            "task_text": "Summarise the latest news on AI safety",
            "cron_expr": "@daily",
            "agent_type": "researcher"
        }
    """
    from src.database import create_scheduled_task

    try:
        sched = await create_scheduled_task(
            user_id=user["user_id"],
            name=req.name,
            task_text=req.task_text,
            cron_expr=req.cron_expr,
            agent_type=req.agent_type,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error("create_schedule failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    return sched


@router.get("")
async def list_schedules(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    enabled_only: bool = Query(default=False),
    user: dict = Depends(require_user),
):
    """List the authenticated user's scheduled tasks (ordered by next_run_at)."""
    from src.database import list_scheduled_tasks

    try:
        schedules = await list_scheduled_tasks(
            user_id=user["user_id"],
            limit=limit,
            offset=offset,
            include_disabled=not enabled_only,
        )
    except Exception as exc:
        logger.error("list_schedules failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    return {"count": len(schedules), "schedules": schedules}


@router.get("/{sched_id}")
async def get_schedule(
    sched_id: int,
    user: dict = Depends(require_user),
):
    """Fetch a single scheduled task by ID."""
    from src.database import get_scheduled_task

    try:
        sched = await get_scheduled_task(sched_id, user["user_id"])
    except Exception as exc:
        logger.error("get_schedule failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    if sched is None:
        raise HTTPException(
            status_code=404,
            detail=f"Schedule {sched_id} not found",
        )
    return sched


@router.put("/{sched_id}")
async def update_schedule(
    sched_id: int,
    req: UpdateScheduleRequest,
    user: dict = Depends(require_user),
):
    """
    Partially update a scheduled task.

    Supply only the fields you want to change.  Changing ``cron_expr``
    automatically recomputes ``next_run_at``.  Set ``enabled: false`` to
    pause the schedule without deleting it.
    """
    from src.database import update_scheduled_task

    try:
        sched = await update_scheduled_task(
            sched_id,
            user["user_id"],
            name=req.name,
            task_text=req.task_text,
            cron_expr=req.cron_expr,
            agent_type=req.agent_type,
            enabled=req.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error("update_schedule failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    if sched is None:
        raise HTTPException(
            status_code=404,
            detail=f"Schedule {sched_id} not found",
        )
    return sched


@router.delete("/{sched_id}")
async def delete_schedule(
    sched_id: int,
    user: dict = Depends(require_user),
):
    """Delete a scheduled task permanently."""
    from src.database import delete_scheduled_task

    try:
        deleted = await delete_scheduled_task(sched_id, user["user_id"])
    except Exception as exc:
        logger.error("delete_schedule failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail=f"Schedule {sched_id} not found",
        )
    return {"id": sched_id, "status": "deleted"}
