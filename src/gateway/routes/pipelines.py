"""
src/gateway/routes/pipelines.py
────────────────────────────────
Gateway endpoints for reusable task pipelines (Phase 27 + 30).

A pipeline is a named sequence of steps.  Each step has a task_text template
that can reference the initial run input (``{{input}}``) or the result of an
earlier step (``{{step_0.result}}``).

Endpoints:
    POST   /pipelines                       — define a new pipeline
    GET    /pipelines                       — list user's pipelines
    GET    /pipelines/{id}                  — get pipeline definition
    PUT    /pipelines/{id}                  — update pipeline
    DELETE /pipelines/{id}                  — delete pipeline
    POST   /pipelines/{id}/run              — start an async run
    GET    /pipelines/{id}/runs             — list runs for a pipeline
    GET    /pipelines/runs/{run_id}         — get run status + step results
    GET    /pipelines/runs/{run_id}/stream  — SSE progress stream (Phase 30)

All endpoints are user-scoped.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sse_starlette.sse import EventSourceResponse

from src.gateway.auth import require_user
from src.security.core import _log_safe

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Request models ─────────────────────────────────────────────────────────────

VALID_AGENT_TYPES = {"orchestrator", "researcher", "base_agent"}


class PipelineStep(BaseModel):
    name: str = Field(default="", max_length=200)
    task_text: str = Field(..., min_length=1, max_length=4000)
    agent_type: str = Field(default="orchestrator")

    @field_validator("agent_type")
    @classmethod
    def _valid_agent(cls, v: str) -> str:
        if v not in VALID_AGENT_TYPES:
            raise ValueError(f"agent_type must be one of {sorted(VALID_AGENT_TYPES)}")
        return v


class CreatePipelineRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="", max_length=1000)
    steps: list[PipelineStep] = Field(..., min_length=1, max_length=20)


class UpdatePipelineRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=1000)
    steps: Optional[list[PipelineStep]] = Field(
        default=None, min_length=1, max_length=20
    )


class RunPipelineRequest(BaseModel):
    input: str = Field(
        default="",
        max_length=4000,
        description=(
            "Initial input injected as {{input}} in step templates. "
            "May be empty if no step uses {{input}}."
        ),
    )


# ── Endpoints ──────────────────────────────────────────────────────────────────


@router.post("", status_code=201)
async def create_pipeline(
    req: CreatePipelineRequest,
    user: dict = Depends(require_user),
):
    """
    Define a new pipeline.

    Each step's ``task_text`` may contain template variables:
    - ``{{input}}`` — the initial input provided when the pipeline runs
    - ``{{step_0.result}}`` — the result of the first step, etc.

    Example::

        POST /pipelines
        {
            "name": "Research + Report",
            "steps": [
                {"name": "Research", "task_text": "Research: {{input}}", "agent_type": "researcher"},
                {"name": "Report", "task_text": "Write a report: {{step_0.result}}", "agent_type": "base_agent"}
            ]
        }
    """
    from src.database import create_pipeline as db_create_pipeline

    try:
        pipeline = await db_create_pipeline(
            user_id=user["user_id"],
            name=req.name,
            description=req.description,
            steps=[s.model_dump() for s in req.steps],
        )
    except Exception as exc:
        logger.error("create_pipeline failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    return pipeline


@router.get("")
async def list_pipelines(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: dict = Depends(require_user),
):
    """List the authenticated user's pipeline definitions."""
    from src.database import list_pipelines as db_list_pipelines

    try:
        pipelines = await db_list_pipelines(user["user_id"], limit=limit, offset=offset)
    except Exception as exc:
        logger.error("list_pipelines failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    return {"count": len(pipelines), "pipelines": pipelines}


@router.get("/runs/{run_id}")
async def get_pipeline_run(
    run_id: int,
    user: dict = Depends(require_user),
):
    """Get the status and step results of a specific pipeline run."""
    from src.database import get_pipeline_run as db_get_run

    try:
        run = await db_get_run(run_id, user["user_id"])
    except Exception as exc:
        logger.error("get_pipeline_run failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    if run is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    return run


@router.get("/runs/{run_id}/stream")
async def stream_pipeline_run(
    run_id: int,
    request: Request,
    user: dict = Depends(require_user),
) -> EventSourceResponse:
    """
    Subscribe to the SSE progress stream for a pipeline run.

    Emits events:
    - ``pipeline_start``         — run started (total_steps)
    - ``pipeline_step_start``    — step N beginning (name, task_id)
    - ``pipeline_step_complete`` — step N done (name, task_id, result)
    - ``pipeline_complete``      — all steps succeeded
    - ``pipeline_failed``        — run failed (error)
    - ``heartbeat``              — keepalive every 15 s

    If the run already completed before the client connects, the terminal
    event is returned immediately (race-safe via cached terminal events).

    Phase 30 — Pipeline SSE Progress Streaming.
    """
    from src.database import get_pipeline_run as db_get_run
    from src.gateway.events import subscribe_pipeline_events

    try:
        run = await db_get_run(run_id, user["user_id"])
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    if run is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")

    async def event_generator():
        # Fast-path: already finished
        run_status = run.get("status", "")
        if run_status == "complete":
            step_results = run.get("step_results", [])
            yield {
                "event": "pipeline_complete",
                "data": json.dumps(
                    {
                        "run_id": run_id,
                        "total_steps": len(step_results),
                        "status": "complete",
                    }
                ),
            }
            return
        if run_status == "failed":
            yield {
                "event": "pipeline_failed",
                "data": json.dumps(
                    {
                        "run_id": run_id,
                        "status": "failed",
                        "error": "Pipeline already failed before stream connected",
                    }
                ),
            }
            return

        # Still running — subscribe to live events
        async for event in subscribe_pipeline_events(run_id):
            if await request.is_disconnected():
                logger.debug("[pipelines/stream] Client disconnected run_id=%s", _log_safe(run_id))
                break
            yield {
                "event": event["event"],
                "data": json.dumps(event["data"]),
            }

    return EventSourceResponse(event_generator())


@router.get("/{pipeline_id}")
async def get_pipeline(
    pipeline_id: int,
    user: dict = Depends(require_user),
):
    """Get a pipeline definition by ID."""
    from src.database import get_pipeline as db_get_pipeline

    try:
        pipeline = await db_get_pipeline(pipeline_id, user["user_id"])
    except Exception as exc:
        logger.error("get_pipeline failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    if pipeline is None:
        raise HTTPException(status_code=404, detail=f"Pipeline {pipeline_id} not found")
    return pipeline


@router.put("/{pipeline_id}")
async def update_pipeline(
    pipeline_id: int,
    req: UpdatePipelineRequest,
    user: dict = Depends(require_user),
):
    """Partially update a pipeline definition."""
    from src.database import update_pipeline as db_update_pipeline

    steps = [s.model_dump() for s in req.steps] if req.steps is not None else None
    try:
        pipeline = await db_update_pipeline(
            pipeline_id,
            user["user_id"],
            name=req.name,
            description=req.description,
            steps=steps,
        )
    except Exception as exc:
        logger.error("update_pipeline failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    if pipeline is None:
        raise HTTPException(status_code=404, detail=f"Pipeline {pipeline_id} not found")
    return pipeline


@router.delete("/{pipeline_id}")
async def delete_pipeline(
    pipeline_id: int,
    user: dict = Depends(require_user),
):
    """Delete a pipeline definition and all its run history."""
    from src.database import delete_pipeline as db_delete_pipeline

    try:
        deleted = await db_delete_pipeline(pipeline_id, user["user_id"])
    except Exception as exc:
        logger.error("delete_pipeline failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    if not deleted:
        raise HTTPException(status_code=404, detail=f"Pipeline {pipeline_id} not found")
    return {"id": pipeline_id, "status": "deleted"}


@router.post("/{pipeline_id}/run", status_code=202)
async def run_pipeline(
    pipeline_id: int,
    req: RunPipelineRequest,
    user: dict = Depends(require_user),
):
    """
    Start an async run of a pipeline.

    Returns immediately with a ``run_id``.  Poll
    ``GET /pipelines/runs/{run_id}`` to check progress and retrieve
    step results.

    Example::

        POST /pipelines/3/run
        {"input": "LangGraph memory management"}
    """
    from src.database import get_pipeline as db_get_pipeline, create_pipeline_run
    from src.pipeline_runner import execute_pipeline

    try:
        pipeline = await db_get_pipeline(pipeline_id, user["user_id"])
    except Exception as exc:
        logger.error("run_pipeline: get_pipeline failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    if pipeline is None:
        raise HTTPException(status_code=404, detail=f"Pipeline {pipeline_id} not found")

    steps = pipeline.get("steps", [])
    if not steps:
        raise HTTPException(status_code=422, detail="Pipeline has no steps")

    try:
        run = await create_pipeline_run(
            pipeline_id=pipeline_id,
            user_id=user["user_id"],
            initial_input=req.input,
        )
    except Exception as exc:
        logger.error("run_pipeline: create_pipeline_run failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    run_id = run["id"]

    # Launch the pipeline executor as a background asyncio task
    asyncio.create_task(
        execute_pipeline(
            pipeline_id=pipeline_id,
            run_id=run_id,
            user_id=user["user_id"],
            steps=steps,
            initial_input=req.input,
        )
    )

    logger.info(
        "[pipelines] Started run %s for pipeline %s user=%s",
        _log_safe(run_id),
        _log_safe(pipeline_id),
        _log_safe(user["username"]),
    )

    return {
        "run_id": run_id,
        "pipeline_id": pipeline_id,
        "status": "running",
        "steps": len(steps),
        "poll_url": f"/pipelines/runs/{run_id}",
    }


@router.get("/{pipeline_id}/runs")
async def list_pipeline_runs(
    pipeline_id: int,
    limit: int = Query(default=20, ge=1, le=100),
    user: dict = Depends(require_user),
):
    """List recent runs for a pipeline."""
    from src.database import (
        get_pipeline as db_get_pipeline,
        list_pipeline_runs as db_list_runs,
    )

    try:
        pipeline = await db_get_pipeline(pipeline_id, user["user_id"])
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    if pipeline is None:
        raise HTTPException(status_code=404, detail=f"Pipeline {pipeline_id} not found")

    try:
        runs = await db_list_runs(pipeline_id, user["user_id"], limit=limit)
    except Exception as exc:
        logger.error("list_pipeline_runs failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    return {"pipeline_id": pipeline_id, "count": len(runs), "runs": runs}
