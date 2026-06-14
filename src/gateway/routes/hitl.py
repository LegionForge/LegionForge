"""
src/gateway/routes/hitl.py
──────────────────────────
Phase 2 HITL (Human-in-the-Loop) approval endpoints.

All endpoints require admin authentication (require_admin dependency).

Endpoints:
    GET  /hitl/pending             — list all pending HITL approval requests
    GET  /hitl/{request_id}        — get a specific HITL request
    POST /hitl/{request_id}/approve — approve + resume the paused graph run
    POST /hitl/{request_id}/reject  — reject + terminate the paused run
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.gateway.auth import require_admin
from src.security.core import _log_safe

logger = logging.getLogger(__name__)

router = APIRouter()


class ResolveRequest(BaseModel):
    operator_note: str = Field(default="", max_length=1000)


# ── Endpoints ──────────────────────────────────────────────────────────────────


@router.get("/pending")
async def list_pending_hitl(admin: dict = Depends(require_admin)) -> dict:
    """
    List all HITL approval requests with status='pending'.

    Returns newest-first so operators see the most recent requests at the top.
    Admin authentication required.
    """
    from src.database import list_pending_hitl_requests

    try:
        requests = await list_pending_hitl_requests()
    except Exception as exc:
        logger.error("[hitl] list_pending_hitl_requests failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    return {"count": len(requests), "requests": requests}


@router.get("/{request_id}")
async def get_hitl_request(
    request_id: str, admin: dict = Depends(require_admin)
) -> dict:
    """
    Get a specific HITL approval request by its UUID.

    Returns the full request including status, action, categories,
    and input_excerpt so the operator can make an informed decision.
    Admin authentication required.
    """
    from src.database import get_hitl_request as db_get_hitl_request

    try:
        req = await db_get_hitl_request(request_id)
    except Exception as exc:
        logger.error("[hitl] get_hitl_request failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    if req is None:
        raise HTTPException(
            status_code=404, detail=f"HITL request {request_id!r} not found"
        )
    return req


@router.post("/{request_id}/approve")
async def approve_hitl_request(
    request_id: str,
    body: ResolveRequest = ResolveRequest(),
    admin: dict = Depends(require_admin),
) -> dict:
    """
    Approve a pending HITL request and resume the paused graph run.

    The graph was paused at the hitl_gate node via LangGraph interrupt_before.
    Approval resumes it by calling graph.ainvoke(None, config) with the
    original thread_id so LangGraph rehydrates state from the checkpoint
    and continues execution past the hitl_gate.

    Admin authentication required.
    """
    from src.database import get_hitl_request as db_get, resolve_hitl_request
    from src.safeguards import resume_run_config

    try:
        req = await db_get(request_id)
    except Exception as exc:
        logger.error("[hitl] get_hitl_request failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    if req is None:
        raise HTTPException(
            status_code=404, detail=f"HITL request {request_id!r} not found"
        )
    if req["status"] != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"HITL request {request_id!r} is already {req['status']!r}",
        )

    # Mark as approved first — if graph resumption fails, the row is still
    # resolved so the operator doesn't retry into an already-running graph.
    try:
        updated = await resolve_hitl_request(
            request_id=request_id,
            decision="approved",
            operator_note=body.operator_note,
        )
    except Exception as exc:
        logger.error("[hitl] resolve_hitl_request failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    if not updated:
        raise HTTPException(
            status_code=409,
            detail=f"HITL request {request_id!r} was already resolved (concurrent update)",
        )

    # Resume the paused graph run.
    # The graph was compiled with interrupt_before=["hitl_gate"].
    # Calling ainvoke(None, config) with the original thread_id causes LangGraph
    # to reload state from the checkpoint and continue past the interrupt point.
    thread_id = req["thread_id"]
    resume_result: dict = {"resumed": False, "thread_id": thread_id}
    try:
        from src.base_graph import build_base_graph
        from src.database import get_checkpointer

        _input, config = resume_run_config(thread_id=thread_id)
        async with get_checkpointer() as checkpointer:
            graph = build_base_graph().compile(
                checkpointer=checkpointer,
                # Do NOT pass interrupt_before here — we want the run to
                # continue past hitl_gate without pausing again.
            )
            # Reset hitl_pending in state via the update dict so routing
            # proceeds normally on resume.
            final_state = await graph.ainvoke(
                {"hitl_pending": False},
                config=config,
            )
        resume_result["resumed"] = True
        resume_result["result"] = final_state.get("result", "")
        logger.info(
            "[hitl] Graph resumed after approval — thread_id=%s request_id=%s",
            _log_safe(thread_id),
            _log_safe(request_id),
        )
    except Exception as exc:
        logger.error(
            "[hitl] Graph resumption failed for thread_id=%s: %s", thread_id, exc
        )
        resume_result["resume_error"] = str(exc)

    return {
        "status": "approved",
        "request_id": request_id,
        "thread_id": thread_id,
        **resume_result,
    }


@router.post("/{request_id}/reject")
async def reject_hitl_request(
    request_id: str,
    body: ResolveRequest = ResolveRequest(),
    admin: dict = Depends(require_admin),
) -> dict:
    """
    Reject a pending HITL request and terminate the paused graph run cleanly.

    The graph checkpoint is left in place (LangGraph does not delete it), but
    we mark the hitl_pending row as 'rejected' and do not resume the run.
    The paused graph run will time out naturally or be garbage-collected by
    the checkpoint pruning job.

    Admin authentication required.
    """
    from src.database import get_hitl_request as db_get, resolve_hitl_request

    try:
        req = await db_get(request_id)
    except Exception as exc:
        logger.error("[hitl] get_hitl_request failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    if req is None:
        raise HTTPException(
            status_code=404, detail=f"HITL request {request_id!r} not found"
        )
    if req["status"] != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"HITL request {request_id!r} is already {req['status']!r}",
        )

    try:
        updated = await resolve_hitl_request(
            request_id=request_id,
            decision="rejected",
            operator_note=body.operator_note,
        )
    except Exception as exc:
        logger.error("[hitl] resolve_hitl_request failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    if not updated:
        raise HTTPException(
            status_code=409,
            detail=f"HITL request {request_id!r} was already resolved (concurrent update)",
        )

    logger.info(
        "[hitl] Run rejected by operator — request_id=%s thread_id=%s action=%s",
        _log_safe(request_id),
        _log_safe(req["thread_id"]),
        _log_safe(req["action"]),
    )
    return {
        "status": "rejected",
        "request_id": request_id,
        "thread_id": req["thread_id"],
        "message": (
            f"Run paused for action '{req['action']}' has been rejected. "
            "The graph will not resume."
        ),
    }
