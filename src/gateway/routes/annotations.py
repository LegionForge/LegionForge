"""
src/gateway/routes/annotations.py
──────────────────────────────────
Task rating & feedback endpoints.

Users can submit a thumbs-up / thumbs-down rating and optional freeform
feedback for any of their completed tasks.  Submitting again overwrites
the previous annotation (UPSERT).  Admins can list all annotations.

User endpoints (mounted under /tasks):
    POST   /tasks/{task_id}/annotate   — create or update annotation
    GET    /tasks/{task_id}/annotation — fetch own annotation (or 404)

Admin endpoints (mounted under /admin):
    GET    /admin/annotations          — list all annotations

Phase 59 — Task Rating & Feedback.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from src.database import (
    get_task_annotation,
    list_annotations_admin,
    upsert_task_annotation,
)
from src.gateway.auth import require_admin, require_user

logger = logging.getLogger(__name__)

# Two routers: user-facing (prefix=/tasks) and admin-facing (prefix=/admin)
router = APIRouter()  # mounted at /tasks
admin_router = APIRouter()  # mounted at /admin


# ── Request schema ────────────────────────────────────────────────────────────


class AnnotateRequest(BaseModel):
    rating: int = Field(
        ...,
        description="Thumbs up=1, neutral/remove=0, thumbs down=-1",
        ge=-1,
        le=1,
    )
    feedback: str | None = Field(
        default=None,
        max_length=2000,
        description="Optional freeform feedback text (max 2000 chars)",
    )


# ── User endpoints ────────────────────────────────────────────────────────────


@router.post(
    "/{task_id}/annotate",
    status_code=status.HTTP_200_OK,
    summary="Rate a task (thumbs up/down) with optional feedback",
    tags=["annotations"],
)
async def annotate_task(
    task_id: str,
    body: AnnotateRequest,
    user=Depends(require_user),
):
    """
    Create or update a rating for a completed task.

    - rating: 1 = thumbs up, -1 = thumbs down, 0 = remove rating
    - feedback: optional text (max 2000 chars)

    Submitting again overwrites the previous annotation.  Returns 404 if the
    task does not exist or is not owned by the authenticated user.
    """
    annotation = await upsert_task_annotation(
        task_id=task_id,
        user_id=user["user_id"],
        rating=body.rating,
        feedback=body.feedback,
    )
    if annotation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found or not owned by this user",
        )
    return annotation


@router.get(
    "/{task_id}/annotation",
    summary="Get your annotation for a task",
    tags=["annotations"],
)
async def get_annotation(
    task_id: str,
    user=Depends(require_user),
):
    """
    Fetch the current user's annotation for a task.

    Returns 404 if no annotation exists yet.
    """
    annotation = await get_task_annotation(
        task_id=task_id,
        user_id=user["user_id"],
    )
    if annotation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No annotation found for this task",
        )
    return annotation


# ── Admin endpoint ────────────────────────────────────────────────────────────


@admin_router.get(
    "/annotations",
    summary="[Admin] List all task annotations",
    tags=["annotations"],
)
async def admin_list_annotations(
    rating: int | None = Query(
        default=None,
        ge=-1,
        le=1,
        description="Filter by rating: -1, 0, or 1",
    ),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _admin=Depends(require_admin),
):
    """
    [Admin] List all task annotations across all users.

    Optionally filter by rating (-1, 0, or 1).  Results are ordered
    newest-first.  Useful for exporting training / quality data.
    """
    return await list_annotations_admin(rating=rating, limit=limit, offset=offset)
