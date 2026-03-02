"""
src/gateway/routes/templates.py
────────────────────────────────
Phase 50 — Task Templates.

Save reusable task configurations (agent_type, input_template, default_tags,
default_priority).  Instantiate a template with variable substitution via
POST /templates/{id}/run.

Endpoints:
    POST   /templates            — create a template
    GET    /templates            — list own templates
    GET    /templates/{id}       — get a template
    DELETE /templates/{id}       — delete a template
    POST   /templates/{id}/run   — submit a task from a template
"""

from __future__ import annotations

import logging
import re

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.gateway.auth import require_user

logger = logging.getLogger(__name__)

router = APIRouter()

# Variable placeholder pattern: {var_name}
_VAR_PATTERN = re.compile(r"\{(\w+)\}")


class TemplateCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    input_template: str = Field(..., min_length=1)
    agent_type: str = "base_agent"
    description: str | None = None
    default_tags: list[str] = []
    default_priority: int = Field(default=5, ge=1, le=10)


class TemplateRun(BaseModel):
    variables: dict[str, str] = {}
    tags: list[str] | None = None
    priority: int | None = Field(default=None, ge=1, le=10)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_template(
    body: TemplateCreate,
    user: dict = Depends(require_user),
) -> dict:
    """
    Create a reusable task template.

    ``input_template`` may contain ``{variable}`` placeholders that are filled
    in at run time via POST /templates/{id}/run.

    Phase 50 — Task Templates.
    """
    from src.database import create_task_template, VALID_AGENT_TYPES

    if body.agent_type not in VALID_AGENT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"agent_type must be one of {sorted(VALID_AGENT_TYPES)}",
        )
    try:
        tmpl = await create_task_template(
            user_id=user["user_id"],
            name=body.name,
            input_template=body.input_template,
            agent_type=body.agent_type,
            description=body.description,
            default_tags=body.default_tags,
            default_priority=body.default_priority,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    logger.info(
        "[templates] Created template_id=%s name=%s user=%s",
        tmpl["template_id"],
        tmpl["name"],
        user["username"],
    )
    return tmpl


@router.get("")
async def list_templates(user: dict = Depends(require_user)) -> dict:
    """List all templates owned by the authenticated user."""
    from src.database import list_task_templates

    templates = await list_task_templates(user["user_id"])
    return {"count": len(templates), "templates": templates}


@router.get("/{template_id}")
async def get_template(
    template_id: str,
    user: dict = Depends(require_user),
) -> dict:
    """Get a single task template."""
    from src.database import get_task_template

    tmpl = await get_task_template(template_id, user["user_id"])
    if tmpl is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Template {template_id!r} not found",
        )
    return tmpl


@router.delete("/{template_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_template(
    template_id: str,
    user: dict = Depends(require_user),
) -> None:
    """Delete a task template."""
    from src.database import delete_task_template

    deleted = await delete_task_template(template_id, user["user_id"])
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Template {template_id!r} not found",
        )


@router.post("/{template_id}/run", status_code=status.HTTP_202_ACCEPTED)
async def run_template(
    template_id: str,
    body: TemplateRun,
    user: dict = Depends(require_user),
) -> dict:
    """
    Submit a task by instantiating a template.

    Fills ``{variable}`` placeholders in ``input_template`` with values from
    ``variables``.  Missing variables are left as-is (not an error).
    Tags and priority default to the template's stored values if not provided.

    Phase 50 — Task Templates.
    """
    from src.database import get_task_template, create_task, VALID_AGENT_TYPES
    from src.gateway.auth import create_stream_token
    from src.gateway.metrics import inc_counter
    from src.rate_limiter import per_user_budget_check
    from src.security.core import sanitize_text

    tmpl = await get_task_template(template_id, user["user_id"])
    if tmpl is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Template {template_id!r} not found",
        )

    # Substitute variables in template
    input_text = tmpl["input_template"]
    for var_name, var_value in body.variables.items():
        input_text = input_text.replace(f"{{{var_name}}}", var_value)

    input_text = sanitize_text(input_text)
    if not input_text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Rendered template input is empty",
        )

    await per_user_budget_check(user, tmpl["agent_type"], input_text)

    tags = body.tags if body.tags is not None else tmpl.get("default_tags", [])
    priority = (
        body.priority if body.priority is not None else tmpl.get("default_priority", 5)
    )

    task = await create_task(
        user_id=user["user_id"],
        input_text=input_text,
        agent_type=tmpl["agent_type"],
        tags=tags,
        priority=priority,
    )
    inc_counter("legionforge_tasks_submitted_total")
    stream_token = await create_stream_token(task["task_id"], user["user_id"])
    logger.info(
        "[templates] Submitted task_id=%s from template=%s user=%s",
        task["task_id"],
        template_id,
        user["username"],
    )
    return {**task, "stream_token": stream_token, "template_id": template_id}
