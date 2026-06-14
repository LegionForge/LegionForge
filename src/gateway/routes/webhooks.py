"""
src/gateway/routes/webhooks.py
───────────────────────────────
Phase 48 — Webhook Registry.

Persistent webhook subscriptions per gateway user.  On task completion
(success or failure) the worker fires all matching active webhooks alongside
the per-task callback_url (Phase 26).

Endpoints:
    POST   /webhooks         — register a new webhook
    GET    /webhooks         — list own webhooks (secrets hidden)
    DELETE /webhooks/{id}    — remove a webhook
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, HttpUrl

from src.gateway.auth import require_user
from src.security.core import _log_safe

logger = logging.getLogger(__name__)

router = APIRouter()

VALID_WEBHOOK_EVENTS = {"task_complete", "task_failed", "all"}


class WebhookCreate(BaseModel):
    url: HttpUrl
    events: list[str] = ["task_complete", "task_failed"]
    secret: str | None = None


@router.post("", status_code=status.HTTP_201_CREATED)
async def register_webhook(
    body: WebhookCreate,
    user: dict = Depends(require_user),
) -> dict:
    """
    Register a new webhook URL for the authenticated user.

    ``events`` controls which task events trigger delivery:
    - ``task_complete`` — task finished successfully
    - ``task_failed``   — task finished with an error
    - ``all``           — all events

    An optional ``secret`` is stored (hashed) and used to sign payloads with
    HMAC-SHA256 in the ``X-LegionForge-Signature`` header.

    Phase 48 — Webhook Registry.
    """
    invalid = [e for e in body.events if e not in VALID_WEBHOOK_EVENTS]
    if invalid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid event type(s): {invalid}. "
            f"Must be one of {sorted(VALID_WEBHOOK_EVENTS)}",
        )

    from src.database import create_webhook

    wh = await create_webhook(
        user_id=user["user_id"],
        url=str(body.url),
        events=body.events,
        secret=body.secret,
    )
    logger.info(
        "[webhooks] Registered webhook_id=%s user=%s url=%s",
        _log_safe(wh["webhook_id"]),
        _log_safe(user["username"]),
        _log_safe(wh["url"]),
    )
    return wh


@router.get("")
async def list_my_webhooks(user: dict = Depends(require_user)) -> dict:
    """
    List all webhook subscriptions for the authenticated user.

    Secrets are never returned.  Phase 48 — Webhook Registry.
    """
    from src.database import list_webhooks

    webhooks = await list_webhooks(user["user_id"])
    return {"count": len(webhooks), "webhooks": webhooks}


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_webhook(
    webhook_id: str,
    user: dict = Depends(require_user),
) -> None:
    """
    Delete a webhook subscription.

    Returns 404 if not found or owned by a different user.
    Phase 48 — Webhook Registry.
    """
    from src.database import delete_webhook

    deleted = await delete_webhook(webhook_id, user["user_id"])
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook {webhook_id!r} not found",
        )
    logger.info(
        "[webhooks] Deleted webhook_id=%s user=%s",
        _log_safe(webhook_id),
        _log_safe(user["username"]),
    )
