"""
src/gateway/routes/auth_routes.py
──────────────────────────────────
Self-service auth endpoints for authenticated gateway users.

    GET  /auth/me                  — return current user profile
    POST /auth/rotate-key          — generate + return a new API key (shown once)
    GET  /auth/preferences         — get stored user preferences (Phase 52)
    PUT  /auth/preferences         — merge update user preferences (Phase 52)
    DELETE /auth/preferences       — clear all preferences (Phase 52)
    DELETE /auth/preferences/{key} — remove one preference key (Phase 52)

Phase 41 — API Key Rotation.
Phase 52 — User Preferences.
"""

from __future__ import annotations

import logging
import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from src.gateway.auth import require_user
from src.security.core import _log_safe

logger = logging.getLogger(__name__)

router = APIRouter()

_API_KEY_BYTES = 32  # 256-bit random key → 64 hex chars


@router.get("/me")
async def get_current_user(user: dict = Depends(require_user)) -> dict:
    """
    Return the authenticated user's profile.

    No sensitive fields (api_key_hash) are included.
    """
    from src.database import get_gateway_user_by_user_id

    row = await get_gateway_user_by_user_id(user["user_id"])
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    return {
        "user_id": row["user_id"],
        "username": row["username"],
        "is_admin": row.get("is_admin", False),
        "is_active": row.get("is_active", True),
        "daily_token_limit": row.get("daily_token_limit"),
        "created_at": (
            row["created_at"].isoformat()
            if hasattr(row.get("created_at"), "isoformat")
            else row.get("created_at")
        ),
    }


@router.post("/rotate-key", status_code=status.HTTP_200_OK)
async def rotate_api_key(user: dict = Depends(require_user)) -> dict:
    """
    Generate a new API key for the authenticated user.

    The new plaintext key is returned **once** and cannot be retrieved again.
    Existing sessions using the old key will stop working immediately.

    Uses bcrypt with cost factor 12 (same as registration).

    Phase 41 — API Key Rotation.
    """
    import bcrypt
    from src.database import rotate_api_key as db_rotate

    # Generate a cryptographically secure random key
    new_key = secrets.token_hex(_API_KEY_BYTES)  # 64 hex chars
    new_hash = bcrypt.hashpw(new_key.encode(), bcrypt.gensalt(rounds=12)).decode()

    updated = await db_rotate(user["user_id"], new_hash)
    if not updated:
        logger.error("[auth] rotate_api_key: user_id=%s not found", _log_safe(user["user_id"]))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to rotate API key — user not found",
        )

    logger.info("[auth] API key rotated for user=%s", _log_safe(user["username"]))
    return {
        "username": user["username"],
        "api_key": new_key,
        "message": (
            "API key rotated successfully. "
            "Store this key securely — it will not be shown again."
        ),
    }


# ── Phase 52: User Preferences ───────────────────────────────────────────────


class PreferencesUpdate(BaseModel):
    prefs: dict

    model_config = {"extra": "forbid"}


@router.get("/preferences")
async def get_preferences(user: dict = Depends(require_user)) -> dict:
    """
    Return the current user's stored preferences.

    Preferences are merged with task submissions as defaults.
    Returns {} if no preferences have been set.

    Phase 52 — User Preferences.
    """
    from src.database import get_user_preferences

    return await get_user_preferences(user["user_id"])


@router.put("/preferences")
async def update_preferences(
    body: PreferencesUpdate,
    user: dict = Depends(require_user),
) -> dict:
    """
    Merge-update stored preferences.

    Only send the keys you want to change — existing keys not included in the
    request body are preserved.  Allowed preference keys:

    - ``default_agent_type``       — ``orchestrator`` | ``researcher`` | ``base_agent``
    - ``default_max_steps``        — integer 1–100
    - ``default_tracing_enabled``  — boolean
    - ``default_priority``         — integer 1–10
    - ``ui_theme``                 — ``dark`` | ``light`` | ``system``
    - ``notification_on_complete`` — boolean
    - ``notification_on_fail``     — boolean

    Phase 52 — User Preferences.
    """
    from src.database import update_user_preferences

    try:
        return await update_user_preferences(user["user_id"], body.prefs)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@router.delete("/preferences", status_code=status.HTTP_200_OK)
async def clear_preferences(user: dict = Depends(require_user)) -> dict:
    """
    Clear all stored preferences for the current user.

    Phase 52 — User Preferences.
    """
    from src.database import delete_user_preferences

    return await delete_user_preferences(user["user_id"])


@router.delete("/preferences/{key}", status_code=status.HTTP_200_OK)
async def remove_preference_key(
    key: str,
    user: dict = Depends(require_user),
) -> dict:
    """
    Remove a single preference key.

    Phase 52 — User Preferences.
    """
    from src.database import delete_user_preferences

    try:
        return await delete_user_preferences(user["user_id"], keys=[key])
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
