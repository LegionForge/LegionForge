"""
src/gateway/routes/auth_routes.py
──────────────────────────────────
Self-service auth endpoints for authenticated gateway users.

    GET  /auth/me           — return current user profile
    POST /auth/rotate-key   — generate + return a new API key (shown once)

Phase 41 — API Key Rotation.
"""

from __future__ import annotations

import logging
import secrets

from fastapi import APIRouter, Depends, HTTPException, status

from src.gateway.auth import require_user

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
        logger.error("[auth] rotate_api_key: user_id=%s not found", user["user_id"])
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to rotate API key — user not found",
        )

    logger.info("[auth] API key rotated for user=%s", user["username"])
    return {
        "username": user["username"],
        "api_key": new_key,
        "message": (
            "API key rotated successfully. "
            "Store this key securely — it will not be shown again."
        ),
    }
