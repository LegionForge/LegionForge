"""
src/gateway/routes/admin.py
────────────────────────────
Admin-only gateway endpoints for user and system management (Phase 24).

All endpoints require ``is_admin = true`` on the authenticated user (enforced
via the ``require_admin`` FastAPI dependency).  Non-admin callers receive HTTP
403.

Endpoints:
    GET    /admin/users                  — list all gateway users
    POST   /admin/users                  — create a user + generate API key
    GET    /admin/users/{username}       — get user + today's usage
    DELETE /admin/users/{username}       — deactivate a user
    PUT    /admin/users/{username}/quota — set daily token limit
    PUT    /admin/users/{username}/admin — promote or demote admin status
    GET    /admin/stats                  — system-wide usage snapshot
    GET    /admin/schedules              — list all scheduled tasks (all users)
"""

from __future__ import annotations

import logging
import secrets
import string

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from src.gateway.auth import require_admin

logger = logging.getLogger(__name__)

router = APIRouter()

# API key generation: 40 URL-safe characters → ~238 bits of entropy.
_KEY_ALPHABET = string.ascii_letters + string.digits
_KEY_LENGTH = 40


def _generate_api_key() -> str:
    """Generate a cryptographically random API key string."""
    return "".join(secrets.choice(_KEY_ALPHABET) for _ in range(_KEY_LENGTH))


# ── Request models ─────────────────────────────────────────────────────────────


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    daily_token_limit: int = Field(default=100_000, ge=0, le=10_000_000)
    is_admin: bool = Field(default=False)


class SetQuotaRequest(BaseModel):
    daily_token_limit: int = Field(..., ge=0, le=10_000_000)


class SetAdminRequest(BaseModel):
    is_admin: bool = Field(...)


# ── Endpoints ──────────────────────────────────────────────────────────────────


@router.get("/users")
async def list_users(admin: dict = Depends(require_admin)):
    """
    List all gateway users (active and inactive).

    Returns user_id, username, is_active, is_admin, daily_token_limit,
    created_at.  Does NOT return API key hashes.
    """
    from src.database import list_gateway_users

    try:
        users = await list_gateway_users()
    except Exception as exc:
        logger.error("admin list_users failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    return {"count": len(users), "users": users}


@router.post("/users", status_code=201)
async def create_user(
    req: CreateUserRequest,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """
    Create a new gateway user and return their generated API key.

    The raw API key is returned **once** in this response and is never stored
    (only a bcrypt hash is persisted).  The caller must save it immediately.

    Example response::

        {
            "user_id": "...",
            "username": "alice",
            "api_key": "abc123...",   ← save this!
            "daily_token_limit": 100000,
            "is_admin": false
        }
    """
    from src.database import create_gateway_user, set_gateway_user_quota
    from src.gateway.auth import hash_api_key

    raw_key = _generate_api_key()
    hashed = hash_api_key(raw_key)

    try:
        user = await create_gateway_user(
            username=req.username,
            api_key_hash=hashed,
            is_admin=req.is_admin,
        )
        if req.daily_token_limit != 100_000:
            await set_gateway_user_quota(req.username, req.daily_token_limit)
    except Exception as exc:
        logger.error("admin create_user failed: %s", exc)
        if "unique" in str(exc).lower() or "duplicate" in str(exc).lower():
            raise HTTPException(
                status_code=409, detail=f"Username '{req.username}' already exists"
            )
        raise HTTPException(status_code=500, detail=str(exc))

    # Audit trail — record admin mutation to tamper-evident log
    try:
        from src.database import append_audit_log

        await append_audit_log(
            event_type="ADMIN_ACTION",
            agent_id=f"admin:{admin['username']}",
            payload={
                "action": "create_user",
                "target": req.username,
                "performed_by": admin["username"],
                "is_admin": req.is_admin,
                "daily_token_limit": req.daily_token_limit,
                "ip": request.client.host if request.client else "unknown",
            },
        )
    except Exception as audit_err:
        logger.warning("admin audit_log write failed (create_user): %s", audit_err)

    return {
        "user_id": user["user_id"],
        "username": user["username"],
        "api_key": raw_key,  # only time this is visible
        "daily_token_limit": req.daily_token_limit,
        "is_admin": user.get("is_admin", False),
        "created_at": (
            user["created_at"].isoformat()
            if hasattr(user.get("created_at"), "isoformat")
            else str(user.get("created_at", ""))
        ),
    }


@router.get("/users/{username}")
async def get_user(username: str, admin: dict = Depends(require_admin)):
    """
    Fetch a single user by username plus their today's token usage.
    """
    from src.database import get_gateway_user_by_username, get_user_usage_summary_today

    try:
        user = await get_gateway_user_by_username(username)
    except Exception as exc:
        logger.error("admin get_user failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    if user is None:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")

    try:
        usage = await get_user_usage_summary_today(user["user_id"])
    except Exception:
        usage = {}

    return {
        "user_id": user["user_id"],
        "username": user["username"],
        "is_active": user.get("is_active", True),
        "is_admin": user.get("is_admin", False),
        "daily_token_limit": user.get("daily_token_limit", 100_000),
        "created_at": (
            user.get("created_at", "").isoformat()
            if hasattr(user.get("created_at"), "isoformat")
            else str(user.get("created_at", ""))
        ),
        "usage_today": usage.get("today", {}),
    }


@router.delete("/users/{username}")
async def deactivate_user(
    username: str,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """
    Deactivate a gateway user.  They can no longer authenticate.

    Does NOT delete the user or their data — use this to revoke access.
    A deactivated user's tasks and schedules remain in the database.
    """
    from src.database import deactivate_gateway_user

    # Prevent self-deactivation
    if username == admin["username"]:
        raise HTTPException(
            status_code=400,
            detail="Cannot deactivate your own account",
        )

    try:
        deactivated = await deactivate_gateway_user(username)
    except Exception as exc:
        logger.error("admin deactivate_user failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    if not deactivated:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")

    # Audit trail — record admin mutation to tamper-evident log
    try:
        from src.database import append_audit_log

        await append_audit_log(
            event_type="ADMIN_ACTION",
            agent_id=f"admin:{admin['username']}",
            payload={
                "action": "deactivate_user",
                "target": username,
                "performed_by": admin["username"],
                "ip": request.client.host if request.client else "unknown",
            },
        )
    except Exception as audit_err:
        logger.warning("admin audit_log write failed (deactivate_user): %s", audit_err)

    return {"username": username, "status": "deactivated"}


@router.put("/users/{username}/quota")
async def set_user_quota(
    username: str,
    req: SetQuotaRequest,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """Set the per-user daily token budget."""
    from src.database import set_gateway_user_quota

    try:
        updated = await set_gateway_user_quota(username, req.daily_token_limit)
    except Exception as exc:
        logger.error("admin set_user_quota failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    if not updated:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")

    # Audit trail — record admin mutation to tamper-evident log
    try:
        from src.database import append_audit_log

        await append_audit_log(
            event_type="ADMIN_ACTION",
            agent_id=f"admin:{admin['username']}",
            payload={
                "action": "set_quota",
                "target": username,
                "performed_by": admin["username"],
                "daily_token_limit": req.daily_token_limit,
                "ip": request.client.host if request.client else "unknown",
            },
        )
    except Exception as audit_err:
        logger.warning("admin audit_log write failed (set_quota): %s", audit_err)

    return {"username": username, "daily_token_limit": req.daily_token_limit}


@router.put("/users/{username}/admin")
async def set_user_admin(
    username: str,
    req: SetAdminRequest,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """Grant or revoke admin privilege for a user."""
    from src.database import promote_gateway_user_to_admin

    # Prevent self-demotion
    if username == admin["username"] and not req.is_admin:
        raise HTTPException(
            status_code=400,
            detail="Cannot revoke your own admin privilege",
        )

    try:
        updated = await promote_gateway_user_to_admin(username, req.is_admin)
    except Exception as exc:
        logger.error("admin set_user_admin failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    if not updated:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")

    # Audit trail — record admin mutation to tamper-evident log
    try:
        from src.database import append_audit_log

        await append_audit_log(
            event_type="ADMIN_ACTION",
            agent_id=f"admin:{admin['username']}",
            payload={
                "action": "promoted" if req.is_admin else "demoted",
                "target": username,
                "performed_by": admin["username"],
                "is_admin": req.is_admin,
                "ip": request.client.host if request.client else "unknown",
            },
        )
    except Exception as audit_err:
        logger.warning("admin audit_log write failed (set_admin): %s", audit_err)

    return {
        "username": username,
        "is_admin": req.is_admin,
        "status": "promoted" if req.is_admin else "demoted",
    }


@router.get("/stats")
async def system_stats(admin: dict = Depends(require_admin)):
    """
    Return a snapshot of system-wide usage for today.

    Aggregates tokens across all users and providers.
    """
    from src.database import get_worker_pool
    from psycopg.rows import dict_row

    pool = get_worker_pool()
    try:
        async with pool.connection() as conn:
            conn.row_factory = dict_row
            cur = await conn.execute(
                """
                SELECT
                    COUNT(DISTINCT user_id) AS active_users,
                    SUM(tokens) AS total_tokens
                FROM api_usage
                WHERE DATE(created_at) = CURRENT_DATE
                """
            )
            usage_row = await cur.fetchone()

            cur2 = await conn.execute(
                "SELECT COUNT(*) AS total FROM tasks "
                "WHERE DATE(created_at) = CURRENT_DATE"
            )
            task_row = await cur2.fetchone()

            cur3 = await conn.execute(
                "SELECT COUNT(*) AS active FROM gateway_users WHERE is_active = true"
            )
            user_row = await cur3.fetchone()

            cur4 = await conn.execute(
                "SELECT COUNT(*) AS enabled FROM scheduled_tasks WHERE enabled = true"
            )
            sched_row = await cur4.fetchone()

    except Exception as exc:
        logger.error("admin system_stats failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    return {
        "today": {
            "active_users_with_usage": int(usage_row["active_users"] or 0),
            "total_tokens": int(usage_row["total_tokens"] or 0),
            "total_tasks": int(task_row["total"] or 0),
        },
        "system": {
            "active_users": int(user_row["active"] or 0),
            "active_schedules": int(sched_row["enabled"] or 0),
        },
    }


@router.get("/schedules")
async def list_all_schedules(
    limit: int = 100,
    offset: int = 0,
    admin: dict = Depends(require_admin),
):
    """List scheduled tasks across all users (admin view)."""
    from src.database import get_worker_pool
    from psycopg.rows import dict_row

    pool = get_worker_pool()
    try:
        async with pool.connection() as conn:
            conn.row_factory = dict_row
            cur = await conn.execute(
                """
                SELECT st.*, gu.username
                FROM scheduled_tasks st
                JOIN gateway_users gu ON st.user_id = gu.user_id
                ORDER BY st.next_run_at ASC
                LIMIT %s OFFSET %s
                """,
                (limit, offset),
            )
            rows = await cur.fetchall()
    except Exception as exc:
        logger.error("admin list_all_schedules failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    schedules = []
    for r in rows:
        d = dict(r)
        for k in ("next_run_at", "last_run_at", "created_at", "updated_at"):
            if d.get(k) and hasattr(d[k], "isoformat"):
                d[k] = d[k].isoformat()
        schedules.append(d)

    return {"count": len(schedules), "schedules": schedules}
