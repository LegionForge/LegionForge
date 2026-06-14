"""
src/gateway/routes/observability.py
────────────────────────────────────
Admin-only observability endpoints for the audit log, threat events, and
system metrics (Phase 25).

All endpoints require ``is_admin = true`` (enforced via ``require_admin``).

Endpoints:
    GET /audit                      — paged audit log (newest first)
    GET /audit/verify               — verify audit chain integrity
    GET /threats                    — paged threat events
    GET /threats/summary            — threat type counts for a time window
    GET /metrics/history            — health_metrics time-series data
    GET /tools                      — list registered tools
    PUT /tools/{tool_id}/status     — approve / revoke a tool (admin)
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from src.gateway.auth import require_admin
from src.security.core import _log_safe

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Audit log ──────────────────────────────────────────────────────────────────


@router.get("/audit")
async def list_audit_log(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    event_type: Optional[str] = Query(default=None),
    agent_id: Optional[str] = Query(default=None),
    admin: dict = Depends(require_admin),
):
    """
    Return paged audit log entries (newest first).

    Filter by ``event_type`` (e.g. ``TASK_SUBMITTED``) or ``agent_id``.
    """
    from src.database import get_worker_pool
    from psycopg.rows import dict_row

    pool = get_worker_pool()
    conditions = []
    params: list = []

    if event_type:
        conditions.append("event_type = %s")
        params.append(event_type)
    if agent_id:
        conditions.append("agent_id = %s")
        params.append(agent_id)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    try:
        async with pool.connection() as conn:
            conn.row_factory = dict_row
            cur = await conn.execute(
                f"SELECT seq, ts, event_type, agent_id, payload "  # nosec B608
                f"FROM audit_log {where} "
                f"ORDER BY seq DESC LIMIT %s OFFSET %s",
                (*params, limit, offset),
            )
            rows = await cur.fetchall()
            cur2 = await conn.execute(
                f"SELECT COUNT(*) AS total FROM audit_log {where}",  # nosec B608
                params,
            )
            total_row = await cur2.fetchone()
    except Exception as exc:
        logger.error("list_audit_log failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    entries = []
    for r in rows:
        d = dict(r)
        if d.get("ts") and hasattr(d["ts"], "isoformat"):
            d["ts"] = d["ts"].isoformat()
        entries.append(d)

    return {
        "total": int(total_row["total"]) if total_row else 0,
        "limit": limit,
        "offset": offset,
        "entries": entries,
    }


@router.get("/audit/verify")
async def verify_audit_chain(admin: dict = Depends(require_admin)):
    """
    Verify the SHA-256 hash chain integrity of the audit log.

    Returns ``{valid: true, rows_checked: N}`` if the chain is intact,
    or ``{valid: false, broken_at_seq: N, error: "..."}`` if tampered.
    """
    from src.database import verify_audit_log_chain

    try:
        valid, rows_checked, error = await verify_audit_log_chain()
    except Exception as exc:
        logger.error("verify_audit_chain failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    result: dict = {"valid": valid, "rows_checked": rows_checked}
    if not valid:
        result["error"] = error
    return result


# ── Threat events ──────────────────────────────────────────────────────────────


@router.get("/threats")
async def list_threat_events(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    threat_type: Optional[str] = Query(default=None),
    since_hours: int = Query(default=24, ge=1, le=720),
    admin: dict = Depends(require_admin),
):
    """
    Return recent threat events (newest first).

    Filter by ``threat_type`` (e.g. ``INJECTION_DETECTED``) and
    ``since_hours`` (default: last 24 hours).
    """
    from src.database import get_worker_pool
    from psycopg.rows import dict_row

    pool = get_worker_pool()
    conditions = ["ts >= now() - interval '%s hours'"]
    params: list = [since_hours]

    if threat_type:
        conditions.append("threat_type = %s")
        params.append(threat_type)

    where = "WHERE " + " AND ".join(conditions)

    try:
        async with pool.connection() as conn:
            conn.row_factory = dict_row
            cur = await conn.execute(
                f"SELECT id, ts, agent_id, run_id, threat_type, confidence, "  # nosec B608
                f"action_taken, metadata "
                f"FROM threat_events {where} "
                f"ORDER BY ts DESC LIMIT %s OFFSET %s",
                (*params, limit, offset),
            )
            rows = await cur.fetchall()
            cur2 = await conn.execute(
                f"SELECT COUNT(*) AS total FROM threat_events {where}",  # nosec B608
                params,
            )
            total_row = await cur2.fetchone()
    except Exception as exc:
        logger.error("list_threat_events failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    events = []
    for r in rows:
        d = dict(r)
        if d.get("ts") and hasattr(d["ts"], "isoformat"):
            d["ts"] = d["ts"].isoformat()
        events.append(d)

    return {
        "total": int(total_row["total"]) if total_row else 0,
        "since_hours": since_hours,
        "limit": limit,
        "offset": offset,
        "events": events,
    }


@router.get("/threats/summary")
async def threat_summary(
    since_hours: int = Query(default=24, ge=1, le=720),
    admin: dict = Depends(require_admin),
):
    """
    Return threat event counts grouped by ``threat_type`` for the given window.

    Useful for dashboards and automated alerting.
    """
    from src.database import get_worker_pool
    from psycopg.rows import dict_row

    pool = get_worker_pool()
    try:
        async with pool.connection() as conn:
            conn.row_factory = dict_row
            cur = await conn.execute(
                """
                SELECT threat_type,
                       COUNT(*) AS count,
                       MAX(ts) AS last_seen,
                       AVG(confidence) AS avg_confidence
                FROM threat_events
                WHERE ts >= now() - interval '%s hours'
                GROUP BY threat_type
                ORDER BY count DESC
                """,
                (since_hours,),
            )
            rows = await cur.fetchall()
    except Exception as exc:
        logger.error("threat_summary failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    breakdown = []
    for r in rows:
        d = dict(r)
        if d.get("last_seen") and hasattr(d["last_seen"], "isoformat"):
            d["last_seen"] = d["last_seen"].isoformat()
        if d.get("avg_confidence") is not None:
            d["avg_confidence"] = round(float(d["avg_confidence"]), 4)
        d["count"] = int(d["count"])
        breakdown.append(d)

    return {
        "since_hours": since_hours,
        "total_events": sum(b["count"] for b in breakdown),
        "breakdown": breakdown,
    }


# ── Health metrics history ──────────────────────────────────────────────────────


@router.get("/metrics/history")
async def metrics_history(
    limit: int = Query(default=100, ge=1, le=1000),
    since_hours: int = Query(default=1, ge=1, le=168),
    admin: dict = Depends(require_admin),
):
    """
    Return health metric time-series data for the given window.

    Data points are written by the health server every 30 seconds.
    """
    from src.database import get_worker_pool
    from psycopg.rows import dict_row

    pool = get_worker_pool()
    try:
        async with pool.connection() as conn:
            conn.row_factory = dict_row
            cur = await conn.execute(
                """
                SELECT ts, cpu_pct, ram_pct, disk_pct, ollama_ok,
                       postgres_ok, active_tasks, active_agents
                FROM health_metrics
                WHERE ts >= now() - interval '%s hours'
                ORDER BY ts DESC
                LIMIT %s
                """,
                (since_hours, limit),
            )
            rows = await cur.fetchall()
    except Exception as exc:
        logger.error("metrics_history failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    points = []
    for r in rows:
        d = dict(r)
        if d.get("ts") and hasattr(d["ts"], "isoformat"):
            d["ts"] = d["ts"].isoformat()
        for k in ("cpu_pct", "ram_pct", "disk_pct"):
            if d.get(k) is not None:
                d[k] = round(float(d[k]), 2)
        points.append(d)

    return {
        "since_hours": since_hours,
        "count": len(points),
        "points": points,
    }


# ── Tool registry ──────────────────────────────────────────────────────────────


@router.get("/tools")
async def list_tools(
    status: Optional[str] = Query(default=None),
    admin: dict = Depends(require_admin),
):
    """
    List all registered tools in the tool registry.

    Filter by ``status``: ``APPROVED``, ``PENDING``, ``REVOKED``.
    """
    from src.database import get_worker_pool
    from psycopg.rows import dict_row

    pool = get_worker_pool()
    conditions = []
    params: list = []
    if status:
        conditions.append("status = %s")
        params.append(status.upper())
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    try:
        async with pool.connection() as conn:
            conn.row_factory = dict_row
            cur = await conn.execute(
                f"SELECT tool_id, source, version, description, status, "  # nosec B608
                f"approved_by, approved_at, declared_side_effects "
                f"FROM tool_registry {where} ORDER BY approved_at DESC",
                params,
            )
            rows = await cur.fetchall()
    except Exception as exc:
        logger.error("list_tools failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    tools = []
    for r in rows:
        d = dict(r)
        if d.get("approved_at") and hasattr(d["approved_at"], "isoformat"):
            d["approved_at"] = d["approved_at"].isoformat()
        tools.append(d)

    return {"count": len(tools), "tools": tools}


class SetToolStatusRequest(BaseModel):
    status: str = Field(..., pattern="^(APPROVED|REVOKED|PENDING)$")
    notes: str = Field(default="", max_length=500)


@router.put("/tools/{tool_id}/status")
async def set_tool_status(
    tool_id: str,
    req: SetToolStatusRequest,
    admin: dict = Depends(require_admin),
):
    """
    Approve or revoke a tool.

    Revoked tools are blocked by Guardian's tool revocation check on every
    invocation.  The block takes effect within Guardian's 10-second
    hot-reload interval.
    """
    from src.database import get_worker_pool

    pool = get_worker_pool()
    try:
        async with pool.connection() as conn:
            cur = await conn.execute(
                "UPDATE tool_registry SET status = %s, approval_notes = %s "
                "WHERE tool_id = %s",
                (req.status, req.notes, tool_id),
            )
            updated = cur.rowcount
    except Exception as exc:
        logger.error("set_tool_status failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    if not updated:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_id}' not found")

    logger.info(
        "[admin] Tool %s status → %s by %s",
        _log_safe(tool_id),
        _log_safe(req.status),
        _log_safe(admin["username"]),
    )
    return {"tool_id": tool_id, "status": req.status, "updated_by": admin["username"]}
