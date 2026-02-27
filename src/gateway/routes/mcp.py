"""
src/gateway/routes/mcp.py
──────────────────────────
MCP (Model Context Protocol) tool discovery and invocation endpoints:

    GET  /mcp/tools           — list registered tools
    POST /mcp/tools/invoke    — invoke a tool through the Guardian pipeline

Phase 8: read-only tool listing only.  Invocation is stubbed — full MCP
invocation (calling real agent tools via the Guardian) is Phase 9 work.

These endpoints require authentication.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from src.gateway.auth import require_user

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Tool listing ──────────────────────────────────────────────────────────────


@router.get("/tools")
async def list_tools(user: dict = Depends(require_user)) -> dict:
    """
    Return the list of tools available to agents.

    In Phase 8 this reads the registered tool names from the tool_registry.
    Full metadata (schemas, capability boundaries) is Phase 9 work.
    """
    try:
        from src.database import get_pool
        from psycopg.rows import dict_row

        pool = get_pool()
        async with pool.connection() as conn:
            conn.row_factory = dict_row
            cur = await conn.execute(
                "SELECT tool_id, tool_name, status FROM tool_registry ORDER BY tool_name"
            )
            rows = await cur.fetchall()
        tools = [
            {"id": r["tool_id"], "name": r["tool_name"], "status": r["status"]}
            for r in rows
        ]
    except Exception as exc:
        logger.warning(f"[mcp] Could not load tool registry: {exc}")
        tools = []

    return {"tools": tools}


# ── Tool invocation (stub) ─────────────────────────────────────────────────────


class InvokeRequest(BaseModel):
    tool_name: str
    arguments: dict = {}


@router.post("/tools/invoke", status_code=status.HTTP_501_NOT_IMPLEMENTED)
async def invoke_tool(
    body: InvokeRequest,
    user: dict = Depends(require_user),
) -> dict:
    """
    Direct MCP tool invocation.

    Not implemented in Phase 8.  Full MCP invocation (Guardian-validated,
    capability-bounded) is planned for Phase 9.
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Direct MCP tool invocation is not available in Phase 8. "
        "Submit a task via POST /tasks to invoke tools through the agent.",
    )
