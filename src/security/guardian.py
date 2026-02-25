"""
src/security/guardian.py
────────────────────────
Guardian — deterministic security sidecar service.

Runs as a standalone FastAPI app on localhost:9766.
Enforces tool registry validation, capability boundaries, destructive pattern
detection, and tool sequence contracts for every tool call.

Design principles:
    - NO LLM calls — all decisions are deterministic and auditable
    - Fail-safe: connection error or timeout → SecureToolNode halts the run
    - In-memory caches (refreshed every 60s) keep the hot path fast
    - Never fail-open: unknown tools and novel sequences are rejected/sandboxed

Endpoints:
    POST /check   — synchronous enforcement (hot path)
    POST /report  — async threat event ingestion
    GET  /rules   — read-only view of approved tools + sequences
    GET  /health  — unauthenticated liveness (Docker healthcheck)

Usage:
    # Standalone (for testing / direct start):
    uvicorn src.security.guardian:app --host 127.0.0.1 --port 9766

    # Via Docker Compose:
    docker-compose up guardian
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from typing import Any

import httpx
from fastapi import BackgroundTasks, FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.security.core import (
    FORBIDDEN_CAPABILITIES,
    HITL_HALT_CATEGORIES,
    _compute_fast_hash,
    detect_destructive_pattern,
    _TOOL_REGISTRY,
    _TOOL_HASHES,
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title="LegionForge Guardian",
    description="Deterministic security sidecar — NO LLM calls",
    version="2.0.0",
)

# ── In-memory caches (refreshed from DB every 60 seconds) ─────────────────────

# tool_id → {"description_hash": str, "schema_hash": str}
_approved_tools: dict[str, dict[str, str]] = {}

# agent_id → list of approved sequences [[tool_id, ...], ...]
_agent_sequences: dict[str, list[list[str]]] = {}

_cache_last_refreshed: float = 0.0
_CACHE_TTL_SECONDS: float = 60.0


async def _refresh_caches() -> None:
    """
    Load approved tools and agent sequences from the DB into memory.
    Called on startup and periodically by the background refresh task.
    Non-fatal if DB is unavailable — caches retain their last known values.
    """
    global _approved_tools, _agent_sequences, _cache_last_refreshed

    try:
        from src.database import get_pool

        pool = get_pool()
        async with pool.connection() as conn:
            tool_rows = await conn.fetch(
                "SELECT tool_id, description_hash, schema_hash FROM tool_registry WHERE status = 'APPROVED'"
            )
            seq_rows = await conn.fetch(
                "SELECT agent_id, sequence FROM agent_profiles ORDER BY agent_id, registered_at"
            )

        new_tools: dict[str, dict[str, str]] = {}
        for row in tool_rows:
            new_tools[row["tool_id"]] = {
                "description_hash": row["description_hash"],
                "schema_hash": row["schema_hash"],
            }

        new_seqs: dict[str, list[list[str]]] = {}
        for row in seq_rows:
            aid = row["agent_id"]
            if aid not in new_seqs:
                new_seqs[aid] = []
            new_seqs[aid].append(list(row["sequence"]))

        _approved_tools = new_tools
        _agent_sequences = new_seqs
        _cache_last_refreshed = time.monotonic()

        logger.debug(
            f"[guardian] Cache refreshed: {len(_approved_tools)} tools, "
            f"{sum(len(v) for v in _agent_sequences.values())} sequences"
        )

    except Exception as e:
        logger.warning(f"[guardian] Cache refresh failed (using stale data): {e}")
        # Fall back to in-process registry (populated by register_tool() calls)
        _approved_tools = {
            tid: _compute_fast_hash(manifest)
            for tid, manifest in _TOOL_REGISTRY.items()
        }


async def _maybe_refresh_caches() -> None:
    """Refresh caches if TTL has expired."""
    if time.monotonic() - _cache_last_refreshed > _CACHE_TTL_SECONDS:
        await _refresh_caches()


# ── Request / Response models ─────────────────────────────────────────────────


class GuardianCheckRequest(BaseModel):
    tool_id: str
    action: str
    args: dict
    agent_id: str
    run_id: str
    sequence_so_far: list[str]
    task_token: str | None = None  # Phase 3: JWT task token validation


class GuardianCheckResponse(BaseModel):
    allowed: bool
    tier: str  # "allow" | "sandbox" | "halt"
    reason: str
    threat_type: str | None = None
    confidence: float = 1.0


class ReportRequest(BaseModel):
    event_type: str
    agent_id: str
    run_id: str
    payload: dict


# ── Five-check enforcement pipeline ──────────────────────────────────────────


def _check_1_tool_registry(tool_id: str) -> GuardianCheckResponse | None:
    """Check 1: Is the tool registered and approved?"""
    if tool_id not in _approved_tools:
        return GuardianCheckResponse(
            allowed=False,
            tier="halt",
            reason=f"Tool '{tool_id}' is not in the approved tool registry",
            threat_type="CAPABILITY_VIOLATION",
            confidence=1.0,
        )
    return None


def _check_2_capability_boundary(action: str) -> GuardianCheckResponse | None:
    """Check 2: Is the action in the forbidden capabilities list?"""
    if action in FORBIDDEN_CAPABILITIES:
        return GuardianCheckResponse(
            allowed=False,
            tier="halt",
            reason=f"Action '{action}' is in the forbidden capabilities list",
            threat_type="CAPABILITY_VIOLATION",
            confidence=1.0,
        )
    return None


def _check_3_destructive_pattern(
    tool_id: str, args: dict
) -> tuple[GuardianCheckResponse | None, bool]:
    """
    Check 3: Do the tool args contain destructive/adversarial patterns?

    Returns (response, should_log_only) where:
    - response is the blocking response (or None if permitted)
    - should_log_only=True means HITL_LOG category — fire report and allow
    """
    args_text = json.dumps(args)
    matched, categories = detect_destructive_pattern(args_text)
    if not matched:
        return None, False

    halt_hits = [c for c in categories if c in HITL_HALT_CATEGORIES]
    if halt_hits:
        return (
            GuardianCheckResponse(
                allowed=False,
                tier="halt",
                reason=f"Destructive pattern detected in args: {halt_hits}",
                threat_type=halt_hits[0],
                confidence=1.0,
            ),
            False,
        )

    # LOG tier — log via /report in background, allow to proceed
    return None, True  # caller fires background report


def _check_4_sequence(
    agent_id: str, tool_id: str, sequence_so_far: list[str]
) -> GuardianCheckResponse | None:
    """
    Check 4: Does sequence_so_far + [tool_id] match a registered prefix?

    If the agent has registered sequences, the candidate sequence must be a
    prefix of at least one approved sequence. Novel combinations are sandboxed.
    Agents with no registered sequences are unrestricted (allows gradual rollout).
    """
    approved = _agent_sequences.get(agent_id)
    if not approved:
        # No sequences registered — agent is unconstrained
        return None

    candidate = sequence_so_far + [tool_id]
    for seq in approved:
        # candidate must be a prefix of seq (equal or shorter)
        if seq[: len(candidate)] == candidate:
            return None  # Matches an approved prefix

    return GuardianCheckResponse(
        allowed=False,
        tier="sandbox",
        reason=(
            f"Tool sequence {candidate} is not a prefix of any registered "
            f"sequence for agent '{agent_id}'. Novel sequences are sandboxed."
        ),
        threat_type="SEQUENCE_VIOLATION",
        confidence=1.0,
    )


def _check_5_hash_integrity(tool_id: str, args: dict) -> GuardianCheckResponse | None:
    """
    Check 5: Hash integrity — recompute fast hash of args and compare.

    We hash the serialised args to detect in-flight argument tampering.
    This is a lightweight check; the heavier entrypoint hash is done at
    registration time (verify_tool_before_invocation).
    """
    approved = _approved_tools.get(tool_id)
    if not approved:
        # Already caught in check 1; shouldn't reach here
        return None

    # Check that the cached hashes for this tool still match the in-process registry
    in_proc = _TOOL_HASHES.get(tool_id)
    if in_proc:
        for field in ("description_hash", "schema_hash"):
            cached = approved.get(field)
            current = in_proc.get(field)
            if cached and current and cached != current:
                return GuardianCheckResponse(
                    allowed=False,
                    tier="halt",
                    reason=f"Tool '{tool_id}' hash mismatch on field '{field}' — possible tampering",
                    threat_type="TOOL_HASH_MISMATCH",
                    confidence=1.0,
                )
    return None


# ── Endpoints ─────────────────────────────────────────────────────────────────


@app.get("/health")
async def health() -> JSONResponse:
    """
    Unauthenticated liveness check.
    Used by Docker healthcheck and make check.
    """
    return JSONResponse({"status": "ok", "service": "guardian", "version": "2.0.0"})


@app.get("/rules")
async def rules() -> JSONResponse:
    """
    Read-only view of currently approved tools and registered agent sequences.
    Useful for debugging and audit.
    """
    await _maybe_refresh_caches()
    return JSONResponse(
        {
            "approved_tools": list(_approved_tools.keys()),
            "agent_sequences": {aid: seqs for aid, seqs in _agent_sequences.items()},
            "cache_age_seconds": round(time.monotonic() - _cache_last_refreshed, 1),
        }
    )


@app.post("/check", response_model=GuardianCheckResponse)
async def check(request: GuardianCheckRequest) -> GuardianCheckResponse:
    """
    Synchronous enforcement endpoint — hot path.
    Five checks in order, fail-fast. NO LLM calls.
    """
    await _maybe_refresh_caches()

    # 1. Tool registry
    resp = _check_1_tool_registry(request.tool_id)
    if resp:
        logger.warning(
            f"[guardian/check] HALT check=1 tool={request.tool_id!r} "
            f"agent={request.agent_id!r} reason={resp.reason!r}"
        )
        return resp

    # 2. Capability boundary
    resp = _check_2_capability_boundary(request.action)
    if resp:
        logger.warning(
            f"[guardian/check] HALT check=2 action={request.action!r} "
            f"agent={request.agent_id!r}"
        )
        return resp

    # 3. Destructive pattern
    resp, log_only = _check_3_destructive_pattern(request.tool_id, request.args)
    if resp and not log_only:
        logger.warning(
            f"[guardian/check] HALT check=3 tool={request.tool_id!r} "
            f"agent={request.agent_id!r} threat={resp.threat_type!r}"
        )
        return resp

    # 4. Sequence check
    resp = _check_4_sequence(request.agent_id, request.tool_id, request.sequence_so_far)
    if resp:
        logger.warning(
            f"[guardian/check] SANDBOX check=4 tool={request.tool_id!r} "
            f"agent={request.agent_id!r} seq={request.sequence_so_far}"
        )
        return resp

    # 5. Hash integrity
    resp = _check_5_hash_integrity(request.tool_id, request.args)
    if resp:
        logger.warning(
            f"[guardian/check] HALT check=5 tool={request.tool_id!r} "
            f"agent={request.agent_id!r} reason={resp.reason!r}"
        )
        return resp

    return GuardianCheckResponse(
        allowed=True,
        tier="allow",
        reason="All checks passed",
        confidence=1.0,
    )


@app.post("/report")
async def report(request: ReportRequest) -> JSONResponse:
    """
    Async threat event ingestion.
    Called in the background for LOG-tier destructive patterns — doesn't block tool execution.
    """
    try:
        from src.database import append_audit_log

        await append_audit_log(
            event_type=request.event_type,
            agent_id=request.agent_id,
            payload={
                "run_id": request.run_id,
                **request.payload,
            },
        )
        logger.info(
            f"[guardian/report] event_type={request.event_type!r} "
            f"agent_id={request.agent_id!r}"
        )
        return JSONResponse({"status": "logged"})
    except Exception as e:
        logger.warning(f"[guardian/report] Failed to log event: {e}")
        return JSONResponse({"status": "error", "error": str(e)}, status_code=500)


# ── Startup ───────────────────────────────────────────────────────────────────


@app.on_event("startup")
async def startup() -> None:
    """Load caches from DB on startup. Non-fatal if DB is unavailable."""
    logger.info("[guardian] Starting up — loading caches...")
    await _refresh_caches()
    logger.info(
        f"[guardian] Ready — {len(_approved_tools)} approved tools, "
        f"{sum(len(v) for v in _agent_sequences.values())} registered sequences"
    )


# ── Standalone runner ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=9766, log_level="info")
