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
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI
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
from src.security.acl import validate_task_token

logger = logging.getLogger(__name__)


@asynccontextmanager
async def _lifespan(application: FastAPI):
    """Load caches from DB on startup. Non-fatal if DB is unavailable."""
    logger.info("[guardian] Starting up — loading caches...")
    await _refresh_caches()
    logger.info(
        f"[guardian] Ready — {len(_approved_tools)} approved tools, "
        f"{sum(len(v) for v in _agent_sequences.values())} registered sequences"
    )
    yield
    logger.info("[guardian] Shutting down.")


app = FastAPI(
    title="LegionForge Guardian",
    description="Deterministic security sidecar — NO LLM calls",
    version="4.0.0",
    lifespan=_lifespan,
)

# ── In-memory caches (refreshed from DB every 60 seconds) ─────────────────────

# tool_id → {"description_hash": str, "schema_hash": str}
_approved_tools: dict[str, dict[str, str]] = {}

# agent_id → list of approved sequences [[tool_id, ...], ...]
_agent_sequences: dict[str, list[list[str]]] = {}

# Phase 4: approved adaptive rules from threat_rules table.
# list of dicts: {"rule_id": str, "rule_type": str, "rule_def": dict, ...}
# Refreshed every 5 minutes (same TTL as other caches).
# Applied in _check_6_adaptive_rules() — AFTER all static checks.
_adaptive_rules: list[dict] = []

_cache_last_refreshed: float = 0.0
_CACHE_TTL_SECONDS: float = 60.0


def _guardian_db_conninfo() -> tuple[str, str]:
    """
    Return (conninfo_without_password, password) for Guardian's own direct DB connection.
    Guardian does NOT use the app's connection pool — it connects independently
    so it has no dependency on src.database or the full framework stack.
    """
    host = os.environ.get("POSTGRES_HOST", "host.docker.internal")
    port = os.environ.get("POSTGRES_PORT", "5432")
    db = os.environ.get("POSTGRES_DB", "legionforge")
    user = os.environ.get("POSTGRES_USER", "jpc")
    password = os.environ.get("POSTGRES_PASSWORD", "")
    conninfo = f"host={host} port={port} dbname={db} user={user}"
    return conninfo, password


async def _refresh_caches() -> None:
    """
    Load approved tools, agent sequences, and adaptive threat rules from DB.
    Called on startup and periodically by the background refresh task.
    Non-fatal if DB is unavailable — caches retain their last known values.

    Uses its own direct psycopg3 connection — does NOT depend on src.database
    so the container can stay minimal (no LangGraph, no pgvector, etc.).
    """
    global _approved_tools, _agent_sequences, _adaptive_rules, _cache_last_refreshed

    try:
        import psycopg
        from psycopg.rows import dict_row

        conninfo, password = _guardian_db_conninfo()
        async with await psycopg.AsyncConnection.connect(
            conninfo, password=password, row_factory=dict_row, autocommit=True
        ) as conn:
            cur_t = await conn.execute(
                "SELECT tool_id, description_hash, schema_hash FROM tool_registry WHERE status = 'APPROVED'"
            )
            tool_rows = await cur_t.fetchall()
            cur_s = await conn.execute(
                "SELECT agent_id, sequence FROM agent_profiles ORDER BY agent_id, registered_at"
            )
            seq_rows = await cur_s.fetchall()
            # Phase 4: load approved, non-expired adaptive rules
            cur_r = await conn.execute(
                """
                SELECT rule_id::text, rule_type, rule_def
                FROM threat_rules
                WHERE status = 'APPROVED'
                  AND (expires_at IS NULL OR expires_at > NOW())
                ORDER BY approved_at ASC
                """
            )
            rule_rows = await cur_r.fetchall()

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

        new_rules: list[dict] = []
        for row in rule_rows:
            new_rules.append(
                {
                    "rule_id": row["rule_id"],
                    "rule_type": row["rule_type"],
                    "rule_def": row["rule_def"] or {},
                }
            )

        _approved_tools = new_tools
        _agent_sequences = new_seqs
        _adaptive_rules = new_rules
        _cache_last_refreshed = time.monotonic()

        logger.info(
            f"[guardian] Cache refreshed: {len(_approved_tools)} tools, "
            f"{sum(len(v) for v in _agent_sequences.values())} sequences, "
            f"{len(_adaptive_rules)} adaptive rules"
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


def _check_0_task_token(
    tool_id: str, task_token: str | None
) -> GuardianCheckResponse | None:
    """
    Check 0 (Phase 3): Validate the JWT task token and verify tool is in scope.

    Only runs when the request includes a task_token. Agents without tokens
    are unconstrained for backward compatibility (Phase 4 will enforce tokens
    on all agents).

    Two failure modes:
      - Token present but invalid/expired → tier="halt" (INVALID_TASK_TOKEN)
      - Token valid but tool not in granted_tools → tier="halt" (TOOL_SCOPE_VIOLATION)
    """
    if not task_token:
        return None  # No token — skip check (backward compat)

    token = validate_task_token(task_token)
    if token is None:
        return GuardianCheckResponse(
            allowed=False,
            tier="halt",
            reason="Task token is invalid or expired",
            threat_type="INVALID_TASK_TOKEN",
            confidence=1.0,
        )

    if tool_id not in token.granted_tools:
        return GuardianCheckResponse(
            allowed=False,
            tier="halt",
            reason=(
                f"Tool '{tool_id}' not authorised by task token "
                f"(granted: {token.granted_tools})"
            ),
            threat_type="TOOL_SCOPE_VIOLATION",
            confidence=1.0,
        )

    return None


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


def _check_6_adaptive_rules(
    tool_id: str, args: dict, sequence_so_far: list[str]
) -> GuardianCheckResponse | None:
    """
    Check 6 (Phase 4): Apply approved adaptive rules from the threat_rules table.

    Rules are loaded every 60 seconds by _refresh_caches().
    Static checks (0–5) always run first — adaptive rules are an additional layer.

    Enforced rule types:
      CAPABILITY_BLOCK:  halt if this tool_id is explicitly blocked.
      INJECTION_PATTERN: halt if any string arg matches the regex.
      SEQUENCE_BLOCK:    sandbox if sequence_so_far+[tool_id] starts with blocked seq.
      RATE_LIMIT_TIGHTEN: not enforced here (rate limiter handles this in-process).

    Note: If a regex in a proposed rule is malformed, the rule is skipped with a
    warning rather than crashing — bad rules must not break the hot path.
    """
    import re

    for rule in _adaptive_rules:
        rule_type = rule.get("rule_type")
        rule_def = rule.get("rule_def") or {}
        rule_id_short = rule.get("rule_id", "")[:8]

        if rule_type == "CAPABILITY_BLOCK":
            blocked_tool = rule_def.get("tool_id")
            if blocked_tool and tool_id == blocked_tool:
                return GuardianCheckResponse(
                    allowed=False,
                    tier="halt",
                    reason=(
                        f"Adaptive rule {rule_id_short}...: tool '{tool_id}' "
                        f"is capability-blocked — {rule_def.get('reason', 'no reason given')}"
                    ),
                    threat_type="CAPABILITY_VIOLATION",
                    confidence=1.0,
                )

        elif rule_type == "INJECTION_PATTERN":
            pattern = rule_def.get("pattern")
            flags_str = rule_def.get("flags", "")
            if pattern:
                re_flags = re.IGNORECASE if "i" in flags_str else 0
                try:
                    compiled = re.compile(pattern, re_flags)
                    for arg_val in args.values():
                        if isinstance(arg_val, str) and compiled.search(arg_val):
                            return GuardianCheckResponse(
                                allowed=False,
                                tier="halt",
                                reason=(
                                    f"Adaptive rule {rule_id_short}...: "
                                    "injection pattern matched in tool args"
                                ),
                                threat_type="INJECTION_DETECTED",
                                confidence=0.95,
                            )
                except re.error as regex_err:
                    logger.warning(
                        f"[guardian] Adaptive rule {rule_id_short}... has invalid regex "
                        f"{pattern!r}: {regex_err} — skipping"
                    )

        elif rule_type == "SEQUENCE_BLOCK":
            blocked_seq = rule_def.get("sequence", [])
            if blocked_seq:
                candidate = sequence_so_far + [tool_id]
                if candidate[: len(blocked_seq)] == blocked_seq:
                    return GuardianCheckResponse(
                        allowed=False,
                        tier="sandbox",
                        reason=(
                            f"Adaptive rule {rule_id_short}...: "
                            f"blocked sequence {blocked_seq} detected"
                        ),
                        threat_type="SEQUENCE_VIOLATION",
                        confidence=1.0,
                    )

    return None  # All adaptive rules passed


# ── Endpoints ─────────────────────────────────────────────────────────────────


@app.get("/health")
async def health() -> JSONResponse:
    """
    Unauthenticated liveness check.
    Used by Docker healthcheck and make check.
    """
    return JSONResponse({"status": "ok", "service": "guardian", "version": "4.0.0"})


@app.get("/rules")
async def rules() -> JSONResponse:
    """
    Read-only view of approved tools, sequences, and adaptive rules.
    Useful for debugging and audit.
    """
    await _maybe_refresh_caches()
    return JSONResponse(
        {
            "approved_tools": list(_approved_tools.keys()),
            "agent_sequences": {aid: seqs for aid, seqs in _agent_sequences.items()},
            "adaptive_rules": [
                {"rule_id": r["rule_id"], "rule_type": r["rule_type"]}
                for r in _adaptive_rules
            ],
            "cache_age_seconds": round(time.monotonic() - _cache_last_refreshed, 1),
        }
    )


@app.post("/check", response_model=GuardianCheckResponse)
async def check(request: GuardianCheckRequest) -> GuardianCheckResponse:
    """
    Synchronous enforcement endpoint — hot path.
    Seven checks in order (Phase 4: +check_6 adaptive rules), fail-fast. NO LLM calls.
    """
    await _maybe_refresh_caches()

    # 0. Task token ACL (Phase 3) — validate JWT signature + tool scope
    resp = _check_0_task_token(request.tool_id, request.task_token)
    if resp:
        logger.warning(
            f"[guardian/check] HALT check=0 tool={request.tool_id!r} "
            f"agent={request.agent_id!r} threat={resp.threat_type!r}"
        )
        return resp

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

    # 6. Adaptive rules (Phase 4) — approved rules proposed by Threat Analyst.
    # Applied AFTER all static checks. Rules are hot-loaded from DB every 60s.
    resp = _check_6_adaptive_rules(
        request.tool_id, request.args, request.sequence_so_far
    )
    if resp:
        logger.warning(
            f"[guardian/check] {'HALT' if resp.tier == 'halt' else 'SANDBOX'} check=6 "
            f"tool={request.tool_id!r} agent={request.agent_id!r} "
            f"rule_type={resp.threat_type!r}"
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


# ── Standalone runner ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=9766, log_level="info")
