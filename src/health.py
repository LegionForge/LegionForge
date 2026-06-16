"""
src/health.py
─────────────
Combined health check and status endpoint.
Runs as a lightweight FastAPI server on localhost:8765.

Start it with: make health-server  (or python -m src.health)

Endpoints:
    GET /health  — quick liveness check (for monitoring)
    GET /status  — full system status (for human inspection)
    GET /metrics — current performance metrics
    GET /usage   — API usage summary for the last 24h

    # Phase 5 — Crystallization review (all Bearer-protected)
    GET  /crystallization/candidates              — list READY_FOR_REVIEW packages
    GET  /crystallization/candidates/{id}         — full package + analysis
    POST /crystallization/candidates/{id}/approve — approve + sign + register
    POST /crystallization/candidates/{id}/reject  — reject with reason
    POST /crystallization/candidates/{id}/revise  — return to Crystallizer with notes

Usage:
    # As a background task in your main app:
    import asyncio
    from src.health import start_health_server
    asyncio.create_task(start_health_server())

    # Or standalone (useful for Makefile targets):
    python -m src.health
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import secrets
import subprocess
import time
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from config.settings import settings
from src.observability import get_metrics_summary
from src.rate_limiter import get_all_daily_status
from src.security.core import _log_safe

logger = logging.getLogger(__name__)

app = FastAPI(
    title="LegionForge",
    description="Health and status API for the local agent framework",
    version="0.7.1-alpha",
)

_startup_time = time.monotonic()

# ── Bearer token management ───────────────────────────────────────────────────
# Simple opaque token (no JWT library needed).
# Token stored in macOS Keychain as service=legionforge_health, account=api_key.
# On first start: generated, stored, printed once to console.
# /health stays unauthenticated (Docker/make check must not require a token).
# /status, /metrics, /usage require Authorization: Bearer <token>.


def _load_or_create_health_token() -> str:
    """
    Load the health server token from Keychain. If not found, generate a new one,
    store it, and print it once to the console.

    Uses the macOS `security` CLI as a fallback (same pattern as get_api_key()).
    Returns the token string.
    """
    service = settings.security.health_token_service

    # Try macOS security CLI (most reliable in server context).
    # `service` is settings.security.health_token_service (a startup-time
    # constant). `security` is /usr/bin/security.
    try:
        result = subprocess.run(  # nosec B603 B607
            ["security", "find-generic-password", "-s", service, "-a", "api_key", "-w"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception as e:
        # nosemgrep: python-logger-credential-disclosure -- logs only the Keychain exception; token value never enters the message.
        logger.debug("[health] Keychain admin-token lookup failed: %s", e)

    # Token not found — generate and store.
    # `service` is a settings constant; `token` is secrets.token_urlsafe(32).
    token = secrets.token_urlsafe(32)
    try:
        subprocess.run(  # nosec B603 B607
            [
                "security",
                "add-generic-password",
                "-s",
                service,
                "-a",
                "api_key",
                "-w",
                token,
                "-U",
            ],
            check=True,
            capture_output=True,
        )
    except Exception as e:
        logger.warning(f"[health-auth] Could not store token in Keychain: {e}")

    print(
        f"\n[health-auth] Generated health server token (store this securely):\n  {token}\n"
    )
    return token


_health_token: str | None = None


def _get_health_token() -> str:
    """Return the cached health token, loading from Keychain if needed."""
    global _health_token
    if _health_token is None:
        _health_token = _load_or_create_health_token()
    return _health_token


# ── /status TTL cache ─────────────────────────────────────────────────────────
# Each /status hit spawns a DB connection, Ollama call, and subprocess.
# Cache the result for _STATUS_CACHE_TTL seconds to prevent resource storms
# from rapid-fire or monitoring tool hammering.

_STATUS_CACHE_TTL: float = 30.0  # seconds

_status_cache: dict[str, Any] = {}
_status_cache_ts: float = 0.0
_status_cache_lock: asyncio.Lock = asyncio.Lock()


def _verify_bearer_token(request: Request) -> bool:
    """
    Check the Authorization header for a valid Bearer token.
    Uses hmac.compare_digest() for constant-time comparison (timing attack safe).
    Returns True if valid, False otherwise.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return False
    provided = auth_header[len("Bearer ") :].strip()
    expected = _get_health_token()
    return hmac.compare_digest(provided, expected)


def _unauthorized() -> JSONResponse:
    return JSONResponse(
        {"error": "Unauthorized", "detail": "Bearer token required"},
        status_code=401,
        headers={"WWW-Authenticate": 'Bearer realm="LegionForge Health"'},
    )


# ── Crystallization signing pipeline helper ───────────────────────────────────


async def _sign_and_register(package: dict, approved_by: str) -> dict:
    """
    Sign an approved crystallization package and register it in tool_registry.

    Called from POST /crystallization/candidates/{id}/approve.
    register_tool() auto-signs via the Ed25519 pipeline if signing is enabled.
    Returns a status dict summarising the outcome.
    """
    import json as _json

    from src.security.core import ToolManifest, register_tool
    from src.database import append_audit_log

    tool_name = package.get("tool_name") or "unknown"
    tool_id = f"{tool_name}@crystallized"

    input_schema = package.get("input_schema") or {}
    if isinstance(input_schema, str):
        try:
            input_schema = _json.loads(input_schema)
        except Exception:
            input_schema = {}

    declared_side_effects = package.get("declared_side_effects") or ["pure"]
    if isinstance(declared_side_effects, str):
        try:
            declared_side_effects = _json.loads(declared_side_effects)
        except Exception:
            declared_side_effects = [declared_side_effects]

    manifest = ToolManifest(
        tool_id=tool_id,
        description=package.get("tool_description") or "",
        input_schema=input_schema,
        declared_side_effects=declared_side_effects,
        source="crystallization_pipeline",
        version="0.7.1-alpha",
        entrypoint_func=None,  # crystallized tools have no Python entrypoint at registration
    )

    signing_status = "skipped"
    try:
        await register_tool(
            manifest,
            approved_by=approved_by,
            approval_notes=f"Crystallized from package {package.get('package_id')}",
        )
        signing_status = "signed_and_registered"
    except Exception as exc:
        logger.warning(f"[crystallization] register_tool failed for {tool_id!r}: {exc}")
        signing_status = f"error: {exc}"

    # Audit event — non-fatal
    try:
        await append_audit_log(
            "TOOL_CRYSTALLIZED",
            agent_id="operator",
            payload={
                "package_id": package.get("package_id"),
                "tool_id": tool_id,
                "tool_name": tool_name,
                "candidate_id": package.get("candidate_id"),
                "approved_by": approved_by,
                "signing_status": signing_status,
            },
        )
    except Exception as exc:
        logger.warning(f"[crystallization] TOOL_CRYSTALLIZED audit log failed: {exc}")

    return {"tool_id": tool_id, "signing_status": signing_status}


# ── Health check helpers ──────────────────────────────────────────────────────


async def _check_ollama() -> dict:
    base_url = settings.local_services.ollama.resolved_url()
    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{base_url}/api/tags")
            resp.raise_for_status()
            models = [m["name"] for m in resp.json().get("models", [])]
            latency_ms = int((time.monotonic() - start) * 1000)
            return {
                "status": "ok",
                "latency_ms": latency_ms,
                "models": models,
            }
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def _check_postgres() -> dict:
    start = time.monotonic()
    try:
        import os
        import psycopg

        # Use keyword arguments — never build a URI with the password embedded,
        # as the full URI can appear in tracebacks and be captured by log handlers.
        async with await psycopg.AsyncConnection.connect(
            host=os.environ.get("POSTGRES_HOST", "localhost"),
            port=int(os.environ.get("POSTGRES_PORT", "5432")),
            dbname=os.environ.get("POSTGRES_DB", "legionforge"),
            user=os.environ.get("POSTGRES_USER", os.environ.get("USER", "postgres")),
            password=os.environ.get("POSTGRES_PASSWORD", ""),
        ) as conn:
            await conn.execute("SELECT 1")
        latency_ms = int((time.monotonic() - start) * 1000)
        return {"status": "ok", "latency_ms": latency_ms}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def _check_external_drive() -> dict:
    import os

    mount = settings.storage.external.mount_path
    try:
        stat = os.statvfs(mount)
        free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
        total_gb = (stat.f_blocks * stat.f_frsize) / (1024**3)
        used_pct = round((1 - stat.f_bavail / stat.f_blocks) * 100, 1)
        return {
            "status": "ok",
            "mount": mount,
            "free_gb": round(free_gb, 2),
            "total_gb": round(total_gb, 2),
            "used_pct": used_pct,
        }
    except Exception as e:
        return {"status": "error", "mount": mount, "error": str(e)}


async def _check_redis() -> dict | None:
    """Check Redis connectivity. Returns None when Redis is not configured."""
    redis_url = getattr(settings.gateway, "redis_url", "")
    if not redis_url:
        return None  # not configured — omit from status
    try:
        import redis.asyncio as aioredis

        client = aioredis.from_url(redis_url, socket_connect_timeout=1)
        await client.ping()
        await client.aclose()
        return {"status": "ok", "url": redis_url}
    except Exception as exc:
        return {"status": "error", "url": redis_url, "error": str(exc)}


def _check_memory() -> dict:
    # `vm_stat` is the macOS system memory tool (/usr/bin/vm_stat); hardcoded argv.
    try:
        import subprocess

        result = subprocess.run(  # nosec B603 B607
            ["vm_stat"], capture_output=True, text=True, timeout=3
        )
        lines = result.stdout.splitlines()
        stats = {}
        for line in lines:
            if ":" in line:
                key, _, val = line.partition(":")
                stats[key.strip()] = val.strip().rstrip(".")

        page_size = 16384  # bytes (M1/M4 Mac)
        free_pages = int(stats.get("Pages free", "0").replace(",", ""))
        active = int(stats.get("Pages active", "0").replace(",", ""))
        wired = int(stats.get("Pages wired down", "0").replace(",", ""))

        free_gb = round((free_pages * page_size) / (1024**3), 2)
        used_gb = round(((active + wired) * page_size) / (1024**3), 2)
        total_gb = settings.memory.total_gb

        return {
            "status": "ok",
            "total_gb": total_gb,
            "used_gb": used_gb,
            "free_gb": free_gb,
            "used_pct": round(used_gb / total_gb * 100, 1),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ── Endpoints ─────────────────────────────────────────────────────────────────


@app.get("/health")
async def health() -> JSONResponse:
    """
    Liveness check. Returns 200 if the server is up.
    Use this for monitoring/alerting (fast, minimal checks only).
    """
    uptime_seconds = int(time.monotonic() - _startup_time)
    return JSONResponse(
        {
            "status": "ok",
            "uptime_seconds": uptime_seconds,
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "profile": settings.profile.name,
        }
    )


@app.get("/status")
async def status(request: Request) -> JSONResponse:
    """
    Full system status. Checks all components.
    Requires Bearer token (Authorization: Bearer <token>).
    Use this for human inspection via curl or make status.

    Results are cached for 30 seconds (_STATUS_CACHE_TTL) to prevent resource
    storms from rapid-fire requests.  Each uncached hit spawns a DB connection,
    an Ollama HTTP call, and a vm_stat subprocess — the cache bounds this cost.
    """
    if not _verify_bearer_token(request):
        return _unauthorized()

    global _status_cache, _status_cache_ts

    now = time.monotonic()
    async with _status_cache_lock:
        if _status_cache and (now - _status_cache_ts) < _STATUS_CACHE_TTL:
            cached = _status_cache
            return JSONResponse(
                content=cached["content"],
                status_code=cached["status_code"],
                headers={"X-Status-Cache": "hit"},
            )

    # Run all checks concurrently.
    # Model integrity uses a process-lifetime cache (SHA256 of multi-GB GGUF
    # files takes 30-60 s — only computed once, not on every /status poll).
    from src.tools.model_integrity import get_model_integrity_status

    ollama_task = asyncio.create_task(_check_ollama())
    postgres_task = asyncio.create_task(_check_postgres())
    drive_task = asyncio.create_task(_check_external_drive())
    redis_task = asyncio.create_task(_check_redis())
    integrity_task = asyncio.create_task(get_model_integrity_status(settings))

    ollama_result, postgres_result, drive_result, redis_result, integrity_result = (
        await asyncio.gather(
            ollama_task,
            postgres_task,
            drive_task,
            redis_task,
            integrity_task,
            return_exceptions=True,
        )
    )

    memory_result = _check_memory()

    # Determine overall status
    components = {
        "ollama": (
            ollama_result
            if isinstance(ollama_result, dict)
            else {"status": "error", "error": str(ollama_result)}
        ),
        "postgres": (
            postgres_result
            if isinstance(postgres_result, dict)
            else {"status": "error", "error": str(postgres_result)}
        ),
        "external_drive": (
            drive_result
            if isinstance(drive_result, dict)
            else {"status": "error", "error": str(drive_result)}
        ),
        "memory": memory_result,
    }

    # Redis: omit entirely when not configured; surface errors when configured.
    if isinstance(redis_result, dict) and redis_result is not None:
        components["redis"] = redis_result
    elif isinstance(redis_result, Exception):
        components["redis"] = {"status": "error", "error": str(redis_result)}

    # Model integrity: always surface (shows "skipped" when hashes not pinned).
    if isinstance(integrity_result, dict):
        components["model_integrity"] = integrity_result
    else:
        components["model_integrity"] = {
            "status": "error",
            "error": str(integrity_result),
        }

    all_ok = all(c.get("status") == "ok" for c in components.values())
    overall = "ok" if all_ok else "degraded"

    # Required models check
    required_models = [
        settings.models.primary.model_id,
        settings.models.router.model_id,
        settings.models.embeddings.model_id,
    ]
    available_models = components["ollama"].get("models", [])
    missing_models = [m for m in required_models if m not in available_models]
    if missing_models:
        overall = "degraded"
        components["ollama"]["missing_models"] = missing_models

    # Phase 3: recent escalation events (alert-policy scope violations)
    # Non-fatal if DB is unavailable — returns empty list.
    escalation_events: list[dict] = []
    try:
        from src.database import get_recent_escalations

        escalation_events = await get_recent_escalations(hours=24)
    except Exception:  # nosec B110
        pass  # DB not running — show empty, don't degrade overall status

    response_content = {
        "status": overall,
        "ts": datetime.now(tz=timezone.utc).isoformat(),
        "uptime_seconds": int(time.monotonic() - _startup_time),
        "profile": settings.profile.name,
        "chip": settings.profile.chip_model,
        "components": components,
        "rate_limits": get_all_daily_status(),
        "escalation_events": escalation_events,  # [] when no violations or DB offline
    }
    response_status = 200 if all_ok else 503

    async with _status_cache_lock:
        _status_cache = {"content": response_content, "status_code": response_status}
        _status_cache_ts = time.monotonic()

    return JSONResponse(
        content=response_content,
        status_code=response_status,
        headers={"X-Status-Cache": "miss"},
    )


@app.get("/metrics")
async def metrics(request: Request) -> JSONResponse:
    """Performance metrics snapshot. Requires Bearer token."""
    if not _verify_bearer_token(request):
        return _unauthorized()
    return JSONResponse(get_metrics_summary())


@app.get("/usage")
async def usage(request: Request) -> JSONResponse:
    """API usage summary for the last 24 hours. Requires Bearer token."""
    if not _verify_bearer_token(request):
        return _unauthorized()
    try:
        from src.database import get_usage_summary

        summary = await get_usage_summary(hours=24)
        return JSONResponse(summary)
    except Exception as e:
        return JSONResponse(
            {"error": str(e), "note": "Database may not be initialized"},
            status_code=503,
        )


@app.get("/bom")
async def bom(request: Request) -> JSONResponse:
    """
    AI Bill of Materials snapshot. Requires Bearer token.

    Returns all tracked models, tools, agents, and security-critical
    dependencies with version, origin, hash, and CVE scan status.
    Used by the Threat Analyst agent for CVE cross-referencing.
    """
    if not _verify_bearer_token(request):
        return _unauthorized()
    try:
        from src.security.bom import get_bom

        report = await get_bom()
        return JSONResponse(report.to_dict())
    except Exception as e:
        return JSONResponse(
            {"error": str(e), "note": "BOM assembly failed"},
            status_code=503,
        )


@app.get("/rules")
async def rules(request: Request) -> JSONResponse:
    """
    Pending threat rules awaiting operator review. Requires Bearer token.

    Returns all PENDING rules proposed by the Threat Analyst.
    Use POST /rules/{rule_id}/approve or /rules/{rule_id}/reject to action them.
    """
    if not _verify_bearer_token(request):
        return _unauthorized()
    try:
        from src.database import get_pending_rules

        pending = await get_pending_rules()
        return JSONResponse({"pending_rules": pending, "count": len(pending)})
    except Exception as e:
        return JSONResponse(
            {"error": str(e), "note": "Database may not be initialized"},
            status_code=503,
        )


@app.post("/rules/{rule_id}/approve")
async def approve_rule(rule_id: str, request: Request) -> JSONResponse:
    """
    Approve a PENDING threat rule. Operator-only action.

    Guardian picks up the change on its next 5-minute poll cycle —
    no immediate in-process effect, preserving an operator review window.
    """
    if not _verify_bearer_token(request):
        return _unauthorized()
    try:
        from src.database import approve_threat_rule

        updated = await approve_threat_rule(rule_id, approved_by="operator")
        if updated:
            return JSONResponse(
                {
                    "status": "approved",
                    "rule_id": rule_id,
                    "note": "Guardian will apply on next 5-minute poll cycle",
                }
            )
        return JSONResponse(
            {"error": "Rule not found or not in PENDING status"}, status_code=404
        )
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=503)


@app.post("/rules/{rule_id}/reject")
async def reject_rule(rule_id: str, request: Request) -> JSONResponse:
    """Reject a PENDING threat rule. Operator-only action."""
    if not _verify_bearer_token(request):
        return _unauthorized()
    try:
        from src.database import reject_threat_rule

        updated = await reject_threat_rule(rule_id, rejected_by="operator")
        if updated:
            return JSONResponse({"status": "rejected", "rule_id": rule_id})
        return JSONResponse(
            {"error": "Rule not found or not in PENDING status"}, status_code=404
        )
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=503)


# ── Crystallization Review Interface (Phase 5) ───────────────────────────────


@app.get("/crystallization/candidates")
async def crystallization_candidates(request: Request) -> JSONResponse:
    """
    List all packages awaiting human review (status=READY_FOR_REVIEW).

    Each entry includes a summary of the Pre-HITL analysis (recommendation,
    test pass/fail counts, security clean flag, risk flags) so you can triage
    without fetching every full report. Requires Bearer token.
    """
    if not _verify_bearer_token(request):
        return _unauthorized()
    try:
        from src.database import get_packages_ready_for_review

        packages = await get_packages_ready_for_review()
        return JSONResponse(
            {
                "packages": packages,
                "count": len(packages),
                "note": (
                    "Use GET /crystallization/candidates/{package_id} for full detail. "
                    "POST …/approve, …/reject, or …/revise to action."
                ),
            }
        )
    except Exception as e:
        return JSONResponse(
            {"error": str(e), "note": "Database may not be initialized"},
            status_code=503,
        )


@app.get("/crystallization/candidates/{package_id}")
async def crystallization_candidate_detail(
    package_id: str, request: Request
) -> JSONResponse:
    """
    Full package record + Pre-HITL analysis report for a single package.

    Read this before approving or rejecting — it includes the generated function
    code, all test cases, and the full analysis with security findings.
    Requires Bearer token.
    """
    if not _verify_bearer_token(request):
        return _unauthorized()
    try:
        from src.database import get_analysis, get_package

        package = await get_package(package_id)
        if package is None:
            return JSONResponse({"error": "Package not found"}, status_code=404)
        analysis = await get_analysis(package_id)
        return JSONResponse(
            {
                "package": package,
                "analysis": analysis,
                "review_actions": {
                    "approve": f"/crystallization/candidates/{package_id}/approve",
                    "reject": f"/crystallization/candidates/{package_id}/reject",
                    "revise": f"/crystallization/candidates/{package_id}/revise",
                },
            }
        )
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=503)


@app.post("/crystallization/candidates/{package_id}/approve")
async def crystallization_approve(package_id: str, request: Request) -> JSONResponse:
    """
    Approve a READY_FOR_REVIEW package.

    After DB approval, immediately triggers the Ed25519 signing pipeline and
    registers the crystallized tool in tool_registry.  Run `make bom` to verify
    the tool appears in the Bill of Materials.  Operator-only. Requires Bearer token.
    """
    if not _verify_bearer_token(request):
        return _unauthorized()
    try:
        from src.database import approve_package, get_package

        updated = await approve_package(package_id, approved_by="operator")
        if not updated:
            return JSONResponse(
                {"error": "Package not found or not in READY_FOR_REVIEW status"},
                status_code=404,
            )

        # Fetch full record for signing
        package = await get_package(package_id)
        if package is None:
            return JSONResponse(
                {
                    "status": "approved",
                    "package_id": package_id,
                    "warning": "Approved in DB but package record unavailable — signing skipped",
                },
                status_code=207,
            )

        sign_result = await _sign_and_register(package, approved_by="operator")
        return JSONResponse(
            {
                "status": "approved",
                "package_id": package_id,
                "tool_name": package.get("tool_name"),
                "signing": sign_result,
                "note": "Tool registered in tool_registry. Run `make bom` to verify.",
            }
        )
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=503)


@app.post("/crystallization/candidates/{package_id}/reject")
async def crystallization_reject(package_id: str, request: Request) -> JSONResponse:
    """
    Reject a READY_FOR_REVIEW package. Reason is optional but strongly recommended.

    Operator-only action. Requires Bearer token.
    Body (optional JSON): {"reason": "explain why this package should not be crystallized"}
    """
    if not _verify_bearer_token(request):
        return _unauthorized()
    try:
        reason = ""
        try:
            body = await request.json()
            reason = str(body.get("reason", ""))
        except Exception:  # nosec B110
            pass  # body absent or not JSON — reason stays empty

        from src.database import reject_package

        updated = await reject_package(
            package_id, rejected_by="operator", reason=reason
        )
        if updated:
            return JSONResponse(
                {"status": "rejected", "package_id": package_id, "reason": reason}
            )
        return JSONResponse(
            {"error": "Package not found or not in a reviewable status"},
            status_code=404,
        )
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=503)


@app.post("/crystallization/candidates/{package_id}/revise")
async def crystallization_revise(package_id: str, request: Request) -> JSONResponse:
    """
    Send a READY_FOR_REVIEW package back to the Crystallizer with revision notes.

    Resets status to PENDING_ANALYSIS so the Pre-HITL Analyzer re-runs
    automatically after the Crystallizer re-submits.
    Operator-only action. Requires Bearer token.

    Body (required JSON): {"notes": "what specifically needs to change"}
    """
    if not _verify_bearer_token(request):
        return _unauthorized()
    try:
        notes = ""
        try:
            body = await request.json()
            notes = str(body.get("notes", ""))
        except Exception:  # nosec B110
            pass

        from src.database import revise_package

        updated = await revise_package(package_id, revision_notes=notes)
        if updated:
            return JSONResponse(
                {
                    "status": "sent_for_revision",
                    "package_id": package_id,
                    "notes": notes,
                    "next_step": "make run-crystallizer CANDIDATE_ID=<candidate_id>",
                }
            )
        return JSONResponse(
            {"error": "Package not found or not in READY_FOR_REVIEW status"},
            status_code=404,
        )
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=503)


# ── Phase 6: Tool revocation endpoint ────────────────────────────────────────


class RevokeToolRequest(BaseModel):
    reason: str = "Revoked by operator"


@app.post("/tools/{tool_id}/revoke")
async def revoke_tool_endpoint(
    tool_id: str,
    request: Request,
    body: RevokeToolRequest,
) -> JSONResponse:
    """
    Immediately revoke a registered tool.

    Sets tool_registry.status = 'REVOKED' and appends a TOOL_REVOKED audit event.
    Guardian picks up the revocation within _CACHE_TTL_SECONDS (≤ 10s).

    Requires Bearer auth (same token as /status, /metrics, /usage).
    """
    if not _verify_bearer_token(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    try:
        from src.database import revoke_tool

        revoked_by = request.headers.get("X-Operator-Id", "health_api")
        success = await revoke_tool(
            tool_id=tool_id,
            revoked_by=revoked_by,
            reason=body.reason,
        )

        if success:
            return JSONResponse(
                {
                    "status": "revoked",
                    "tool_id": tool_id,
                    "revoked_by": revoked_by,
                    "reason": body.reason,
                    "note": "Guardian cache will reflect this within 10 seconds",
                }
            )
        else:
            return JSONResponse(
                {
                    "error": f"Tool '{tool_id}' not found or already revoked",
                    "tool_id": tool_id,
                },
                status_code=404,
            )
    except Exception as e:
        logger.error("[health] revoke_tool failed for '%s': %s", _log_safe(tool_id), e)
        return JSONResponse({"error": str(e)}, status_code=503)


# ── Phase 6: PentestAgent endpoints ──────────────────────────────────────────


class StartPentestRequest(BaseModel):
    mode: str = "verify"  # "verify" | "resilience"
    classes: list[str] = []  # empty = all 8 attack classes


@app.post("/pentest/run")
async def start_pentest_run(
    body: StartPentestRequest, request: Request
) -> JSONResponse:
    """
    Start a new pentest run asynchronously.

    Bearer-protected. The run executes in a background task; poll
    GET /pentest/runs/{run_id} for status.

    Body: {"mode": "verify", "classes": ["PROMPT_INJECTION", ...]}
    Returns: {"run_id": "...", "status": "started", "mode": "verify"}
    """
    if not _verify_bearer_token(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    valid_modes = {"verify", "resilience"}
    if body.mode not in valid_modes:
        return JSONResponse(
            {"error": f"mode must be one of {sorted(valid_modes)}"},
            status_code=400,
        )

    try:
        import asyncio
        import subprocess as _sp

        from src.database import create_pentest_run

        # Hardcoded argv; `git` is the dev-environment binary on PATH.
        try:
            git_ref = (
                _sp.check_output(  # nosec B603 B607
                    ["git", "rev-parse", "--short", "HEAD"], stderr=_sp.DEVNULL
                )
                .decode()
                .strip()
            )
        except Exception:
            git_ref = "unknown"

        run_id = await create_pentest_run(mode=body.mode, git_ref=git_ref)

        # Fire-and-forget background task
        async def _run_pentest() -> None:
            from src.agents.synthetic_env import SyntheticEnvironment
            from src.agents.pentest_agent import build_pentest_graph
            from src.tools.pentest_tools import ALL_ATTACK_CLASSES
            from datetime import datetime, timezone

            attack_queue = body.classes if body.classes else list(ALL_ATTACK_CLASSES)
            initial_state = {
                "run_id": run_id,
                "mode": body.mode,
                "attack_queue": attack_queue,
                "current_class": None,
                "results": [],
                "critical_found": False,
                "force_end": False,
                "started_at": datetime.now(timezone.utc).isoformat(),
            }
            try:
                async with SyntheticEnvironment() as env:
                    compiled = build_pentest_graph(env)
                    await compiled.ainvoke(initial_state)
            except Exception as exc:
                logger.error(f"[health] Background pentest run {run_id} failed: {exc}")

        asyncio.get_event_loop().create_task(_run_pentest())

        return JSONResponse({"run_id": run_id, "status": "started", "mode": body.mode})

    except Exception as e:
        logger.error(f"[health] start_pentest_run failed: {e}")
        return JSONResponse({"error": str(e)}, status_code=503)


@app.get("/pentest/runs")
async def list_pentest_runs(request: Request) -> JSONResponse:
    """
    List the 10 most recent pentest runs.

    Bearer-protected. Returns run_id, mode, status, started_at, summary.
    """
    if not _verify_bearer_token(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    try:
        from src.database import get_worker_pool
        from psycopg.rows import dict_row

        pool = get_worker_pool()
        async with pool.connection() as conn:
            conn.row_factory = dict_row
            rows = await conn.fetchall(
                """
                SELECT run_id::text, mode, status, started_at, finished_at, summary, git_ref
                FROM pentest_runs
                ORDER BY started_at DESC
                LIMIT 10
                """
            )
        return JSONResponse(
            [
                {
                    "run_id": str(r["run_id"]),
                    "mode": r["mode"],
                    "status": r["status"],
                    "started_at": (
                        r["started_at"].isoformat() if r["started_at"] else None
                    ),
                    "finished_at": (
                        r["finished_at"].isoformat() if r["finished_at"] else None
                    ),
                    "git_ref": r.get("git_ref"),
                    "summary": r.get("summary"),
                }
                for r in rows
            ]
        )
    except Exception as e:
        logger.error(f"[health] list_pentest_runs failed: {e}")
        return JSONResponse({"error": str(e)}, status_code=503)


@app.get("/pentest/runs/{run_id}")
async def get_pentest_run_status(run_id: str, request: Request) -> JSONResponse:
    """
    Get status and summary for a specific pentest run.

    Bearer-protected.
    """
    if not _verify_bearer_token(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    try:
        from src.database import get_pentest_run

        run = await get_pentest_run(run_id)
        if not run:
            return JSONResponse({"error": f"Run {run_id} not found"}, status_code=404)

        return JSONResponse(
            {
                "run_id": str(run["run_id"]),
                "mode": run["mode"],
                "status": run["status"],
                "started_at": (
                    run["started_at"].isoformat() if run.get("started_at") else None
                ),
                "finished_at": (
                    run["finished_at"].isoformat() if run.get("finished_at") else None
                ),
                "git_ref": run.get("git_ref"),
                "summary": run.get("summary"),
            }
        )
    except Exception as e:
        logger.error(
            "[health] get_pentest_run_status failed for %s: %s", _log_safe(run_id), e
        )
        return JSONResponse({"error": str(e)}, status_code=503)


@app.get("/pentest/runs/{run_id}/findings")
async def get_pentest_run_findings(run_id: str, request: Request) -> JSONResponse:
    """
    Return all findings for a specific pentest run.

    Bearer-protected. Returns list of {attack_class, variant, severity, defense_held, detail}.
    """
    if not _verify_bearer_token(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    try:
        from src.database import list_pentest_findings

        findings = await list_pentest_findings(run_id)
        return JSONResponse(
            [
                {
                    "id": f["id"],
                    "attack_class": f["attack_class"],
                    "variant": f["variant"],
                    "severity": f["severity"],
                    "defense_held": f["defense_held"],
                    "detail": f.get("detail"),
                    "payload": f.get("payload"),
                    "logged_at": (
                        f["logged_at"].isoformat() if f.get("logged_at") else None
                    ),
                }
                for f in findings
            ]
        )
    except Exception as e:
        logger.error(
            "[health] get_pentest_run_findings failed for %s: %s", _log_safe(run_id), e
        )
        return JSONResponse({"error": str(e)}, status_code=503)


@app.get("/pentest/runs/{run_id}/report")
async def get_pentest_run_report(
    run_id: str, request: Request, format: str = "json"
) -> JSONResponse:
    """
    Return the full pentest report for a run.

    Bearer-protected. Query param: ?format=json|markdown|html (default: json).
    """
    if not _verify_bearer_token(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    valid_formats = {"json", "markdown", "html"}
    if format not in valid_formats:
        return JSONResponse(
            {"error": f"format must be one of {sorted(valid_formats)}"},
            status_code=400,
        )

    try:
        from datetime import datetime, timezone
        from src.database import get_pentest_run, list_pentest_findings
        from src.agents.pentest_report import (
            PentestFinding,
            PentestReport,
            PentestSummary,
        )

        run = await get_pentest_run(run_id)
        if not run:
            return JSONResponse({"error": f"Run {run_id} not found"}, status_code=404)

        raw_findings = await list_pentest_findings(run_id)
        findings = [
            PentestFinding(
                attack_class=f["attack_class"],
                variant=f["variant"],
                severity=f["severity"],
                defense_held=f["defense_held"],
                detail=f.get("detail") or "",
                payload=f.get("payload"),
            )
            for f in raw_findings
        ]

        total = len(findings)
        passed = sum(1 for f in findings if f.defense_held)
        bypasses = total - passed
        by_severity: dict = {}
        by_class: dict = {}
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            if f.attack_class not in by_class:
                by_class[f.attack_class] = {"passed": 0, "bypassed": 0}
            if f.defense_held:
                by_class[f.attack_class]["passed"] += 1
            else:
                by_class[f.attack_class]["bypassed"] += 1

        report = PentestReport(
            run_id=run_id,
            mode=run.get("mode", "unknown"),
            started_at=run.get("started_at", datetime.now(timezone.utc)),
            finished_at=run.get("finished_at", datetime.now(timezone.utc)),
            git_ref=run.get("git_ref", "unknown"),
            findings=findings,
            summary=PentestSummary(
                total_tests=total,
                defenses_held=passed,
                bypasses_found=bypasses,
                by_severity=by_severity,
                by_class=by_class,
                proposed_rules_count=0,
            ),
        )

        if format == "json":
            return JSONResponse(content={"report": report.to_json()})
        else:
            content_type = "text/markdown" if format == "markdown" else "text/html"
            from fastapi.responses import Response

            renderer = report.to_markdown if format == "markdown" else report.to_html
            return Response(content=renderer(), media_type=content_type)

    except Exception as e:
        logger.error(
            "[health] get_pentest_run_report failed for %s: %s", _log_safe(run_id), e
        )
        return JSONResponse({"error": str(e)}, status_code=503)


class ApproveRuleRequest(BaseModel):
    approved_by: str = "operator"


@app.post("/pentest/rules/{finding_id}/approve")
async def approve_pentest_rule(
    finding_id: int, body: ApproveRuleRequest, request: Request
) -> JSONResponse:
    """
    HITL gate: Approve a proposed rule generated from a pentest finding.

    Phase 7 enhancement: after updating pentest_proposed_rules.status to
    APPROVED, this endpoint promotes the rule into threat_rules so Guardian
    enforces it within its next 10-second cache refresh cycle.

    Bearer-protected. Returns the updated rule plus the new threat_rule_id.
    """
    if not _verify_bearer_token(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    try:
        from src.database import (
            append_audit_log,
            get_worker_pool,
            promote_pentest_rule_to_threat_rule,
        )
        from psycopg.rows import dict_row

        pool = get_worker_pool()
        async with pool.connection() as conn:
            conn.row_factory = dict_row
            rows = await conn.fetchall(
                """
                UPDATE pentest_proposed_rules
                SET status = 'APPROVED'
                WHERE id = %s AND status = 'PROPOSED'
                RETURNING id, run_id::text, finding_id, rule_type,
                          rule_content, rationale, status
                """,
                (finding_id,),
            )
            if not rows:
                return JSONResponse(
                    {"error": f"Rule {finding_id} not found or already processed"},
                    status_code=404,
                )
        rule = rows[0]
        logger.info(
            "[health] Pentest rule %s approved by '%s'",
            _log_safe(finding_id),
            _log_safe(body.approved_by),
        )

        # Phase 7: promote the approved rule into threat_rules so Guardian enforces it.
        try:
            threat_rule_id = await promote_pentest_rule_to_threat_rule(
                finding_id=rule["id"],
                rule_type=rule["rule_type"],
                rule_content=rule["rule_content"],
                rationale=rule["rationale"],
                run_id=rule["run_id"],
            )
            logger.info(
                "[health] Promoted pentest rule %s → threat_rule %s (enforced within 10s)",
                _log_safe(finding_id),
                _log_safe(threat_rule_id),
            )
        except ValueError as ve:
            # Unknown rule_type — return 422 rather than silently dropping
            logger.warning(
                "[health] Cannot promote pentest rule %s: %s", _log_safe(finding_id), ve
            )
            return JSONResponse({"error": str(ve)}, status_code=422)
        except Exception as promo_err:
            # Promotion failed (e.g. DB unavailable) — log and continue;
            # the pentest rule is still marked APPROVED in its table.
            logger.error(
                "[health] promote_pentest_rule_to_threat_rule failed for finding %s: %s",
                _log_safe(finding_id),
                promo_err,
            )
            threat_rule_id = None

        # Append an audit log entry for the promotion event.
        try:
            await append_audit_log(
                event_type="PENTEST_RULE_PROMOTED",
                agent_id=body.approved_by,
                payload={
                    "pentest_finding_id": finding_id,
                    "threat_rule_id": threat_rule_id,
                    "rule_type": rule["rule_type"],
                    "run_id": rule["run_id"],
                },
            )
        except Exception as audit_err:
            logger.warning(
                "[health] audit_log write failed for rule %s: %s",
                _log_safe(finding_id),
                audit_err,
            )

        return JSONResponse(
            {
                "status": "approved",
                "rule_id": rule["id"],
                "rule_type": rule["rule_type"],
                "rule_content": rule["rule_content"],
                "approved_by": body.approved_by,
                "threat_rule_id": threat_rule_id,
                "enforcement": (
                    "active_within_10s" if threat_rule_id else "promotion_failed"
                ),
            }
        )
    except Exception as e:
        logger.error(
            "[health] approve_pentest_rule failed for %s: %s", _log_safe(finding_id), e
        )
        return JSONResponse({"error": str(e)}, status_code=503)


# ── Phase 10: Per-user token usage ────────────────────────────────────────────


@app.get("/usage/me")
async def get_my_usage(request: Request) -> JSONResponse:
    """
    Return today's token usage for the authenticated gateway user.

    Requires Authorization: Bearer <api_key>.

    Response:
        {
          "user_id":     "...",
          "username":    "...",
          "daily_limit": 100000,
          "today": {
            "tokens_used":      12500,
            "tokens_in_flight": 3000,
            "tokens_remaining": 84500
          },
          "providers": {"ollama": 10000, "openai": 2500}
        }
    """
    # ── Auth ──────────────────────────────────────────────────────────────
    auth_header = request.headers.get("authorization")
    if not auth_header:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    from src.gateway.auth import authenticate, extract_bearer_token

    raw_key = extract_bearer_token(auth_header)
    if not raw_key:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    user = await authenticate(raw_key)
    if user is None:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    # ── Usage ─────────────────────────────────────────────────────────────
    try:
        from src.database import (
            get_user_usage_summary_today,
        )

        usage = await get_user_usage_summary_today(user["user_id"])
        daily_limit = user.get("daily_token_limit", 100000)
        tokens_used = usage["today"]["tokens_used"]
        tokens_in_flight = usage["today"]["tokens_in_flight"]
        tokens_remaining = max(0, daily_limit - tokens_used - tokens_in_flight)

        return JSONResponse(
            {
                "user_id": user["user_id"],
                "username": user["username"],
                "daily_limit": daily_limit,
                "today": {
                    "tokens_used": tokens_used,
                    "tokens_in_flight": tokens_in_flight,
                    "tokens_remaining": tokens_remaining,
                },
                "providers": usage["providers"],
            }
        )
    except Exception as e:
        logger.error(f"[health] /usage/me failed: {e}")
        return JSONResponse({"error": str(e)}, status_code=503)


# ── Server runner ─────────────────────────────────────────────────────────────


async def start_health_server(host: str = "127.0.0.1", port: int = 8765) -> None:
    """Start the health server as a background coroutine."""
    import uvicorn

    config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    logger.info(f"Health server starting at http://{host}:{port}")
    await server.serve()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app, host="0.0.0.0", port=8765, log_level="info"  # nosec B104
    )  # intentional LAN binding for operator health API
