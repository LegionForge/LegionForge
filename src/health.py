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

logger = logging.getLogger(__name__)

app = FastAPI(
    title="LegionForge",
    description="Health and status API for the local agent framework",
    version="1.0.0",
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

    # Try macOS security CLI (most reliable in server context)
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", "api_key", "-w"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass

    # Token not found — generate and store
    token = secrets.token_urlsafe(32)
    try:
        subprocess.run(
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
        version="1.0.0",
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


def _check_memory() -> dict:
    try:
        import subprocess

        result = subprocess.run(["vm_stat"], capture_output=True, text=True, timeout=3)
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
    """
    if not _verify_bearer_token(request):
        return _unauthorized()
    # Run all checks concurrently
    ollama_task = asyncio.create_task(_check_ollama())
    postgres_task = asyncio.create_task(_check_postgres())
    drive_task = asyncio.create_task(_check_external_drive())

    ollama_result, postgres_result, drive_result = await asyncio.gather(
        ollama_task,
        postgres_task,
        drive_task,
        return_exceptions=True,
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
    except Exception:
        pass  # DB not running — show empty, don't degrade overall status

    return JSONResponse(
        content={
            "status": overall,
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "uptime_seconds": int(time.monotonic() - _startup_time),
            "profile": settings.profile.name,
            "chip": settings.profile.chip_model,
            "components": components,
            "rate_limits": get_all_daily_status(),
            "escalation_events": escalation_events,  # [] when no violations or DB offline
        },
        status_code=200 if all_ok else 503,
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
        except Exception:
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
        except Exception:
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
        logger.error(f"[health] revoke_tool failed for '{tool_id}': {e}")
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

    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")
