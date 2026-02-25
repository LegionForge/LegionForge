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
            user=os.environ.get("POSTGRES_USER", "jpc"),
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

    return JSONResponse(
        content={
            "status": overall,
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "uptime_seconds": int(time.monotonic() - _startup_time),
            "profile": settings.profile.name,
            "chip": settings.profile.chip_model,
            "components": components,
            "rate_limits": get_all_daily_status(),
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
