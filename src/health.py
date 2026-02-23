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
import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI
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

        conn_str = (
            f"postgresql://{os.environ.get('POSTGRES_USER','jpc')}"
            f":{os.environ.get('POSTGRES_PASSWORD','')}"
            f"@{os.environ.get('POSTGRES_HOST','localhost')}"
            f":{os.environ.get('POSTGRES_PORT','5432')}"
            f"/{os.environ.get('POSTGRES_DB','jpc_agents')}"
        )
        async with await psycopg.AsyncConnection.connect(conn_str) as conn:
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
async def status() -> JSONResponse:
    """
    Full system status. Checks all components.
    Use this for human inspection via browser or curl.
    """
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
async def metrics() -> JSONResponse:
    """Performance metrics snapshot."""
    return JSONResponse(get_metrics_summary())


@app.get("/usage")
async def usage() -> JSONResponse:
    """API usage summary for the last 24 hours."""
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
