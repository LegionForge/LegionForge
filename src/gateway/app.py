"""
src/gateway/app.py
───────────────────
FastAPI application factory for the Phase 8 gateway.

Serves on :8080 (user-facing).
Separate from the operator health server (src/health.py, :8765).

Start: make gateway-start
       uvicorn src.gateway.app:app --host 0.0.0.0 --port 8080

Endpoints:
    POST   /tasks
    GET    /tasks
    GET    /tasks/{id}
    DELETE /tasks/{id}
    GET    /tasks/{id}/stream              (SSE)
    GET    /.well-known/agent.json         (A2A Agent Card — public)
    POST   /a2a/tasks
    GET    /a2a/tasks/{id}
    GET    /mcp/tools
    POST   /mcp/tools/invoke               (501 stub in Phase 8)
    GET    /ui                             (minimal HTML streaming demo)
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from src.database import init_db, close_db, get_user_usage_summary_today
from src.gateway.auth import require_user
from src.gateway.routes import tasks, stream, a2a, mcp
from src.gateway.worker import task_worker

logger = logging.getLogger(__name__)


# ── Lifespan ──────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB and start the background task worker on startup."""
    await init_db()
    worker_task = asyncio.create_task(task_worker(), name="gateway-task-worker")
    logger.info("[gateway] Startup complete — worker running")
    try:
        yield
    finally:
        worker_task.cancel()
        try:
            await worker_task
        except asyncio.CancelledError:
            pass
        await close_db()
        logger.info("[gateway] Shutdown complete")


# ── App factory ───────────────────────────────────────────────────────────────


app = FastAPI(
    title="LegionForge Gateway",
    version="1.0.0",
    description="User-facing task API for LegionForge agents.",
    lifespan=lifespan,
    # Disable /docs and /redoc in production — enable in dev via env flag
    # docs_url=None, redoc_url=None,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# In production, lock CORS_ALLOW_ORIGINS to known origins.
# Default: localhost only (safe for household deployment).
# Override: CORS_ALLOW_ORIGINS="https://yourdomain.com" in environment.

import os

_cors_origins = os.environ.get(
    "CORS_ALLOW_ORIGINS", "http://localhost:3000,http://localhost:8080"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(tasks.router, prefix="/tasks", tags=["tasks"])
app.include_router(stream.router, prefix="/tasks", tags=["stream"])
app.include_router(a2a.router, tags=["a2a"])
app.include_router(mcp.router, prefix="/mcp", tags=["mcp"])


# ── Minimal Web UI ────────────────────────────────────────────────────────────


_UI_PATH = Path(__file__).parent / "static" / "index.html"


@app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
async def web_ui() -> HTMLResponse:
    """Serve the minimal streaming demo UI."""
    if _UI_PATH.exists():
        return HTMLResponse(_UI_PATH.read_text())
    return HTMLResponse("<h1>LegionForge Gateway</h1><p>UI not found.</p>")


# ── Health ────────────────────────────────────────────────────────────────────


@app.get("/health", include_in_schema=False)
async def health() -> dict:
    return {"status": "ok", "service": "legionforge-gateway"}


# ── Per-user usage ─────────────────────────────────────────────────────────────


@app.get("/usage/me", tags=["usage"])
async def get_my_usage(user: dict = Depends(require_user)) -> JSONResponse:
    """Return today's token usage for the authenticated gateway user."""
    try:
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
    except Exception as exc:
        logger.error(f"[gateway] /usage/me failed: {exc}")
        return JSONResponse({"error": str(exc)}, status_code=503)


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    uvicorn.run(
        "src.gateway.app:app",
        host="0.0.0.0",  # nosec B104 — intentional: gateway must be reachable on LAN
        port=8080,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
