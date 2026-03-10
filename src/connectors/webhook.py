"""
src/connectors/webhook.py
──────────────────────────
Generic inbound/outbound webhook connector for LegionForge.

Serves a minimal FastAPI server (:8081 by default) that:

  POST /inbound
    Accepts a task + callback_url, optionally verifies HMAC-SHA256 signature,
    queues the task to the gateway, streams to completion, then POSTs the
    result JSON to the callback_url.
    Returns HTTP 202 immediately (fire-and-forget background task).

  GET /health
    Returns {status: "ok", gateway_url: "...", version: "0.7.1-alpha"}

This covers GitHub webhooks, Zapier, Make/Integromat, IFTTT, cron scripts,
and any other HTTP client — no platform-specific SDK needed on the caller side.

Security:
    - HMAC-SHA256 signature verification via X-Hub-Signature-256 header
      (same format as GitHub webhooks) when legionforge_webhook_inbound_secret
      is set in Keychain. Empty secret = verification skipped.
    - The connector authenticates to the gateway as 'webhook-bot' user only.
    - action="webhook" is set in all submitted tasks for Guardian audit logs.
    - Input length is capped at 4000 chars before submission.
    - Callback URL must be http:// or https:// (rejects other schemes).

Setup (one-time):
    1. Create the gateway user:
         make create-user USERNAME=webhook-bot
       (copy the printed API key)
    2. Store the gateway API key in Keychain:
         security add-generic-password -s legionforge_webhook_api_key -a api_key -w '<key>'
    3. (Optional) Set an HMAC secret for inbound verification:
         security add-generic-password -s legionforge_webhook_inbound_secret -a api_key -w '<secret>'
    4. Start the connector:
         make webhook-start
    5. Send a task:
         curl -X POST http://localhost:8081/inbound \\
           -H "Content-Type: application/json" \\
           -d '{"task": "Summarise the LLM safety landscape", "callback_url": "https://example.com/cb"}'

Inbound request body (JSON):
    task         (str, required)   — task text, max 4000 chars
    callback_url (str, required)   — HTTP/HTTPS URL to POST result to
    agent_type   (str, optional)   — "orchestrator" | "researcher" | "base_agent"
    secret       (str, optional)   — per-request HMAC secret override

Outbound callback POST body (JSON):
    task_id      (str)   — gateway task ID
    status       (str)   — "complete" | "error" | "cancelled"
    result       (str)   — accumulated agent output (or error message)
    elapsed_seconds (float) — wall time from submission to completion

Environment / Keychain:
    legionforge_webhook_api_key        — Gateway Bearer API key (Keychain, required)
    legionforge_webhook_inbound_secret — HMAC-SHA256 secret (Keychain, optional)
    WEBHOOK_GATEWAY_URL                — default http://localhost:8080
    WEBHOOK_HOST                       — bind address; default 127.0.0.1 (set 0.0.0.0 behind a reverse proxy)
    WEBHOOK_PORT                       — default 8081
    WEBHOOK_AGENT_TYPE                 — default "orchestrator"
    WEBHOOK_WORKERS                    — uvicorn worker count, default 1
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import time

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.connectors.base import _load_secret, _run_task

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────

GATEWAY_URL = os.environ.get("WEBHOOK_GATEWAY_URL", "http://localhost:8080")
PORT = int(os.environ.get("WEBHOOK_PORT", "8081"))
# Default to loopback — set WEBHOOK_HOST=0.0.0.0 when running behind a reverse proxy
# or when the connector needs to receive webhooks directly from the internet.
HOST = os.environ.get("WEBHOOK_HOST", "127.0.0.1")
AGENT_TYPE = os.environ.get("WEBHOOK_AGENT_TYPE", "orchestrator")
WORKERS = int(os.environ.get("WEBHOOK_WORKERS", "1"))

_TASK_MAX_LEN = 4000
_ALLOWED_SCHEMES = ("http://", "https://")


# ── HMAC verification ──────────────────────────────────────────────────────────


def _verify_hmac(body: bytes, signature_header: str, secret: str) -> bool:
    """
    Verify a GitHub-style HMAC-SHA256 signature.

    Expected header format: ``sha256=<hex_digest>``

    Returns True if valid, False otherwise.
    Uses ``hmac.compare_digest`` to prevent timing attacks.
    """
    if not signature_header.startswith("sha256="):
        return False
    expected_hex = signature_header[len("sha256=") :]
    computed = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, expected_hex)


# ── Request / response models ──────────────────────────────────────────────────


class InboundRequest(BaseModel):
    task: str
    callback_url: str
    agent_type: str = AGENT_TYPE
    secret: str = ""  # per-request HMAC override (use Keychain secret by default)


# ── FastAPI app ────────────────────────────────────────────────────────────────


def build_app(api_key: str, inbound_secret: str) -> FastAPI:
    """
    Build the webhook FastAPI application.

    Args:
        api_key:        Gateway Bearer API key for task submission.
        inbound_secret: HMAC-SHA256 secret for inbound verification.
                        Empty string = verification skipped.
    """
    app = FastAPI(title="LegionForge Webhook Connector", docs_url=None, redoc_url=None)

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "gateway_url": GATEWAY_URL,
                "version": "0.7.1-alpha",
            }
        )

    @app.post("/inbound", status_code=202)
    async def inbound(req: InboundRequest, request: Request) -> JSONResponse:
        # ── HMAC verification ────────────────────────────────────────────────
        effective_secret = req.secret or inbound_secret
        if effective_secret:
            sig = request.headers.get("x-hub-signature-256", "")
            body = await request.body()
            if not _verify_hmac(body, sig, effective_secret):
                raise HTTPException(
                    status_code=401,
                    detail="HMAC signature verification failed.",
                )

        # ── Input validation ─────────────────────────────────────────────────
        task_text = req.task.strip()
        if not task_text:
            raise HTTPException(status_code=422, detail="task must not be empty.")
        if len(task_text) > _TASK_MAX_LEN:
            raise HTTPException(
                status_code=422,
                detail=f"task exceeds {_TASK_MAX_LEN} character limit.",
            )

        callback_url = req.callback_url.strip()
        if not any(callback_url.startswith(s) for s in _ALLOWED_SCHEMES):
            raise HTTPException(
                status_code=422,
                detail="callback_url must start with http:// or https://",
            )

        logger.info(
            f"[webhook] Queuing task len={len(task_text)} "
            f"agent={req.agent_type} callback={callback_url!r}"
        )

        # ── Fire background task (don't block the response) ──────────────────
        asyncio.create_task(
            _process_and_callback(
                task_text=task_text,
                api_key=api_key,
                agent_type=req.agent_type,
                callback_url=callback_url,
            )
        )

        return JSONResponse(
            status_code=202,
            content={"message": "queued", "callback_url": callback_url},
        )

    return app


async def _process_and_callback(
    task_text: str,
    api_key: str,
    agent_type: str,
    callback_url: str,
) -> None:
    """
    Run a task to completion via the gateway and POST the result to callback_url.

    This runs as a background asyncio task — errors are logged, not raised.
    """
    on_token: asyncio.Queue = asyncio.Queue()
    accumulated = ""
    status = "complete"
    start = time.monotonic()

    async def _collect() -> None:
        nonlocal accumulated, status
        done = False
        while not done:
            try:
                item = await asyncio.wait_for(on_token.get(), timeout=300.0)
            except asyncio.TimeoutError:
                status = "error"
                accumulated += "\n\n[timeout waiting for task result]"
                return

            if isinstance(item, str):
                accumulated += item
            elif isinstance(item, dict):
                if item.get("done"):
                    done = True
                elif "error" in item:
                    accumulated += f"\n\n{item['error']}"
                    status = "error"
                    done = True

    try:
        await asyncio.gather(
            _run_task(
                task_text, api_key, GATEWAY_URL, agent_type, on_token, action="webhook"
            ),
            _collect(),
        )
    except Exception as exc:
        logger.error(f"[webhook] Task runner error: {exc}")
        status = "error"
        accumulated = str(exc)

    elapsed = time.monotonic() - start

    payload = {
        "status": status,
        "result": accumulated,
        "elapsed_seconds": round(elapsed, 2),
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(callback_url, json=payload)
            logger.info(
                f"[webhook] Callback POST {callback_url} → {resp.status_code} "
                f"elapsed={elapsed:.1f}s"
            )
    except Exception as exc:
        logger.error(f"[webhook] Callback POST failed: {exc}")


# ── Entry point ────────────────────────────────────────────────────────────────


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    api_key = _load_secret("legionforge_webhook_api_key", "WEBHOOK_GATEWAY_API_KEY")

    # Inbound secret is optional — empty string = verification skipped
    try:
        inbound_secret = _load_secret(
            "legionforge_webhook_inbound_secret", "WEBHOOK_INBOUND_SECRET"
        )
    except RuntimeError:
        inbound_secret = ""
        logger.warning(
            "[webhook] No inbound secret configured — HMAC verification disabled. "
            "Set legionforge_webhook_inbound_secret in Keychain for production use."
        )

    logger.info(
        f"[webhook] Starting connector "
        f"host={HOST} port={PORT} gateway={GATEWAY_URL} agent={AGENT_TYPE} "
        f"hmac={'enabled' if inbound_secret else 'disabled'}"
    )

    app = build_app(api_key, inbound_secret)
    uvicorn.run(app, host=HOST, port=PORT, workers=WORKERS, log_level="info")


if __name__ == "__main__":
    main()
