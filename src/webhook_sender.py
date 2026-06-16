"""
src/webhook_sender.py
──────────────────────
Fire-and-forget task completion webhook sender for Phase 26.

When a task has a ``callback_url``, the worker calls ``send_callback()``
after the task reaches a terminal state (complete or failed).

Security:
    - Only http:// and https:// callback URLs are accepted.
    - If ``legionforge_webhook_inbound_secret`` is set in the macOS Keychain,
      the request body is signed with HMAC-SHA256 and the signature is sent
      in the ``X-LegionForge-Signature-256`` header (``sha256=<hex>``).
      Callers can verify the signature to confirm the callback is authentic.
    - Errors are logged but never propagated — a failed callback does not
      affect the task's status.

Retry policy:
    3 attempts with exponential backoff (2s, 4s, 8s) before giving up.
    Each attempt uses a 10-second read timeout.

Callback payload (POST body, application/json):
    {
        "task_id":      "<uuid>",
        "status":       "complete" | "failed",
        "result":       "<text>" | null,
        "error":        "<text>" | null,
        "agent_type":   "<type>",
        "completed_at": "<ISO 8601 UTC>"
    }

Usage (internal, called from src/gateway/worker.py):
    from src.webhook_sender import send_callback
    await send_callback(task_id, callback_url, payload)
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

_ALLOWED_SCHEMES = {"http", "https"}
_MAX_RETRIES = 3
_BACKOFF_BASE = 2.0  # seconds — doubles each retry
_TIMEOUT = 10.0  # seconds per attempt


def _get_hmac_secret() -> bytes | None:
    """Return the webhook signing secret, or None if unset.

    Checks (in order):
      1. ``LEGIONFORGE_WEBHOOK_INBOUND_SECRET`` env var (injected by gateway-start)
      2. CredentialStore in-memory cache (populated at gateway startup)
    """
    secret: str | None = os.environ.get("LEGIONFORGE_WEBHOOK_INBOUND_SECRET") or None
    if not secret:
        try:
            from src.credentials import creds

            secret = creds.get("legionforge_webhook_inbound_secret")
        except Exception:  # nosec B110
            pass
    return secret.encode() if secret else None


def _sign_body(body: bytes, secret: bytes) -> str:
    """Return ``sha256=<hex>`` HMAC-SHA256 signature of ``body``."""
    mac = hmac.new(secret, body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def _is_valid_url(url: str) -> bool:
    """Return True if url is an HTTP(S) URL."""
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return parsed.scheme in _ALLOWED_SCHEMES and bool(parsed.netloc)
    except Exception:
        return False


async def send_callback(
    task_id: str,
    callback_url: str,
    payload: dict[str, Any],
) -> None:
    """
    POST ``payload`` as JSON to ``callback_url`` with up to 3 retries.

    Errors are logged but never raised — callers should not await this in a
    way that can block task finalization.  Wrap in ``asyncio.create_task()``
    for true fire-and-forget if preferred.

    Args:
        task_id:      Task UUID (used in log messages).
        callback_url: HTTP(S) URL to POST to.
        payload:      JSON-serializable dict.
    """
    if not _is_valid_url(callback_url):
        logger.warning(
            "[webhook] Invalid callback_url for task %s — skipping: %r",
            task_id,
            callback_url,
        )
        return

    try:
        import httpx
    except ImportError:
        logger.warning(
            "[webhook] httpx not available — cannot send callback for task %s", task_id
        )
        return

    body = json.dumps(payload, default=str).encode()
    headers = {"Content-Type": "application/json", "X-LegionForge-Task-ID": task_id}

    secret = _get_hmac_secret()
    if secret:
        headers["X-LegionForge-Signature-256"] = _sign_body(body, secret)

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(callback_url, content=body, headers=headers)
            if resp.status_code < 500:
                logger.info(
                    "[webhook] Callback for task %s → %s HTTP %d (attempt %d)",
                    task_id,
                    callback_url,
                    resp.status_code,
                    attempt,
                )
                return
            logger.warning(
                "[webhook] Callback for task %s returned HTTP %d — will retry",
                task_id,
                resp.status_code,
            )
        except Exception as exc:
            logger.warning(
                "[webhook] Callback attempt %d/%d failed for task %s: %s",
                attempt,
                _MAX_RETRIES,
                task_id,
                exc,
            )

        if attempt < _MAX_RETRIES:
            backoff = _BACKOFF_BASE**attempt
            await asyncio.sleep(backoff)

    logger.error(
        "[webhook] All %d callback attempts failed for task %s → %s",
        _MAX_RETRIES,
        task_id,
        callback_url,
    )
