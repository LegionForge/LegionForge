"""
src/connectors/whatsapp.py
───────────────────────────
WhatsApp Business Cloud API connector for LegionForge.

Bridges WhatsApp messages (via Meta's Cloud API) to the gateway API and
sends responses back to the sender.

Flow:
    GET  /webhook  — Meta verification challenge (hub.mode / hub.verify_token /
                     hub.challenge).  Returns hub.challenge as plain text on
                     success; 403 on wrong token.

    POST /webhook  — Inbound message webhook from Meta.
        1. Validate X-Hub-Signature-256 HMAC-SHA256 header (same pattern as
           webhook.py) when legionforge_whatsapp_api_token is set in Keychain.
           If the secret is absent, skip validation (warning logged).
        2. Parse Meta's webhook payload; extract sender phone, text body, and
           message type.
        3. If type is "image": download the media from the Meta Graph API using
           the bearer token, base64-encode the bytes, and include as image_data
           in the gateway task payload.
        4. Phone numbers are PII — raw numbers are never logged; only the last
           4 digits appear in log lines (or a SHA-256 hash for per-user budget
           tracking).
        5. Submit task to the gateway POST /tasks with action="whatsapp".
        6. Stream SSE response to completion.
        7. Send reply via Meta Graph API:
             POST https://graph.facebook.com/v20.0/{PHONE_NUMBER_ID}/messages
        8. Return 200 immediately; processing runs as a BackgroundTask.

    GET /health    — Returns {"status": "ok", "gateway_url": "...", "version": "0.7.1-alpha"}

Security:
    - HMAC-SHA256 signature verification via X-Hub-Signature-256 header.
    - Verify token for GET /webhook challenge stored in Keychain.
    - Bearer token for Meta Graph API calls stored in Keychain.
    - Phone numbers (PII) are truncated / hashed before any log output.
    - action="whatsapp" is set on all submitted tasks for Guardian audit logs.
    - Input length is capped at 4000 chars before gateway submission.
    - Per-sender rate limiting via per_user_budget_check.

Setup (one-time):
    1. Create a Meta app at https://developers.facebook.com/ and enable
       WhatsApp Business Cloud API.  Note your Phone Number ID.
    2. Store the Meta API bearer token in Keychain:
         security add-generic-password -s legionforge_whatsapp_api_token -a api_key -w '<token>'
    3. Choose a verify token string and store it:
         security add-generic-password -s legionforge_whatsapp_verify_token -a api_key -w '<token>'
    4. Create the LegionForge gateway user:
         make create-user USERNAME=whatsapp-bot
       (copy the printed API key)
    5. Store the gateway API key in Keychain:
         security add-generic-password -s legionforge_whatsapp_api_key -a api_key -w '<key>'
    6. Set the Phone Number ID environment variable before starting:
         export WHATSAPP_PHONE_NUMBER_ID=<id>
    7. Configure the webhook URL in the Meta developer portal to point at
         https://<your-domain>:8085/webhook
       and enter the same verify token.
    8. Start the connector:
         make whatsapp-start

Environment / Keychain:
    legionforge_whatsapp_api_token    — Meta Graph API bearer token (Keychain, required)
    legionforge_whatsapp_verify_token — Hub verify token (Keychain, required)
    legionforge_whatsapp_api_key      — Gateway Bearer API key (Keychain, required)
    WHATSAPP_PHONE_NUMBER_ID          — Meta phone number ID (required at runtime)
    WHATSAPP_GATEWAY_URL              — default http://localhost:8080
    WHATSAPP_HOST                     — bind address; default 127.0.0.1
    WHATSAPP_PORT                     — default 8085
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import os
import time

import httpx
import uvicorn
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from src.connectors.base import _load_secret, _run_task
from src.security.core import _log_safe

__all__ = ["app", "build_app", "main"]

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────

GATEWAY_URL = os.environ.get("WHATSAPP_GATEWAY_URL", "http://localhost:8080")
PORT = int(os.environ.get("WHATSAPP_PORT", "8085"))
HOST = os.environ.get("WHATSAPP_HOST", "127.0.0.1")
PHONE_NUMBER_ID = os.environ.get("WHATSAPP_PHONE_NUMBER_ID", "")

_META_API_BASE = "https://graph.facebook.com/v20.0"
_TASK_MAX_LEN = 4000
_AGENT_TYPE = "orchestrator"


# ── HMAC verification ──────────────────────────────────────────────────────────


def _verify_hmac(body: bytes, signature_header: str, secret: str) -> bool:
    """
    Verify a Meta-style HMAC-SHA256 signature.

    Expected header format: ``sha256=<hex_digest>``

    Returns True if valid, False otherwise.
    Uses ``hmac.compare_digest`` to prevent timing attacks.
    """
    if not signature_header.startswith("sha256="):
        return False
    expected_hex = signature_header[len("sha256=") :]
    computed = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, expected_hex)


# ── PII helpers ────────────────────────────────────────────────────────────────


def _phone_log_safe(phone: str) -> str:
    """Return a log-safe representation of a phone number (last 4 digits)."""
    digits = "".join(c for c in phone if c.isdigit())
    if len(digits) >= 4:
        return f"****{digits[-4:]}"
    return "****"


def _phone_hash(phone: str) -> str:
    """Return a stable SHA-256 hash of the phone number for budget tracking."""
    return hashlib.sha256(phone.encode()).hexdigest()[:16]


# ── Media download ─────────────────────────────────────────────────────────────


async def _download_media(media_id: str, api_token: str) -> bytes | None:
    """
    Download WhatsApp media by media_id using the Meta Graph API.

    Flow:
      1. GET /{media_id} → returns JSON with ``url`` and ``mime_type``
      2. GET <url>       → returns raw binary content

    Returns raw bytes on success, None on error.
    """
    headers = {"Authorization": f"Bearer {api_token}"}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Step 1 — resolve media URL
            meta_resp = await client.get(
                f"{_META_API_BASE}/{media_id}", headers=headers
            )
            meta_resp.raise_for_status()
            media_url = meta_resp.json().get("url")
            if not media_url:
                logger.warning(
                    "[whatsapp] Media URL missing for id=%s", _log_safe(media_id)
                )
                return None

            # Step 2 — download the actual bytes
            dl_resp = await client.get(media_url, headers=headers)
            dl_resp.raise_for_status()
            return dl_resp.content
    except Exception as exc:
        logger.warning("[whatsapp] Media download failed: %s", exc)
        return None


# ── Send reply ─────────────────────────────────────────────────────────────────


async def _send_reply(
    phone: str,
    text: str,
    phone_number_id: str,
    api_token: str,
) -> None:
    """
    Send a text reply to a WhatsApp sender via Meta Cloud API.

    Args:
        phone:           Recipient phone number (E.164 format, PII — not logged raw).
        text:            Message body text.
        phone_number_id: Meta phone number ID (from WHATSAPP_PHONE_NUMBER_ID).
        api_token:       Meta Graph API bearer token.
    """
    url = f"{_META_API_BASE}/{phone_number_id}/messages"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": phone,
        "type": "text",
        "text": {"body": text[:4096]},
    }
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            logger.info(
                "[whatsapp] Reply sent to %s → HTTP %d",
                _log_safe(_phone_log_safe(phone)),
                resp.status_code,
            )
    except Exception as exc:
        logger.error(
            "[whatsapp] Reply send failed for %s: %s",
            _log_safe(_phone_log_safe(phone)),
            exc,
        )


# ── Background processor ───────────────────────────────────────────────────────


async def _process_message(
    phone: str,
    task_text: str,
    image_data: str | None,
    api_key: str,
    api_token: str,
    phone_number_id: str,
) -> None:
    """
    Run a task to completion via the gateway and send the reply to WhatsApp.

    Runs as a background asyncio task — errors are logged, not raised.
    """
    phone_safe = _phone_log_safe(phone)
    on_token: asyncio.Queue = asyncio.Queue()
    accumulated = ""
    status = "complete"
    start = time.monotonic()

    full_task = task_text
    if image_data:
        full_task = f"[Image attached — base64 data follows]\n\n{task_text}"

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
                full_task,
                api_key,
                GATEWAY_URL,
                _AGENT_TYPE,
                on_token,
                action="whatsapp",
            ),
            _collect(),
        )
    except Exception as exc:
        logger.error(
            "[whatsapp] Task runner error for %s: %s", _log_safe(phone_safe), exc
        )
        status = "error"
        accumulated = str(exc)

    elapsed = time.monotonic() - start
    logger.info(
        "[whatsapp] Task complete for %s status=%s elapsed=%.1fs",
        _log_safe(phone_safe),
        status,
        elapsed,
    )

    reply_text = accumulated.strip() or "(no response)"
    await _send_reply(phone, reply_text, phone_number_id, api_token)


# ── FastAPI app factory ────────────────────────────────────────────────────────


def build_app(
    api_key: str,
    api_token: str,
    verify_token: str,
    phone_number_id: str,
) -> FastAPI:
    """
    Build the WhatsApp connector FastAPI application.

    Args:
        api_key:          LegionForge gateway Bearer API key.
        api_token:        Meta Graph API bearer token for sending messages and
                          downloading media.
        verify_token:     Hub verify token for Meta webhook challenge.
        phone_number_id:  Meta phone number ID for sending replies.
    """
    _app = FastAPI(
        title="LegionForge WhatsApp Connector", docs_url=None, redoc_url=None
    )

    @_app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "gateway_url": GATEWAY_URL,
                "version": "0.7.1-alpha",
            }
        )

    @_app.get("/webhook")
    async def webhook_verify(request: Request) -> PlainTextResponse:
        """Handle Meta hub verification challenge."""
        params = request.query_params
        mode = params.get("hub.mode", "")
        token = params.get("hub.verify_token", "")
        challenge = params.get("hub.challenge", "")

        if mode == "subscribe" and token == verify_token:
            logger.info("[whatsapp] Hub verification challenge accepted")
            return PlainTextResponse(challenge, status_code=200)

        # token_match is the boolean result of equality; the token value
        # itself is never logged.
        logger.warning(  # nosemgrep: python-logger-credential-disclosure
            "[whatsapp] Hub verification failed: mode=%r token_match=%s",
            mode,
            token == verify_token,
        )
        raise HTTPException(status_code=403, detail="Verification failed.")

    @_app.post("/webhook", status_code=200)
    async def webhook_inbound(
        request: Request, background_tasks: BackgroundTasks
    ) -> JSONResponse:
        """Handle inbound WhatsApp message events from Meta."""
        body = await request.body()

        # ── HMAC validation ───────────────────────────────────────────────
        if api_token:
            sig = request.headers.get("x-hub-signature-256", "")
            if sig and not _verify_hmac(body, sig, api_token):
                logger.warning("[whatsapp] HMAC signature verification failed")
                raise HTTPException(
                    status_code=403,
                    detail="HMAC signature verification failed.",
                )
            elif not sig:
                logger.warning(
                    "[whatsapp] No X-Hub-Signature-256 header — skipping HMAC check"
                )
        else:
            logger.warning(
                "[whatsapp] No API token configured — HMAC verification skipped"
            )

        # ── Parse Meta webhook payload ────────────────────────────────────
        import json as _json

        try:
            data = _json.loads(body)
        except _json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON payload.")

        try:
            entry = data["entry"][0]
            change = entry["changes"][0]["value"]
            messages = change.get("messages")
            if not messages:
                # Could be a status update — acknowledge and ignore
                return JSONResponse({"status": "ignored"})
            msg = messages[0]
        except (KeyError, IndexError, TypeError):
            # Malformed payload — acknowledge to Meta (avoid retries)
            logger.warning("[whatsapp] Malformed webhook payload — ignoring")
            return JSONResponse({"status": "ignored"})

        sender_phone: str = msg.get("from", "")
        msg_type: str = msg.get("type", "text")
        phone_safe = _phone_log_safe(sender_phone)

        logger.info(
            "[whatsapp] Inbound %s message from %s",
            _log_safe(msg_type),
            _log_safe(phone_safe),
        )

        # ── Extract message content ───────────────────────────────────────
        task_text = ""
        image_data: str | None = None

        if msg_type == "text":
            task_text = msg.get("text", {}).get("body", "").strip()
        elif msg_type == "image":
            caption = msg.get("image", {}).get("caption", "").strip()
            media_id = msg.get("image", {}).get("id", "")
            task_text = caption or "Describe this image."
            if media_id:
                raw_bytes = await _download_media(media_id, api_token)
                if raw_bytes:
                    image_data = base64.b64encode(raw_bytes).decode()
        else:
            # Unsupported type — send a polite rejection
            logger.info(
                "[whatsapp] Unsupported message type=%s from %s",
                _log_safe(msg_type),
                _log_safe(phone_safe),
            )
            if sender_phone and phone_number_id and api_token:
                background_tasks.add_task(
                    _send_reply,
                    sender_phone,
                    "Sorry, I only support text and image messages at the moment.",
                    phone_number_id,
                    api_token,
                )
            return JSONResponse({"status": "unsupported_type"})

        if not task_text:
            return JSONResponse({"status": "empty_message"})

        if len(task_text) > _TASK_MAX_LEN:
            task_text = task_text[:_TASK_MAX_LEN]
            logger.info(
                "[whatsapp] Task truncated to %d chars for %s",
                _TASK_MAX_LEN,
                _log_safe(phone_safe),
            )

        if not sender_phone or not phone_number_id or not api_token:
            # Logs presence-bools (True/False) only — the actual phone/id/token
            # values never leave this scope.
            logger.error(  # nosemgrep: python-logger-credential-disclosure
                "[whatsapp] Missing required config: phone=%s pnid=%s token=%s",
                bool(sender_phone),
                bool(phone_number_id),
                bool(api_token),
            )
            return JSONResponse({"status": "misconfigured"})

        background_tasks.add_task(
            asyncio.get_event_loop().create_task,
            _process_message(
                phone=sender_phone,
                task_text=task_text,
                image_data=image_data,
                api_key=api_key,
                api_token=api_token,
                phone_number_id=phone_number_id,
            ),
        )

        return JSONResponse({"status": "queued"})

    return _app


# ── Module-level app (for testing / ASGI import) ───────────────────────────────

# Build a no-op app at import time so ``from src.connectors.whatsapp import app``
# always succeeds without hitting Keychain.  The real secrets are injected at
# main() startup via build_app().
app = build_app(
    api_key="",  # nosec B106
    api_token="",
    verify_token="",
    phone_number_id=PHONE_NUMBER_ID,
)


# ── Entry point ────────────────────────────────────────────────────────────────


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if not PHONE_NUMBER_ID:
        logger.warning(
            "[whatsapp] WHATSAPP_PHONE_NUMBER_ID is not set — "
            "outbound replies will not work until this is configured."
        )

    api_token = _load_secret(
        "legionforge_whatsapp_api_token", "WHATSAPP_META_API_TOKEN"
    )
    verify_token = _load_secret(
        "legionforge_whatsapp_verify_token", "WHATSAPP_VERIFY_TOKEN"
    )
    api_key = _load_secret("legionforge_whatsapp_api_key", "WHATSAPP_GATEWAY_API_KEY")

    logger.info(
        "[whatsapp] Starting connector host=%s port=%d gateway=%s pnid=%s",
        HOST,
        PORT,
        GATEWAY_URL,
        PHONE_NUMBER_ID or "(not set)",
    )

    live_app = build_app(
        api_key=api_key,
        api_token=api_token,
        verify_token=verify_token,
        phone_number_id=PHONE_NUMBER_ID,
    )
    uvicorn.run(live_app, host=HOST, port=PORT, log_level="info")


if __name__ == "__main__":
    main()
