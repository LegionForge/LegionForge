"""
src/tools/http_tools.py
────────────────────────
Phase 9 HTTP tools: http_get and http_post.

Both tools enforce:
  - SSRF protection via validate_fetch_url() (private IPs, localhost, metadata
    endpoints, non-HTTP schemes all blocked).
  - Input sanitization on all string arguments (PII redaction + injection detection).
  - Output sanitization on the response body before it enters agent context.
  - Response size cap (settings.tools.max_response_bytes, default 50 KB).
  - Hard timeout (settings.tools.http_timeout_seconds, default 30 s).
  - POST body size cap (settings.tools.max_post_body_bytes, default 10 KB).
  - content_type restricted to application/json or text/plain.

Startup:
    await register_http_tools()   # call once at application startup
"""

from __future__ import annotations

import logging
from typing import Literal

import httpx
from langchain_core.tools import tool

from config.settings import settings
from src.security import (
    ToolManifest,
    register_tool,
    sanitize_tool_input,
    sanitize_output,
    validate_fetch_url,
    SecurityError,
)

logger = logging.getLogger(__name__)

_ALLOWED_CONTENT_TYPES: frozenset[str] = frozenset({"application/json", "text/plain"})


# ── Tools ─────────────────────────────────────────────────────────────────────


@tool
async def http_get(url: str) -> str:
    """Fetch the body of a URL via HTTP GET. Returns up to 50 KB of response text."""
    clean_url, meta = sanitize_tool_input(url, tool_id="http_get")
    if meta.get("pii_redacted"):
        logger.warning("[http_get] PII redacted from URL.")
    if meta.get("injection_detected"):
        logger.warning("[http_get] Injection pattern detected in URL.")

    try:
        validate_fetch_url(clean_url)
    except (SecurityError, ValueError) as exc:
        return f"[http_get] URL blocked: {exc}"

    timeout = settings.tools.http_timeout_seconds
    max_bytes = settings.tools.max_response_bytes

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(clean_url)
            resp.raise_for_status()
            raw = resp.text[:max_bytes]
    except httpx.HTTPStatusError as exc:
        return (
            f"[http_get] HTTP {exc.response.status_code}: {exc.response.reason_phrase}"
        )
    except httpx.RequestError as exc:
        return f"[http_get] Request error: {type(exc).__name__}"

    clean_body, out_meta = sanitize_output(raw)
    if out_meta.get("injection_detected"):
        logger.warning("[http_get] Injection pattern detected in response body.")
    return clean_body


@tool
async def http_post(
    url: str,
    body: str,
    content_type: Literal["application/json", "text/plain"] = "application/json",
) -> str:
    """POST a string body to a URL. content_type must be application/json or text/plain.
    Body is capped at 10 KB. Returns up to 50 KB of response text."""
    clean_url, url_meta = sanitize_tool_input(url, tool_id="http_post")
    if url_meta.get("pii_redacted"):
        logger.warning("[http_post] PII redacted from URL.")

    # Validate body size before sanitising (avoids processing huge inputs)
    max_body = settings.tools.max_post_body_bytes
    if len(body.encode()) > max_body:
        return f"[http_post] Body too large (max {max_body} bytes)."

    clean_body_in, body_meta = sanitize_tool_input(body, tool_id="http_post")
    if body_meta.get("pii_redacted"):
        logger.warning("[http_post] PII redacted from POST body before sending.")
    if body_meta.get("injection_detected"):
        logger.warning("[http_post] Injection pattern detected in POST body.")

    if content_type not in _ALLOWED_CONTENT_TYPES:
        return (
            f"[http_post] content_type must be one of {sorted(_ALLOWED_CONTENT_TYPES)}."
        )

    try:
        validate_fetch_url(clean_url)
    except (SecurityError, ValueError) as exc:
        return f"[http_post] URL blocked: {exc}"

    timeout = settings.tools.http_timeout_seconds
    max_resp = settings.tools.max_response_bytes

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.post(
                clean_url,
                content=clean_body_in.encode(),
                headers={"Content-Type": content_type},
            )
            resp.raise_for_status()
            raw = resp.text[:max_resp]
    except httpx.HTTPStatusError as exc:
        return (
            f"[http_post] HTTP {exc.response.status_code}: {exc.response.reason_phrase}"
        )
    except httpx.RequestError as exc:
        return f"[http_post] Request error: {type(exc).__name__}"

    clean_resp, out_meta = sanitize_output(raw)
    if out_meta.get("injection_detected"):
        logger.warning("[http_post] Injection pattern detected in response body.")
    return clean_resp


# ── Manifests ──────────────────────────────────────────────────────────────────

HTTP_TOOL_MANIFESTS: list[ToolManifest] = [
    ToolManifest(
        tool_id="http_get",
        description="Fetch the body of a URL via HTTP GET (max 50 KB, SSRF-guarded).",
        input_schema={"url": "str"},
        declared_side_effects=["calls_external_api"],
        source="local",
        entrypoint_func=http_get,
    ),
    ToolManifest(
        tool_id="http_post",
        description=(
            "POST a string body to a URL (application/json or text/plain, max 10 KB body, "
            "SSRF-guarded, PII-sanitized before send)."
        ),
        input_schema={
            "url": "str",
            "body": "str",
            "content_type": "str",
        },
        declared_side_effects=["calls_external_api", "sends_data_externally"],
        source="local",
        entrypoint_func=http_post,
    ),
]

# Approved tool-call sequences that include HTTP tools.
HTTP_TOOL_SEQUENCES: list[list[str]] = [
    ["http_get"],
    ["http_post"],
    ["web_search", "http_get"],
    ["http_get", "http_post"],
    ["web_fetch", "http_post"],
]


# ── Registration ───────────────────────────────────────────────────────────────


async def register_http_tools() -> None:
    """Register http_get and http_post in the tool registry. Call once at startup."""
    for manifest in HTTP_TOOL_MANIFESTS:
        await register_tool(
            manifest,
            approved_by="operator",
            approval_notes="Phase 9 HTTP tools — SSRF-guarded, I/O sanitized",
        )
    logger.info("[http_tools] http_get and http_post registered.")
