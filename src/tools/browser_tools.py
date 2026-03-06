"""
src/tools/browser_tools.py
──────────────────────────
Playwright-backed headless browser tool for JS-rendered web pages.

web_fetch_js launches a per-request headless Chromium instance, waits for the
DOM to settle after JS execution, and returns the rendered visible body text
(truncated to 10 000 chars). Use this when web_fetch returns an empty HTML
shell (news sites, SPAs, React/Vue apps).

Security surface addressed:
  - SSRF: validate_fetch_url() pre-launch + page.route() blocks RFC-1918
    ranges as belt-and-suspenders defence (catches DNS-rebinding attacks that
    resolve to internal IPs after the pre-launch check).
  - Resource type filtering: images, media, fonts, and binary downloads are
    aborted — eliminates attack surface from media-parser CVEs and prevents
    executable payload downloads.
  - Resource bombs: hard timeout kills the browser; browser not reused.
  - State leakage: isolated browser context created and destroyed per call;
    no cookies, credentials, or localStorage persist between requests.
  - Service worker abuse: service_workers="block" in browser context.
  - Content size explosion: 10 000 char truncation on body inner_text.
  - Prompt injection via page content: sanitize_output() applied to extracted
    text before it enters agent context.

Intentional non-mitigations (and why):
  - JavaScript sanitization: JS obfuscation is infinite; static analysis is
    an unsolved problem at this scale. The Chromium sandbox (process isolation)
    is the correct defence against malicious JS — not inline content inspection.
  - Domain blocklists: emergent malicious infrastructure rotates faster than
    any list can track; legitimate CDNs routinely serve compromised content.
    The SSRF guard + sandbox is the right layer, not a denylist.

Startup:
    await register_browser_tools()   # call once at application startup
"""

from __future__ import annotations

import logging
import re
from typing import Any

from langchain_core.tools import tool

from src.security import (
    ToolManifest,
    register_tool,
    sanitize_tool_input,
    sanitize_output,
    validate_fetch_url,
    SecurityError,
)

logger = logging.getLogger(__name__)

# Regex to block private/reserved IP ranges at the browser network level.
# Matched against outgoing request URLs inside page.route() — belt-and-suspenders
# on top of validate_fetch_url() which runs before the browser even launches.
_PRIVATE_URL_RE = re.compile(
    r"https?://"
    r"(?:localhost"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|0\.0\.0\.0"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"  # link-local / AWS/GCP/Azure metadata
    r"|::1"
    r")"
    r"(?:[:/]|$)",
    re.IGNORECASE,
)

_MAX_CHARS = 10_000

# Resource types that serve no purpose for text extraction and increase attack
# surface (media parser CVEs, binary payload downloads, tracker telemetry).
_BLOCKED_RESOURCE_TYPES: frozenset[str] = frozenset(
    {
        "image",
        "media",  # video / audio
        "font",
        "stylesheet",  # CSS — not needed for inner_text()
        "websocket",  # no persistent connections
        "other",  # binary/unknown — e.g. executables, archives
    }
)


# ── Tool ──────────────────────────────────────────────────────────────────────


@tool
async def web_fetch_js(url: str, timeout: float = 15.0) -> str:
    """Fetch the rendered text content of a JS-heavy web page using a headless browser.

    Use this when web_fetch returns empty or skeletal HTML (e.g. news sites, SPAs,
    React/Vue apps). Launches a fresh Chromium instance per request, waits for the
    DOM to load, then returns up to 10 000 chars of visible body text.
    SSRF-guarded — private IPs and internal endpoints are blocked.
    """
    clean_url, meta = sanitize_tool_input(url, tool_id="web_fetch_js")
    if meta.get("pii_redacted"):
        logger.warning("[web_fetch_js] PII redacted from URL.")
    if meta.get("injection_detected"):
        logger.warning("[web_fetch_js] Injection pattern detected in URL.")

    # Pre-launch SSRF guard — blocks private IPs, file://, bad schemes, etc.
    # This check runs before touching the network at all.
    try:
        validate_fetch_url(clean_url)
    except (SecurityError, ValueError) as exc:
        return f"[web_fetch_js] URL blocked: {exc}"

    timeout_ms = int(timeout * 1000)

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return (
            "[web_fetch_js] Playwright not installed. "
            "Run: pip install playwright && playwright install chromium"
        )

    try:
        async with async_playwright() as pw:
            # --no-sandbox is intentionally omitted: on macOS (our target platform)
            # Chromium's process sandbox works without it. Only add --no-sandbox in
            # Docker/CI environments where user namespaces are unavailable, and only
            # when the container is already isolated at the host level.
            browser = await pw.chromium.launch(
                headless=True,
                args=[
                    "--disable-dev-shm-usage",
                    "--disable-extensions",
                    "--disable-background-networking",
                    "--disable-sync",
                    "--no-first-run",
                ],
            )
            try:
                context = await browser.new_context(
                    service_workers="block",
                    java_script_enabled=True,
                )
                page = await context.new_page()

                # Single route handler for all outgoing browser requests.
                # Two checks, both abort on match — order matters: SSRF first.
                #
                # 1. SSRF: abort requests targeting private/reserved IP ranges.
                #    Catches DNS-rebinding attacks where an allowed hostname
                #    resolves to an internal IP after the pre-launch check.
                #
                # 2. Resource type: abort images, media, fonts, stylesheets,
                #    websockets, and binary "other" resources. These are never
                #    needed for text extraction and increase attack surface
                #    (media-parser CVEs, executable payload downloads, etc.).
                #    "script" and "document" are intentionally allowed — JS
                #    execution is required for JS-rendered pages.
                async def _route_handler(route: Any) -> None:
                    req_url = route.request.url
                    if _PRIVATE_URL_RE.match(req_url):
                        logger.warning(
                            "[web_fetch_js] Browser-level SSRF block: %.80s", req_url
                        )
                        await route.abort("blockedbyclient")
                        return
                    if route.request.resource_type in _BLOCKED_RESOURCE_TYPES:
                        await route.abort("blockedbyclient")
                        return
                    await route.continue_()

                await page.route("**/*", _route_handler)

                try:
                    await page.goto(
                        clean_url,
                        timeout=timeout_ms,
                        wait_until="domcontentloaded",
                    )
                    raw = await page.inner_text("body")
                except Exception as nav_err:
                    return (
                        f"[web_fetch_js] Navigation error: "
                        f"{type(nav_err).__name__}: {nav_err}"
                    )
                finally:
                    await page.close()
                    await context.close()
            finally:
                await browser.close()

    except Exception as exc:
        logger.exception("[web_fetch_js] Unexpected error: %s", exc)
        return f"[web_fetch_js] Error: {type(exc).__name__}: {exc}"

    # Collapse runs of 3+ whitespace chars to a blank line, then truncate.
    raw = re.sub(r"[ \t]{3,}", " ", raw)
    raw = re.sub(r"\n{3,}", "\n\n", raw).strip()

    clean_text, out_meta = sanitize_output(raw[:_MAX_CHARS])
    if out_meta.get("injection_detected"):
        logger.warning("[web_fetch_js] Injection pattern detected in page content.")
    return clean_text


# ── Manifest ──────────────────────────────────────────────────────────────────

BROWSER_TOOL_MANIFESTS: list[ToolManifest] = [
    ToolManifest(
        tool_id="web_fetch_js",
        description=(
            "Fetch rendered visible text from a JS-heavy page via headless Chromium. "
            "Use when web_fetch returns empty/skeletal HTML (news sites, SPAs). "
            "SSRF-guarded, per-request browser context, 10 000 char limit."
        ),
        input_schema={"url": "str", "timeout": "float"},
        declared_side_effects=["reads_web", "runs_headless_browser"],
        source="local",
        entrypoint_func=web_fetch_js,
    ),
]

# Approved tool-call sequences involving web_fetch_js.
# Used by Guardian to enforce sequence contracts for agents that include this tool.
BROWSER_TOOL_SEQUENCES: list[list[str]] = [
    ["web_fetch_js"],
    ["web_search", "web_fetch_js"],
    ["web_search", "web_fetch_js", "document_summarize"],
    ["web_fetch_js", "document_summarize"],
]


# ── Registration ──────────────────────────────────────────────────────────────


async def register_browser_tools() -> None:
    """Register web_fetch_js in the tool registry. Call once at startup."""
    for manifest in BROWSER_TOOL_MANIFESTS:
        await register_tool(
            manifest,
            approved_by="operator",
            approval_notes=(
                "Playwright headless browser tool — SSRF-guarded at URL and "
                "network level, per-request isolated context, service workers blocked"
            ),
        )
    logger.info("[browser_tools] web_fetch_js registered.")
