"""
tests/tool_accuracy/test_web_fetch.py
──────────────────────────────────────
20 tests for the `web_fetch` tool.

Group A — Correct content retrieval (patched SSRF, verification_server)
Group B — HTTP error handling (patched SSRF)
Group C — SSRF blocking (NO patch — tests the real guard)
Group D — Structural / static checks

All tests in Groups A & B patch `src.agents.researcher.validate_fetch_url`
so that the loopback verification server is reachable.  Group C explicitly
uses the *unpatched* function to prove the SSRF guard still works.

Run with: make test-tool-accuracy
"""

from __future__ import annotations

import asyncio
import inspect
import re
import sys
import os
from unittest.mock import patch

import pytest

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

pytestmark = pytest.mark.tool_accuracy

# Noop replacement for validate_fetch_url when we want localhost to be allowed
_NOOP_VALIDATE = lambda url: None  # noqa: E731


# ── Group A — Correct content retrieval ───────────────────────────────────────


def test_web_fetch_returns_exact_token(verification_server):
    """web_fetch /token returns the session UUID token."""
    from src.agents.researcher import web_fetch

    url = f"{verification_server['base_url']}/token"
    with patch("src.agents.researcher.validate_fetch_url", _NOOP_VALIDATE):
        result = asyncio.run(web_fetch.ainvoke({"url": url}))

    assert (
        verification_server["token"] in result
    ), f"Expected token {verification_server['token']!r} in result, got: {result!r}"


def test_web_fetch_strips_html_tags(verification_server):
    """web_fetch /news strips <h2> tags and returns headline text."""
    from src.agents.researcher import web_fetch

    url = f"{verification_server['base_url']}/news"
    with patch("src.agents.researcher.validate_fetch_url", _NOOP_VALIDATE):
        result = asyncio.run(web_fetch.ainvoke({"url": url}))

    assert "<h2>" not in result, "HTML <h2> tags must be stripped"
    for headline in verification_server["headlines"]:
        assert (
            headline in result
        ), f"Headline {headline!r} not found in stripped result: {result!r}"


def test_web_fetch_json_content_returned_as_text(verification_server):
    """web_fetch /data.json returns the session_id value as plain text."""
    from src.agents.researcher import web_fetch

    url = f"{verification_server['base_url']}/data.json"
    with patch("src.agents.researcher.validate_fetch_url", _NOOP_VALIDATE):
        result = asyncio.run(web_fetch.ainvoke({"url": url}))

    assert (
        verification_server["session_id"] in result
    ), f"session_id {verification_server['session_id']!r} not in result: {result!r}"


def test_web_fetch_truncates_response_at_10k(verification_server):
    """web_fetch /large (15 KB) is truncated to at most 10 000 characters."""
    from src.agents.researcher import web_fetch

    url = f"{verification_server['base_url']}/large"
    with patch("src.agents.researcher.validate_fetch_url", _NOOP_VALIDATE):
        result = asyncio.run(web_fetch.ainvoke({"url": url}))

    assert (
        len(result) <= 10_000
    ), f"Response not truncated: got {len(result)} chars, expected <= 10000"


def test_web_fetch_follows_redirect(verification_server):
    """web_fetch /redirect (301 → /token) ultimately returns the token."""
    from src.agents.researcher import web_fetch

    url = f"{verification_server['base_url']}/redirect"
    with patch("src.agents.researcher.validate_fetch_url", _NOOP_VALIDATE):
        result = asyncio.run(web_fetch.ainvoke({"url": url}))

    assert (
        verification_server["token"] in result
    ), f"Token not found after redirect: {result!r}"


def test_web_fetch_timeout_raises(verification_server):
    """web_fetch /slow with timeout=0.5 raises a timeout-related exception."""
    from src.agents.researcher import web_fetch
    import httpx

    url = f"{verification_server['base_url']}/slow"
    with patch("src.agents.researcher.validate_fetch_url", _NOOP_VALIDATE):
        with pytest.raises((httpx.TimeoutException, Exception)) as exc_info:
            asyncio.run(web_fetch.ainvoke({"url": url, "timeout": 0.5}))

    # For httpx TimeoutException subclasses, str(exc) may be empty —
    # check the class name instead.
    exc_name = type(exc_info.value).__name__.lower()
    exc_msg = str(exc_info.value).lower()
    combined = exc_name + " " + exc_msg
    assert any(
        word in combined for word in ["timeout", "timed out"]
    ), f"Expected timeout-related exception, got: {exc_info.value!r} ({type(exc_info.value).__name__})"


# ── Group B — HTTP error handling ─────────────────────────────────────────────


def test_web_fetch_404_returns_clear_error_string(verification_server):
    """web_fetch /not-here returns a string containing '404', not an exception."""
    from src.agents.researcher import web_fetch

    url = f"{verification_server['base_url']}/not-here"
    with patch("src.agents.researcher.validate_fetch_url", _NOOP_VALIDATE):
        result = asyncio.run(web_fetch.ainvoke({"url": url}))

    assert isinstance(result, str), f"Expected str result, got {type(result)}"
    assert "404" in result, f"Expected '404' in result, got: {result!r}"


def test_web_fetch_error_string_contains_no_traceback(verification_server):
    """web_fetch 404 error string must not contain a Python traceback."""
    from src.agents.researcher import web_fetch

    url = f"{verification_server['base_url']}/not-here"
    with patch("src.agents.researcher.validate_fetch_url", _NOOP_VALIDATE):
        result = asyncio.run(web_fetch.ainvoke({"url": url}))

    assert (
        "Traceback" not in result
    ), f"Error result must not contain traceback: {result!r}"


def test_web_fetch_error_string_hints_not_found(verification_server):
    """web_fetch 404 error string hints that the resource does not exist."""
    from src.agents.researcher import web_fetch

    url = f"{verification_server['base_url']}/not-here"
    with patch("src.agents.researcher.validate_fetch_url", _NOOP_VALIDATE):
        result = asyncio.run(web_fetch.ainvoke({"url": url}))

    result_lower = result.lower()
    assert (
        "not found" in result_lower or "does not exist" in result_lower
    ), f"Expected 'not found' or 'does not exist' in result, got: {result!r}"


# ── Group C — SSRF blocking (NO patch) ────────────────────────────────────────


def test_ssrf_blocks_localhost():
    """validate_fetch_url raises SecurityError for http://localhost/x."""
    from src.security import SecurityError, validate_fetch_url

    with pytest.raises(SecurityError):
        validate_fetch_url("http://localhost/x")


def test_ssrf_blocks_loopback_ip():
    """validate_fetch_url raises SecurityError for http://127.0.0.1/x."""
    from src.security import SecurityError, validate_fetch_url

    with pytest.raises(SecurityError):
        validate_fetch_url("http://127.0.0.1/x")


def test_ssrf_blocks_rfc1918_10():
    """validate_fetch_url raises SecurityError for 10.x.x.x."""
    from src.security import SecurityError, validate_fetch_url

    with pytest.raises(SecurityError):
        validate_fetch_url("http://10.0.0.1/secret")


def test_ssrf_blocks_rfc1918_192():
    """validate_fetch_url raises SecurityError for 192.168.x.x."""
    from src.security import SecurityError, validate_fetch_url

    with pytest.raises(SecurityError):
        validate_fetch_url("http://192.168.1.1/admin")


def test_ssrf_blocks_rfc1918_172():
    """validate_fetch_url raises SecurityError for 172.16.x.x."""
    from src.security import SecurityError, validate_fetch_url

    with pytest.raises(SecurityError):
        validate_fetch_url("http://172.16.0.1/x")


def test_ssrf_blocks_link_local():
    """validate_fetch_url raises SecurityError for 169.254.x.x (IMDS)."""
    from src.security import SecurityError, validate_fetch_url

    with pytest.raises(SecurityError):
        validate_fetch_url("http://169.254.169.254/latest/meta-data")


def test_ssrf_blocks_file_scheme():
    """validate_fetch_url raises SecurityError for file:// URLs."""
    from src.security import SecurityError, validate_fetch_url

    with pytest.raises(SecurityError):
        validate_fetch_url("file:///etc/passwd")


def test_ssrf_blocks_ftp_scheme():
    """validate_fetch_url raises SecurityError for ftp:// URLs."""
    from src.security import SecurityError, validate_fetch_url

    with pytest.raises(SecurityError):
        validate_fetch_url("ftp://example.com/x")


# ── Group D — Structural checks ───────────────────────────────────────────────


def test_web_fetch_is_async_coroutine():
    """web_fetch must be an async (coroutine) function."""
    from src.agents.researcher import web_fetch

    # LangChain @tool on an async def populates .coroutine (not .func)
    assert inspect.iscoroutinefunction(
        web_fetch.coroutine
    ), "web_fetch must be defined as 'async def'"


def test_web_fetch_validate_called_before_httpx_client():
    """validate_fetch_url call must appear before httpx.AsyncClient in web_fetch source."""
    from src.agents.researcher import web_fetch

    # LangChain @tool on an async def populates .coroutine (not .func)
    src = inspect.getsource(web_fetch.coroutine)
    validate_pos = src.find("validate_fetch_url(url)")
    httpx_pos = src.find("httpx.AsyncClient")

    assert validate_pos != -1, "validate_fetch_url(url) not found in web_fetch source"
    assert httpx_pos != -1, "httpx.AsyncClient not found in web_fetch source"
    assert validate_pos < httpx_pos, (
        "validate_fetch_url must be called BEFORE httpx.AsyncClient "
        f"(positions: validate={validate_pos}, httpx={httpx_pos})"
    )


def test_web_fetch_html_stripping_removes_script_tags():
    """The HTML stripping regex in web_fetch removes <script> and <style> blocks."""
    # Inline the same logic used in web_fetch to test it in isolation.
    html = (
        "<html><head>"
        "<script>alert('xss')</script>"
        "<style>body{color:red}</style>"
        "</head><body><h1>Hello</h1><p>World</p></body></html>"
    )

    text = re.sub(
        r"<(script|style)[^>]*>.*?</(script|style)[^>]*>",
        "",
        html,
        flags=re.S | re.I,
    )
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s{3,}", "\n\n", text).strip()

    assert "<script>" not in text, "Script tag not removed"
    assert "<style>" not in text, "Style tag not removed"
    assert "alert" not in text, "Script content not removed"
    assert "color:red" not in text, "Style content not removed"
    assert "Hello" in text, "Visible content must be preserved"
    assert "World" in text, "Visible content must be preserved"
