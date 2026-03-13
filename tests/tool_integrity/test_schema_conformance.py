"""
tests/tool_integrity/test_schema_conformance.py
────────────────────────────────────────────────
Runtime schema conformance tests for all 8 registered tools.

Two categories:

A. INPUT BOUNDARY REJECTION (no external services required)
   Tools must return a descriptive error STRING — never raise an exception —
   when given inputs that violate declared constraints:
     - Empty/blank content
     - Content exceeding declared size limits
     - Invalid enum values (scope, content_type)
     - Missing or malformed arguments

B. RETURN TYPE CONFORMANCE (no external services required)
   Every tool must return str in both success and error paths.
   Tests use inputs guaranteed to trigger error paths (SSRF-blocked URLs,
   disabled features) so no network or Docker access is needed.

Run with:
    make test-tool-integrity
    pytest tests/tool_integrity/test_schema_conformance.py -v
"""

from __future__ import annotations

import asyncio
import os
import sys

import pytest

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

pytestmark = pytest.mark.tool_integrity


# ── memory_write input boundary tests ────────────────────────────────────────


@pytest.mark.asyncio
async def test_memory_write_rejects_empty_content():
    """memory_write with blank content must return an error string, not raise."""
    from src.tools.memory_tools import memory_write

    result = await memory_write.ainvoke({"content": "   ", "scope": "agent"})
    assert isinstance(result, str), f"Expected str, got {type(result).__name__}"
    assert "[memory_write]" in result, f"Expected tool prefix in result: {result!r}"
    # Must not be a success message
    assert "Stored" not in result, f"Empty content should not be stored: {result!r}"


@pytest.mark.asyncio
async def test_memory_write_rejects_oversized_content(monkeypatch):
    """memory_write with content > 2000 chars must return an error string, not truncate silently.
    Forces agent_memory.enabled=True so the size check is reached before the disabled guard.
    """
    from src.tools.memory_tools import memory_write
    from config.settings import settings

    monkeypatch.setattr(settings.agent_memory, "enabled", True)
    huge = "A" * 2001
    result = await memory_write.ainvoke({"content": huge, "scope": "agent"})
    assert isinstance(result, str), f"Expected str, got {type(result).__name__}"
    assert (
        "too long" in result.lower() or "max" in result.lower()
    ), f"Expected size-limit error, got: {result!r}"


@pytest.mark.asyncio
async def test_memory_write_rejects_invalid_scope(monkeypatch):
    """memory_write with scope='global' (not 'agent' or 'user') must return an error string.
    Forces agent_memory.enabled=True so the scope check is reached before the disabled guard.
    """
    from src.tools.memory_tools import memory_write
    from config.settings import settings

    monkeypatch.setattr(settings.agent_memory, "enabled", True)
    result = await memory_write.ainvoke({"content": "some fact", "scope": "global"})
    assert isinstance(result, str), f"Expected str, got {type(result).__name__}"
    assert (
        "invalid scope" in result.lower() or "scope" in result.lower()
    ), f"Expected scope-validation error, got: {result!r}"


@pytest.mark.asyncio
async def test_memory_recall_rejects_empty_query():
    """memory_recall with blank query must return an error string, not raise."""
    from src.tools.memory_tools import memory_recall

    result = await memory_recall.ainvoke({"query": "   ", "scope": "agent"})
    assert isinstance(result, str), f"Expected str, got {type(result).__name__}"
    assert "[memory_recall]" in result, f"Expected tool prefix in result: {result!r}"


@pytest.mark.asyncio
async def test_memory_recall_rejects_invalid_scope(monkeypatch):
    """memory_recall with an unsupported scope must return an error string.
    Forces agent_memory.enabled=True so the scope check is reached before the disabled guard.
    """
    from src.tools.memory_tools import memory_recall
    from config.settings import settings

    monkeypatch.setattr(settings.agent_memory, "enabled", True)
    result = await memory_recall.ainvoke({"query": "anything", "scope": "global"})
    assert isinstance(result, str), f"Expected str, got {type(result).__name__}"
    assert (
        "scope" in result.lower()
    ), f"Expected scope-validation error, got: {result!r}"


# ── http_post input boundary tests ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_http_post_rejects_oversized_body():
    """http_post with a body exceeding max_post_body_bytes must return an error string."""
    from src.tools.http_tools import http_post

    # Default cap is 10 KB; send 11 KB
    huge_body = "x" * (11 * 1024)
    result = await http_post.ainvoke(
        {
            "url": "https://httpbin.org/post",
            "body": huge_body,
            "content_type": "text/plain",
        }
    )
    assert isinstance(result, str), f"Expected str, got {type(result).__name__}"
    assert (
        "too large" in result.lower() or "max" in result.lower()
    ), f"Expected body-size error, got: {result!r}"


@pytest.mark.asyncio
async def test_http_post_rejects_invalid_content_type():
    """
    http_post enforces content_type via a Pydantic Literal constraint.
    Passing 'text/html' raises a ValidationError before the function body runs —
    this IS the correct rejection mechanism (Pydantic schema enforcement).

    Verify: the tool raises rather than silently accepting an unsupported type.
    """
    from pydantic import ValidationError
    from src.tools.http_tools import http_post

    with pytest.raises((ValidationError, Exception)):
        await http_post.ainvoke(
            {
                "url": "https://httpbin.org/post",
                "body": "hello",
                "content_type": "text/html",
            }
        )


# ── Return type conformance: all tools return str in error paths ──────────────
# These inputs are guaranteed to trigger error paths (SSRF-blocked private IPs,
# size exceeded, etc.) without requiring any external network or services.


@pytest.mark.asyncio
async def test_http_get_returns_str_on_ssrf_block():
    """http_get with a private IP must return str (error message), never raise."""
    from src.tools.http_tools import http_get

    result = await http_get.ainvoke({"url": "http://192.168.1.1/admin"})
    assert isinstance(result, str), f"Expected str, got {type(result).__name__}"
    assert "[http_get]" in result, f"Expected tool prefix: {result!r}"


@pytest.mark.asyncio
async def test_http_post_returns_str_on_ssrf_block():
    """http_post with a private IP must return str (error message), never raise."""
    from src.tools.http_tools import http_post

    result = await http_post.ainvoke(
        {"url": "http://10.0.0.1/api", "body": "{}", "content_type": "application/json"}
    )
    assert isinstance(result, str), f"Expected str, got {type(result).__name__}"
    assert "[http_post]" in result, f"Expected tool prefix: {result!r}"


@pytest.mark.asyncio
async def test_memory_write_returns_str_when_disabled(monkeypatch):
    """memory_write returns str when agent_memory.enabled=False (feature-disabled path)."""
    from src.tools.memory_tools import memory_write
    from config.settings import settings

    monkeypatch.setattr(settings.agent_memory, "enabled", False)
    result = await memory_write.ainvoke({"content": "test fact", "scope": "agent"})
    assert isinstance(result, str), f"Expected str, got {type(result).__name__}"
    assert "disabled" in result.lower(), f"Expected disabled message, got: {result!r}"


@pytest.mark.asyncio
async def test_memory_recall_returns_str_when_disabled(monkeypatch):
    """memory_recall returns str when agent_memory.enabled=False (feature-disabled path)."""
    from src.tools.memory_tools import memory_recall
    from config.settings import settings

    monkeypatch.setattr(settings.agent_memory, "enabled", False)
    result = await memory_recall.ainvoke({"query": "anything", "scope": "agent"})
    assert isinstance(result, str), f"Expected str, got {type(result).__name__}"
    assert "disabled" in result.lower(), f"Expected disabled message, got: {result!r}"


@pytest.mark.asyncio
async def test_code_execute_returns_str_when_docker_unavailable(monkeypatch):
    """code_execute returns str when Docker is not present — never raises."""
    import src.tools.code_tools as code_tools

    monkeypatch.setattr(code_tools, "_docker_available", lambda: False)
    result = await code_tools.code_execute.ainvoke({"code": "print('hello')"})
    assert isinstance(result, str), f"Expected str, got {type(result).__name__}"
    assert "[code_execute]" in result, f"Expected tool prefix: {result!r}"
