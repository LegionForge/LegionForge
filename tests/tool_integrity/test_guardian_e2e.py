"""
tests/tool_integrity/test_guardian_e2e.py
──────────────────────────────────────────
End-to-end tests for the Guardian sidecar → SecureToolNode enforcement path.

These tests call guardian_check() directly (the same function SecureToolNode
calls) with real inputs and assert the response tier.

Requires Guardian running on localhost:9766.  Start with:
    make guardian-start

Tests
─────
1. Forbidden tool ID → tier="halt"
   Guardian Check 2 blocks any tool_id in the forbidden-capabilities list
   (register_tool, write_executable, spawn_agent_direct, etc.)

2. Destructive pattern in args → tier="halt" or "sandbox"
   Guardian Check 3 pattern-matches tool arguments for destructive commands.
   Passing `rm -rf /` in a file_write path argument must not produce tier="allow".

3. Legitimate tool + benign args → tier="allow"
   web_fetch with a safe URL should pass all 7 Guardian checks.

4. Guardian health check — service is alive
   Basic liveness probe; if this fails, all other Guardian tests are invalid.

Run with:
    make test-tool-integrity
    pytest tests/tool_integrity/test_guardian_e2e.py -v -s
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from tests.tool_integrity.conftest import requires_guardian

pytestmark = pytest.mark.tool_integrity_guardian


# ── Test 1: Guardian health ───────────────────────────────────────────────────


@requires_guardian
@pytest.mark.asyncio
async def test_guardian_health_endpoint_responds():
    """Guardian /health must return 200 — basic liveness before other Guardian tests."""
    import httpx

    resp = httpx.get("http://localhost:9766/health", timeout=3.0)
    assert resp.status_code == 200, (
        f"Guardian /health returned {resp.status_code}. "
        "Run 'make guardian-start' to start the sidecar."
    )


# ── Test 2: Forbidden tool ID → halt ─────────────────────────────────────────


@requires_guardian
@pytest.mark.asyncio
async def test_guardian_halts_forbidden_tool_id():
    """
    Guardian Check 2 blocks any tool_id in the forbidden-capabilities list.

    'register_tool' is a canonical forbidden capability — no agent should be
    able to self-register new tools at runtime.

    Expected: tier="halt", allowed=False.
    """
    from src.base_graph import guardian_check

    resp = await guardian_check(
        tool_id="register_tool",
        args={},
        state={
            "agent_id": "test_agent",
            "run_id": "integrity_test",
            "sequence_so_far": [],
        },
    )

    assert not resp.allowed, (
        f"Guardian allowed a forbidden tool ('register_tool'). "
        f"tier={resp.tier!r}, reason={resp.reason!r}"
    )
    assert resp.tier in (
        "halt",
        "sandbox",
    ), f"Expected tier='halt' or 'sandbox' for forbidden tool, got tier={resp.tier!r}"


# ── Test 3: Destructive pattern in args → not allow ──────────────────────────


@requires_guardian
@pytest.mark.asyncio
async def test_guardian_blocks_destructive_pattern_in_args():
    """
    Guardian Check 3 pattern-matches tool arguments for destructive commands.

    Passing 'rm -rf /' as the path argument to file_write must not produce
    tier="allow" — it must at minimum trigger sandbox or halt.
    """
    from src.base_graph import guardian_check

    resp = await guardian_check(
        tool_id="file_write",
        args={"path": "/tmp/test.txt", "content": "rm -rf / --no-preserve-root"},
        state={
            "agent_id": "test_agent",
            "run_id": "integrity_test",
            "sequence_so_far": [],
        },
    )

    assert resp.tier != "allow", (
        f"Guardian allowed a file_write with destructive content in args. "
        f"tier={resp.tier!r}, reason={resp.reason!r}\n"
        "Guardian Check 3 (destructive pattern detection) may not be firing."
    )


# ── Test 4: Legitimate tool + benign args → allow ────────────────────────────


@requires_guardian
@pytest.mark.asyncio
async def test_guardian_allows_legitimate_tool_with_benign_args():
    """
    A registered tool (web_fetch) with a safe HTTPS URL and no destructive
    patterns must pass all 7 Guardian checks and return tier="allow".
    """
    from src.base_graph import guardian_check

    resp = await guardian_check(
        tool_id="web_fetch",
        args={"url": "https://httpbin.org/json"},
        state={
            "agent_id": "test_agent",
            "run_id": "integrity_test",
            "sequence_so_far": [],
        },
    )

    assert resp.allowed, (
        f"Guardian blocked a legitimate web_fetch call. "
        f"tier={resp.tier!r}, reason={resp.reason!r}"
    )
    assert (
        resp.tier == "allow"
    ), f"Expected tier='allow' for benign web_fetch, got tier={resp.tier!r}"


# ── Test 5: Guardian fails closed on unknown tool ─────────────────────────────


@requires_guardian
@pytest.mark.asyncio
async def test_guardian_denies_unregistered_tool_id():
    """
    A tool_id that does not exist in the registry must not pass Guardian.

    This prevents a "phantom tool" attack where an adversary invents a tool
    name not in the approved set and attempts to invoke it.
    """
    from src.base_graph import guardian_check

    resp = await guardian_check(
        tool_id="totally_fake_tool_xyz_does_not_exist",
        args={},
        state={
            "agent_id": "test_agent",
            "run_id": "integrity_test",
            "sequence_so_far": [],
        },
    )

    # Either denied outright OR not in allowed set — should not be tier="allow"
    # (Guardian may return sandbox or halt depending on rule configuration)
    assert resp.tier != "allow" or not resp.allowed, (
        f"Guardian allowed an unregistered tool 'totally_fake_tool_xyz_does_not_exist'. "
        f"tier={resp.tier!r}, allowed={resp.allowed}"
    )
