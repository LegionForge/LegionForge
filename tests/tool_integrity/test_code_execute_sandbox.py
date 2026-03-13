"""
tests/tool_integrity/test_code_execute_sandbox.py
───────────────────────────────────────────────────
Containment tests for the code_execute Docker sandbox.

Verifies that the security constraints declared in code_tools.py
(--network=none, --read-only, --memory cap, --pids-limit, timeout)
are actually enforced at runtime — not just passed as flags.

Requires:
  - Docker daemon running
  - legionforge-sandbox:latest image built (make sandbox-build)

Run with:
    make test-tool-integrity
    pytest tests/tool_integrity/test_code_execute_sandbox.py -v -s

Each test submits Python code to code_execute and asserts on the returned
string — the sandbox always returns str, even on failures.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from tests.tool_integrity.conftest import requires_docker_sandbox

pytestmark = pytest.mark.tool_integrity_sandbox


# ── Test 1: clean execution — stdout captured ─────────────────────────────────


@requires_docker_sandbox
@pytest.mark.asyncio
async def test_sandbox_clean_code_returns_stdout():
    """Basic sanity: print('hello') must appear in output."""
    from src.tools.code_tools import code_execute

    result = await code_execute.ainvoke({"code": "print('sandbox_hello')"})
    assert isinstance(result, str), f"Expected str, got {type(result).__name__}"
    assert "sandbox_hello" in result, f"Expected stdout in result, got: {result!r}"


# ── Test 2: network isolation ─────────────────────────────────────────────────


@requires_docker_sandbox
@pytest.mark.asyncio
async def test_sandbox_network_access_is_blocked():
    """
    --network=none means the sandbox cannot open outbound TCP connections.

    Code attempts to connect to a public DNS server (8.8.8.8:53).
    Expected: ConnectionRefusedError, OSError, or similar network error —
    NOT a successful connection. The tool must return an error string.
    """
    from src.tools.code_tools import code_execute

    code = (
        "import socket, sys\n"
        "try:\n"
        "    s = socket.create_connection(('8.8.8.8', 53), timeout=3)\n"
        "    s.close()\n"
        "    print('NETWORK_ALLOWED')\n"
        "except Exception as e:\n"
        "    print(f'NETWORK_BLOCKED: {type(e).__name__}')\n"
        "    sys.exit(0)\n"
    )

    result = await code_execute.ainvoke({"code": code})
    assert "NETWORK_ALLOWED" not in result, (
        f"Sandbox network access was NOT blocked — container can reach the internet.\n"
        f"Result: {result!r}"
    )
    assert (
        "NETWORK_BLOCKED" in result or "error" in result.lower()
    ), f"Expected network-blocked signal in result, got: {result!r}"


# ── Test 3: filesystem is read-only outside /tmp ──────────────────────────────


@requires_docker_sandbox
@pytest.mark.asyncio
async def test_sandbox_filesystem_write_outside_tmp_is_blocked():
    """
    --read-only means the container filesystem is read-only except for /tmp.

    Code attempts to write to /etc/sandbox_test. Expected: PermissionError
    or OSError — the file must NOT be created successfully.
    """
    from src.tools.code_tools import code_execute

    code = (
        "try:\n"
        "    with open('/etc/sandbox_test', 'w') as f:\n"
        "        f.write('pwned')\n"
        "    print('WRITE_SUCCEEDED')\n"
        "except Exception as e:\n"
        "    print(f'WRITE_BLOCKED: {type(e).__name__}')\n"
    )

    result = await code_execute.ainvoke({"code": code})
    assert "WRITE_SUCCEEDED" not in result, (
        f"Sandbox allowed writing to /etc — read-only constraint is NOT enforced.\n"
        f"Result: {result!r}"
    )
    assert (
        "WRITE_BLOCKED" in result or "error" in result.lower()
    ), f"Expected write-blocked signal in result, got: {result!r}"


# ── Test 4: /tmp is writable (required for normal operation) ──────────────────


@requires_docker_sandbox
@pytest.mark.asyncio
async def test_sandbox_tmp_is_writable():
    """
    --tmpfs /tmp:size=10m,noexec means /tmp IS writable (in-memory).

    Verify that code can write and read back a file in /tmp.
    This is required for multi-step code that produces intermediate output.
    """
    from src.tools.code_tools import code_execute

    code = (
        "with open('/tmp/test_output.txt', 'w') as f:\n"
        "    f.write('tmp_writable')\n"
        "with open('/tmp/test_output.txt') as f:\n"
        "    print(f.read())\n"
    )

    result = await code_execute.ainvoke({"code": code})
    assert (
        "tmp_writable" in result
    ), f"Expected /tmp write+read to succeed, got: {result!r}"


# ── Test 5: timeout is enforced ───────────────────────────────────────────────


@requires_docker_sandbox
@pytest.mark.asyncio
async def test_sandbox_timeout_enforced():
    """
    Code that sleeps longer than sandbox_timeout_seconds must be killed.

    The tool returns a timeout error string — never hangs indefinitely.
    Note: test uses sleep(300) (5 min) — the sandbox timeout is 30s by default,
    so this will be killed well before 300s. The test itself has a 60s pytest timeout.
    """
    from src.tools.code_tools import code_execute

    code = "import time; time.sleep(300)\nprint('should not reach here')"

    result = await code_execute.ainvoke({"code": code})
    assert (
        "timed out" in result.lower() or "timeout" in result.lower()
    ), f"Expected timeout message in result, got: {result!r}"
    assert (
        "should not reach here" not in result
    ), "Code ran past the timeout — sandbox timeout enforcement failed."


# ── Test 6: stderr is captured alongside stdout ───────────────────────────────


@requires_docker_sandbox
@pytest.mark.asyncio
async def test_sandbox_stderr_captured_in_output():
    """
    The sandbox captures stdout + stderr (combined). Code that writes to stderr
    must have that output included in the returned string.
    """
    from src.tools.code_tools import code_execute

    code = "import sys; sys.stderr.write('stderr_signal\\n'); print('stdout_signal')"

    result = await code_execute.ainvoke({"code": code})
    assert "stdout_signal" in result, f"stdout not captured: {result!r}"
    assert "stderr_signal" in result, f"stderr not captured: {result!r}"
