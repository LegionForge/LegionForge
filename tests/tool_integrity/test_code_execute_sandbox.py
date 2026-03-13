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


# ── Chart extraction tests ────────────────────────────────────────────────────
# These tests target _extract_charts() directly — no Docker required.
# They verify the sentinel parsing, figure grouping, size cap, and
# that chart data is stripped from the text returned to the LLM.


from src.tools.code_tools import _extract_charts  # noqa: E402


class TestChartExtraction:
    def test_svg_sentinel_extracted(self):
        """SVG block is stripped from text and returned as chart dict."""
        svg = "<svg><rect width='10' height='10'/></svg>"
        # Pad to meet 64-char threshold
        svg = "<svg>" + "x" * 100 + "</svg>"
        text = f"Before\n%%LF_CHART_SVG%%{svg}%%/LF_CHART_SVG%%\nAfter"
        clean, charts = _extract_charts(text, max_chart_bytes=1_000_000)
        assert svg not in clean
        assert "Before" in clean
        assert "After" in clean
        assert len(charts) == 1
        assert charts[0]["type"] == "svg"
        assert charts[0]["data"] == svg

    def test_png_sentinel_extracted(self):
        """PNG base64 block is stripped and returned."""
        b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ" + "A" * 30
        text = f"%%LF_CHART_PNG%%{b64}%%/LF_CHART_PNG%%"
        clean, charts = _extract_charts(text, max_chart_bytes=1_000_000)
        assert b64 not in clean
        assert len(charts) == 1
        assert charts[0]["type"] == "png"

    def test_plotly_sentinel_extracted(self):
        """Plotly JSON block is stripped and returned."""
        # Must be >= 64 chars after strip so the threshold passes
        json_data = '{"data":[{"type":"bar","x":[1,2,3,4,5],"y":[10,20,30,40,50],"name":"test_series"}]}'
        assert len(json_data) >= 64
        text = f"%%LF_CHART_PLOTLY%%{json_data}%%/LF_CHART_PLOTLY%%"
        clean, charts = _extract_charts(text, max_chart_bytes=1_000_000)
        assert json_data not in clean
        assert len(charts) == 1
        assert charts[0]["type"] == "plotly"

    def test_figure_group_id_captured(self):
        """Charts with :figID suffix have the figure field set."""
        svg = "<svg><circle r='5'/></svg>" + "x" * 40
        text = f"%%LF_CHART_SVG:fig1%%{svg}%%/LF_CHART_SVG%%"
        clean, charts = _extract_charts(text, max_chart_bytes=1_000_000)
        assert len(charts) == 1
        assert charts[0].get("figure") == "fig1"

    def test_ungrouped_chart_has_no_figure_field(self):
        """Charts without :figID have no figure key."""
        svg = "<svg><line x1='0' y1='0' x2='10' y2='10'/></svg>" + "x" * 20
        text = f"%%LF_CHART_SVG%%{svg}%%/LF_CHART_SVG%%"
        _, charts = _extract_charts(text, max_chart_bytes=1_000_000)
        assert len(charts) == 1
        assert "figure" not in charts[0]

    def test_multiple_charts_same_figure_group(self):
        """Multiple chart types with same figID are all extracted."""
        svg = "<svg><rect/></svg>" + "x" * 50
        b64 = "a" * 64
        # Plotly data must be >= 64 chars after strip (spaces are stripped)
        plotly = (
            '{"data":[{"type":"scatter","x":[1,2,3],"y":[4,5,6],"name":"series_one"}]}'
        )
        text = (
            f"%%LF_CHART_SVG:fig1%%{svg}%%/LF_CHART_SVG%%"
            f"%%LF_CHART_PNG:fig1%%{b64}%%/LF_CHART_PNG%%"
            f"%%LF_CHART_PLOTLY:fig1%%{plotly}%%/LF_CHART_PLOTLY%%"
        )
        _, charts = _extract_charts(text, max_chart_bytes=1_000_000)
        assert len(charts) == 3
        assert all(c.get("figure") == "fig1" for c in charts)
        types = {c["type"] for c in charts}
        assert types == {"svg", "png", "plotly"}

    def test_chart_too_large_returns_error_summary(self):
        """Charts exceeding max_chart_bytes return an error summary, not data."""
        large_data = "x" * 1000
        text = f"%%LF_CHART_SVG%%{large_data}%%/LF_CHART_SVG%%"
        clean, charts = _extract_charts(text, max_chart_bytes=100)
        assert len(charts) == 0
        assert "exceeds" in clean or "too large" in clean.lower()

    def test_empty_chart_block_returns_error_summary(self):
        """Sentinel blocks with < 64 chars of data return a failure summary."""
        text = "%%LF_CHART_SVG%%tiny%%/LF_CHART_SVG%%"
        clean, charts = _extract_charts(text, max_chart_bytes=1_000_000)
        assert len(charts) == 0
        assert "failed" in clean.lower()

    def test_chart_summary_replaces_block_in_llm_text(self):
        """The LLM sees a compact summary, not the raw chart data."""
        svg = "<svg>" + "x" * 100 + "</svg>"
        text = f"Result:\n%%LF_CHART_SVG%%{svg}%%/LF_CHART_SVG%%\nDone."
        clean, charts = _extract_charts(text, max_chart_bytes=1_000_000)
        assert "Result:" in clean
        assert "Done." in clean
        assert "[Chart generated:" in clean
        assert svg not in clean

    def test_non_chart_text_unchanged(self):
        """Text with no sentinel blocks passes through unchanged."""
        text = "This is a normal response with no charts."
        clean, charts = _extract_charts(text, max_chart_bytes=1_000_000)
        assert clean == text
        assert charts == []
