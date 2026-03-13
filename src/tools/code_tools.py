"""
src/tools/code_execute
────────────────────────
Phase 9 sandboxed code execution tool.

The code_execute tool runs Python 3 code in an air-gapped Docker container:
  --network none          no outbound network access
  --read-only             container filesystem is read-only
  --tmpfs /tmp:size=10m   only /tmp is writable (in-memory, 10 MB)
  --memory=<N>m           memory cap (settings.tools.sandbox_memory_mb, default 256)
  --cpus=<N>              CPU cap (settings.tools.sandbox_cpus, default 0.5)
  --pids-limit=20         prevents fork bombs
  --rm                    container removed immediately after exit

Accepted residual risks (documented):
  - Timing-based side channels from within the container.
  - CPU topology mapping via /proc (mitigated by --pids-limit + --cpus).

Startup:
    await register_code_tool()   # call once at application startup

Pre-requisite:
    make sandbox-build           # builds the legionforge-sandbox:latest image
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import re
import shutil
from typing import Any

from langchain_core.tools import tool

from config.settings import settings
from src.security import (
    ToolManifest,
    register_tool,
    sanitize_tool_input,
    sanitize_output,
)

logger = logging.getLogger(__name__)

_PYTHON_HEADER = "# LegionForge sandbox — Python 3\n"

# ── Chart output channel ───────────────────────────────────────────────────────
# When agent code prints %%LF_CHART_SVG%%, %%LF_CHART_PNG%%, or
# %%LF_CHART_PLOTLY%% sentinel blocks to stdout, code_execute strips them
# from the text returned to the LLM (keeping only a compact summary) and
# stores the raw chart data here, keyed by the current task_id.
#
# The worker reads and clears the store after _stream_agent() returns, then
# passes the charts list through the task_complete SSE event to the browser.
#
# Charts are excluded from the text output cap and from sanitize_output so
# that large SVG / base64 PNG / Plotly JSON payloads don't trigger false
# positives in the injection scanner.

_chart_task_ctx: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_chart_task_id", default=""
)
_chart_store: dict[str, list[dict[str, Any]]] = {}

_CHART_RE = re.compile(
    r"%%LF_CHART_(SVG|PNG|PLOTLY)%%(.*?)%%/LF_CHART_(?:SVG|PNG|PLOTLY)%%",
    re.DOTALL,
)


def set_chart_task_id(task_id: str) -> None:
    """Call once per task in the worker before running the agent graph."""
    _chart_task_ctx.set(task_id)


def pop_charts(task_id: str) -> list[dict[str, Any]]:
    """Return and clear all charts produced by code_execute for *task_id*."""
    return _chart_store.pop(task_id, [])


def _extract_charts(
    text: str, max_chart_bytes: int
) -> tuple[str, list[dict[str, Any]]]:
    """
    Strip %%LF_CHART_*%% sentinel blocks from *text*.

    Returns (clean_text, charts) where *clean_text* has each block replaced by
    a compact human-readable summary, and *charts* is a list of
    {"type": "svg"|"png"|"plotly", "data": "<raw data>"} dicts.
    """
    charts: list[dict[str, Any]] = []

    def _replace(m: re.Match) -> str:  # type: ignore[type-arg]
        chart_type = m.group(1).lower()
        data = m.group(2).strip()
        size_kb = len(data.encode()) // 1024
        if len(data.encode()) > max_chart_bytes:
            return (
                f"[Chart too large — {size_kb} KB exceeds "
                f"{max_chart_bytes // 1024} KB limit. Reduce figure size or DPI.]"
            )
        if len(data) < 64:
            return "[Chart rendering failed — no data in sentinel block.]"
        charts.append({"type": chart_type, "data": data})
        return f"[Chart generated: {chart_type.upper()}, {size_kb} KB — rendered in UI]"

    clean = _CHART_RE.sub(_replace, text)
    return clean, charts


def _docker_available() -> bool:
    return shutil.which("docker") is not None


# ── Tool ───────────────────────────────────────────────────────────────────────


@tool
async def code_execute(code: str) -> str:
    """Execute Python 3 code in an air-gapped Docker sandbox (no network, read-only fs).
    Returns combined stdout + stderr, capped at 10 KB. Timeout: 30 seconds."""
    if not _docker_available():
        return "[code_execute] Docker is not available on this host."

    clean_code, meta = sanitize_tool_input(code, tool_id="code_execute")
    if meta.get("injection_detected"):
        logger.warning("[code_execute] Injection pattern detected in code argument.")

    cfg = settings.tools
    image = cfg.sandbox_image
    timeout = cfg.sandbox_timeout_seconds
    mem_mb = cfg.sandbox_memory_mb
    cpus = cfg.sandbox_cpus
    max_out = cfg.sandbox_max_output_bytes
    max_chart = cfg.sandbox_max_chart_bytes

    script = _PYTHON_HEADER + clean_code

    cmd = [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        f"--memory={mem_mb}m",
        "--memory-swap=0",  # disable swap — keep the memory cap hard
        f"--cpus={cpus}",
        "--pids-limit=20",
        "--tmpfs=/tmp:size=64m,noexec",  # 64 MB — matplotlib font cache needs space
        "--security-opt=no-new-privileges",
        # Matplotlib/Plotly environment — MPLBACKEND and MPLCONFIGDIR are also
        # baked into the image, but explicit -e flags survive image rebuilds.
        "-e",
        "MPLBACKEND=Agg",
        "-e",
        "MPLCONFIGDIR=/tmp",
        image,
        "python3",
        "-c",
        script,
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=float(timeout)
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return f"[code_execute] Timed out after {timeout}s."
    except FileNotFoundError:
        return "[code_execute] Docker binary not found."
    except OSError as exc:
        return f"[code_execute] Failed to start container: {type(exc).__name__}"

    combined = (stdout_b + b"\n" + stderr_b).decode("utf-8", errors="replace")

    # ── Chart extraction (must happen BEFORE the output cap and sanitizer) ─────
    # Strip %%LF_CHART_*%% blocks from the text so they don't consume the 10 KB
    # text quota or pass through the injection scanner.  Extracted charts are
    # stored in _chart_store under the current task_id; the worker reads them
    # after the agent graph completes and delivers them via the task_complete
    # SSE event so the browser can render them.
    text_out, charts = _extract_charts(combined, max_chart)
    if charts:
        task_id = _chart_task_ctx.get("")
        if task_id:
            _chart_store.setdefault(task_id, []).extend(charts)
        else:
            logger.warning(
                "[code_execute] Chart produced but no task_id in context — "
                "chart will not reach the UI."
            )

    combined = text_out  # LLM sees only the compact summaries

    if len(combined.encode()) > max_out:
        combined = (
            combined[:max_out]
            + f"\n[code_execute] Output truncated at {max_out} bytes."
        )

    clean_out, out_meta = sanitize_output(combined)
    if out_meta.get("injection_detected"):
        logger.warning("[code_execute] Injection pattern detected in sandbox output.")

    exit_code = proc.returncode
    if exit_code not in (0, None):
        return f"[code_execute] Exit code {exit_code}:\n{clean_out}"
    return clean_out


# ── Manifest ───────────────────────────────────────────────────────────────────

CODE_TOOL_MANIFEST = ToolManifest(
    tool_id="code_execute",
    description=(
        "Execute Python 3 code in an air-gapped Docker sandbox "
        "(--network none, --read-only, memory+CPU capped, 30s timeout). "
        "Returns stdout + stderr (max 10 KB). "
        "matplotlib, numpy, and plotly are available. "
        "To render charts in the UI, print sentinel blocks: "
        "%%LF_CHART_SVG%%<svg...>%%/LF_CHART_SVG%% for matplotlib SVG, "
        "%%LF_CHART_PNG%%<base64>%%/LF_CHART_PNG%% for PNG, or "
        "%%LF_CHART_PLOTLY%%<fig.to_json()>%%/LF_CHART_PLOTLY%% for interactive Plotly. "
        "Use plt.rcParams['svg.fonttype']='none' to keep SVG compact."
    ),
    input_schema={"code": "str"},
    declared_side_effects=["spawns_docker_container", "executes_arbitrary_code"],
    source="local",
    entrypoint_func=code_execute,
)

# Approved tool-call sequences that include code_execute.
CODE_TOOL_SEQUENCES: list[list[str]] = [
    ["code_execute"],
    ["file_read", "code_execute"],
    ["http_get", "code_execute"],
    ["code_execute", "file_write"],
]


# ── Registration ───────────────────────────────────────────────────────────────


async def register_code_tool() -> None:
    """Register code_execute in the tool registry. Call once at startup.
    Requires legionforge-sandbox:latest Docker image (make sandbox-build).
    """
    await register_tool(
        CODE_TOOL_MANIFEST,
        approved_by="operator",
        approval_notes=(
            "Phase 9 code execution — air-gapped Docker sandbox, "
            "--network none, --read-only, memory+CPU+pid limits enforced"
        ),
    )
    logger.info("[code_tools] code_execute registered.")
