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
import logging
import shutil

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
        "--tmpfs=/tmp:size=10m,noexec",
        "--security-opt=no-new-privileges",
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
        "Returns stdout + stderr (max 10 KB)."
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
