"""
src/tools/file_tools.py
────────────────────────
Phase 9 file tools: file_read and file_write.

Security model:
  - Path allowlist: settings.tools.allowed_read_paths / allowed_write_paths.
    Empty list = tool refuses every path until operator configures the YAML.
  - Symlink / traversal guard: os.path.realpath() is resolved before the
    allowlist check, so ../../../etc/passwd chains are caught.
  - Executable extension block (file_write): .py .sh .bash .rb .pl .exe .bat
    are always refused — maps to the FORBIDDEN_CAPABILITY "write_executable".
  - Size caps: max_file_read_bytes (50 KB) / max_file_write_bytes (50 KB).
  - UTF-8 only: binary files are refused on read.
  - Input sanitization on all string arguments (PII + injection detection).
  - Output sanitization on file content before it enters agent context.

Startup:
    await register_file_tools()   # call once at application startup
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from langchain_core.tools import tool

from config.settings import settings
from src.security import (
    ToolManifest,
    register_tool,
    sanitize_tool_input,
    sanitize_output,
)

logger = logging.getLogger(__name__)

# Extensions that map to the FORBIDDEN_CAPABILITY "write_executable".
# Agents may never write files with these suffixes.
_BLOCKED_WRITE_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".sh", ".bash", ".zsh", ".rb", ".pl", ".exe", ".bat", ".cmd", ".ps1"}
)


def _resolve_and_check(path: str, allowed_roots: list[str], label: str) -> Path:
    """Resolve symlinks and verify the resulting absolute path is within an allowed root.

    Raises ValueError with a human-readable message if the check fails.
    Never reveals the allowed_roots list to callers (avoid info leakage).
    """
    if not allowed_roots:
        raise ValueError(
            f"[{label}] No allowed paths configured — operator must set tools.{label.replace('file_', 'allowed_') + 'paths'} in the hardware profile."
        )

    resolved = Path(os.path.realpath(path))
    for root in allowed_roots:
        root_resolved = Path(os.path.realpath(root))
        try:
            resolved.relative_to(root_resolved)
            return resolved  # within this allowed root
        except ValueError:
            continue
    raise ValueError(f"[{label}] Path is outside the configured workspace.")


# ── Tools ─────────────────────────────────────────────────────────────────────


@tool
def file_read(path: str) -> str:
    """Read a text file from the workspace. Returns up to 50 KB of UTF-8 content."""
    clean_path, meta = sanitize_tool_input(path, tool_id="file_read")
    if meta.get("injection_detected"):
        logger.warning("[file_read] Injection pattern detected in path argument.")

    try:
        resolved = _resolve_and_check(
            clean_path, settings.tools.allowed_read_paths, "file_read"
        )
    except ValueError as exc:
        return str(exc)

    max_bytes = settings.tools.max_file_read_bytes
    try:
        raw_bytes = resolved.read_bytes()
    except FileNotFoundError:
        return f"[file_read] File not found: {resolved.name}"
    except PermissionError:
        return f"[file_read] Permission denied: {resolved.name}"
    except OSError as exc:
        return f"[file_read] OS error: {type(exc).__name__}"

    # Refuse binary files
    try:
        raw_text = raw_bytes[:max_bytes].decode("utf-8")
    except UnicodeDecodeError:
        return "[file_read] File is not valid UTF-8 text."

    truncated = len(raw_bytes) > max_bytes
    clean_text, out_meta = sanitize_output(raw_text)
    if out_meta.get("injection_detected"):
        logger.warning("[file_read] Injection pattern detected in file content.")

    suffix = (
        f"\n[file_read] Output truncated at {max_bytes} bytes." if truncated else ""
    )
    return clean_text + suffix


@tool
def file_write(path: str, content: str) -> str:
    """Write text content to a file in the workspace output directory.
    Executable file extensions (.py, .sh, .bash, etc.) are always refused.
    Existing files are overwritten. Returns a confirmation string."""
    clean_path, path_meta = sanitize_tool_input(path, tool_id="file_write")
    if path_meta.get("injection_detected"):
        logger.warning("[file_write] Injection pattern detected in path argument.")

    # Block executable extensions before any path resolution
    ext = Path(clean_path).suffix.lower()
    if ext in _BLOCKED_WRITE_EXTENSIONS:
        return (
            f"[file_write] Writing executable files ({ext}) is not permitted. "
            "Use a non-executable extension."
        )

    try:
        resolved = _resolve_and_check(
            clean_path, settings.tools.allowed_write_paths, "file_write"
        )
    except ValueError as exc:
        return str(exc)

    max_bytes = settings.tools.max_file_write_bytes
    clean_content, content_meta = sanitize_tool_input(content, tool_id="file_write")
    if content_meta.get("pii_redacted"):
        logger.warning("[file_write] PII redacted from file content before writing.")
    if content_meta.get("injection_detected"):
        logger.warning("[file_write] Injection pattern detected in file content.")

    encoded = clean_content.encode("utf-8")
    if len(encoded) > max_bytes:
        return f"[file_write] Content too large (max {max_bytes} bytes)."

    try:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_bytes(encoded)
    except PermissionError:
        return f"[file_write] Permission denied: {resolved.name}"
    except OSError as exc:
        return f"[file_write] OS error: {type(exc).__name__}"

    return f"[file_write] Written {len(encoded)} bytes to {resolved.name}."


# ── Manifests ──────────────────────────────────────────────────────────────────

FILE_TOOL_MANIFESTS: list[ToolManifest] = [
    ToolManifest(
        tool_id="file_read",
        description=(
            "Read a UTF-8 text file from the operator-configured workspace "
            "(path allowlist enforced, symlinks resolved, max 50 KB)."
        ),
        input_schema={"path": "str"},
        declared_side_effects=["reads_local_file"],
        source="local",
        entrypoint_func=file_read,
    ),
    ToolManifest(
        tool_id="file_write",
        description=(
            "Write text content to a file in the workspace output directory "
            "(path allowlist enforced, executable extensions refused, max 50 KB)."
        ),
        input_schema={"path": "str", "content": "str"},
        declared_side_effects=["writes_local_file"],
        source="local",
        entrypoint_func=file_write,
    ),
]

# Approved tool-call sequences that include file tools.
FILE_TOOL_SEQUENCES: list[list[str]] = [
    ["file_read"],
    ["file_write"],
    ["file_read", "file_write"],
    ["http_get", "file_write"],
    ["web_fetch", "file_write"],
    ["file_read", "http_post"],
]


# ── Registration ───────────────────────────────────────────────────────────────


async def register_file_tools() -> None:
    """Register file_read and file_write in the tool registry. Call once at startup."""
    for manifest in FILE_TOOL_MANIFESTS:
        await register_tool(
            manifest,
            approved_by="operator",
            approval_notes="Phase 9 file tools — path allowlist enforced, executable extensions blocked",
        )
    logger.info("[file_tools] file_read and file_write registered.")
