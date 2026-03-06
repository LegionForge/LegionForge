"""
src/tools/memory_tools.py
─────────────────────────
Gap 3: memory_write and memory_recall tools — agents actively store and
retrieve facts during a run, making the memory system self-maintaining.

memory_write: persist a fact/observation to the agent's scoped namespace.
memory_recall: semantic search over stored memory for relevant context.

Both tools are gated by settings.agent_memory.enabled.

Namespace is resolved from a per-task context variable set by the gateway
worker (set_agent_memory_context) so agents can only write to their own
scoped namespace — not global or other agents' namespaces.

Content is sanitized (PII redaction + injection detection) before storage.
Content length is capped at MEMORY_WRITE_MAX_CHARS (2000 chars).

Startup:
    await register_memory_tools()         # call once at application startup
    set_agent_memory_context("researcher", "user123")  # per-task, in worker
"""

from __future__ import annotations

import contextvars
import logging

from langchain_core.tools import tool

from src.security import (
    ToolManifest,
    register_tool,
    sanitize_tool_input,
)

logger = logging.getLogger(__name__)

MEMORY_WRITE_MAX_CHARS = 2000

# ── Per-task context ───────────────────────────────────────────────────────────
# Set by the gateway worker before each run so memory tools know which agent
# and user they belong to.  Uses contextvars so concurrent asyncio Tasks each
# see their own value (same pattern as set_task_model_preference in llm_factory).

_agent_memory_context: contextvars.ContextVar[dict] = contextvars.ContextVar(
    "agent_memory_context", default={}
)


def set_agent_memory_context(agent_id: str, user_id: str | None) -> None:
    """Set the memory namespace context for the current async task.

    Call once per task run, after agent_id is determined.
    """
    _agent_memory_context.set({"agent_id": agent_id, "user_id": user_id})


def get_agent_memory_context() -> dict:
    """Return the current memory context dict (agent_id, user_id)."""
    return _agent_memory_context.get()


# ── Tools ──────────────────────────────────────────────────────────────────────


@tool
async def memory_write(content: str, scope: str = "agent") -> str:
    """Store a fact or observation to persistent memory for future recall.

    Use this to remember important information discovered during a task.
    scope: 'agent' (shared across users for this agent type) or
           'user' (private to the submitting user).
    Content is limited to 2000 characters.
    """
    from config.settings import settings as _settings

    if not _settings.agent_memory.enabled:
        return "[memory_write] Memory is disabled — nothing stored."

    if scope not in ("agent", "user"):
        return "[memory_write] Invalid scope. Use 'agent' or 'user'."

    if not content.strip():
        return "[memory_write] Content is empty — nothing stored."

    if len(content) > MEMORY_WRITE_MAX_CHARS:
        return (
            f"[memory_write] Content too long ({len(content)} chars, "
            f"max {MEMORY_WRITE_MAX_CHARS}). Summarize before storing."
        )

    clean_content, meta = sanitize_tool_input(content, tool_id="memory_write")
    if meta.get("injection_detected"):
        logger.warning(
            "[memory_write] Injection pattern detected in content — blocked."
        )
        return "[memory_write] Content blocked: injection pattern detected."

    ctx = _agent_memory_context.get()
    agent_id = ctx.get("agent_id", "base_agent")
    user_id = ctx.get("user_id")

    if scope == "user" and not user_id:
        return "[memory_write] No user context available — use scope='agent' instead."

    from src.memory import get_memory_store, MemoryStore

    if scope == "user":
        namespace = MemoryStore.agent_user_namespace(agent_id, user_id)
    else:
        namespace = MemoryStore.agent_namespace(agent_id)

    try:
        store = get_memory_store()
        doc_id = await store.store(
            clean_content,
            namespace=namespace,
            metadata={"type": "agent_observation", "scope": scope},
        )
        logger.info("[memory_write] Stored doc %d in namespace '%s'", doc_id, namespace)
        return f"[memory_write] Stored (doc_id={doc_id}, namespace={namespace!r})."
    except Exception as exc:
        logger.warning("[memory_write] Storage failed: %s", exc)
        return f"[memory_write] Storage failed: {type(exc).__name__}"


@tool
async def memory_recall(query: str, scope: str = "agent") -> str:
    """Search persistent memory for facts relevant to a query.

    Returns the top matching stored observations.
    scope: 'agent' (shared agent memory) or 'user' (private user memory).
    """
    from config.settings import settings as _settings

    if not _settings.agent_memory.enabled:
        return "[memory_recall] Memory is disabled."

    if scope not in ("agent", "user"):
        return "[memory_recall] Invalid scope. Use 'agent' or 'user'."

    if not query.strip():
        return "[memory_recall] Query is empty."

    clean_query, meta = sanitize_tool_input(query, tool_id="memory_recall")
    if meta.get("injection_detected"):
        logger.warning("[memory_recall] Injection pattern in query — blocked.")
        return "[memory_recall] Query blocked: injection pattern detected."

    ctx = _agent_memory_context.get()
    agent_id = ctx.get("agent_id", "base_agent")
    user_id = ctx.get("user_id")

    if scope == "user" and not user_id:
        return "[memory_recall] No user context available — use scope='agent'."

    from src.memory import get_memory_store, MemoryStore

    if scope == "user":
        namespace = MemoryStore.agent_user_namespace(agent_id, user_id)
    else:
        namespace = MemoryStore.agent_namespace(agent_id)

    try:
        store = get_memory_store()
        results = await store.search(clean_query, namespace=namespace)
        if not results:
            return "[memory_recall] No relevant memories found."
        lines = []
        for r in results:
            score = r.get("similarity", 0)
            snippet = r["content"][:400].replace("\n", " ")
            lines.append(f"[{score:.3f}] {snippet}")
        return "\n".join(lines)
    except Exception as exc:
        logger.warning("[memory_recall] Search failed: %s", exc)
        return f"[memory_recall] Search failed: {type(exc).__name__}"


# ── Manifests ─────────────────────────────────────────────────────────────────


MEMORY_TOOL_MANIFESTS: list[ToolManifest] = [
    ToolManifest(
        tool_id="memory_write",
        description=(
            "Store a fact or observation to persistent agent memory "
            "(max 2000 chars, PII-sanitized, injection-guarded)."
        ),
        input_schema={"content": "str", "scope": "str"},
        declared_side_effects=["writes_memory"],
        source="local",
        entrypoint_func=memory_write,
    ),
    ToolManifest(
        tool_id="memory_recall",
        description=(
            "Semantic search over persistent agent memory. "
            "Returns top matching stored observations."
        ),
        input_schema={"query": "str", "scope": "str"},
        declared_side_effects=[],
        source="local",
        entrypoint_func=memory_recall,
    ),
]

MEMORY_TOOL_SEQUENCES: list[list[str]] = [
    ["memory_write"],
    ["memory_recall"],
    ["memory_recall", "memory_write"],
    ["web_search", "memory_write"],
    ["web_fetch", "memory_write"],
    ["memory_recall", "web_search"],
    ["memory_recall", "web_search", "memory_write"],
]


# ── Registration ───────────────────────────────────────────────────────────────


async def register_memory_tools() -> None:
    """Register memory_write and memory_recall in the tool registry."""
    for manifest in MEMORY_TOOL_MANIFESTS:
        await register_tool(
            manifest,
            approved_by="operator",
            approval_notes="Gap 3 memory tools — namespace-scoped, I/O sanitized",
        )
    logger.info("[memory_tools] memory_write and memory_recall registered.")
