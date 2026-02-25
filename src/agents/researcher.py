"""
src/agents/researcher.py
────────────────────────
Researcher agent — web search, page fetch, and document summarization.
All tools run through SecureToolNode: registry check, guardian check,
action-loop detection, and output sanitization before entering agent context.

Startup:
    await register_researcher_tools()   # call once at application startup
    result = await run_researcher("What is LangGraph?")
"""

from __future__ import annotations

import logging
from typing import Annotated, Any
import operator

import httpx
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
from langchain_core.tools import tool
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages

from config.settings import settings
from src.base_graph import AgentState, SecureToolNode, guardian_check
from src.safeguards import (
    SafeguardedState,
    check_safeguards,
    create_run_config,
    check_token_budget,
    increment_step,
    record_error,
)
from src.llm_factory import get_primary_llm, get_router_llm
from src.observability import log_agent_event, get_metrics, timed
from src.security import (
    ToolManifest,
    register_tool,
    sanitize_messages,
    sanitize_output,
    sanitize_tool_input,
    validate_fetch_url,
    SecurityError,
)
from src.rate_limiter import preflight_budget_check, estimate_tokens

logger = logging.getLogger(__name__)


# ── State ─────────────────────────────────────────────────────────────────────


class ResearcherState(AgentState):
    """Extends AgentState with a list of source URLs collected during research."""

    sources: list[str]


# ── Tools ─────────────────────────────────────────────────────────────────────


@tool
def web_search(query: str, max_results: int = 5) -> list[dict]:
    """Search the web using DuckDuckGo. Returns list of {title, url, snippet} dicts."""
    # TODO Phase 2: replace DDGS with self-hosted SearxNG to keep queries off
    # third-party infrastructure entirely and gain full audit logging.

    # Last-line-of-defense: sanitize the query before it leaves the process.
    # SecureToolNode also calls this, but belt-and-suspenders is warranted here
    # because query leakage to DDG is unrecoverable once the request fires.
    clean_query, meta = sanitize_tool_input(query, tool_id="web_search")
    if meta.get("pii_redacted"):
        logger.warning(
            "[web_search] PII redacted from search query before sending to DDG."
        )
    if meta.get("injection_detected"):
        logger.warning("[web_search] Injection pattern detected in search query.")

    from duckduckgo_search import DDGS

    with DDGS() as ddgs:
        results = list(ddgs.text(clean_query, max_results=max_results))
    return results


@tool
async def web_fetch(url: str, timeout: float = 10.0) -> str:
    """Fetch and return the text content of a web page (truncated to 10 000 chars)."""
    # Last-line-of-defense SSRF check — SecureToolNode also validates, but we
    # must protect here too in case the tool is ever called outside the graph.
    validate_fetch_url(url)  # raises SecurityError for private IPs, bad schemes, etc.

    # Manual redirect following with per-hop URL validation.
    # Using follow_redirects=False to intercept and validate each redirect
    # destination before following — prevents redirect-based SSRF.
    _MAX_REDIRECTS = 5
    current_url = url
    redirect_count = 0

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        while redirect_count <= _MAX_REDIRECTS:
            resp = await client.get(current_url)

            if resp.is_redirect:
                location = resp.headers.get("location", "")
                if not location:
                    break
                # Resolve relative redirects to absolute
                if location.startswith("/"):
                    from urllib.parse import urlparse

                    p = urlparse(current_url)
                    location = f"{p.scheme}://{p.netloc}{location}"
                # Validate redirect destination before following
                try:
                    validate_fetch_url(location)
                except SecurityError as e:
                    raise SecurityError(
                        f"[web_fetch] Redirect to unsafe URL blocked: {e}"
                    ) from e
                current_url = location
                redirect_count += 1
            else:
                resp.raise_for_status()
                return resp.text[:10_000]

    raise RuntimeError(f"[web_fetch] Too many redirects fetching {url!r}")


@tool
async def document_summarize(text: str, focus: str = "") -> str:
    """Summarize a document using the local router model (qwen2.5:3b)."""
    llm = get_router_llm()
    focus_clause = f" focusing on {focus}" if focus else ""
    prompt = f"Summarize the following{focus_clause}:\n\n{text[:4000]}"
    response = await llm.ainvoke([HumanMessage(content=prompt)])
    return response.content


RESEARCHER_TOOLS = [web_search, web_fetch, document_summarize]


# ── Tool manifests ────────────────────────────────────────────────────────────

RESEARCHER_TOOL_MANIFESTS = [
    ToolManifest(
        tool_id="web_search",
        description="Search the web using DuckDuckGo",
        input_schema={"query": "str", "max_results": "int"},
        declared_side_effects=["calls_external_api:duckduckgo.com"],
        source="local",
        entrypoint_func=web_search,
    ),
    ToolManifest(
        tool_id="web_fetch",
        description="Fetch text content from a URL",
        input_schema={"url": "str", "timeout": "float"},
        declared_side_effects=["reads_web"],
        source="local",
        entrypoint_func=web_fetch,
    ),
    ToolManifest(
        tool_id="document_summarize",
        description="Summarize text using the local router LLM",
        input_schema={"text": "str", "focus": "str"},
        declared_side_effects=["calls_local_llm:qwen2.5:3b"],
        source="local",
        entrypoint_func=document_summarize,
    ),
]


# ── Approved tool-call sequences ─────────────────────────────────────────────
# Guardian uses these to enforce sequence contracts for the Researcher agent.
# Novel sequences not matching any prefix below are sandboxed in Phase 2
# (Phase 3 will retry them in an isolated environment).
# Register with: make register-agent-sequences
RESEARCHER_EXPECTED_SEQUENCES: list[list[str]] = [
    ["web_search", "web_fetch", "document_summarize"],
    ["web_search", "document_summarize"],
    ["web_fetch", "document_summarize"],
    ["web_search"],
    ["web_fetch"],
    ["document_summarize"],
]


async def register_researcher_tools() -> None:
    """
    Register all researcher tools in the tool registry.
    Call once at startup or via: make register-researcher-tools
    """
    for manifest in RESEARCHER_TOOL_MANIFESTS:
        await register_tool(
            manifest,
            approved_by="operator",
            approval_notes="Phase 1 researcher agent tools",
        )
    logger.info("[researcher] All tools registered.")


# ── Graph nodes ───────────────────────────────────────────────────────────────


def _build_researcher_agent_node(llm_with_tools: Any):
    """
    Build the researcher's agent_node with a pre-bound LLM.
    The LLM is bound once at graph-build time, not per-invocation.
    """

    async def agent_node(state: ResearcherState) -> dict:
        updates = increment_step(state)

        log_agent_event(
            "llm_call",
            "researcher",
            {"step": state["step_count"], "task": state.get("task", "")},
            run_id=state.get("run_id"),
        )

        try:
            # Sanitize outbound messages (PII redaction)
            clean_messages = sanitize_messages(state["messages"])

            # Pre-flight budget check
            msg_text = " ".join(
                m.content if isinstance(m.content, str) else str(m.content)
                for m in clean_messages
            )
            preflight_budget_check(estimate_tokens(msg_text), "ollama")

            with timed("llm_latency_ms", get_metrics()):
                response = await llm_with_tools.ainvoke(clean_messages)

            # Track token usage
            if hasattr(response, "usage_metadata") and response.usage_metadata:
                usage = response.usage_metadata
                token_updates = check_token_budget(state, usage.get("total_tokens", 0))
                updates.update(token_updates)
                get_metrics().record_tokens(
                    state.get("run_id", "unknown"), usage.get("total_tokens", 0)
                )

            log_agent_event(
                "llm_response",
                "researcher",
                {"step": state["step_count"], "content": str(response.content)[:200]},
                run_id=state.get("run_id"),
            )

            updates["messages"] = [response]

            # Collect source URLs from any tool calls requested
            tool_calls = getattr(response, "tool_calls", []) or []
            new_sources: list[str] = list(state.get("sources", []))
            for tc in tool_calls:
                args = (
                    tc.get("args", {})
                    if isinstance(tc, dict)
                    else getattr(tc, "args", {})
                )
                if url := args.get("url"):
                    new_sources.append(url)
                if query := args.get("query"):
                    new_sources.append(f"search:{query}")
            updates["sources"] = new_sources

            return updates

        except Exception as e:
            error_updates = record_error(state, e, context="researcher/agent_node")
            updates.update(error_updates)
            logger.exception(f"Error in researcher agent_node: {e}")
            return updates

    return agent_node


async def finalizer_node(state: ResearcherState) -> dict:
    """Extract final result from last message."""
    messages = state.get("messages", [])
    if messages:
        last = messages[-1]
        result = last.content if isinstance(last.content, str) else str(last.content)
    else:
        result = "No result produced."

    log_agent_event(
        "run_end",
        "researcher",
        {
            "steps": state.get("step_count", 0),
            "tokens": state.get("token_count", 0),
            "errors": state.get("error_count", 0),
            "sources": len(state.get("sources", [])),
        },
        run_id=state.get("run_id"),
    )

    return {"result": result}


# ── Routing ───────────────────────────────────────────────────────────────────


def route_after_researcher(state: ResearcherState) -> str:
    """Route after agent node — tools if LLM requested them, otherwise finalize."""
    safeguard_result = check_safeguards(state)
    if safeguard_result == "end":
        return "finalize"

    last_msg = state["messages"][-1] if state["messages"] else None
    if isinstance(last_msg, AIMessage) and getattr(last_msg, "tool_calls", None):
        return "tools"

    return "finalize"


# ── Graph builder ─────────────────────────────────────────────────────────────


def build_researcher_graph() -> StateGraph:
    """Build the researcher graph (uncompiled). Bind tools to LLM here."""
    llm = get_primary_llm(temperature=0.1).bind_tools(RESEARCHER_TOOLS)
    tool_node = SecureToolNode(RESEARCHER_TOOLS)

    agent_node = _build_researcher_agent_node(llm)

    graph = StateGraph(ResearcherState)

    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_node("finalize", finalizer_node)

    graph.set_entry_point("agent")

    graph.add_conditional_edges(
        "agent",
        route_after_researcher,
        {
            "tools": "tools",
            "finalize": "finalize",
        },
    )
    graph.add_edge("tools", "agent")
    graph.add_edge("finalize", END)

    return graph


# ── Public entry point ────────────────────────────────────────────────────────


async def run_researcher(
    task: str,
    thread_id: str | None = None,
    tracing_enabled: bool = True,
    max_steps: int | None = None,
) -> dict[str, Any]:
    """
    Run the Researcher agent on a task. High-level entry point.

    Args:
        task:            Research question or task description.
        thread_id:       Optional thread ID for checkpoint resumption.
        tracing_enabled: Set False to disable LangSmith for this run.
        max_steps:       Override the profile's default recursion limit.

    Returns:
        dict with 'result', 'steps', 'tokens', 'sources', 'run_id', 'errors' keys.
    """
    from src.security import sanitize_text

    task, sanitize_meta = sanitize_text(task)
    if sanitize_meta.get("injection_detected"):
        logger.warning(
            "Injection patterns detected in researcher task input — sanitized."
        )

    init = SafeguardedState.initial(
        tracing_enabled=tracing_enabled,
        max_steps=max_steps,
    )
    state: ResearcherState = {
        **init,
        "task": task,
        "result": None,
        "sources": [],
        "sequence_so_far": [],
        "messages": [HumanMessage(content=task)],
    }

    config = create_run_config(
        thread_id=thread_id,
        tracing_enabled=tracing_enabled,
        run_name=f"researcher: {task[:50]}",
        tags=["researcher", "phase-1"],
        recursion_limit=max_steps or settings.safeguards.default_recursion_limit,
    )

    log_agent_event(
        "run_start",
        "researcher",
        {
            "task": task[:100],
            "tracing": tracing_enabled,
            "max_steps": state["max_steps"],
        },
        run_id=state["run_id"],
    )

    from src.database import get_checkpointer

    async with get_checkpointer() as checkpointer:
        graph = build_researcher_graph().compile(checkpointer=checkpointer)
        final_state = await graph.ainvoke(state, config)

    return {
        "result": final_state.get("result", ""),
        "steps": final_state.get("step_count", 0),
        "tokens": final_state.get("token_count", 0),
        "sources": final_state.get("sources", []),
        "run_id": final_state.get("run_id"),
        "errors": final_state.get("error_count", 0),
    }
