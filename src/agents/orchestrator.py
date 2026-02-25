"""
src/agents/orchestrator.py
──────────────────────────
Orchestrator agent — coordinates sub-agents with privilege-narrowing token derivation.

Key design principles (Phase 3):
    1. Master token: issued at run start with the union of all sub-agent tool IDs.
    2. Derived tokens: each sub-agent receives a token ⊆ master (child never exceeds
       parent scope — enforced by derive_task_token's PrivilegeEscalationError guard).
    3. No direct agent-to-agent comms: all inter-agent traffic routes through here.
    4. Sub-agent results are returned as structured dicts, not raw message injection.

Startup:
    await register_orchestrator_tools()   # call once at application startup
    result = await run_orchestrator("Research and summarize LangGraph checkpointing")
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.messages import BaseMessage, AIMessage, HumanMessage
from langchain_core.tools import tool
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages

from config.settings import settings
from src.base_graph import AgentState, SecureToolNode
from src.safeguards import (
    SafeguardedState,
    check_safeguards,
    create_run_config,
    check_token_budget,
    increment_step,
    record_error,
)
from src.llm_factory import get_primary_llm
from src.observability import log_agent_event, get_metrics, timed
from src.security import (
    ToolManifest,
    register_tool,
    sanitize_messages,
    sanitize_text,
)
from src.rate_limiter import preflight_budget_check, estimate_tokens

logger = logging.getLogger(__name__)


# ── State ──────────────────────────────────────────────────────────────────────


class OrchestratorState(AgentState):
    """Extends AgentState with accumulated sub-agent results."""

    sub_agent_results: list[dict]


# ── Token management ───────────────────────────────────────────────────────────

# Policy for the orchestrator's own master token.
# "deny" — any scope violation is a security incident (orchestrator is high-trust).
_ORCHESTRATOR_ESCALATION_POLICY = "deny"
_ORCHESTRATOR_DATA_CLASSES = ["public", "internal"]


def _issue_master_token(run_id: str, all_tool_ids: list[str]) -> str | None:
    """
    Issue a master analyst-role JWT for this orchestrator run.

    The master token is scoped to the union of all sub-agent tool IDs.
    Sub-agents receive narrower derived tokens (⊆ master) via _derive_researcher_token.

    Non-fatal if the JWT signing secret is not configured — returns None
    (unconstrained mode; Phase 4 will make tokens mandatory).
    """
    try:
        from src.security import issue_task_token

        return issue_task_token(
            agent_id="orchestrator",
            run_id=run_id,
            granted_tools=all_tool_ids,
            granted_tables=["documents"],
            granted_data_classes=_ORCHESTRATOR_DATA_CLASSES,
            escalation_policy=_ORCHESTRATOR_ESCALATION_POLICY,
        )
    except RuntimeError:
        logger.warning(
            "[orchestrator] JWT secret not configured — running without task token. "
            "Run: make setup-task-token-secret"
        )
        return None


def _derive_researcher_token(master_jwt: str) -> str | None:
    """
    Derive a narrower researcher token from the orchestrator's master token.

    Narrowing applied:
      - Tools: restricted to RESEARCHER_TOOL_MANIFESTS (⊆ master tools)
      - data_classes: 'public' only (master includes 'internal')
      - TTL: capped at master's remaining lifetime

    Returns None if derivation fails — callers treat it as unconstrained
    (backward compat; Phase 4 will make tokens mandatory everywhere).
    """
    try:
        from src.security import derive_task_token
        from src.agents.researcher import RESEARCHER_TOOL_MANIFESTS

        return derive_task_token(
            parent_jwt=master_jwt,
            granted_tools=[m.tool_id for m in RESEARCHER_TOOL_MANIFESTS],
            granted_data_classes=["public"],
        )
    except Exception as e:
        logger.warning(f"[orchestrator] Could not derive researcher token: {e}")
        return None


# ── Sub-agent spawner ──────────────────────────────────────────────────────────


async def _spawn_researcher_sub_agent(sub_task: str, derived_token: str | None) -> dict:
    """
    Spawn the Researcher sub-agent with a derived (narrowed) task token.

    Security invariant: derived_token ⊆ master token.
    The researcher cannot access tools or data beyond what the orchestrator granted.

    Args:
        sub_task:       Task string delegated to the researcher.
        derived_token:  JWT narrowed from the orchestrator's master token.
                        None → researcher issues its own reader-role token (compat).

    Returns:
        Structured result dict from run_researcher().
    """
    from src.agents.researcher import run_researcher

    return await run_researcher(
        task=sub_task,
        task_token=derived_token,
    )


# ── Tools ──────────────────────────────────────────────────────────────────────

# Module-level token ref populated at run start so the spawn_researcher closure
# can access the master JWT without needing state injection.
# Using a mutable dict (not bare str) so the reference persists across Python calls.
_master_token_ref: dict[str, str | None] = {"token": None}


@tool
async def spawn_researcher(sub_task: str) -> str:
    """
    Delegate a bounded research task to the Researcher sub-agent.

    The Researcher receives a derived token scoped to public data only.
    Use this for any task that requires web search or document retrieval.
    Returns a summary of the research result (truncated at 1000 chars).
    """
    master_jwt = _master_token_ref.get("token")
    derived = _derive_researcher_token(master_jwt) if master_jwt else None

    result = await _spawn_researcher_sub_agent(sub_task, derived)

    research_result = result.get("result", "No result.")
    sources = result.get("sources", [])
    steps = result.get("steps", 0)
    errors = result.get("errors", 0)

    summary = (
        f"Research complete ({steps} steps, {len(sources)} sources"
        + (f", {errors} errors" if errors else "")
        + f"):\n{research_result[:800]}"
    )
    return summary


ORCHESTRATOR_TOOLS = [spawn_researcher]

# ── Tool manifests ─────────────────────────────────────────────────────────────

ORCHESTRATOR_TOOL_MANIFESTS = [
    ToolManifest(
        tool_id="spawn_researcher",
        description="Delegate a bounded research task to the Researcher sub-agent",
        input_schema={"sub_task": "str"},
        declared_side_effects=["spawns_sub_agent:researcher"],
        source="local",
        entrypoint_func=spawn_researcher,
    ),
]

# ── Approved tool-call sequences ───────────────────────────────────────────────
ORCHESTRATOR_EXPECTED_SEQUENCES: list[list[str]] = [
    ["spawn_researcher"],
    ["spawn_researcher", "spawn_researcher"],  # multi-step research
]


async def register_orchestrator_tools() -> None:
    """
    Register all orchestrator tools in the tool registry.
    Call once at startup or via: make register-orchestrator-tools
    """
    for manifest in ORCHESTRATOR_TOOL_MANIFESTS:
        await register_tool(
            manifest,
            approved_by="operator",
            approval_notes="Phase 3 orchestrator tools",
        )
    logger.info("[orchestrator] All tools registered.")


# ── Graph nodes ────────────────────────────────────────────────────────────────


def _build_orchestrator_agent_node(llm_with_tools: Any):
    """Build the orchestrator agent_node with pre-bound LLM."""

    async def agent_node(state: OrchestratorState) -> dict:
        updates = increment_step(state)

        log_agent_event(
            "llm_call",
            "orchestrator",
            {"step": state["step_count"], "task": state.get("task", "")},
            run_id=state.get("run_id"),
        )

        try:
            clean_messages = sanitize_messages(state["messages"])
            msg_text = " ".join(
                m.content if isinstance(m.content, str) else str(m.content)
                for m in clean_messages
            )
            preflight_budget_check(estimate_tokens(msg_text), "ollama")

            with timed("llm_latency_ms", get_metrics()):
                response = await llm_with_tools.ainvoke(clean_messages)

            if hasattr(response, "usage_metadata") and response.usage_metadata:
                usage = response.usage_metadata
                token_updates = check_token_budget(state, usage.get("total_tokens", 0))
                updates.update(token_updates)
                get_metrics().record_tokens(
                    state.get("run_id", "unknown"), usage.get("total_tokens", 0)
                )

            log_agent_event(
                "llm_response",
                "orchestrator",
                {"step": state["step_count"], "content": str(response.content)[:200]},
                run_id=state.get("run_id"),
            )

            updates["messages"] = [response]
            return updates

        except Exception as e:
            error_updates = record_error(state, e, context="orchestrator/agent_node")
            updates.update(error_updates)
            logger.exception(f"Error in orchestrator agent_node: {e}")
            return updates

    return agent_node


async def finalizer_node(state: OrchestratorState) -> dict:
    """Extract final result from last message."""
    messages = state.get("messages", [])
    if messages:
        last = messages[-1]
        result = last.content if isinstance(last.content, str) else str(last.content)
    else:
        result = "No result produced."

    log_agent_event(
        "run_end",
        "orchestrator",
        {
            "steps": state.get("step_count", 0),
            "tokens": state.get("token_count", 0),
            "errors": state.get("error_count", 0),
            "sub_agents": len(state.get("sub_agent_results", [])),
        },
        run_id=state.get("run_id"),
    )

    return {"result": result}


# ── Routing ────────────────────────────────────────────────────────────────────


def route_after_orchestrator(state: OrchestratorState) -> str:
    """Route after agent node — tools if LLM requested them, otherwise finalize."""
    safeguard_result = check_safeguards(state)
    if safeguard_result == "end":
        return "finalize"

    last_msg = state["messages"][-1] if state["messages"] else None
    if isinstance(last_msg, AIMessage) and getattr(last_msg, "tool_calls", None):
        return "tools"

    return "finalize"


# ── Graph builder ──────────────────────────────────────────────────────────────


def build_orchestrator_graph() -> StateGraph:
    """Build the orchestrator graph (uncompiled). Bind tools to LLM here."""
    llm = get_primary_llm(temperature=0.1).bind_tools(ORCHESTRATOR_TOOLS)
    tool_node = SecureToolNode(ORCHESTRATOR_TOOLS)
    agent_node = _build_orchestrator_agent_node(llm)

    graph = StateGraph(OrchestratorState)

    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_node("finalize", finalizer_node)

    graph.set_entry_point("agent")

    graph.add_conditional_edges(
        "agent",
        route_after_orchestrator,
        {
            "tools": "tools",
            "finalize": "finalize",
        },
    )
    graph.add_edge("tools", "agent")
    graph.add_edge("finalize", END)

    return graph


# ── Public entry point ─────────────────────────────────────────────────────────


async def run_orchestrator(
    task: str,
    thread_id: str | None = None,
    tracing_enabled: bool = True,
    max_steps: int | None = None,
) -> dict[str, Any]:
    """
    Run the Orchestrator agent on a high-level task.

    The orchestrator breaks down the task and delegates to sub-agents. Each
    sub-agent receives a derived token narrowed from the orchestrator's master
    token — privilege never escalates downward.

    Args:
        task:            High-level task description.
        thread_id:       Optional thread ID for checkpoint resumption.
        tracing_enabled: Set False to disable LangSmith for this run.
        max_steps:       Override the profile's default recursion limit.

    Returns:
        dict with 'result', 'steps', 'tokens', 'sub_agent_results', 'run_id', 'errors'.
    """
    from src.database import get_checkpointer

    task, sanitize_meta = sanitize_text(task)
    if sanitize_meta.get("injection_detected"):
        logger.warning(
            "Injection pattern detected in orchestrator task input — sanitized."
        )

    init = SafeguardedState.initial(
        tracing_enabled=tracing_enabled,
        max_steps=max_steps,
    )
    run_id = init["run_id"]

    # Master token: union of orchestrator + all sub-agent tool IDs.
    # Sub-agents get derived (narrower) tokens — privilege flows strictly downward.
    from src.agents.researcher import RESEARCHER_TOOL_MANIFESTS

    all_tool_ids = [m.tool_id for m in ORCHESTRATOR_TOOL_MANIFESTS] + [
        m.tool_id for m in RESEARCHER_TOOL_MANIFESTS
    ]

    master_token = _issue_master_token(run_id, all_tool_ids)

    # Populate module-level closure ref so spawn_researcher tool can derive tokens.
    _master_token_ref["token"] = master_token

    logger.debug(
        f"[orchestrator] Master token {'issued' if master_token else 'absent'} "
        f"for run={run_id[:8]}... tools={all_tool_ids}"
    )

    state: OrchestratorState = {
        **init,
        "task": task,
        "result": None,
        "sub_agent_results": [],
        "sequence_so_far": [],
        "task_token": master_token,
        "messages": [HumanMessage(content=task)],
    }

    config = create_run_config(
        thread_id=thread_id,
        tracing_enabled=tracing_enabled,
        run_name=f"orchestrator: {task[:50]}",
        tags=["orchestrator", "phase-3"],
        recursion_limit=max_steps or settings.safeguards.default_recursion_limit,
    )

    log_agent_event(
        "run_start",
        "orchestrator",
        {
            "task": task[:100],
            "tracing": tracing_enabled,
            "max_steps": state["max_steps"],
            "has_master_token": master_token is not None,
        },
        run_id=run_id,
    )

    async with get_checkpointer() as checkpointer:
        graph = build_orchestrator_graph().compile(checkpointer=checkpointer)
        final_state = await graph.ainvoke(state, config)

    return {
        "result": final_state.get("result", ""),
        "steps": final_state.get("step_count", 0),
        "tokens": final_state.get("token_count", 0),
        "sub_agent_results": final_state.get("sub_agent_results", []),
        "run_id": final_state.get("run_id"),
        "errors": final_state.get("error_count", 0),
    }
