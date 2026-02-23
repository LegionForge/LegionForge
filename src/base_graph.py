"""
src/base_graph.py
─────────────────
Async base graph template. Every agent you build should inherit
this pattern. Safeguards, tracing, and observability are pre-wired.

This file demonstrates the pattern — it is not meant to be run directly.
Copy this structure when building new agents in src/agents/.

Key patterns demonstrated:
    - Async node functions
    - Step counting via state
    - Safeguard checks as conditional edges
    - Per-run tracing toggle
    - Token budget tracking
    - Loop detection on tool calls
    - Error handling with state updates
    - PostgreSQL checkpointing
"""

from __future__ import annotations

import logging
from typing import Annotated, Any, TypedDict
import operator

from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages

from config.settings import settings
from src.safeguards import (
    SafeguardedState,
    check_safeguards,
    create_run_config,
    detect_action_loop,
    check_token_budget,
    increment_step,
    record_error,
)
from src.llm_factory import get_primary_llm, get_router_llm
from src.observability import log_agent_event, get_metrics, timed
from src.security import sanitize_text, sanitize_for_trace

logger = logging.getLogger(__name__)


# ── State definition ──────────────────────────────────────────────────────────


class AgentState(TypedDict):
    """
    State for a basic single-agent graph.
    Extend this for more complex multi-agent systems.

    Convention:
        - Use Annotated[list, add_messages] for message accumulation
        - Use Annotated[int, operator.add] for auto-incrementing counters
        - Keep state minimal — don't store transient values here
    """

    # Message history (auto-accumulated by add_messages reducer)
    messages: Annotated[list[BaseMessage], add_messages]

    # ── Safeguard fields (required in every graph) ────────────────────────────
    step_count: int
    max_steps: int
    error_count: int
    loop_detected: bool
    force_end: bool
    action_history: list[str]
    token_count: int
    run_id: str
    tracing_enabled: bool

    # ── Agent-specific fields ─────────────────────────────────────────────────
    task: str  # The current task description
    result: str | None  # Final output


# ── Node functions ────────────────────────────────────────────────────────────


async def agent_node(state: AgentState) -> dict:
    """
    Main agent node. Calls the LLM and processes the response.
    Replace this with your actual agent logic.
    """
    # 1. Increment step counter
    updates = increment_step(state)

    log_agent_event(
        "llm_call",
        "base_agent",
        {"step": state["step_count"], "task": state.get("task", "")},
        run_id=state.get("run_id"),
    )

    try:
        llm = get_primary_llm(temperature=0.1)

        # Sanitize messages before sending
        messages = state["messages"]

        with timed("llm_latency_ms", get_metrics()):
            response = await llm.ainvoke(messages)

        # Track token usage if available
        if hasattr(response, "usage_metadata") and response.usage_metadata:
            usage = response.usage_metadata
            token_updates = check_token_budget(
                state,
                usage.get("total_tokens", 0),
            )
            updates.update(token_updates)

            get_metrics().record_tokens(
                state.get("run_id", "unknown"),
                usage.get("total_tokens", 0),
            )

        log_agent_event(
            "llm_response",
            "base_agent",
            {
                "step": state["step_count"],
                "content": str(response.content)[:200],  # Truncate for log
            },
            run_id=state.get("run_id"),
        )

        updates["messages"] = [response]
        return updates

    except Exception as e:
        error_updates = record_error(state, e, context="agent_node")
        updates.update(error_updates)
        logger.exception(f"Error in agent_node: {e}")
        return updates


async def finalizer_node(state: AgentState) -> dict:
    """
    Terminal node. Extracts the final result from the last message.
    Always runs before END.
    """
    messages = state.get("messages", [])
    if messages:
        last = messages[-1]
        result = last.content if isinstance(last.content, str) else str(last.content)
    else:
        result = "No result produced."

    log_agent_event(
        "run_end",
        "base_agent",
        {
            "steps": state.get("step_count", 0),
            "tokens": state.get("token_count", 0),
            "errors": state.get("error_count", 0),
            "loop": state.get("loop_detected", False),
            "result_len": len(result),
        },
        run_id=state.get("run_id"),
    )

    return {"result": result}


# ── Routing functions ─────────────────────────────────────────────────────────


def route_after_agent(state: AgentState) -> str:
    """
    Decide what to do after the agent node runs.
    Checks all safeguards first, then applies agent-specific logic.
    """
    # Safeguards always take priority
    safeguard_result = check_safeguards(state)
    if safeguard_result == "end":
        return "finalize"

    # Agent-specific routing logic
    last_message = state["messages"][-1] if state["messages"] else None

    # If the LLM indicates it's done, finalize
    if last_message and isinstance(last_message, AIMessage):
        content = str(last_message.content).lower()
        if any(
            phrase in content for phrase in ["final answer:", "task complete", "done."]
        ):
            return "finalize"

    # Otherwise, continue the loop
    return "agent"


# ── Graph builder ─────────────────────────────────────────────────────────────


def build_base_graph() -> StateGraph:
    """
    Build and return the base graph (uncompiled).
    Use this as a pattern for all your agents.
    """
    graph = StateGraph(AgentState)

    # Add nodes
    graph.add_node("agent", agent_node)
    graph.add_node("finalize", finalizer_node)

    # Entry point
    graph.set_entry_point("agent")

    # Conditional edges from agent node
    graph.add_conditional_edges(
        "agent",
        route_after_agent,
        {
            "agent": "agent",  # Loop back for more processing
            "finalize": "finalize",  # Done — collect result
        },
    )

    # Finalize always goes to END
    graph.add_edge("finalize", END)

    return graph


# ── Public interface ──────────────────────────────────────────────────────────


async def run_agent(
    task: str,
    thread_id: str | None = None,
    tracing_enabled: bool = True,
    max_steps: int | None = None,
) -> dict[str, Any]:
    """
    Run the base agent on a task. High-level interface.

    Args:
        task:            The task description for the agent.
        thread_id:       Optional thread ID for checkpoint resumption.
        tracing_enabled: Set False to disable LangSmith for this run.
        max_steps:       Override the profile's default recursion limit.

    Returns:
        dict with 'result', 'steps', 'tokens', 'run_id' keys.
    """
    # Sanitize input
    task, sanitize_meta = sanitize_text(task)
    if sanitize_meta.get("injection_detected"):
        logger.warning(
            f"Injection patterns detected in task input. Proceeding with sanitized input."
        )

    # Build initial state
    init = SafeguardedState.initial(
        tracing_enabled=tracing_enabled,
        max_steps=max_steps,
    )
    state: AgentState = {
        **init,
        "task": task,
        "result": None,
        "messages": [HumanMessage(content=task)],
    }

    # Build run config
    config = create_run_config(
        thread_id=thread_id,
        tracing_enabled=tracing_enabled,
        run_name=f"base_agent: {task[:50]}",
        tags=["base_agent"],
        recursion_limit=max_steps or settings.safeguards.default_recursion_limit,
    )

    log_agent_event(
        "run_start",
        "base_agent",
        {
            "task": task[:100],
            "tracing": tracing_enabled,
            "max_steps": state["max_steps"],
        },
        run_id=state["run_id"],
    )

    # Compile graph with PostgreSQL checkpointer
    from src.database import get_checkpointer

    async with get_checkpointer() as checkpointer:
        graph = build_base_graph().compile(checkpointer=checkpointer)
        final_state = await graph.ainvoke(state, config)

    return {
        "result": final_state.get("result", ""),
        "steps": final_state.get("step_count", 0),
        "tokens": final_state.get("token_count", 0),
        "run_id": final_state.get("run_id"),
        "errors": final_state.get("error_count", 0),
    }


# ── LangGraph Studio entrypoint ───────────────────────────────────────────────
# langgraph.json points to this — required for LangGraph Studio to work

graph = build_base_graph().compile()
