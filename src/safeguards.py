"""
src/safeguards.py
─────────────────
Three-layer loop protection, token budget enforcement, and
per-run LangSmith tracing toggle. Wire these into every graph.

Usage:
    from src.safeguards import (
        SafeguardedState,
        check_safeguards,
        create_run_config,
        token_budget_guard,
    )
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from typing import Annotated, Any
import operator

from src.security import HITL_HALT_CATEGORIES, HITL_LOG_CATEGORIES

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages

from config.settings import settings

logger = logging.getLogger(__name__)


# ── State schema with built-in safeguard fields ───────────────────────────────


class SafeguardedState(dict):
    """
    Base state dict that includes all safeguard tracking fields.
    Use this (or extend it) as your graph's state type.

    Minimal usage:
        from src.safeguards import SafeguardedState
        from langgraph.graph import StateGraph

        graph = StateGraph(SafeguardedState)
    """

    # These are the keys every safeguarded graph should carry.
    # Defined here as documentation — actual typing is via TypedDict in subclasses.
    _SAFEGUARD_FIELDS = {
        "step_count": 0,  # Auto-increments each node
        "max_steps": None,  # Set from profile at run creation
        "error_count": 0,  # Incremented on node errors
        "loop_detected": False,  # Set by detect_action_loop()
        "force_end": False,  # Set by any safeguard to terminate graph
        "action_history": [],  # Last N tool call signatures
        "token_count": 0,  # Running token total
        "run_id": None,  # UUID for this run
        "tracing_enabled": True,  # Per-run LangSmith toggle
    }

    @classmethod
    def initial(
        cls,
        tracing_enabled: bool = True,
        max_steps: int | None = None,
        agent_id: str = "base_agent",
    ) -> dict:
        """Create a fresh initial state with all safeguard fields populated.

        Args:
            tracing_enabled: Set False to disable LangSmith for this run.
            max_steps:       Override the profile's default recursion limit.
            agent_id:        Identifies which agent owns this run.
                             MUST match the agent_id used in issue_task_token()
                             in the same run_* function — divergence causes
                             threat events and task token audit trails to
                             disagree on identity.

        Checkpoint resume behaviour:
            This method is called ONCE at run start.  When a LangGraph graph is
            resumed from a checkpoint (e.g. after an interruption), LangGraph
            hydrates the full state dict from the checkpoint store — it does NOT
            call initial() again.  As a result, step_count, action_history, and
            token_count all persist correctly across resume.

            The only edge case is if a caller constructs a new initial() dict
            and passes it as the state for a resumed thread_id.  In that case
            the counters would reset.  To resume correctly, pass only the
            thread_id in config and let LangGraph reload state from the
            checkpoint — do not pass a new initial() state.
        """
        return {
            "step_count": 0,
            "max_steps": max_steps or settings.safeguards.default_recursion_limit,
            "error_count": 0,
            "loop_detected": False,
            "force_end": False,
            "action_history": [],
            "token_count": 0,
            "run_id": str(uuid.uuid4()),
            "tracing_enabled": tracing_enabled,
            "messages": [],
            "agent_id": agent_id,
        }


# ── Per-run LangSmith tracing toggle ─────────────────────────────────────────


def create_run_config(
    thread_id: str | None = None,
    tracing_enabled: bool = True,
    run_name: str | None = None,
    tags: list[str] | None = None,
    metadata: dict | None = None,
    recursion_limit: int | None = None,
) -> dict:
    """
    Create a LangGraph run config with optional LangSmith tracing.

    Args:
        thread_id:       Checkpoint thread ID for persistence/resumption.
        tracing_enabled: Set False to disable LangSmith for this run only.
                         Useful for runs involving sensitive data.
        run_name:        Display name in LangSmith UI.
        tags:            Tags for filtering in LangSmith.
        metadata:        Extra metadata attached to the trace.
        recursion_limit: Override profile default for this run only.

    Usage:
        config = create_run_config(
            thread_id="user-123-session-1",
            tracing_enabled=False,   # sensitive data — skip LangSmith
        )
        result = await graph.ainvoke(state, config)
    """
    thread_id = thread_id or str(uuid.uuid4())
    recursion_limit = recursion_limit or settings.safeguards.default_recursion_limit

    config: dict[str, Any] = {
        "configurable": {
            "thread_id": thread_id,
        },
        "recursion_limit": recursion_limit,
    }

    # LangSmith tracing config
    if not tracing_enabled:
        # Disable tracing for this specific run
        config["callbacks"] = []
        os.environ["LANGCHAIN_TRACING_V2"] = "false"
        logger.info(f"[run:{thread_id}] LangSmith tracing DISABLED for this run.")
    else:
        # Re-enable if previously disabled
        if os.environ.get("LANGCHAIN_TRACING_V2") == "false":
            from dotenv import load_dotenv

            load_dotenv()  # Reload from .env to restore tracing setting
        langsmith_meta: dict[str, Any] = {}
        if run_name:
            langsmith_meta["run_name"] = run_name
        if tags:
            config["tags"] = tags
        if metadata or langsmith_meta:
            config["metadata"] = {**(metadata or {}), **langsmith_meta}

    return config


# ── Checkpoint resume helper ─────────────────────────────────────────────────


def resume_run_config(
    thread_id: str,
    tracing_enabled: bool = True,
) -> tuple[None, dict]:
    """
    Return the correct (input, config) pair for resuming an interrupted run.

    When resuming from a LangGraph checkpoint the graph input MUST be None so
    that LangGraph hydrates the full state (including safeguard counters) from
    the checkpoint store.  Passing a new SafeguardedState.initial() dict instead
    resets step_count, action_history, and token_count to zero, silently
    bypassing all three loop-protection layers for the resumed portion of the run.

    Correct pattern::

        input, config = resume_run_config(thread_id="existing-thread-id")
        result = await graph.ainvoke(input, config=config)
        # LangGraph loads state from checkpoint; counters continue from
        # wherever the interrupted run left off.

    Wrong pattern (DO NOT DO)::

        # This resets all loop-protection counters:
        state = SafeguardedState.initial(agent_id="researcher")
        config = create_run_config(thread_id="existing-thread-id")
        result = await graph.ainvoke(state, config=config)

    Args:
        thread_id:       The checkpoint thread ID of the interrupted run.
                         Must match the thread_id used in the original run.
        tracing_enabled: Passed through to the run config; does not affect
                         state hydration from the checkpoint.

    Returns:
        (None, config) — unpack directly into graph.ainvoke / astream_events.
    """
    config = create_run_config(thread_id=thread_id, tracing_enabled=tracing_enabled)
    return None, config


# ── Layer 1: Step counter check ───────────────────────────────────────────────


def check_step_limit(state: dict) -> bool:
    """
    Returns True if the step limit has been reached.
    Use as a conditional edge check.

    Usage:
        graph.add_conditional_edges(
            "my_node",
            lambda s: "end" if check_step_limit(s) else "continue",
        )
    """
    step = state.get("step_count", 0)
    max_steps = state.get("max_steps", settings.safeguards.default_recursion_limit)

    if step >= max_steps:
        logger.warning(
            f"🛑 Step limit reached: {step}/{max_steps}. Forcing graph termination."
        )
        return True
    return False


def increment_step(state: dict) -> dict:
    """Node function to increment the step counter. Add as first line of each node."""
    return {"step_count": state.get("step_count", 0) + 1}


# ── Layer 2: Action history loop detection ────────────────────────────────────


def _action_signature(tool_name: str, tool_input: Any) -> str:
    """Create a stable hash signature for a tool call."""
    payload = f"{tool_name}:{str(tool_input)}"
    return hashlib.sha256(payload.encode()).hexdigest()[:12]


def detect_action_loop(
    state: dict,
    tool_name: str,
    tool_input: Any,
) -> dict:
    """
    Check if the same tool call has been repeated. Returns state updates.
    Call at the start of any tool-executing node.

    Returns dict to merge into state (always call with state.update(...) or
    return from a node alongside other updates).
    """
    window = settings.safeguards.loop_detection_window
    threshold = settings.safeguards.loop_detection_threshold

    sig = _action_signature(tool_name, tool_input)
    history = list(state.get("action_history", []))
    history.append(sig)

    # Keep only the recent window
    if len(history) > window * 2:
        history = history[-(window * 2) :]

    # Count occurrences in the recent window
    recent = history[-window:]
    count = recent.count(sig)

    loop_detected = count >= threshold
    if loop_detected:
        logger.warning(
            f"🔄 Loop detected: tool '{tool_name}' called identically "
            f"{count} times in last {window} steps. Forcing termination."
        )

    return {
        "action_history": history,
        "loop_detected": loop_detected,
        "force_end": loop_detected,
    }


# ── Layer 3: Token budget guard ───────────────────────────────────────────────


def check_token_budget(state: dict, tokens_used: int) -> dict:
    """
    Update token count and check if budget is exceeded.
    Returns state updates including force_end if budget exceeded.

    Call after each LLM invocation with the actual token count.
    """
    budget = settings.safeguards.default_token_budget
    current = state.get("token_count", 0)
    new_total = current + tokens_used

    force_end = new_total >= budget
    if force_end:
        logger.warning(
            f"💰 Token budget exceeded: {new_total:,} / {budget:,}. "
            f"Forcing graph termination."
        )
    elif new_total > budget * 0.8:
        logger.warning(
            f"⚠️  Token budget at {new_total/budget:.0%}: "
            f"{new_total:,} / {budget:,} tokens used."
        )

    return {
        "token_count": new_total,
        "force_end": force_end,
    }


# ── Unified safeguard check ───────────────────────────────────────────────────


def check_safeguards(state: dict) -> str:
    """
    Master safeguard check for use as a conditional edge.
    Returns "end" if any safeguard is triggered, "continue" otherwise.

    Usage:
        graph.add_conditional_edges(
            "agent_node",
            check_safeguards,
            {"end": END, "continue": "next_node"},
        )
    """
    if state.get("force_end"):
        return "end"
    if state.get("loop_detected"):
        return "end"
    if check_step_limit(state):
        return "end"
    if state.get("error_count", 0) >= settings.safeguards.max_errors_per_run:
        logger.warning(
            f"🚨 Max errors reached: {state['error_count']} errors. Terminating."
        )
        return "end"
    return "continue"


# ── HITL (Human-in-the-Loop) gate ────────────────────────────────────────────
# Phase 1: detect and halt. Phase 2: pause via LangGraph interrupt_before and
# surface an approval request to the operator dashboard.


def check_hitl_required(
    action: str,
    input_text: str,
    state: dict,
    categories: list[str] | None = None,
) -> dict:
    """
    Determine if a human must approve before the agent proceeds.

    Tiered response based on category risk level:
      HALT tier  — force-end immediately (CMD_INJECTION, SELF_PROBE,
                   DATA_STAGING, PRIVILEGE_ESCALATION).
      LOG tier   — log warning and continue (CREDENTIAL_PROBE, RECONNAISSANCE,
                   INTERNAL_PROBE, BULK_DESTRUCTIVE, SYSTEM_PATH_PROBE).

    Phase 1 behaviour:
      HALT tier → logger.warning() + return {"force_end": True}
      LOG tier  → logger.warning() + return {} (run continues)

    Phase 2 behaviour (TODO): use LangGraph interrupt_before to pause the graph
    and wait for operator approval via the approval API. The 'hitl_pending' flag
    in state will be checked by the routing function.

    Args:
        action:     The tool or action being attempted (for logging).
        input_text: The text that triggered the HITL check (sanitized excerpt).
        state:      Current agent state (for run_id).
        categories: List of matched DESTRUCTIVE_PATTERN category names.

    Returns:
        {} if no HITL required, or only LOG-tier categories matched.
        {"force_end": True} if any HALT-tier category matched.
    """
    if not categories:
        return {}

    run_id = state.get("run_id", "unknown")
    run_prefix = run_id[:8] if run_id != "unknown" else run_id

    halt_cats = [c for c in categories if c in HITL_HALT_CATEGORIES]
    log_cats = [c for c in categories if c in HITL_LOG_CATEGORIES]

    # LOG tier: suspicious but ambiguous — record and continue
    if log_cats:
        logger.warning(
            f"[hitl] Suspicious pattern (log-and-continue) — "
            f"action='{action}' categories={log_cats} run={run_prefix}..."
        )
        # TODO Phase 4: await log_threat_event(
        #     agent_id="safeguards", run_id=run_id,
        #     threat_type="DESTRUCTIVE_PATTERN", severity="LOW",
        #     details={"action": action, "categories": log_cats, "excerpt": input_text},
        # )

    # HALT tier: unambiguously adversarial — force-end immediately
    if halt_cats:
        logger.warning(
            f"[hitl] HITL HALT — action='{action}' categories={halt_cats} "
            f"run={run_prefix}... Forcing termination. "
            f"Phase 2 will surface approval request instead."
        )
        # TODO Phase 4: make this function `async def`, replace the block below with:
        #   await log_threat_event(agent_id="safeguards", run_id=run_id,
        #       threat_type="DESTRUCTIVE_PATTERN", severity="HIGH",
        #       details={"action": action, "categories": halt_cats})
        # and update the call site in SecureToolNode to `await check_hitl_required(...)`.
        #
        # DB logging is intentionally omitted in Phase 1 because calling
        # asyncio.get_event_loop().run_until_complete() from inside an already-running
        # async event loop raises RuntimeError. logger.warning() is the Phase 1 audit
        # record. Phase 4 wires the Threat Analyst, at which point reliable DB
        # persistence of DESTRUCTIVE_PATTERN events is required.
        return {"force_end": True}

    # Only LOG-tier categories matched — run continues
    return {}


# ── Error tracking ────────────────────────────────────────────────────────────


def record_error(state: dict, error: Exception, context: str = "") -> dict:
    """
    Record an error in state. Returns state updates.
    Use in node exception handlers.
    """
    count = state.get("error_count", 0) + 1
    logger.error(
        f"Agent error [{context}] ({count}/{settings.safeguards.max_errors_per_run}): {error}"
    )
    return {
        "error_count": count,
        "force_end": count >= settings.safeguards.max_errors_per_run,
    }
