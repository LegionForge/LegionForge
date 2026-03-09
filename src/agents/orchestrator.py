"""
src/agents/orchestrator.py
──────────────────────────
Orchestrator agent — coordinates sub-agents with privilege-narrowing token derivation.

Key design principles (Phase 3 / Phase 9):
    1. Master token: issued at run start with the union of all sub-agent tool IDs.
    2. Derived tokens: each sub-agent receives a token ⊆ master (child never exceeds
       parent scope — enforced by derive_task_token's PrivilegeEscalationError guard).
    3. No direct agent-to-agent comms: all inter-agent traffic routes through here.
    4. Sub-agent results are returned as structured dicts, not raw message injection.

Tools:
    spawn_researcher(sub_task)           — serial: one researcher at a time.
    fan_out_researchers(sub_tasks_json)  — parallel: N researchers via asyncio.gather().

Startup:
    await register_orchestrator_tools()   # call once at application startup
    result = await run_orchestrator("Research and summarize LangGraph checkpointing")
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.messages import BaseMessage, AIMessage, HumanMessage, SystemMessage
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

# Maximum self-verification passes per run (Phase 71).
# After this many verify rounds the answer is accepted as-is to prevent loops.
MAX_VERIFY_ROUNDS: int = 1


# ── State ──────────────────────────────────────────────────────────────────────


class OrchestratorState(AgentState):
    """Extends AgentState with accumulated sub-agent results."""

    sub_agent_results: list[dict]
    verify_rounds: int  # number of self-verification passes taken (Phase 71)


# ── Orchestrator system prompt ─────────────────────────────────────────────────

_ORCHESTRATOR_SYSTEM_CONTENT = (
    "You are an orchestrator agent with two tools:\n"
    "- spawn_researcher(sub_task): delegate a task to a sub-agent that has "
    "web search and page-fetch capabilities.\n"
    "- fan_out_researchers(sub_tasks_json): run multiple independent research "
    "tasks in parallel (pass a JSON array of task strings).\n\n"
    "RULES:\n"
    "1. For ANY task requiring current events, news, real-world data, URLs, "
    "or information beyond your training cutoff — you MUST call "
    "spawn_researcher or fan_out_researchers. Never answer from memory.\n"
    "2. Break complex tasks into focused sub-tasks and delegate each one.\n"
    "3. Synthesize the sub-agent results into a final answer for the user.\n"
    "4. If a sub-agent returns an error, report it clearly — never fabricate "
    "an answer."
)


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

# Module-level refs populated at run start so tool closures can access
# the master JWT and run_id without state injection.
# Mutable dicts (not bare str/None) so references persist across Python calls.
_master_token_ref: dict[str, str | None] = {"token": None}
_run_id_ref: dict[str, str] = {"run_id": "unknown"}


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


@tool
async def fan_out_researchers(sub_tasks_json: str) -> str:
    """
    Dispatch multiple independent research tasks to Researcher sub-agents IN PARALLEL.

    sub_tasks_json: JSON array of task strings (max 10), e.g.:
        '["Summarize LangGraph docs", "Find LangChain changelog", "Check httpx API"]'

    Use this instead of sequential spawn_researcher calls when tasks are independent.
    Each branch runs concurrently (up to 5 at a time) and receives its own derived
    task token scoped to public data only.  Returns a structured summary of all results.
    """
    import json
    from src.agents.fan_out import SubTask, fan_out, aggregate_results
    from src.agents.researcher import RESEARCHER_TOOL_MANIFESTS

    try:
        raw = json.loads(sub_tasks_json)
    except json.JSONDecodeError as exc:
        return f"[fan_out_researchers] Invalid JSON: {exc}"

    if not isinstance(raw, list) or not raw:
        return "[fan_out_researchers] Expected a non-empty JSON array of task strings."

    if len(raw) > 10:
        return "[fan_out_researchers] Maximum 10 tasks per fan-out batch."

    researcher_tools = [m.tool_id for m in RESEARCHER_TOOL_MANIFESTS]
    tasks = [
        SubTask(
            task_id=f"branch_{i}",
            task=str(t),
            granted_tools=researcher_tools,
            granted_data_classes=["public"],
        )
        for i, t in enumerate(raw)
    ]

    master_jwt = _master_token_ref.get("token")
    run_id = _run_id_ref.get("run_id", "unknown")

    async def _runner(task: str, token: str | None, branch_run_id: str) -> dict:
        return await _spawn_researcher_sub_agent(task, token)

    results = await fan_out(
        tasks,
        parent_jwt=master_jwt,
        run_id=run_id,
        agent_runner=_runner,
    )
    return aggregate_results(results)


ORCHESTRATOR_TOOLS = [spawn_researcher, fan_out_researchers]

# ── Tool manifests ─────────────────────────────────────────────────────────────

ORCHESTRATOR_TOOL_MANIFESTS = [
    ToolManifest(
        tool_id="spawn_researcher",
        description="Delegate a bounded research task to the Researcher sub-agent (serial)",
        input_schema={"sub_task": "str"},
        declared_side_effects=["spawns_sub_agent:researcher"],
        source="local",
        entrypoint_func=spawn_researcher,
    ),
    ToolManifest(
        tool_id="fan_out_researchers",
        description=(
            "Dispatch multiple independent research tasks to Researcher sub-agents "
            "IN PARALLEL (asyncio.gather, max 10 tasks, each gets a derived token)"
        ),
        input_schema={"sub_tasks_json": "str"},
        declared_side_effects=["spawns_sub_agent:researcher", "parallel_dispatch"],
        source="local",
        entrypoint_func=fan_out_researchers,
    ),
]

# ── Approved tool-call sequences ───────────────────────────────────────────────
ORCHESTRATOR_EXPECTED_SEQUENCES: list[list[str]] = [
    ["spawn_researcher"],
    ["spawn_researcher", "spawn_researcher"],  # serial multi-step research
    ["fan_out_researchers"],  # single parallel batch
    ["fan_out_researchers", "spawn_researcher"],  # parallel batch then serial follow-up
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
            approval_notes="Phase 9 orchestrator tools (serial + parallel fan-out)",
        )
    logger.info("[orchestrator] All tools registered.")


# ── Graph nodes ────────────────────────────────────────────────────────────────


def _build_orchestrator_agent_node(llm_forced: Any, llm_free: Any):
    """Build the orchestrator agent_node with pre-bound LLMs.

    llm_forced: bound with tool_choice="required" — used on step 1 to prevent
                the orchestrator from answering from training data instead of
                delegating to a researcher sub-agent.
    llm_free:   standard binding — used on step 2+ for synthesis.
    """

    async def agent_node(state: OrchestratorState) -> dict:
        updates = increment_step(state)

        # If a security halt already set force_end, skip the LLM call.
        # Calling the LLM with dangling tool_calls produces empty content → [No result].
        if state.get("force_end"):
            return updates

        # After increment_step, step_count reflects the current step number.
        # Use the forced LLM on the first step only.
        step = updates.get("step_count", state.get("step_count", 1))
        llm_with_tools = llm_forced if step <= 1 else llm_free

        log_agent_event(
            "llm_call",
            "orchestrator",
            {
                "step": state["step_count"],
                "task": state.get("task", ""),
                "forced": step <= 1,
            },
            run_id=state.get("run_id"),
        )

        # Ensure the orchestrator system message is present.
        # The gateway worker initialises state with only [HumanMessage(task)] — no
        # SystemMessage — so we inject it here on step 1 if it is absent.
        if step == 1 and not any(
            isinstance(m, SystemMessage) for m in state.get("messages", [])
        ):
            state = {
                **state,
                "messages": [SystemMessage(content=_ORCHESTRATOR_SYSTEM_CONTENT)]
                + list(state["messages"]),
            }

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
    result = ""
    if messages:
        last = messages[-1]
        result = last.content if isinstance(last.content, str) else str(last.content)
    # Fallback: if LLM returned empty synthesis, surface the last tool output instead.
    if not result.strip():
        for msg in reversed(messages):
            if hasattr(msg, "type") and msg.type == "tool" and msg.content:
                result = str(msg.content)
                break
    if not result.strip():
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


# ── Self-verification node (Phase 71) ─────────────────────────────────────────


def _build_verify_node(llm_plain: Any):
    """
    Build the self-verification node with a pre-bound plain LLM (no tools).

    The verifier asks the LLM to judge whether the current answer fully addresses
    the original task.  If not, it adds a refinement HumanMessage and increments
    verify_rounds so route_after_verify returns "agent" for one more pass.

    MAX_VERIFY_ROUNDS caps the loop — after that the answer is accepted as-is.
    """

    async def verify_node(state: OrchestratorState) -> dict:
        rounds = state.get("verify_rounds", 0)
        if rounds >= MAX_VERIFY_ROUNDS:
            # Already did max passes — accept the answer.
            return {}

        messages = state.get("messages", [])
        last = messages[-1] if messages else None
        current_answer = last.content if last and isinstance(last.content, str) else ""
        task = state.get("task", "")

        if not current_answer or not task:
            return {}

        verify_prompt = (
            f"Task: {task}\n\n"
            f"Proposed answer:\n{current_answer[:1200]}\n\n"
            "Does this answer fully address the task above? "
            "Reply with exactly 'VERIFIED' if yes, or briefly state what is "
            "missing or incomplete if no."
        )
        try:
            response = await llm_plain.ainvoke(
                [
                    SystemMessage(
                        content=(
                            "You are a strict answer reviewer. "
                            "Your only job is to verify whether the proposed answer "
                            "fully addresses the task. Be concise."
                        )
                    ),
                    HumanMessage(content=verify_prompt),
                ]
            )
            feedback = (
                response.content
                if isinstance(response.content, str)
                else str(response.content)
            )
        except Exception as exc:
            logger.warning("[orchestrator] verify_node LLM error: %s", exc)
            return {}

        if "VERIFIED" in feedback.upper():
            log_agent_event(
                "verify_pass",
                "orchestrator",
                {"rounds": rounds, "verdict": "verified"},
                run_id=state.get("run_id"),
            )
            return {}

        # Ask the agent to improve its answer.
        log_agent_event(
            "verify_fail",
            "orchestrator",
            {"rounds": rounds, "feedback": feedback[:200]},
            run_id=state.get("run_id"),
        )
        refinement_msg = HumanMessage(
            content=(
                f"Your answer was incomplete. Reviewer feedback: {feedback}\n\n"
                "Please revise your answer to fully address the original task."
            )
        )
        return {
            "messages": [refinement_msg],
            "verify_rounds": rounds + 1,
        }

    return verify_node


# ── Routing ────────────────────────────────────────────────────────────────────


def route_after_orchestrator(state: OrchestratorState) -> str:
    """Route after agent node — tools if LLM requested them, otherwise verify."""
    safeguard_result = check_safeguards(state)
    if safeguard_result == "end":
        return "finalize"  # Skip verify on safety halt.

    last_msg = state["messages"][-1] if state["messages"] else None
    if isinstance(last_msg, AIMessage) and getattr(last_msg, "tool_calls", None):
        return "tools"

    return "verify"  # Phase 71: pass through self-verification before finalizing.


def route_after_verify(state: OrchestratorState) -> str:
    """
    Route after verify_node.

    If the verifier added a HumanMessage (refinement request), go back to the
    agent for another pass.  Otherwise finalize.
    """
    messages = state.get("messages", [])
    last = messages[-1] if messages else None
    if isinstance(last, HumanMessage) and state.get("verify_rounds", 0) > 0:
        return "agent"
    return "finalize"


# ── Graph builder ──────────────────────────────────────────────────────────────


def build_orchestrator_graph() -> StateGraph:
    """Build the orchestrator graph (uncompiled). Bind tools to LLM here."""
    # Step 1 uses tool_choice="required" so the orchestrator always delegates to
    # a researcher sub-agent rather than answering from training data.
    # Step 2+ uses the free binding for synthesis (no forced tool call).
    llm_forced = get_primary_llm(temperature=0.1).bind_tools(
        ORCHESTRATOR_TOOLS, tool_choice="required"
    )
    llm_free = get_primary_llm(temperature=0.1).bind_tools(ORCHESTRATOR_TOOLS)
    llm_plain = get_primary_llm(temperature=0.0)  # verifier — no tools needed
    tool_node = SecureToolNode(ORCHESTRATOR_TOOLS)
    agent_node = _build_orchestrator_agent_node(llm_forced, llm_free)
    verify_node = _build_verify_node(llm_plain)  # Phase 71

    graph = StateGraph(OrchestratorState)

    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_node("verify", verify_node)  # Phase 71
    graph.add_node("finalize", finalizer_node)

    graph.set_entry_point("agent")

    graph.add_conditional_edges(
        "agent",
        route_after_orchestrator,
        {
            "tools": "tools",
            "verify": "verify",  # Phase 71
            "finalize": "finalize",
        },
    )
    graph.add_edge("tools", "agent")
    graph.add_conditional_edges(  # Phase 71
        "verify",
        route_after_verify,
        {"agent": "agent", "finalize": "finalize"},
    )
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

    # Build initial state first — run_id needed for threat logging.
    # ORDERING RULE: always call SafeguardedState.initial() before sanitize_text()
    # so the run_id is available for DB logging if injection is detected.
    # agent_id MUST match the agent_id in issue_task_token() (via _issue_master_token).
    init = SafeguardedState.initial(
        tracing_enabled=tracing_enabled,
        max_steps=max_steps,
        agent_id="orchestrator",
    )
    run_id = init["run_id"]

    # Sanitize input — after init so run_id is available for DB logging.
    # check_injection is gated by prompt_injection_guard setting so dev/test
    # environments can disable user-input scanning without affecting tool-arg
    # detection (SecureToolNode always-on regardless of this setting).
    task, sanitize_meta = sanitize_text(
        task,
        check_injection=settings.security.prompt_injection_guard,
    )
    if sanitize_meta.get("injection_detected"):
        logger.warning(
            "Injection pattern detected in orchestrator task input — sanitized."
        )
        try:
            from src.database import log_threat_event

            await log_threat_event(
                agent_id="orchestrator",
                run_id=run_id,
                threat_type="INJECTION_DETECTED",
                action_taken="LOGGED",
                confidence=0.8,
                raw_input=task[:200],
                metadata={
                    "patterns": sanitize_meta.get("injection_patterns", []),
                    "source": "task_input",
                },
            )
        except Exception as _db_err:
            logger.debug(
                f"[run_orchestrator] Could not log INJECTION_DETECTED to DB: {_db_err}"
            )

    # Master token: union of orchestrator + all sub-agent tool IDs.
    # Sub-agents get derived (narrower) tokens — privilege flows strictly downward.
    from src.agents.researcher import RESEARCHER_TOOL_MANIFESTS

    # Master token covers all orchestrator tools (spawn_researcher +
    # fan_out_researchers) plus all researcher tools — sub-agents always
    # receive a derived subset, never an escalation.
    all_tool_ids = [m.tool_id for m in ORCHESTRATOR_TOOL_MANIFESTS] + [
        m.tool_id for m in RESEARCHER_TOOL_MANIFESTS
    ]

    master_token = _issue_master_token(run_id, all_tool_ids)

    # Populate module-level closure refs so tool closures can access the
    # master JWT and run_id without state injection into every tool call.
    _master_token_ref["token"] = master_token
    _run_id_ref["run_id"] = run_id

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
        "messages": [
            SystemMessage(content=_ORCHESTRATOR_SYSTEM_CONTENT),
            HumanMessage(content=task),
        ],
        "verify_rounds": 0,  # Phase 71 — self-verification pass counter
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
