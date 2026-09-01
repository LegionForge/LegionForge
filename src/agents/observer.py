"""
src/agents/observer.py
──────────────────────
Observer agent — Phase 5 Crystallization Pipeline.

Reads tool-call history from the audit_log and nominates patterns that
qualify for crystallization (conversion from AI-driven to deterministic).

The Observer is read-only and nomination-only. It NEVER generates code.
It cannot modify the tool registry or approve anything.

Startup:
    await register_observer_tools()
    result = await run_observer(hours=168, min_occurrences=5)
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.tools import tool
from langgraph.graph import END, StateGraph

from config.settings import settings
from src.base_graph import AgentState, SecureToolNode
from src.llm_factory import get_primary_llm
from src.observability import get_metrics, log_agent_event, timed
from src.rate_limiter import estimate_tokens, preflight_budget_check
from src.safeguards import (
    SafeguardedState,
    check_safeguards,
    check_token_budget,
    create_run_config,
    increment_step,
    record_error,
)
from src.security import (
    ToolManifest,
    register_tool,
    sanitize_messages,
    sanitize_text,
)

logger = logging.getLogger(__name__)


# ── State ─────────────────────────────────────────────────────────────────────


class ObserverState(AgentState):
    """Extends AgentState with crystallization observation context."""

    candidates_nominated: list[str]  # candidate_ids created this run
    analysis_window_hours: int  # how far back to look in audit_log


# ── Tools ─────────────────────────────────────────────────────────────────────


@tool
async def read_tool_call_history(hours: int = 168, min_occurrences: int = 3) -> str:
    """
    Read tool call history from audit_log for pattern analysis.

    Aggregates tool calls by operation name, counting occurrences and
    collecting representative input/output samples. Returns a JSON summary
    suitable for crystallization candidate analysis.

    Args:
        hours:           How far back to look (default: 168 = 7 days).
        min_occurrences: Minimum calls to include an operation (default: 3).
    """
    try:
        from src.database import get_worker_pool

        pool = get_worker_pool()
        async with pool.connection() as conn:
            # Read TOOL_CALL events from audit_log — these are written by
            # SecureToolNode on each successful tool execution.
            cur = await conn.execute(
                """
                SELECT payload, ts
                FROM audit_log
                WHERE event_type = 'TOOL_CALL'
                  AND ts > NOW() - make_interval(hours => %s)
                ORDER BY ts DESC
                LIMIT 2000
                """,
                (hours,),
            )
            rows = await cur.fetchall()

        # Aggregate by tool_id
        aggregated: dict[str, dict] = {}
        for row in rows:
            payload = row["payload"] if isinstance(row["payload"], dict) else {}
            tool_id = payload.get("tool_id", "unknown")
            if tool_id not in aggregated:
                aggregated[tool_id] = {
                    "tool_id": tool_id,
                    "count": 0,
                    "example_inputs": [],
                    "example_outputs": [],
                    "token_estimates": [],
                }
            entry = aggregated[tool_id]
            entry["count"] += 1
            if len(entry["example_inputs"]) < 5:
                entry["example_inputs"].append(payload.get("inputs", {}))
                entry["example_outputs"].append(payload.get("output_summary", ""))

        # Filter by min_occurrences
        candidates = {
            k: v for k, v in aggregated.items() if v["count"] >= min_occurrences
        }

        summary = {
            "total_events_scanned": len(rows),
            "window_hours": hours,
            "min_occurrences": min_occurrences,
            "operations_found": len(candidates),
            "operations": list(candidates.values()),
        }
        return json.dumps(summary, default=str)

    except Exception as e:
        logger.warning(f"[observer] read_tool_call_history failed: {e}")
        return json.dumps(
            {
                "error": str(e),
                "total_events_scanned": 0,
                "operations_found": 0,
                "operations": [],
                "note": "Audit log may be empty — run some agent tasks first.",
            }
        )


@tool
async def nominate_candidate(
    operation_name: str,
    observed_count: int,
    example_inputs: str,
    example_outputs: str,
    reasoning: str,
    disqualifying_factors: str,
    token_cost_total: int,
    estimated_savings_pct: float,
) -> str:
    """
    Nominate a tool call pattern as a crystallization candidate.

    Only call this when ALL six crystallization criteria are satisfied:
    1. Same logical operation performed N+ times
    2. Inputs follow a consistent structure
    3. Outputs are consistent and deterministic given the same inputs
    4. No ambiguity, judgment, or natural language interpretation required
    5. A deterministic algorithm would produce the correct result
    6. Token cost of AI approach is measurably higher than deterministic equivalent

    Args:
        operation_name:          Human-readable name for this operation.
        observed_count:          How many times this was observed.
        example_inputs:          JSON string — list of 3-5 representative input dicts.
        example_outputs:         JSON string — list of corresponding output strings.
        reasoning:               Why this qualifies (must address all 6 criteria).
        disqualifying_factors:   JSON string — honest list of reasons it might NOT qualify.
        token_cost_total:        Total tokens spent on this operation historically.
        estimated_savings_pct:   Estimated token reduction if crystallized (0-100).

    Returns:
        JSON with candidate_id on success, or error message.
    """
    try:
        inputs_list = json.loads(example_inputs) if example_inputs else []
        outputs_list = json.loads(example_outputs) if example_outputs else []
        disqualifiers = (
            json.loads(disqualifying_factors) if disqualifying_factors else []
        )
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON in arguments: {e}"})

    candidate_id = f"cand_{uuid.uuid4().hex[:12]}"

    try:
        from src.database import nominate_candidate as db_nominate

        result = await db_nominate(
            candidate_id=candidate_id,
            operation_name=operation_name,
            observed_count=observed_count,
            example_inputs=inputs_list,
            example_outputs=outputs_list,
            input_schema={},  # Observer infers schema; Crystallizer refines it
            output_schema={},
            token_cost_total=token_cost_total,
            estimated_savings_pct=estimated_savings_pct,
            reasoning=reasoning,
            disqualifying_factors=disqualifiers,
        )
        if result:
            logger.info(
                f"[observer] Nominated candidate={candidate_id!r} "
                f"operation={operation_name!r}"
            )
            return json.dumps(
                {
                    "status": "nominated",
                    "candidate_id": candidate_id,
                    "operation_name": operation_name,
                    "observed_count": observed_count,
                }
            )
        return json.dumps({"error": "DB write failed — candidate not stored"})
    except Exception as e:
        logger.warning(f"[observer] nominate_candidate failed: {e}")
        return json.dumps({"error": str(e)})


OBSERVER_TOOLS = [read_tool_call_history, nominate_candidate]


# ── Tool manifests ─────────────────────────────────────────────────────────────


OBSERVER_TOOL_MANIFESTS = [
    ToolManifest(
        tool_id="read_tool_call_history",
        description="Read tool call history from audit_log for pattern analysis",
        input_schema={"hours": "int", "min_occurrences": "int"},
        declared_side_effects=["reads_db:audit_log"],
        source="local",
        entrypoint_func=read_tool_call_history,
    ),
    ToolManifest(
        tool_id="nominate_candidate",
        description="Nominate a tool call pattern as a crystallization candidate",
        input_schema={
            "operation_name": "str",
            "observed_count": "int",
            "example_inputs": "str",
            "example_outputs": "str",
            "reasoning": "str",
            "disqualifying_factors": "str",
            "token_cost_total": "int",  # nosec B105
            "estimated_savings_pct": "float",
        },
        declared_side_effects=["writes_db:crystallization_candidates"],
        source="local",
        entrypoint_func=nominate_candidate,
    ),
]


# ── Approved tool-call sequences ──────────────────────────────────────────────

OBSERVER_EXPECTED_SEQUENCES: list[list[str]] = [
    ["read_tool_call_history"],
    ["read_tool_call_history", "nominate_candidate"],
    ["read_tool_call_history", "nominate_candidate", "nominate_candidate"],
    [
        "read_tool_call_history",
        "nominate_candidate",
        "nominate_candidate",
        "nominate_candidate",
    ],
]


async def register_observer_tools() -> None:
    """Register all Observer tools. Call once at startup."""
    for manifest in OBSERVER_TOOL_MANIFESTS:
        await register_tool(
            manifest,
            approved_by="operator",
            approval_notes="Phase 5 Observer agent tools",
        )
    logger.info("[observer] All tools registered.")


# ── System prompt ─────────────────────────────────────────────────────────────

_OBSERVER_SYSTEM_PROMPT = """You are the LegionForge Observer — part of the Crystallization Pipeline.

Your ONLY job is pattern recognition. You read tool call history and identify operations
that could be replaced by a deterministic function instead of an AI call.

== Crystallization criteria (ALL must be satisfied to nominate) ==
1. The same logical operation was performed 3 or more times.
2. The inputs follow a consistent structure across instances.
3. The outputs are consistent and deterministic given the same inputs.
4. The operation involves NO ambiguity, judgment, or natural language interpretation.
5. A simple algorithm would produce the correct result across all observed instances.
6. The token cost of the AI-based approach is measurably higher than a deterministic equivalent.

== Hard constraints ==
- You NEVER generate code. You only nominate patterns.
- If no patterns qualify, say so clearly and return without nominating anything.
- Do not hallucinate candidates. Only nominate what the data shows.
- Be honest about disqualifying factors. A real disqualifier list is better than a fake clean bill.
- The reasoning field must address ALL SIX criteria specifically.

== Workflow ==
1. Call read_tool_call_history to get the aggregated call data.
2. Analyze each operation against all six criteria.
3. For any that qualify, call nominate_candidate with honest reasoning.
4. Return a summary of what you found and nominated (or why you nominated nothing).

If the audit log is empty or has fewer than 3 calls for any operation,
report that finding and do NOT nominate anything."""


# ── Graph nodes ───────────────────────────────────────────────────────────────


def _build_observer_agent_node(llm_with_tools: Any):
    """Build the observer agent node with pre-bound LLM."""

    async def agent_node(state: ObserverState) -> dict:
        updates = increment_step(state)

        log_agent_event(
            "llm_call",
            "observer",
            {"step": state["step_count"], "task": state.get("task", "")},
            run_id=state.get("run_id"),
        )

        try:
            all_messages = [SystemMessage(content=_OBSERVER_SYSTEM_PROMPT)] + list(
                state["messages"]
            )
            clean_messages = sanitize_messages(all_messages)

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

            updates["messages"] = [response]
            return updates

        except Exception as e:
            error_updates = record_error(state, e, context="observer/agent_node")
            updates.update(error_updates)
            logger.exception(f"Error in observer agent_node: {e}")
            return updates

    return agent_node


async def finalizer_node(state: ObserverState) -> dict:
    """Extract final result from last message."""
    messages = state.get("messages", [])
    if messages:
        last = messages[-1]
        result = last.content if isinstance(last.content, str) else str(last.content)
    else:
        result = "Observer completed with no output."

    # Count candidate_ids found in messages
    nominated = state.get("candidates_nominated", [])

    log_agent_event(
        "run_end",
        "observer",
        {
            "steps": state.get("step_count", 0),
            "tokens": state.get("token_count", 0),
            "errors": state.get("error_count", 0),
            "candidates_nominated": len(nominated),
        },
        run_id=state.get("run_id"),
    )

    return {"result": result}


def route_after_observer(state: ObserverState) -> str:
    """Route after agent node."""
    safeguard_result = check_safeguards(state)
    if safeguard_result == "end":
        return "finalize"

    last_msg = state["messages"][-1] if state["messages"] else None
    if isinstance(last_msg, AIMessage) and getattr(last_msg, "tool_calls", None):
        return "tools"

    return "finalize"


# ── Graph builder ─────────────────────────────────────────────────────────────


def build_observer_graph() -> StateGraph:
    """Build the Observer graph (uncompiled)."""
    llm = get_primary_llm(temperature=0.1).bind_tools(OBSERVER_TOOLS)
    tool_node = SecureToolNode(OBSERVER_TOOLS)
    agent_node = _build_observer_agent_node(llm)

    graph = StateGraph(ObserverState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_node("finalize", finalizer_node)

    graph.set_entry_point("agent")
    graph.add_conditional_edges(
        "agent",
        route_after_observer,
        {"tools": "tools", "finalize": "finalize"},
    )
    graph.add_edge("tools", "agent")
    graph.add_edge("finalize", END)

    return graph


# ── Public entry point ────────────────────────────────────────────────────────


async def run_observer(
    hours: int = 168,
    min_occurrences: int = 3,
    thread_id: str | None = None,
    tracing_enabled: bool = True,
    task_token: str | None = None,
) -> dict[str, Any]:
    """
    Run the Observer agent to find crystallization candidates.

    Args:
        hours:            Lookback window for audit_log (default: 7 days).
        min_occurrences:  Minimum tool calls to consider a pattern (default: 3).
        thread_id:        Optional thread ID for checkpoint resumption.
        tracing_enabled:  Set False to disable LangSmith tracing.
        task_token:       Optional pre-issued JWT task token.

    Returns:
        dict with 'result', 'steps', 'tokens', 'errors', 'candidates_nominated' keys.
    """
    task = (
        f"Analyze the last {hours} hours of tool call history "
        f"(minimum {min_occurrences} occurrences per operation) "
        "and nominate any patterns that meet all six crystallization criteria."
    )

    # Build initial state first — run_id needed for threat logging.
    # ORDERING RULE: always call SafeguardedState.initial() before sanitize_text()
    # so the run_id is available for DB logging if injection is detected.
    # agent_id MUST match the agent_id in issue_task_token() below.
    init = SafeguardedState.initial(
        tracing_enabled=tracing_enabled,
        agent_id="observer",
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
        logger.warning("Injection pattern detected in observer task input — sanitized.")
        try:
            from src.database import log_threat_event

            await log_threat_event(
                agent_id="observer",
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
                f"[run_observer] Could not log INJECTION_DETECTED to DB: {_db_err}"
            )

    if task_token is None:
        try:
            from src.security import issue_task_token

            task_token = issue_task_token(
                agent_id="observer",
                run_id=run_id,
                granted_tools=[m.tool_id for m in OBSERVER_TOOL_MANIFESTS],
                granted_tables=["audit_log", "crystallization_candidates"],
                granted_data_classes=["internal"],
                escalation_policy="deny",
            )
            logger.debug(f"[observer] Task token issued for run={run_id[:8]}...")
        except RuntimeError:
            logger.warning(
                "[observer] JWT secret not configured — running without task token."
            )

    state: ObserverState = {
        **init,
        "task": task,
        "result": None,
        "candidates_nominated": [],
        "analysis_window_hours": hours,
        "sequence_so_far": [],
        "task_token": task_token,
        "messages": [HumanMessage(content=task)],
    }

    config = create_run_config(
        thread_id=thread_id,
        tracing_enabled=tracing_enabled,
        run_name=f"observer: {hours}h window",
        tags=["observer", "phase-5"],
        recursion_limit=settings.safeguards.default_recursion_limit,
    )

    log_agent_event(
        "run_start",
        "observer",
        {
            "hours": hours,
            "min_occurrences": min_occurrences,
            "tracing": tracing_enabled,
        },
        run_id=run_id,
    )

    from src.database import get_checkpointer

    async with get_checkpointer() as checkpointer:
        graph = build_observer_graph().compile(checkpointer=checkpointer)
        final_state = await graph.ainvoke(state, config)

    return {
        "result": final_state.get("result", ""),
        "steps": final_state.get("step_count", 0),
        "tokens": final_state.get("token_count", 0),
        "run_id": final_state.get("run_id"),
        "errors": final_state.get("error_count", 0),
        "candidates_nominated": final_state.get("candidates_nominated", []),
    }
