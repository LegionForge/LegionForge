"""
src/agents/crystallizer.py
──────────────────────────
Crystallizer agent — Phase 5 Crystallization Pipeline.

Takes a nominated crystallization candidate and generates a complete package:
  - Deterministic Python function implementation
  - Tool manifest
  - Test suite (test cases + edge cases + adversarial cases)
  - Self-assessed confidence score

The generated package goes to the Pre-HITL Analyzer automatically.
The Crystallizer CANNOT register the tool or deploy anything.

Startup:
    await register_crystallizer_tools()
    result = await run_crystallizer(candidate_id="cand_abc123")
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.tools import tool
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages

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


class CrystallizerState(AgentState):
    """Extends AgentState with crystallization context."""

    candidate_id: str  # which candidate we're processing
    packages_created: list[str]  # package_ids submitted this run


# ── Tools ─────────────────────────────────────────────────────────────────────


@tool
async def read_crystallization_candidate(candidate_id: str) -> str:
    """
    Read a crystallization candidate from the database.

    Returns the full candidate record including example inputs/outputs,
    observed count, reasoning, and disqualifying factors identified by the Observer.
    Use this to understand what you need to crystallize before writing code.

    Args:
        candidate_id: The candidate ID (e.g. 'cand_abc123def456').
    """
    try:
        from src.database import get_candidate

        candidate = await get_candidate(candidate_id)
        if not candidate:
            return json.dumps(
                {"error": f"Candidate {candidate_id!r} not found in database"}
            )
        return json.dumps(candidate, default=str)
    except Exception as e:
        logger.warning(f"[crystallizer] read_crystallization_candidate failed: {e}")
        return json.dumps({"error": str(e)})


@tool
async def submit_crystallization_package(
    candidate_id: str,
    tool_name: str,
    tool_description: str,
    function_code: str,
    function_signature: str,
    input_schema: str,
    output_schema: str,
    declared_side_effects: str,
    test_cases: str,
    edge_cases: str,
    adversarial_cases: str,
    confidence_score: float,
    known_limitations: str,
    suggested_fallback: str,
) -> str:
    """
    Submit a complete crystallization package for automated analysis.

    The package will be analyzed by the Pre-HITL Analyzer automatically.
    If analysis passes, it will appear in the human review queue.

    Requirements:
    - function_code must be a pure Python function (no imports that aren't stdlib)
    - test_cases must contain at least 3 {input, expected_output} pairs
    - declared_side_effects should be '["pure"]' for stateless functions
    - confidence_score is your honest 0.0-1.0 self-assessment

    Args:
        candidate_id:          ID of the candidate being crystallized.
        tool_name:             Snake_case name for the tool (e.g. 'normalize_url').
        tool_description:      One-sentence description for the tool registry.
        function_code:         The complete deterministic Python function (no class, just def).
        function_signature:    The typed signature line (e.g. 'def normalize_url(url: str) -> str:').
        input_schema:          JSON string — dict of arg_name to type string.
        output_schema:         JSON string — dict describing return value.
        declared_side_effects: JSON string — ['pure'] or explicit effect list.
        test_cases:            JSON string — list of {input: dict, expected_output: any}.
        edge_cases:            JSON string — list of {input: dict, expected_output: any}.
        adversarial_cases:     JSON string — list of {input: dict, expected_behavior: str}.
        confidence_score:      0.0-1.0 — your honest confidence this is correct.
        known_limitations:     JSON string — list of strings describing known gaps.
        suggested_fallback:    What should happen if this tool fails at runtime.
    """
    # Validate minimum test cases
    try:
        tc_list = json.loads(test_cases) if test_cases else []
        if len(tc_list) < 3:
            return json.dumps(
                {
                    "error": "Rejected: at least 3 test cases required. "
                    f"You provided {len(tc_list)}. Add more test cases and resubmit."
                }
            )
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON in test_cases: {e}"})

    # Parse all JSON args
    try:
        input_schema_dict = json.loads(input_schema) if input_schema else {}
        output_schema_dict = json.loads(output_schema) if output_schema else {}
        side_effects = (
            json.loads(declared_side_effects) if declared_side_effects else ["pure"]
        )
        edge_list = json.loads(edge_cases) if edge_cases else []
        adversarial_list = json.loads(adversarial_cases) if adversarial_cases else []
        limitations = json.loads(known_limitations) if known_limitations else []
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON in arguments: {e}"})

    # Reject if function_code contains forbidden constructs (quick client-side check)
    forbidden = ["exec(", "eval(", "__import__", "subprocess", "os.system", "socket."]
    for f in forbidden:
        if f in function_code:
            return json.dumps(
                {
                    "error": f"Rejected: function_code contains forbidden construct: {f!r}. "
                    "Crystallized functions must be pure and stateless."
                }
            )

    package_id = f"pkg_{uuid.uuid4().hex[:12]}"

    try:
        from src.database import create_package

        result = await create_package(
            package_id=package_id,
            candidate_id=candidate_id,
            tool_name=tool_name,
            tool_description=tool_description,
            function_code=function_code,
            function_signature=function_signature,
            input_schema=input_schema_dict,
            output_schema=output_schema_dict,
            declared_side_effects=side_effects,
            test_cases=tc_list,
            edge_cases=edge_list,
            adversarial_cases=adversarial_list,
            confidence_score=confidence_score,
            known_limitations=limitations,
            suggested_fallback=suggested_fallback,
        )

        if not result:
            return json.dumps({"error": "DB write failed — package not stored"})

        # Trigger Pre-HITL analysis asynchronously
        try:
            from src.tools.crystallization_analyzer import analyze_package

            await analyze_package(package_id)
            logger.info(f"[crystallizer] Analysis triggered for {package_id!r}")
        except Exception as e:
            logger.warning(
                f"[crystallizer] Pre-HITL analysis trigger failed for {package_id!r}: {e}"
            )

        logger.info(
            f"[crystallizer] Package submitted: {package_id!r} "
            f"candidate={candidate_id!r} tool={tool_name!r}"
        )
        return json.dumps(
            {
                "status": "submitted",
                "package_id": package_id,
                "tool_name": tool_name,
                "test_cases": len(tc_list),
                "confidence_score": confidence_score,
                "note": "Package queued for Pre-HITL analysis.",
            }
        )
    except Exception as e:
        logger.warning(f"[crystallizer] submit_crystallization_package failed: {e}")
        return json.dumps({"error": str(e)})


CRYSTALLIZER_TOOLS = [read_crystallization_candidate, submit_crystallization_package]


# ── Tool manifests ─────────────────────────────────────────────────────────────


CRYSTALLIZER_TOOL_MANIFESTS = [
    ToolManifest(
        tool_id="read_crystallization_candidate",
        description="Read a crystallization candidate from the database",
        input_schema={"candidate_id": "str"},
        declared_side_effects=["reads_db:crystallization_candidates"],
        source="local",
        entrypoint_func=read_crystallization_candidate,
    ),
    ToolManifest(
        tool_id="submit_crystallization_package",
        description="Submit a complete crystallization package for Pre-HITL analysis",
        input_schema={
            "candidate_id": "str",
            "tool_name": "str",
            "tool_description": "str",
            "function_code": "str",
            "function_signature": "str",
            "input_schema": "str",
            "output_schema": "str",
            "declared_side_effects": "str",
            "test_cases": "str",
            "edge_cases": "str",
            "adversarial_cases": "str",
            "confidence_score": "float",
            "known_limitations": "str",
            "suggested_fallback": "str",
        },
        declared_side_effects=[
            "writes_db:crystallization_packages",
            "triggers:crystallization_analyzer",
        ],
        source="local",
        entrypoint_func=submit_crystallization_package,
    ),
]


# ── Approved sequences ────────────────────────────────────────────────────────

CRYSTALLIZER_EXPECTED_SEQUENCES: list[list[str]] = [
    ["read_crystallization_candidate", "submit_crystallization_package"],
    ["read_crystallization_candidate"],  # read-only exploration run
]


async def register_crystallizer_tools() -> None:
    """Register all Crystallizer tools. Call once at startup."""
    for manifest in CRYSTALLIZER_TOOL_MANIFESTS:
        await register_tool(
            manifest,
            approved_by="operator",
            approval_notes="Phase 5 Crystallizer agent tools",
        )
    logger.info("[crystallizer] All tools registered.")


# ── System prompt ─────────────────────────────────────────────────────────────

_CRYSTALLIZER_SYSTEM_PROMPT = """You are the LegionForge Crystallizer — part of the Crystallization Pipeline.

Your job: take a crystallization candidate and generate a complete, correct, deterministic
Python function that replaces what the AI agent was doing.

== Workflow ==
1. Call read_crystallization_candidate with the candidate_id you've been given.
2. Analyze the example inputs and outputs carefully.
3. Write a pure Python function that reproduces the observed behavior.
4. Write a comprehensive test suite (minimum 3 test_cases from the observed examples,
   plus edge_cases and adversarial_cases you design yourself).
5. Call submit_crystallization_package with everything.

== Code requirements ==
- Function must be pure (no side effects unless absolutely required and declared).
- Only stdlib imports allowed (json, re, datetime, math, hashlib, etc.).
- No: exec, eval, __import__, subprocess, os.system, requests, httpx, socket.
- Function should be under 50 lines — if it needs more, that's a complexity red flag.
- Include docstring explaining inputs and outputs.
- Handle edge cases gracefully (empty inputs, None, wrong types).

== Test case format ==
test_cases (observed examples):
  [{"input": {"arg1": "value"}, "expected_output": "result"}, ...]

edge_cases (you design these):
  [{"input": {"arg1": ""}, "expected_output": ""}, ...]  # empty string, etc.

adversarial_cases (designed to break the function):
  [{"input": {"arg1": "A" * 10000}, "expected_behavior": "handles gracefully without crash"}]

== Self-assessment ==
confidence_score: 0.0-1.0 — be honest. If you're not sure all edge cases are handled, say 0.7.
known_limitations: list every case this function might handle incorrectly.

== Hard constraints ==
- Do NOT generate code that is not a deterministic function.
- Do NOT submit if you cannot produce 3 meaningful test cases from the examples.
- Do NOT lie about confidence — the Pre-HITL Analyzer will run your test cases."""


# ── Graph nodes ───────────────────────────────────────────────────────────────


def _build_crystallizer_agent_node(llm_with_tools: Any):
    """Build the crystallizer agent node with pre-bound LLM."""

    async def agent_node(state: CrystallizerState) -> dict:
        updates = increment_step(state)

        log_agent_event(
            "llm_call",
            "crystallizer",
            {
                "step": state["step_count"],
                "candidate_id": state.get("candidate_id", ""),
            },
            run_id=state.get("run_id"),
        )

        try:
            all_messages = [SystemMessage(content=_CRYSTALLIZER_SYSTEM_PROMPT)] + list(
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
            error_updates = record_error(state, e, context="crystallizer/agent_node")
            updates.update(error_updates)
            logger.exception(f"Error in crystallizer agent_node: {e}")
            return updates

    return agent_node


async def finalizer_node(state: CrystallizerState) -> dict:
    """Extract final result."""
    messages = state.get("messages", [])
    if messages:
        last = messages[-1]
        result = last.content if isinstance(last.content, str) else str(last.content)
    else:
        result = "Crystallizer completed with no output."

    log_agent_event(
        "run_end",
        "crystallizer",
        {
            "steps": state.get("step_count", 0),
            "tokens": state.get("token_count", 0),
            "errors": state.get("error_count", 0),
            "packages_created": len(state.get("packages_created", [])),
        },
        run_id=state.get("run_id"),
    )

    return {"result": result}


def route_after_crystallizer(state: CrystallizerState) -> str:
    """Route after agent node."""
    safeguard_result = check_safeguards(state)
    if safeguard_result == "end":
        return "finalize"

    last_msg = state["messages"][-1] if state["messages"] else None
    if isinstance(last_msg, AIMessage) and getattr(last_msg, "tool_calls", None):
        return "tools"

    return "finalize"


# ── Graph builder ─────────────────────────────────────────────────────────────


def build_crystallizer_graph() -> StateGraph:
    """Build the Crystallizer graph (uncompiled)."""
    llm = get_primary_llm(temperature=0.2).bind_tools(CRYSTALLIZER_TOOLS)
    tool_node = SecureToolNode(CRYSTALLIZER_TOOLS)
    agent_node = _build_crystallizer_agent_node(llm)

    graph = StateGraph(CrystallizerState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_node("finalize", finalizer_node)

    graph.set_entry_point("agent")
    graph.add_conditional_edges(
        "agent",
        route_after_crystallizer,
        {"tools": "tools", "finalize": "finalize"},
    )
    graph.add_edge("tools", "agent")
    graph.add_edge("finalize", END)

    return graph


# ── Public entry point ────────────────────────────────────────────────────────


async def run_crystallizer(
    candidate_id: str,
    thread_id: str | None = None,
    tracing_enabled: bool = True,
    task_token: str | None = None,
) -> dict[str, Any]:
    """
    Run the Crystallizer agent on a specific candidate.

    Args:
        candidate_id:     The candidate ID to crystallize (e.g. 'cand_abc123').
        thread_id:        Optional thread ID for checkpoint resumption.
        tracing_enabled:  Set False to disable LangSmith tracing.
        task_token:       Optional pre-issued JWT task token.

    Returns:
        dict with 'result', 'steps', 'tokens', 'errors', 'packages_created' keys.
    """
    task = (
        f"Crystallize candidate {candidate_id!r}. "
        "Read the candidate, then write a deterministic function and submit a package."
    )

    # Build initial state first — run_id needed for threat logging.
    # ORDERING RULE: always call SafeguardedState.initial() before sanitize_text()
    # so the run_id is available for DB logging if injection is detected.
    # agent_id MUST match the agent_id in issue_task_token() below.
    init = SafeguardedState.initial(
        tracing_enabled=tracing_enabled,
        agent_id="crystallizer",
    )
    run_id = init["run_id"]

    # Sanitize input — after init so run_id is available for DB logging.
    # check_injection is gated by prompt_injection_guard setting so dev/test
    # environments can disable user-input scanning without affecting tool-arg
    # detection (SecureToolNode always-on regardless of this setting).
    # NOTE: Previously used `_` to discard sanitize_meta — injection results
    # were silently lost. Fixed to capture and log injection events.
    task, sanitize_meta = sanitize_text(
        task,
        check_injection=settings.security.prompt_injection_guard,
    )
    if sanitize_meta.get("injection_detected"):
        logger.warning(
            "Injection pattern detected in crystallizer task input — sanitized."
        )
        try:
            from src.database import log_threat_event

            await log_threat_event(
                agent_id="crystallizer",
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
                f"[run_crystallizer] Could not log INJECTION_DETECTED to DB: {_db_err}"
            )

    if task_token is None:
        try:
            from src.security import issue_task_token

            task_token = issue_task_token(
                agent_id="crystallizer",
                run_id=run_id,
                granted_tools=[m.tool_id for m in CRYSTALLIZER_TOOL_MANIFESTS],
                granted_tables=[
                    "crystallization_candidates",
                    "crystallization_packages",
                ],
                granted_data_classes=["internal"],
                escalation_policy="deny",
            )
            logger.debug(f"[crystallizer] Task token issued for run={run_id[:8]}...")
        except RuntimeError:
            logger.warning(
                "[crystallizer] JWT secret not configured — running without task token."
            )

    state: CrystallizerState = {
        **init,
        "task": task,
        "result": None,
        "candidate_id": candidate_id,
        "packages_created": [],
        "sequence_so_far": [],
        "task_token": task_token,
        "messages": [HumanMessage(content=task)],
    }

    config = create_run_config(
        thread_id=thread_id,
        tracing_enabled=tracing_enabled,
        run_name=f"crystallizer: {candidate_id}",
        tags=["crystallizer", "phase-5"],
        recursion_limit=settings.safeguards.default_recursion_limit,
    )

    log_agent_event(
        "run_start",
        "crystallizer",
        {"candidate_id": candidate_id, "tracing": tracing_enabled},
        run_id=run_id,
    )

    from src.database import get_checkpointer

    async with get_checkpointer() as checkpointer:
        graph = build_crystallizer_graph().compile(checkpointer=checkpointer)
        final_state = await graph.ainvoke(state, config)

    return {
        "result": final_state.get("result", ""),
        "steps": final_state.get("step_count", 0),
        "tokens": final_state.get("token_count", 0),
        "run_id": final_state.get("run_id"),
        "errors": final_state.get("error_count", 0),
        "packages_created": final_state.get("packages_created", []),
    }
