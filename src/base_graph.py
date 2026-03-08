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

import asyncio
import logging
import os
import socket
from typing import Annotated, Any, TypedDict
import operator

import httpx
from langchain_core.callbacks import adispatch_custom_event
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, ToolMessage
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages

from config.settings import settings
from src.safeguards import (
    SafeguardedState,
    check_safeguards,
    check_hitl_required,
    create_run_config,
    detect_action_loop,
    check_token_budget,
    increment_step,
    record_error,
)
from src.llm_factory import get_primary_llm, get_router_llm
from src.observability import log_agent_event, get_metrics, timed
from src.security import (
    sanitize_text,
    sanitize_for_trace,
    sanitize_messages,
    sanitize_output,
    sanitize_tool_input,
    verify_tool_before_invocation,
    validate_fetch_url,
    detect_destructive_pattern,
    check_capability_boundary,
    Guardian,
    FORBIDDEN_CAPABILITIES,
    SecurityError,
    has_halt_worthy_injection,
    # Phase 3: task token ACL
    validate_task_token,
    EscalationRequest,
)
from src.security.guardian import GuardianCheckResponse
from src.rate_limiter import preflight_budget_check, estimate_tokens

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
    # Identifies which agent owns this run (set by SafeguardedState.initial).
    # Must match the agent_id used in issue_task_token() in the same run_* function.
    agent_id: str

    # ── Security: tool call sequence tracking ─────────────────────────────────
    # Maintained by SecureToolNode; passed to Guardian /check for sequence validation.
    sequence_so_far: list[str]

    # ── Phase 3: Task-scoped JWT token ────────────────────────────────────────
    # Signed JWT issued at run start. Declares which tools + data classes this
    # agent run may access. Sub-agents receive derived (narrower) tokens.
    # None = no token required (backward compat — agents without tokens are
    # unconstrained for now; Phase 4 will make tokens mandatory).
    task_token: str | None

    # ── Agent-specific fields ─────────────────────────────────────────────────
    task: str  # The current task description
    result: str | None  # Final output

    # ── Memory: submitting user identity ──────────────────────────────────────
    # Set by the gateway worker from the authenticated task request.
    # Used to inject per-user preferences (bootstrap_user_prefs) and to scope
    # per-user memory namespaces. None for headless/internal runs.
    user_id: str | None


# ── Node functions ────────────────────────────────────────────────────────────


async def agent_node(state: AgentState) -> dict:
    """
    Main agent node. Calls the LLM and processes the response.
    Replace this with your actual agent logic.
    """
    # 1. Increment step counter
    updates = increment_step(state)

    # If a security halt already set force_end (e.g., Guardian unavailable,
    # ACL violation, Tier 1 injection), skip the LLM call. Calling the LLM
    # with dangling tool_calls (no ToolMessage) produces empty content → [No result].
    if state.get("force_end"):
        return updates

    log_agent_event(
        "llm_call",
        "base_agent",
        {"step": state["step_count"], "task": state.get("task", "")},
        run_id=state.get("run_id"),
    )

    try:
        llm = get_primary_llm(temperature=0.1)

        # ── Memory: persona bootstrap (Gap 1) ────────────────────────────────
        # Inject freeform persona text from persona:agent:<id> and
        # persona:user:<uid> namespaces — the SOUL.md equivalent.
        # Outermost SystemMessage: persona → prefs → recall → HumanMessage.
        if settings.agent_memory.enabled and settings.agent_memory.persona_bootstrap:
            from src.memory import persona_bootstrap as _persona_bootstrap
            from langchain_core.messages import SystemMessage as _SM

            _persona = await _persona_bootstrap(
                agent_id=state.get("agent_id", "base_agent"),
                user_id=state.get("user_id"),
            )
            if _persona:
                state = {
                    **state,
                    "messages": [_SM(content=_persona)] + list(state["messages"]),
                }

        # ── Memory: user preference bootstrap (Gap 5) ────────────────────────
        # Inject the submitting user's stored preferences as a SystemMessage so
        # the agent knows who it's talking to without re-explanation each run.
        if settings.agent_memory.enabled and settings.agent_memory.bootstrap_user_prefs:
            _uid = state.get("user_id")
            if _uid:
                from src.memory import user_context_bootstrap
                from langchain_core.messages import SystemMessage as _SM

                _bootstrap = await user_context_bootstrap(_uid)
                if _bootstrap:
                    state = {
                        **state,
                        "messages": [_SM(content=_bootstrap)] + list(state["messages"]),
                    }

        # ── Phase 21: Memory recall ───────────────────────────────────────────
        # Inject relevant past context before LLM call (no-op when disabled).
        if settings.agent_memory.enabled and settings.agent_memory.recall_on_task:
            task = state.get("task", "")
            if task:
                from src.memory import recall_for_task

                ns = f"agent:{state.get('agent_id', 'base_agent')}"
                memory_ctx = await recall_for_task(task, ns)
                if memory_ctx:
                    from langchain_core.messages import SystemMessage

                    _mem_msg = SystemMessage(
                        content=f"[Relevant memory from past runs]\n{memory_ctx}"
                    )
                    state = {**state, "messages": [_mem_msg] + list(state["messages"])}

        # Sanitize outbound messages (PII redaction before sending to LLM)
        clean_messages = sanitize_messages(state["messages"])

        # Pre-flight budget check before incurring token cost
        msg_text = " ".join(
            m.content if isinstance(m.content, str) else str(m.content)
            for m in clean_messages
        )
        preflight_budget_check(estimate_tokens(msg_text), "ollama")

        with timed("llm_latency_ms", get_metrics()):
            response = await llm.ainvoke(clean_messages)

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

    # ── Phase 21: Memory store ────────────────────────────────────────────────
    # Persist task+result for future recall (no-op when disabled or result empty).
    if settings.agent_memory.enabled and settings.agent_memory.store_results:
        task = state.get("task", "")
        if task and result and result != "No result produced.":
            from src.memory import store_task_result

            ns = f"agent:{state.get('agent_id', 'base_agent')}"
            await store_task_result(task, result, ns, run_id=state.get("run_id", ""))

    # ── Gap 4: Pre-compaction flush ───────────────────────────────────────────
    # When force_end=True (token budget hit or loop detected), extract key facts
    # from the message history before the context is discarded.
    if state.get("force_end") and settings.agent_memory.enabled:
        from src.memory import flush_key_facts

        asyncio.create_task(
            flush_key_facts(
                messages=state.get("messages", []),
                namespace=f"agent:{state.get('agent_id', 'base_agent')}",
                run_id=state.get("run_id", ""),
            )
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


# ── Security helpers ──────────────────────────────────────────────────────────


async def validate_fetch_url_async(url: str) -> None:
    """
    Async wrapper around validate_fetch_url().

    The underlying DNS lookup (socket.getaddrinfo) is synchronous.
    This wrapper runs it in a thread executor to avoid blocking the event loop.
    Raises SecurityError for SSRF-blocked URLs (same as validate_fetch_url()).
    """
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, validate_fetch_url, url)


async def guardian_check(
    tool_id: str, args: dict, state: dict
) -> GuardianCheckResponse:
    """
    Phase 3: Call the Guardian sidecar service for capability enforcement.

    Returns the full GuardianCheckResponse so SecureToolNode can branch on tier:
      - tier="allow"   → proceed
      - tier="sandbox" → skip this tool call, inject error ToolMessage, continue run
      - tier="halt"    → force_end=True (security violation)

    Falls back to check_capability_boundary() if guardian_enabled=False —
    allows make test-smoke to pass without Docker running.

    Guardian unavailability is a FAIL-SAFE: any connection error or timeout
    returns tier="halt". Never fail-open.

    Args:
        tool_id: The name/id of the tool being invoked.
        args:    The actual tool arguments dict (was previously always {} — Gap 1 fix).
                 Guardian checks 3, 5, and 6 pattern-match against this.
        state:   Current agent state dict.
    """
    if not settings.security.guardian_enabled:
        # Offline fallback — return a proper GuardianCheckResponse
        allowed = check_capability_boundary(tool_id)
        return GuardianCheckResponse(
            allowed=allowed,
            tier="allow" if allowed else "halt",
            reason=(
                "capability boundary check (offline mode)"
                if allowed
                else f"Capability boundary violation: {tool_id}"
            ),
            confidence=1.0,
        )

    try:
        agent_id = state.get("agent_id", state.get("run_id", "unknown"))
        run_id = state.get("run_id", "unknown")
        sequence_so_far = state.get("sequence_so_far", [])
        task_token = state.get("task_token")

        # Gap 2 fix: derive action from state (gateway sets action="a2a"/"discord"/etc.
        # for non-invoke contexts). Standard tool calls remain "invoke" — correct.
        action = state.get("action", "invoke")

        payload = {
            "tool_id": tool_id,
            "action": action,
            "args": args,  # Gap 1 fix: real args, not {}. Enables checks 3, 5, 6.
            "agent_id": agent_id,
            "run_id": run_id,
            "sequence_so_far": sequence_so_far,
            "task_token": task_token,  # Phase 3: forward JWT to Guardian check_0
        }

        # Build Guardian request headers — include Bearer auth if token is available.
        # This authenticates the framework as a trusted caller of the Guardian API.
        # Prevents rogue processes on the same host from submitting /check requests.
        guardian_headers: dict[str, str] = {"Content-Type": "application/json"}
        try:
            from src.credentials import creds as _creds

            guardian_secret = _creds.get("legionforge_task_tokens")
            if guardian_secret:
                guardian_headers["Authorization"] = f"Bearer {guardian_secret}"
        except ImportError:
            # credentials module not available (test environments)
            _env_secret = os.environ.get("TASK_TOKEN_SECRET", "")
            if _env_secret:
                guardian_headers["Authorization"] = f"Bearer {_env_secret}"

        async with httpx.AsyncClient(
            timeout=settings.security.guardian_timeout_seconds
        ) as client:
            resp = await client.post(
                f"{settings.security.guardian_url}/check",
                json=payload,
                headers=guardian_headers,
            )
            resp.raise_for_status()
            guardian_resp = GuardianCheckResponse(**resp.json())
            if not guardian_resp.allowed:
                logger.warning(
                    f"[guardian] {guardian_resp.tier.upper()} tool={tool_id!r} "
                    f"reason={guardian_resp.reason!r} threat={guardian_resp.threat_type!r}"
                )
            return guardian_resp

    except (httpx.ConnectError, httpx.TimeoutException) as e:
        logger.error(
            f"[guardian] Connection failed ({type(e).__name__}: {e}). "
            "Failing safe — halting run."
        )
        return GuardianCheckResponse(
            allowed=False,
            tier="halt",
            reason=f"Guardian unavailable: {type(e).__name__}",
            confidence=1.0,
        )
    except Exception as e:
        logger.error(f"[guardian] Unexpected error: {e}. Failing safe — halting run.")
        return GuardianCheckResponse(
            allowed=False,
            tier="halt",
            reason=f"Guardian error: {e}",
            confidence=1.0,
        )


async def validate_acl_token(state: dict, tool_id: str) -> bool:
    """
    Phase 3: Validate the task token and check the requested tool is in scope.

    Behaviour:
      - No task_token in state → True (backward compat; tokens not yet mandatory)
      - Token present + tool in granted_tools → True
      - Token present + tool NOT in granted_tools:
          policy="deny"  → log to threat_events (TOOL_SCOPE_VIOLATION), halt
          policy="alert" → log to audit_log (ESCALATION_BLOCKED), halt
        Both are surfaced on /status for operator review.
      - Token present but invalid/expired → log to threat_events, halt (fail-safe)

    Never raises — callers treat False as a halt condition.
    Security invariant: escalation logging never grants capability. Run is dead.
    """
    token_str = state.get("task_token")
    if not token_str:
        # No token — unconstrained run (Phase 4 will make this mandatory)
        return True

    run_id = state.get("run_id", "unknown")

    token = validate_task_token(token_str)
    if token is None:
        logger.error(
            f"[acl] Invalid or expired task token for run={run_id[:8]}. Halting."
        )
        # Log to threat_events — invalid token is always suspicious
        try:
            from src.database import log_threat_event

            await log_threat_event(
                agent_id=state.get("agent_id", "unknown"),
                run_id=run_id,
                threat_type="INVALID_TASK_TOKEN",
                action_taken="BLOCKED",
                confidence=1.0,
                metadata={"tool_id": tool_id},
            )
        except Exception as db_err:
            logger.warning(f"[acl] Could not log INVALID_TASK_TOKEN to DB: {db_err}")
        return False

    if tool_id not in token.granted_tools:
        escalation = EscalationRequest(
            token_id=token.token_id,
            agent_id=token.agent_id,
            requested_tool=tool_id,
            reason=f"Tool '{tool_id}' not in token scope {token.granted_tools}",
            escalation_policy=token.escalation_policy,
        )

        if token.escalation_policy == "alert":
            # Operational under-scoping — log to audit_log, surface on /status
            logger.warning(
                f"[acl] ESCALATION_BLOCKED (alert) token={token.token_id[:8]}... "
                f"tool={tool_id!r} — run halted, visible on /status"
            )
            try:
                from src.database import append_audit_log

                await append_audit_log(
                    event_type="ESCALATION_BLOCKED",
                    agent_id=token.agent_id,
                    payload={
                        "token_id": token.token_id,
                        "run_id": run_id,
                        "requested_tool": tool_id,
                        "granted_tools": token.granted_tools,
                        "reason": escalation.reason,
                        "policy": "alert",
                    },
                )
            except Exception as db_err:
                logger.warning(
                    f"[acl] Could not log ESCALATION_BLOCKED to audit_log: {db_err}"
                )
        else:
            # deny policy — suspicious, treat as a security incident
            logger.error(
                f"[acl] TOOL_SCOPE_VIOLATION (deny) token={token.token_id[:8]}... "
                f"tool={tool_id!r} not in granted_tools. Halting run."
            )
            try:
                from src.database import log_threat_event

                await log_threat_event(
                    agent_id=token.agent_id,
                    run_id=run_id,
                    threat_type="TOOL_SCOPE_VIOLATION",
                    action_taken="BLOCKED",
                    confidence=1.0,
                    metadata={
                        "token_id": token.token_id,
                        "requested_tool": tool_id,
                        "granted_tools": token.granted_tools,
                    },
                )
            except Exception as db_err:
                logger.warning(
                    f"[acl] Could not log TOOL_SCOPE_VIOLATION to DB: {db_err}"
                )

        return False

    return True


async def score_embedding_trust(doc: dict) -> float:
    """
    Phase 2: Look up document trust_score from DB by doc id.
    Returns 0.5 (neutral) if doc_id is not present or DB is unavailable.
    """
    doc_id = doc.get("id")
    if doc_id is None:
        return 0.5
    try:
        from src.database import get_pool

        pool = get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                "SELECT trust_score FROM documents WHERE id = %s", (doc_id,)
            )
            row = await cur.fetchone()
        if row and row["trust_score"] is not None:
            return float(row["trust_score"])
    except Exception:
        pass
    return 0.5


# ── SecureToolNode ────────────────────────────────────────────────────────────


class SecureToolNode:
    """
    Wraps LangGraph ToolNode with pre/post security controls:
      1. verify_tool_before_invocation() — registry + hash integrity check
      2a. validate_acl_token()           — JWT task token scope check
      2b. guardian_check()               — capability boundary + sequence enforcement
          tier="halt"   → force_end=True (security violation, run is dead)
          tier="sandbox"→ skip tool, inject error ToolMessage, run continues
      3. detect_action_loop()            — repeated-call detection
      4. Execute approved tools via inner ToolNode
      5. sanitize_output()               — PII + injection scan on tool responses

    Use this instead of raw ToolNode for all agents.
    """

    def __init__(self, tools: list) -> None:
        from langgraph.prebuilt import ToolNode

        self._inner = ToolNode(tools)
        self._tool_names = {t.name for t in tools}

    async def __call__(self, state: AgentState, config=None) -> dict:
        result: dict = {}

        # Extract tool calls from the last AI message
        last_msg = state["messages"][-1] if state["messages"] else None
        tool_calls = getattr(last_msg, "tool_calls", None) or []

        # Sequence tracking for Guardian
        sequence_so_far = list(state.get("sequence_so_far") or [])

        # Phase 6: TOCTOU mitigation — snapshot approved {call_id → tool_id} BEFORE
        # the Guardian check loop runs. After inner ToolNode execution, we verify
        # that every ToolMessage.tool_call_id was in this snapshot. Any unexpected
        # call_id indicates that the inner ToolNode executed a call that was not
        # approved by Guardian (possible TOCTOU or message injection).
        approved_snapshot: dict[str, str] = {}  # call_id → tool_id

        # Phase 3: track which calls were approved vs sandboxed
        approved_tc_ids: set[str] = set()
        sandbox_messages: list[ToolMessage] = []

        for tc in tool_calls:
            tool_id = tc["name"] if isinstance(tc, dict) else tc.name
            tc_id = tc.get("id", "") if isinstance(tc, dict) else getattr(tc, "id", "")
            tool_input = (
                tc.get("args", {}) if isinstance(tc, dict) else getattr(tc, "args", {})
            )

            # 1. Registry + hash integrity check
            approved = await verify_tool_before_invocation(tool_id)
            if not approved:
                logger.error(
                    f"[SecureToolNode] Tool '{tool_id}' failed registry check. Halting."
                )
                # Notify the SSE stream so the UI can show a blocked indicator
                # and tooltip. Uses LangChain custom event dispatch so the worker
                # can forward it as a 'tool_blocked' SSE event — no circular import.
                try:
                    await adispatch_custom_event(
                        "tool_blocked",
                        {"tool": tool_id, "reason": "registry_check_failed"},
                    )
                except Exception:
                    pass  # Non-fatal: UI falls back to client-side detection
                # Inject an error ToolMessage so the LLM can:
                #   (a) retry with a different tool if one is available, OR
                #   (b) explicitly flag unverified output with [UNVERIFIED DATA].
                # Without this the LLM silently fills the dangling tool call
                # from training data (hallucination).
                # Note: tool_id is LLM-generated but LangChain validates it against
                # bound tools before SecureToolNode runs, so arbitrary names are
                # rejected upstream.
                sandbox_messages.append(
                    ToolMessage(
                        content=(
                            f"[TOOL BLOCKED] '{tool_id}' could not execute — "
                            "security registry check failed "
                            "(tool integrity hash mismatch).\n"
                            "Follow these rules exactly:\n"
                            "1. If another available tool can accomplish the same goal, "
                            "call it now instead.\n"
                            "2. If no alternative tool is available, you MUST write the "
                            "exact text '[UNVERIFIED DATA]' on its own line before your "
                            "response, then clearly state you cannot verify the information "
                            "and why.\n"
                            "3. NEVER state unverified information as fact.\n"
                            "4. Tell the user which tool failed. An administrator can "
                            "restore it with: make verify-tool-registry"
                        ),
                        tool_call_id=tc_id,
                        name=tool_id,
                    )
                )
                result["messages"] = sandbox_messages
                result["force_end"] = True
                result["loop_detected"] = False
                return result

            # 2a. Task token ACL check (Phase 3)
            # Validates the JWT in state["task_token"] and checks tool is in scope.
            # No-op if task_token is None (backward compat).
            acl_ok = await validate_acl_token(state, tool_id)
            if not acl_ok:
                logger.error(
                    f"[SecureToolNode] ACL denied tool='{tool_id}' "
                    "— token scope violation or invalid token. Halting."
                )
                try:
                    await adispatch_custom_event(
                        "tool_blocked",
                        {"tool": tool_id, "reason": "acl_token_violation"},
                    )
                except Exception:
                    pass
                # Add synthetic ToolMessages for every pending tool_call so the
                # conversation state stays valid (no dangling tool_calls without a
                # ToolMessage response). Without this the next agent_node gets
                # confused messages and the LLM produces empty content → [No result].
                _acl_halt_msgs = [
                    ToolMessage(
                        content=(
                            f"[SECURITY HALT] Tool"
                            f" '{_tc['name'] if isinstance(_tc, dict) else _tc.name}'"
                            " blocked: task token does not grant access to this tool."
                        ),
                        tool_call_id=(
                            _tc.get("id", "")
                            if isinstance(_tc, dict)
                            else getattr(_tc, "id", "")
                        ),
                        name=_tc["name"] if isinstance(_tc, dict) else _tc.name,
                    )
                    for _tc in tool_calls
                ]
                return {
                    "messages": _acl_halt_msgs,
                    "force_end": True,
                    "loop_detected": False,
                    "result": "Halted: task token does not grant access to this tool.",
                }

            # 2b. Guardian capability boundary + sequence check (Phase 3)
            # Now returns GuardianCheckResponse so we can branch on tier.
            # Pass real tool_input so checks 3, 5, 6 see actual arguments (Gap 1 fix).
            state_with_seq = {**state, "sequence_so_far": sequence_so_far}
            guardian_resp = await guardian_check(tool_id, tool_input, state_with_seq)

            if not guardian_resp.allowed:
                if guardian_resp.tier == "sandbox":
                    # Novel sequence — skip this tool, feed agent an error message,
                    # let the run continue so the agent can try a different approach.
                    logger.warning(
                        f"[SecureToolNode] SANDBOX '{tool_id}': {guardian_resp.reason}"
                    )
                    try:
                        from src.database import log_threat_event

                        await log_threat_event(
                            agent_id=state.get("run_id", "unknown"),
                            run_id=state.get("run_id", "unknown"),
                            threat_type="SEQUENCE_VIOLATION",
                            action_taken="SANDBOX_RETRY",
                            confidence=guardian_resp.confidence,
                            metadata={
                                "tool_id": tool_id,
                                "sequence": sequence_so_far,
                                "reason": guardian_resp.reason,
                            },
                        )
                    except Exception:
                        pass  # Non-fatal — run continues regardless

                    try:
                        await adispatch_custom_event(
                            "tool_blocked",
                            {"tool": tool_id, "reason": "sandbox_sequence_violation"},
                        )
                    except Exception:
                        pass
                    sandbox_messages.append(
                        ToolMessage(
                            content=(
                                f"[TOOL SKIPPED] '{tool_id}' was skipped — "
                                "the call sequence requires approval.\n"
                                "Follow these rules:\n"
                                "1. If another available tool can accomplish the same goal, "
                                "call it now instead.\n"
                                "2. If no alternative is available, write '[UNVERIFIED DATA]' "
                                "before your response and clearly state you cannot verify "
                                "the information."
                            ),
                            tool_call_id=tc_id,
                            name=tool_id,
                        )
                    )
                    continue  # Skip to next tool call; don't add to approved set

                else:
                    # halt — security violation, run is dead
                    logger.error(
                        f"[SecureToolNode] Guardian HALT '{tool_id}': "
                        f"{guardian_resp.reason}"
                    )
                    try:
                        await adispatch_custom_event(
                            "tool_blocked",
                            {
                                "tool": tool_id,
                                "reason": "capability_boundary_violation",
                            },
                        )
                    except Exception:
                        pass
                    # Add synthetic ToolMessages to close dangling tool_calls.
                    _guardian_halt_msgs = [
                        ToolMessage(
                            content=(
                                f"[SECURITY HALT] Tool"
                                f" '{_tc['name'] if isinstance(_tc, dict) else _tc.name}'"
                                f" blocked by security policy: {guardian_resp.reason}"
                            ),
                            tool_call_id=(
                                _tc.get("id", "")
                                if isinstance(_tc, dict)
                                else getattr(_tc, "id", "")
                            ),
                            name=_tc["name"] if isinstance(_tc, dict) else _tc.name,
                        )
                        for _tc in tool_calls
                    ]
                    return {
                        "messages": _guardian_halt_msgs,
                        "force_end": True,
                        "loop_detected": False,
                        "result": f"Halted: {guardian_resp.reason}",
                    }

            # 3. Action loop detection
            loop_updates = detect_action_loop(state, tool_id, tool_input)
            result.update(loop_updates)
            if result.get("loop_detected"):
                logger.warning(
                    f"[SecureToolNode] Loop detected for '{tool_id}'. Halting."
                )
                try:
                    await adispatch_custom_event(
                        "tool_blocked",
                        {"tool": tool_id, "reason": "action_loop_detected"},
                    )
                except Exception:
                    pass
                return result

            # 4. Sanitize and validate every tool argument (belt-and-suspenders)
            for arg_name, arg_value in (tool_input or {}).items():
                if not isinstance(arg_value, str):
                    continue

                # 4a. Outbound sanitization — strip PII / detect injection in args
                clean_arg, san_meta = sanitize_tool_input(arg_value, tool_id=tool_id)

                # 4a-inject: Pattern-tiered response when LLM-generated tool args
                # contain injection patterns.
                # Tier 1 (halt-worthy): unambiguous jailbreak/override patterns —
                #   the agent context is likely compromised. Force-end the run.
                # Tier 2 (soft): patterns that also appear in legitimate research
                #   content (educational framing, hypothetical, etc.) — log and
                #   continue so valid research queries are not blocked.
                # See SECURITY.md §"Injection Detection Architecture".
                if san_meta.get("injection_detected"):
                    matched = san_meta.get("injection_patterns", [])
                    if has_halt_worthy_injection(matched):
                        # Tier 1: halt. Unambiguous injection pattern in tool arg.
                        logger.error(
                            f"[SecureToolNode] TOOL_ARG_INJECTION (Tier 1) in "
                            f"'{tool_id}' arg='{arg_name}' — agent context may be "
                            "compromised. Halting."
                        )
                        try:
                            from src.database import log_threat_event

                            await log_threat_event(
                                agent_id=state.get("agent_id", "unknown"),
                                run_id=state.get("run_id", "unknown"),
                                threat_type="TOOL_ARG_INJECTION",
                                action_taken="BLOCKED",
                                confidence=0.9,
                                raw_input=arg_value[:200],
                                metadata={
                                    "tool_id": tool_id,
                                    "arg_name": arg_name,
                                    "patterns": matched,
                                    "tier": "halt",
                                },
                            )
                        except Exception as _db_err:
                            logger.debug(
                                f"[SecureToolNode] Could not log TOOL_ARG_INJECTION: {_db_err}"
                            )
                        try:
                            await adispatch_custom_event(
                                "tool_blocked",
                                {"tool": tool_id, "reason": "injection_detected"},
                            )
                        except Exception:
                            pass
                        return {"force_end": True, "loop_detected": False}
                    else:
                        # Tier 2: soft pattern — log event and continue.
                        # These patterns appear in legitimate research content.
                        logger.warning(
                            f"[SecureToolNode] Soft injection pattern (Tier 2) in "
                            f"'{tool_id}' arg='{arg_name}' — logging, not halting."
                        )
                        try:
                            from src.database import log_threat_event

                            await log_threat_event(
                                agent_id=state.get("agent_id", "unknown"),
                                run_id=state.get("run_id", "unknown"),
                                threat_type="INJECTION_DETECTED",
                                action_taken="LOGGED",
                                confidence=0.5,
                                raw_input=arg_value[:200],
                                metadata={
                                    "tool_id": tool_id,
                                    "arg_name": arg_name,
                                    "patterns": matched,
                                    "tier": "soft",
                                },
                            )
                        except Exception as _db_err:
                            logger.debug(
                                f"[SecureToolNode] Could not log soft injection: {_db_err}"
                            )

                # 4b. Async SSRF prevention for any argument that looks like a URL
                if arg_name in ("url", "uri", "endpoint", "href", "src"):
                    try:
                        await validate_fetch_url_async(clean_arg)
                    except SecurityError as e:
                        logger.error(
                            f"[SecureToolNode] SSRF blocked for '{tool_id}': {e}"
                        )
                        try:
                            await adispatch_custom_event(
                                "tool_blocked",
                                {"tool": tool_id, "reason": "ssrf_protection"},
                            )
                        except Exception:
                            pass
                        return {"force_end": True, "loop_detected": False}

                # 4c. Destructive / HITL pattern detection
                requires_hitl, categories = detect_destructive_pattern(clean_arg)
                if requires_hitl:
                    hitl_updates = await check_hitl_required(
                        action=f"{tool_id}.{arg_name}",
                        input_text=clean_arg[:200],
                        state=state,
                        categories=categories,
                    )
                    result.update(hitl_updates)
                    if result.get("force_end"):
                        logger.warning(
                            f"[SecureToolNode] HITL halt on '{tool_id}' "
                            f"arg='{arg_name}' categories={categories}"
                        )
                        try:
                            await adispatch_custom_event(
                                "tool_blocked",
                                {"tool": tool_id, "reason": "hitl_required"},
                            )
                        except Exception:
                            pass
                        return result

            # All checks passed — mark as approved
            sequence_so_far = sequence_so_far + [tool_id]
            approved_tc_ids.add(tc_id)
            # Phase 6: record in TOCTOU snapshot
            approved_snapshot[tc_id] = tool_id

        # Persist updated sequence to state
        result["sequence_so_far"] = sequence_so_far

        # 5. Execute approved tools via inner ToolNode
        if not approved_tc_ids:
            # All calls were sandboxed — return synthetic messages, no inner execution
            result["messages"] = sandbox_messages
            return result

        # If some calls were sandboxed, filter the last message to only approved calls
        exec_state = state
        if sandbox_messages:
            try:
                approved_tcs = [
                    tc
                    for tc in tool_calls
                    if (
                        tc.get("id", "")
                        if isinstance(tc, dict)
                        else getattr(tc, "id", "")
                    )
                    in approved_tc_ids
                ]
                filtered_msg = last_msg.model_copy(update={"tool_calls": approved_tcs})
                exec_state = {
                    **state,
                    "messages": [*state["messages"][:-1], filtered_msg],
                }
            except Exception:
                exec_state = state  # Fallback: run all (inner skips unknown calls)

        if config is not None:
            inner_result = await self._inner.ainvoke(exec_state, config)
        else:
            inner_result = await self._inner.ainvoke(exec_state)
        result.update(inner_result)

        # Phase 6: TOCTOU verification — check that inner ToolNode only produced
        # ToolMessages for call_ids that were approved in our snapshot. Any
        # unexpected call_id means the inner node executed a call we did not vet.
        if approved_snapshot:
            for msg in result.get("messages", []):
                if not isinstance(msg, ToolMessage):
                    continue
                tc_id = getattr(msg, "tool_call_id", None)
                if (
                    tc_id
                    and tc_id not in approved_tc_ids
                    and tc_id
                    not in {
                        m.tool_call_id
                        for m in sandbox_messages
                        if hasattr(m, "tool_call_id")
                    }
                ):
                    logger.error(
                        f"[SecureToolNode] TOCTOU violation: ToolMessage with "
                        f"tool_call_id={tc_id!r} was not in approved snapshot. Halting."
                    )
                    try:
                        from src.database import log_threat_event

                        await log_threat_event(
                            agent_id=state.get("agent_id", "unknown"),
                            run_id=state.get("run_id", "unknown"),
                            threat_type="CAPABILITY_VIOLATION",
                            confidence=1.0,
                            raw_input=f"Unexpected tool_call_id: {tc_id}",
                            action_taken="BLOCKED",
                            metadata={
                                "approved_snapshot": approved_snapshot,
                                "unexpected_call_id": tc_id,
                            },
                        )
                    except Exception:
                        pass
                    try:
                        await adispatch_custom_event(
                            "tool_blocked",
                            {"tool": "unknown", "reason": "toctou_violation"},
                        )
                    except Exception:
                        pass
                    return {"force_end": True, "loop_detected": False}

        # Append sandbox ToolMessages after real tool results
        if sandbox_messages:
            result["messages"] = list(result.get("messages", [])) + sandbox_messages

        # 6. Sanitize tool output before it enters agent context.
        # Only sanitize inner results — sandbox messages are system-generated.
        #
        # Tiered response mirrors step 4a (tool args):
        #   Tier 1 (halt-worthy patterns): log TOOL_RESULT_INJECTION action=BLOCKED,
        #     confidence=0.9. If halt_on_tool_result_injection=True, force-end the run.
        #   Tier 2 (soft/research patterns): log TOOL_RESULT_INJECTION action=LOGGED,
        #     confidence=0.5. Never halt — the content has already been sanitized before
        #     it enters context, so the risk is significantly reduced.
        #
        # This prevents halt_on_tool_result_injection=True from firing on every
        # security research page that mentions "for educational purposes" etc.
        if "messages" in result:
            sanitized_msgs = []
            for msg in result["messages"]:
                # Skip sanitizing our own synthetic sandbox messages
                if isinstance(msg, ToolMessage) and msg in sandbox_messages:
                    sanitized_msgs.append(msg)
                    continue
                if hasattr(msg, "content") and isinstance(msg.content, str):
                    clean_content, meta = sanitize_output(msg.content)
                    if meta.get("injection_detected"):
                        matched = meta.get("injection_patterns", [])
                        _tool_id_for_msg = getattr(msg, "name", "unknown_tool")
                        _is_tier1 = has_halt_worthy_injection(matched)

                        if _is_tier1:
                            logger.warning(
                                f"[SecureToolNode] Tier 1 injection pattern in tool "
                                f"result from '{_tool_id_for_msg}' — content sanitized, "
                                "logging TOOL_RESULT_INJECTION (BLOCKED)."
                            )
                        else:
                            logger.debug(
                                f"[SecureToolNode] Soft injection pattern (Tier 2) in "
                                f"tool result from '{_tool_id_for_msg}' — content "
                                "sanitized, logging TOOL_RESULT_INJECTION (LOGGED)."
                            )

                        try:
                            from src.database import log_threat_event

                            await log_threat_event(
                                agent_id=state.get("agent_id", "unknown"),
                                run_id=state.get("run_id", "unknown"),
                                threat_type="TOOL_RESULT_INJECTION",
                                confidence=0.9 if _is_tier1 else 0.5,
                                raw_input=msg.content[:500],
                                action_taken="BLOCKED" if _is_tier1 else "LOGGED",
                                metadata={
                                    "tool_id": _tool_id_for_msg,
                                    "patterns": matched,
                                    "sanitized": True,
                                    "tier": "halt" if _is_tier1 else "soft",
                                },
                            )
                        except Exception as _db_err:
                            logger.debug(
                                f"[SecureToolNode] Could not log TOOL_RESULT_INJECTION: {_db_err}"
                            )

                        # Halt only on Tier 1 patterns when the setting is enabled.
                        # Tier 2 patterns never halt — they appear in legitimate research
                        # content, and the content has already been sanitized anyway.
                        if _is_tier1 and getattr(
                            settings.security, "halt_on_tool_result_injection", False
                        ):
                            logger.error(
                                f"[SecureToolNode] Halting run: Tier 1 injection pattern "
                                f"in result from '{_tool_id_for_msg}' "
                                "(halt_on_tool_result_injection=True)"
                            )
                            # Replace **state spread with synthetic ToolMessages.
                            # The injected content is intentionally excluded; synthetic
                            # messages close the dangling tool_calls cleanly.
                            _t1_halt_msgs = [
                                ToolMessage(
                                    content=(
                                        f"[SECURITY HALT] Tool result from"
                                        f" '{_tc['name'] if isinstance(_tc, dict) else _tc.name}'"
                                        " blocked: Tier 1 injection pattern detected in"
                                        " tool output. Content redacted."
                                    ),
                                    tool_call_id=(
                                        _tc.get("id", "")
                                        if isinstance(_tc, dict)
                                        else getattr(_tc, "id", "")
                                    ),
                                    name=(
                                        _tc["name"]
                                        if isinstance(_tc, dict)
                                        else _tc.name
                                    ),
                                )
                                for _tc in tool_calls
                            ]
                            return {
                                "messages": _t1_halt_msgs,
                                "force_end": True,
                                "result": "Halted: Tier 1 injection detected in tool result",
                            }

                    try:
                        msg = msg.model_copy(update={"content": clean_content})
                    except AttributeError:
                        try:
                            msg = msg.copy(update={"content": clean_content})
                        except Exception:
                            # Both copy paths failed — synthesize a ToolMessage with
                            # sanitized content so the agent ALWAYS sees clean content
                            # regardless of the message object's copy capabilities.
                            _tool_name = getattr(msg, "name", "unknown_tool")
                            logger.warning(
                                f"[SecureToolNode] Message copy failed for tool "
                                f"'{_tool_name}'; synthesizing ToolMessage with "
                                "sanitized content."
                            )
                            msg = ToolMessage(
                                content=clean_content,
                                tool_call_id=getattr(msg, "tool_call_id", "unknown"),
                                name=_tool_name,
                            )
                sanitized_msgs.append(msg)
            result["messages"] = sanitized_msgs

        return result


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
    task_token: str | None = None,
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
    # Build initial state first — run_id needed for threat logging.
    # ORDERING RULE: always call SafeguardedState.initial() before sanitize_text()
    # so the run_id is available for DB logging if injection is detected.
    # agent_id MUST match the agent_id in issue_task_token() below.
    init = SafeguardedState.initial(
        tracing_enabled=tracing_enabled,
        max_steps=max_steps,
        agent_id="base_agent",
    )

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
            "Injection patterns detected in task input. Proceeding with sanitized input."
        )
        try:
            from src.database import log_threat_event

            await log_threat_event(
                agent_id="base_agent",
                run_id=init["run_id"],
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
                f"[run_agent] Could not log INJECTION_DETECTED to DB: {_db_err}"
            )

    state: AgentState = {
        **init,
        "task": task,
        "result": None,
        "sequence_so_far": [],
        "task_token": task_token,
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
