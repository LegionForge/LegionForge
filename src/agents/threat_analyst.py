"""
src/agents/threat_analyst.py
────────────────────────────
Phase 4: Threat Analyst agent — reads threat_events, proposes Guardian rules.

Role: security_analyst (read-only access to threat_events and audit_log).

What it does:
    1. Reads recent threat_events from the database (7-day window by default).
    2. Cross-references active components against the AI Bill of Materials.
    3. Identifies patterns: recurring threat types, high-confidence injections,
       novel sequences, scope violations.
    4. Proposes new Guardian detection rules (PENDING — human approval required).
    5. Generates a structured threat digest (stored in the documents table).

Hard constraints:
    - Cannot write to threat_events (read-only token).
    - Cannot apply its own proposed rules (PENDING only — operator approves).
    - Cannot call web_search or any external network tool.
    - Cannot modify roles.yaml, the tool registry, or ACLs.

Startup:
    await register_threat_analyst_tools()
    result = await run_threat_analyst()
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import tool
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages

from config.settings import settings
from src.base_graph import AgentState, SecureToolNode
from src.llm_factory import get_router_llm  # router model — analysis is cheap
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


# ── State ──────────────────────────────────────────────────────────────────────


class ThreatAnalystState(AgentState):
    """Extends AgentState with threat analysis context."""

    threat_events: list[dict]  # events fetched for analysis
    proposed_rules: list[str]  # rule_ids proposed this run
    digest: str | None  # the generated threat digest


# ── Tools ──────────────────────────────────────────────────────────────────────


@tool
async def fetch_threat_events(hours: int = 168) -> str:
    """
    Fetch recent threat events from the database for analysis.
    Returns a JSON summary of threat events grouped by type.
    Default window: 7 days (168 hours).
    """
    try:
        from src.database import get_threat_events_for_analysis

        events = await get_threat_events_for_analysis(hours=min(hours, 720))
        if not events:
            return json.dumps({"events": [], "count": 0, "note": "No events in window"})

        # Group by threat_type for the LLM
        by_type: dict[str, list[dict]] = {}
        for e in events:
            tt = e["threat_type"]
            by_type.setdefault(tt, []).append(
                {
                    "id": e["id"],
                    "run_id": e["run_id"],
                    "agent_id": e["agent_id"],
                    "action_taken": e["action_taken"],
                    "confidence": e["confidence"],
                    "ts": e["ts"],
                    # Include safe metadata fields only (no raw_input)
                    "metadata": {
                        k: v
                        for k, v in (e.get("metadata") or {}).items()
                        if k
                        not in (
                            "raw_input",
                            "pii",
                            "redacted_content",
                        )
                    },
                }
            )

        summary = {
            "total_events": len(events),
            "window_hours": hours,
            "by_type": {
                t: {"count": len(evs), "events": evs[:5]} for t, evs in by_type.items()
            },
        }
        return json.dumps(summary, default=str)

    except Exception as e:
        logger.warning(f"[threat-analyst] fetch_threat_events failed: {e}")
        return json.dumps({"error": str(e), "events": [], "count": 0})


@tool
async def fetch_bom() -> str:
    """
    Fetch the current AI Bill of Materials for CVE cross-referencing.
    Returns a JSON summary of all tracked models, tools, agents, and dependencies.
    """
    try:
        from src.security.bom import get_bom

        report = await get_bom()
        d = report.to_dict()
        # Trim for LLM context — just names, versions, scan status
        slim = {
            "generated_at": d["generated_at"],
            "summary": d["summary"],
            "models": [
                {
                    "name": e["name"],
                    "version": e["version"],
                    "cve_scan_status": e["cve_scan_status"],
                }
                for e in d["models"]
            ],
            "tools": [
                {
                    "name": e["name"],
                    "version": e["version"],
                    "cve_scan_status": e["cve_scan_status"],
                }
                for e in d["tools"]
            ],
            "agents": [
                {"name": e["name"], "metadata": e.get("metadata", {})}
                for e in d["agents"]
            ],
            "dependencies": [
                {
                    "name": e["name"],
                    "version": e["version"],
                    "cve_scan_status": e["cve_scan_status"],
                }
                for e in d["dependencies"]
            ],
        }
        return json.dumps(slim, default=str)
    except Exception as e:
        logger.warning(f"[threat-analyst] fetch_bom failed: {e}")
        return json.dumps({"error": str(e)})


@tool
async def propose_rule(
    rule_type: str,
    rule_def: str,
    justification: str,
    evidence_run_ids: str = "",
) -> str:
    """
    Propose a new Guardian detection rule (status=PENDING, requires human approval).

    Args:
        rule_type:         One of: INJECTION_PATTERN, CAPABILITY_BLOCK,
                           SEQUENCE_BLOCK, RATE_LIMIT_TIGHTEN
        rule_def:          JSON string with rule payload. Schema by type:
                           INJECTION_PATTERN: {"pattern": "regex", "flags": "i"}
                           CAPABILITY_BLOCK:  {"tool_id": "name", "reason": "..."}
                           SEQUENCE_BLOCK:    {"sequence": ["tool_a", "tool_b"]}
                           RATE_LIMIT_TIGHTEN: {"provider": "name", "new_daily_limit": N}
        justification:     Human-readable explanation (referenced threat_event IDs).
        evidence_run_ids:  Comma-separated run_ids from threat_events (optional).

    Returns a JSON result with the new rule_id.
    """
    from src.database import RULE_TYPES, propose_threat_rule

    # Validate rule_type
    if rule_type not in RULE_TYPES:
        return json.dumps(
            {
                "error": f"Invalid rule_type '{rule_type}'. Must be one of {sorted(RULE_TYPES)}"
            }
        )

    # Parse rule_def JSON
    try:
        rule_def_dict = json.loads(rule_def)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"rule_def is not valid JSON: {e}"})

    # Parse evidence run_ids
    evidence_ids = [r.strip() for r in evidence_run_ids.split(",") if r.strip()]

    try:
        rule_id = await propose_threat_rule(
            proposed_by="threat_analyst",
            rule_type=rule_type,
            rule_def=rule_def_dict,
            justification=justification,
            evidence_ids=evidence_ids or None,
        )
        logger.info(
            f"[threat-analyst] Rule proposed: type={rule_type} rule_id={rule_id}"
        )
        return json.dumps(
            {
                "status": "proposed",
                "rule_id": rule_id,
                "rule_type": rule_type,
                "note": "Rule is PENDING. Operator must approve via POST /rules/{rule_id}/approve",
            }
        )
    except Exception as e:
        logger.error(f"[threat-analyst] propose_rule failed: {e}")
        return json.dumps({"error": str(e)})


@tool
async def store_digest(digest_content: str) -> str:
    """
    Store the threat digest in the documents table for future reference.
    Returns the document ID.
    """
    try:
        from src.database import store_document_with_provenance

        doc_id = await store_document_with_provenance(
            content=digest_content,
            metadata={
                "type": "threat_digest",
                "generated_by": "threat_analyst",
                "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            },
            source_url=None,
            ingested_by="threat_analyst",
        )
        logger.info(f"[threat-analyst] Digest stored doc_id={doc_id}")
        return json.dumps({"status": "stored", "doc_id": str(doc_id)})
    except Exception as e:
        logger.warning(f"[threat-analyst] store_digest failed: {e}")
        return json.dumps({"error": str(e), "note": "Digest not persisted"})


THREAT_ANALYST_TOOLS = [fetch_threat_events, fetch_bom, propose_rule, store_digest]

# ── Tool manifests ─────────────────────────────────────────────────────────────

THREAT_ANALYST_TOOL_MANIFESTS = [
    ToolManifest(
        tool_id="fetch_threat_events",
        description="Fetch recent threat events from the database for analysis",
        input_schema={"hours": "int"},
        declared_side_effects=["reads_db:threat_events"],
        source="local",
        entrypoint_func=fetch_threat_events,
    ),
    ToolManifest(
        tool_id="fetch_bom",
        description="Fetch the AI Bill of Materials for CVE cross-referencing",
        input_schema={},
        declared_side_effects=["reads_db:tool_registry"],
        source="local",
        entrypoint_func=fetch_bom,
    ),
    ToolManifest(
        tool_id="propose_rule",
        description="Propose a new Guardian detection rule (PENDING — needs human approval)",
        input_schema={
            "rule_type": "str",
            "rule_def": "str",
            "justification": "str",
            "evidence_run_ids": "str",
        },
        declared_side_effects=["writes_db:threat_rules"],
        source="local",
        entrypoint_func=propose_rule,
    ),
    ToolManifest(
        tool_id="store_digest",
        description="Store the threat digest in the documents table",
        input_schema={"digest_content": "str"},
        declared_side_effects=["writes_db:documents"],
        source="local",
        entrypoint_func=store_digest,
    ),
]

# ── Approved tool-call sequences ───────────────────────────────────────────────
THREAT_ANALYST_EXPECTED_SEQUENCES: list[list[str]] = [
    ["fetch_threat_events", "fetch_bom", "propose_rule", "store_digest"],
    ["fetch_threat_events", "fetch_bom", "store_digest"],
    ["fetch_threat_events", "propose_rule", "store_digest"],
    ["fetch_threat_events", "fetch_bom"],
    ["fetch_threat_events", "store_digest"],
    ["fetch_threat_events"],
]


async def register_threat_analyst_tools() -> None:
    """
    Register all threat analyst tools in the tool registry.
    Call once at startup or via: make register-threat-analyst-tools
    """
    for manifest in THREAT_ANALYST_TOOL_MANIFESTS:
        await register_tool(
            manifest,
            approved_by="operator",
            approval_notes="Phase 4 threat analyst tools",
        )
    logger.info("[threat-analyst] All tools registered.")


# ── System prompt ─────────────────────────────────────────────────────────────

_THREAT_ANALYST_SYSTEM_PROMPT = """You are the LegionForge Threat Analyst. Your role is security_analyst.

Your responsibilities:
1. Fetch and analyze recent threat events using fetch_threat_events.
2. Cross-reference the AI Bill of Materials using fetch_bom to identify vulnerable components.
3. Identify patterns: repeated injection attempts, novel tool sequences, scope violations.
4. Propose specific Guardian detection rules using propose_rule (they require human approval).
5. Generate a concise threat digest and store it using store_digest.

Hard constraints you must never violate:
- You are READ-ONLY on threat_events. You may not modify historical records.
- You may only INSERT rules with status=PENDING. You cannot approve your own proposals.
- You have no network access. Do not attempt web searches or external API calls.
- Do not include raw user input or PII in proposed rules or digests.
- Each rule proposal must reference specific evidence_run_ids from the fetched events.

Threat digest format:
  # Threat Digest — {date}
  ## Summary
  ## Top Threat Patterns
  ## Proposed Rules
  ## Recommended Operator Actions
  ## Components Requiring Security Review

Be precise and evidence-based. Speculative rules without supporting events will be rejected."""


# ── Graph nodes ────────────────────────────────────────────────────────────────


def _build_threat_analyst_node(llm_with_tools: Any):
    """Build the threat analyst agent node with pre-bound LLM."""

    async def agent_node(state: ThreatAnalystState) -> dict:
        updates = increment_step(state)

        log_agent_event(
            "llm_call",
            "threat_analyst",
            {"step": state["step_count"], "task": state.get("task", "")},
            run_id=state.get("run_id"),
        )

        try:
            # Prepend system prompt to messages
            from langchain_core.messages import SystemMessage

            all_messages = [
                SystemMessage(content=_THREAT_ANALYST_SYSTEM_PROMPT)
            ] + list(state["messages"])
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
            error_updates = record_error(state, e, context="threat_analyst/agent_node")
            updates.update(error_updates)
            logger.exception(f"Error in threat_analyst agent_node: {e}")
            return updates

    return agent_node


async def finalizer_node(state: ThreatAnalystState) -> dict:
    """Extract final digest from last message."""
    messages = state.get("messages", [])
    if messages:
        last = messages[-1]
        result = last.content if isinstance(last.content, str) else str(last.content)
    else:
        result = "No digest produced."

    log_agent_event(
        "run_end",
        "threat_analyst",
        {
            "steps": state.get("step_count", 0),
            "tokens": state.get("token_count", 0),
            "errors": state.get("error_count", 0),
            "proposed_rules": len(state.get("proposed_rules", [])),
        },
        run_id=state.get("run_id"),
    )

    return {"result": result, "digest": result}


# ── Routing ────────────────────────────────────────────────────────────────────


def route_after_analyst(state: ThreatAnalystState) -> str:
    """Route after agent node — tools if LLM requested them, otherwise finalize."""
    safeguard_result = check_safeguards(state)
    if safeguard_result == "end":
        return "finalize"

    last_msg = state["messages"][-1] if state["messages"] else None
    if isinstance(last_msg, AIMessage) and getattr(last_msg, "tool_calls", None):
        return "tools"

    return "finalize"


# ── Graph builder ──────────────────────────────────────────────────────────────


def build_threat_analyst_graph() -> StateGraph:
    """Build the threat analyst graph (uncompiled)."""
    # Use router LLM — analysis is structured reasoning, not creative generation.
    # qwen2.5:3b is fast and sufficient for pattern analysis over structured data.
    llm = get_router_llm().bind_tools(THREAT_ANALYST_TOOLS)
    tool_node = SecureToolNode(THREAT_ANALYST_TOOLS)
    agent_node = _build_threat_analyst_node(llm)

    graph = StateGraph(ThreatAnalystState)

    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_node("finalize", finalizer_node)

    graph.set_entry_point("agent")

    graph.add_conditional_edges(
        "agent",
        route_after_analyst,
        {"tools": "tools", "finalize": "finalize"},
    )
    graph.add_edge("tools", "agent")
    graph.add_edge("finalize", END)

    return graph


# ── Public entry point ─────────────────────────────────────────────────────────


async def run_threat_analyst(
    analysis_window_hours: int = 168,
    thread_id: str | None = None,
    tracing_enabled: bool = True,
    max_steps: int | None = None,
) -> dict[str, Any]:
    """
    Run the Threat Analyst agent.

    Reads threat_events, proposes rules, and produces a threat digest.
    Typically scheduled daily via cron or LangGraph triggers.

    Args:
        analysis_window_hours: Hours of threat_events to analyze (default 168 = 7 days).
        thread_id:             Optional thread ID for checkpoint resumption.
        tracing_enabled:       Set False to disable LangSmith for this run.
        max_steps:             Override the profile's default recursion limit.

    Returns:
        dict with 'result', 'digest', 'proposed_rules', 'steps', 'tokens', 'errors'.
    """
    from src.database import get_checkpointer

    task = f"Analyze threat events from the last {analysis_window_hours} hours. Fetch events, review the BOM, identify patterns, propose rules for any novel threats, and produce a threat digest."

    init = SafeguardedState.initial(
        tracing_enabled=tracing_enabled,
        max_steps=max_steps,
    )
    run_id = init["run_id"]

    # Issue a security_analyst-role token — read-only scope.
    # escalation_policy="deny": this agent should NEVER need tools outside its role.
    task_token: str | None = None
    try:
        from src.security import issue_task_token

        task_token = issue_task_token(
            agent_id="threat_analyst",
            run_id=run_id,
            granted_tools=[m.tool_id for m in THREAT_ANALYST_TOOL_MANIFESTS],
            granted_tables=["threat_events", "audit_log", "threat_rules", "documents"],
            granted_data_classes=["security", "internal"],
            escalation_policy="deny",  # any out-of-scope call is a security incident
        )
        logger.debug(
            f"[threat-analyst] Task token issued for run={run_id[:8]}... "
            f"tools={[m.tool_id for m in THREAT_ANALYST_TOOL_MANIFESTS]}"
        )
    except RuntimeError:
        logger.warning(
            "[threat-analyst] JWT secret not configured — running without task token. "
            "Run: make setup-task-token-secret"
        )

    state: ThreatAnalystState = {
        **init,
        "task": task,
        "result": None,
        "threat_events": [],
        "proposed_rules": [],
        "digest": None,
        "sequence_so_far": [],
        "task_token": task_token,
        "messages": [HumanMessage(content=task)],
    }

    config = create_run_config(
        thread_id=thread_id,
        tracing_enabled=tracing_enabled,
        run_name=f"threat_analyst: {analysis_window_hours}h window",
        tags=["threat_analyst", "phase-4"],
        recursion_limit=max_steps or settings.safeguards.default_recursion_limit,
    )

    log_agent_event(
        "run_start",
        "threat_analyst",
        {
            "analysis_window_hours": analysis_window_hours,
            "tracing": tracing_enabled,
            "max_steps": state["max_steps"],
        },
        run_id=run_id,
    )

    async with get_checkpointer() as checkpointer:
        graph = build_threat_analyst_graph().compile(checkpointer=checkpointer)
        final_state = await graph.ainvoke(state, config)

    return {
        "result": final_state.get("result", ""),
        "digest": final_state.get("digest", ""),
        "proposed_rules": final_state.get("proposed_rules", []),
        "steps": final_state.get("step_count", 0),
        "tokens": final_state.get("token_count", 0),
        "errors": final_state.get("error_count", 0),
        "run_id": final_state.get("run_id"),
    }
