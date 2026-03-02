"""
src/agent_registry.py
─────────────────────
Phase 37 — Agent Capabilities Registry.

A static registry describing the capabilities, limitations, and intended
use-cases of each agent type available in LegionForge.  Exposed via the
/agents gateway endpoints so API clients can discover agents without
reading source code.

All values are strings/lists of strings so the registry serialises to
JSON directly.  The registry is intentionally read-only at runtime.
"""

from __future__ import annotations

# ── Registry ──────────────────────────────────────────────────────────────────

AGENT_REGISTRY: dict[str, dict] = {
    "base_agent": {
        "agent_type": "base_agent",
        "name": "Base Agent",
        "description": (
            "General-purpose LangGraph agent.  Answers questions, drafts text, "
            "summarises content, and runs basic tool calls.  Lowest overhead — "
            "fastest for simple tasks."
        ),
        "supports_tools": True,
        "max_steps": 10,
        "use_cases": [
            "Question answering",
            "Text summarisation",
            "Simple data extraction",
            "Code explanation",
            "General-purpose chat",
        ],
        "limitations": [
            "No multi-step research or web search",
            "No sub-agent delegation",
            "Limited context window compared to orchestrator",
        ],
        "provider": "ollama",
        "model_hint": "llama3.1:8b",
    },
    "orchestrator": {
        "agent_type": "orchestrator",
        "name": "Orchestrator Agent",
        "description": (
            "Multi-step planning and delegation agent.  Breaks complex tasks "
            "into sub-tasks, delegates to specialist agents, and synthesises "
            "results.  Best for tasks requiring multiple tools or multi-hop "
            "reasoning."
        ),
        "supports_tools": True,
        "max_steps": 25,
        "use_cases": [
            "Multi-step task planning",
            "Sub-agent orchestration",
            "Tool chaining",
            "Complex data pipelines",
            "Research + summarisation workflows",
        ],
        "limitations": [
            "Higher latency than base_agent",
            "More token usage per task",
            "Requires well-scoped task descriptions",
        ],
        "provider": "ollama",
        "model_hint": "llama3.1:8b",
    },
    "researcher": {
        "agent_type": "researcher",
        "name": "Researcher Agent",
        "description": (
            "Deep-research agent specialised for information gathering, "
            "synthesis, and report generation.  Uses RAG (vector search over "
            "ingested documents) and structured output to produce detailed, "
            "cited answers."
        ),
        "supports_tools": True,
        "max_steps": 30,
        "use_cases": [
            "Literature review and synthesis",
            "Document Q&A (RAG)",
            "Fact gathering across multiple sources",
            "Structured report generation",
            "Technical deep-dives",
        ],
        "limitations": [
            "Highest token usage per task",
            "Slowest to complete",
            "Quality depends on ingested document corpus",
        ],
        "provider": "ollama",
        "model_hint": "llama3.1:8b",
    },
}

VALID_AGENT_TYPES: frozenset[str] = frozenset(AGENT_REGISTRY.keys())


def get_agent(agent_type: str) -> dict | None:
    """Return the capability dict for *agent_type*, or None if unknown."""
    return AGENT_REGISTRY.get(agent_type)


def list_agents() -> list[dict]:
    """Return all agent capability dicts as a list, sorted by agent_type."""
    return sorted(AGENT_REGISTRY.values(), key=lambda a: a["agent_type"])
