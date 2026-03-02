"""
src/cost_estimator.py
─────────────────────
Phase 36 — Lightweight pre-flight token cost estimator.

Estimates the expected token usage for a task *before* it is queued,
enabling callers to preview cost without running the agent.

Algorithm
─────────
Input tokens ≈ len(input_text.split()) × WORD_TO_TOKEN_RATIO
              + SYSTEM_PROMPT_OVERHEAD[agent_type]

Output tokens ≈ input_tokens × OUTPUT_EXPANSION[agent_type]

Total tokens  = input_tokens + output_tokens

Cost (USD)    = (input_tokens  / 1_000_000) × PRICE_PER_M_INPUT[provider]
              + (output_tokens / 1_000_000) × PRICE_PER_M_OUTPUT[provider]

These are conservative heuristic estimates — real usage will differ.
For local Ollama models the cost is $0.00 (no API fees).
"""

from __future__ import annotations

# ── Constants ─────────────────────────────────────────────────────────────────

# Average tokens per English word (GPT-family tokenizers average ≈ 1.3)
WORD_TO_TOKEN_RATIO: float = 1.3

# Fixed overhead for system prompt + scaffolding per agent type (tokens)
SYSTEM_PROMPT_OVERHEAD: dict[str, int] = {
    "base_agent": 400,
    "orchestrator": 800,
    "researcher": 1200,
}

# How much larger the output tends to be relative to input for each agent
OUTPUT_EXPANSION: dict[str, float] = {
    "base_agent": 1.5,
    "orchestrator": 2.5,
    "researcher": 4.0,
}

# USD per million tokens — input / output (2026 published rates, approximate)
# Ollama (local) = $0 per token
PROVIDER_PRICING: dict[str, dict[str, float]] = {
    "ollama": {"input": 0.0, "output": 0.0},
    "openai": {"input": 0.15, "output": 0.60},  # gpt-4o-mini
    "anthropic": {"input": 0.25, "output": 1.25},  # claude-haiku-3.5
}

# Agent type → provider mapping (mirrors tasks route)
_AGENT_PROVIDER: dict[str, str] = {
    "base_agent": "ollama",
    "orchestrator": "ollama",
    "researcher": "ollama",
}


# ── Public API ────────────────────────────────────────────────────────────────


def estimate_tokens(agent_type: str, input_text: str) -> dict[str, int]:
    """
    Return estimated ``{"input": N, "output": N, "total": N}`` token counts.

    Args:
        agent_type: One of ``"base_agent"``, ``"orchestrator"``, ``"researcher"``.
        input_text: The raw task text submitted by the user.

    Returns:
        Dict with keys ``input``, ``output``, ``total`` (all integers).
    """
    overhead = SYSTEM_PROMPT_OVERHEAD.get(agent_type, 400)
    expansion = OUTPUT_EXPANSION.get(agent_type, 1.5)

    word_count = len(input_text.split()) if input_text.strip() else 0
    input_tokens = int(word_count * WORD_TO_TOKEN_RATIO + overhead)
    output_tokens = int(input_tokens * expansion)
    return {
        "input": input_tokens,
        "output": output_tokens,
        "total": input_tokens + output_tokens,
    }


def estimate_cost(agent_type: str, token_counts: dict[str, int]) -> dict[str, float]:
    """
    Return estimated cost in USD for the given token counts.

    Args:
        agent_type: Determines which provider's pricing to use.
        token_counts: Dict with ``input`` and ``output`` keys (from estimate_tokens).

    Returns:
        Dict with keys ``input_usd``, ``output_usd``, ``total_usd``, ``provider``.
    """
    provider = _AGENT_PROVIDER.get(agent_type, "ollama")
    pricing = PROVIDER_PRICING.get(provider, PROVIDER_PRICING["ollama"])

    input_usd = (token_counts["input"] / 1_000_000) * pricing["input"]
    output_usd = (token_counts["output"] / 1_000_000) * pricing["output"]
    return {
        "input_usd": round(input_usd, 8),
        "output_usd": round(output_usd, 8),
        "total_usd": round(input_usd + output_usd, 8),
        "provider": provider,
    }


def estimate_task_cost(agent_type: str, input_text: str) -> dict:
    """
    Combined helper: estimate tokens + cost for a task in one call.

    Returns a dict suitable for the dry_run API response:
    ``{estimated_tokens, estimated_cost_usd, input_tokens, output_tokens, provider}``.
    """
    tokens = estimate_tokens(agent_type, input_text)
    cost = estimate_cost(agent_type, tokens)
    return {
        "input_tokens": tokens["input"],
        "output_tokens": tokens["output"],
        "estimated_tokens": tokens["total"],
        "estimated_cost_usd": cost["total_usd"],
        "provider": cost["provider"],
    }
