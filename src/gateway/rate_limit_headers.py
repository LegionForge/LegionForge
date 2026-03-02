"""
src/gateway/rate_limit_headers.py
──────────────────────────────────
Phase 42 — Rate Limit Response Headers.

Computes X-RateLimit-* headers for gateway responses so API clients can
implement adaptive back-off without polling the usage endpoint.

Headers emitted:
    X-RateLimit-Limit     — daily token budget for the user
    X-RateLimit-Remaining — estimated remaining tokens (limit - used today)
    X-RateLimit-Reset     — Unix timestamp of midnight UTC (budget resets)
    X-RateLimit-Provider  — provider the budget applies to
"""

from __future__ import annotations

import math
from datetime import datetime, timezone


def _midnight_utc_epoch() -> int:
    """Return the Unix timestamp of the next midnight UTC."""
    now = datetime.now(timezone.utc)
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    # Add one day to get tomorrow's midnight (reset time)
    from datetime import timedelta

    reset = midnight + timedelta(days=1)
    return int(reset.timestamp())


async def compute_rate_limit_headers(
    user_id: str,
    provider: str,
    daily_limit: int,
) -> dict[str, str]:
    """
    Return a dict of X-RateLimit-* header values.

    Queries actual usage for today to compute remaining tokens.
    Falls back to daily_limit if the query fails (best-effort, non-blocking).

    Args:
        user_id:     The gateway user's ID.
        provider:    The LLM provider ('ollama', 'openai', 'anthropic').
        daily_limit: The user's configured daily token budget.

    Returns:
        Dict of header name → string value.
    """
    try:
        from src.database import get_user_actual_usage_today

        used = await get_user_actual_usage_today(user_id, provider)
    except Exception:
        used = 0

    remaining = max(0, daily_limit - used)

    return {
        "X-RateLimit-Limit": str(daily_limit),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(_midnight_utc_epoch()),
        "X-RateLimit-Provider": provider,
    }
