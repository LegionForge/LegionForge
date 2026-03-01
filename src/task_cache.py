"""
src/task_cache.py
──────────────────
Lightweight task result cache for Phase 29.

Identical task inputs (same agent_type + sanitized task text) within a
configurable TTL window return the cached result immediately — no LLM call,
no queue slot, instant response.

Cache key: SHA-256(agent_type + ":" + input_text)
Cache store: tasks table (content_hash column, status='complete')

This approach is free-riding on existing storage — no new cache table, no
Redis required, no TTL demon to run.  The downside is that the lookup is a
DB query on every submission (fast — indexed), and cache entries are never
explicitly invalidated (they expire naturally via the TTL filter).

Usage (called from the task submission route):
    from src.task_cache import compute_task_hash, CACHE_TTL_SECONDS
    content_hash = compute_task_hash(agent_type, sanitized_text)
    hit = await lookup_cached_task(content_hash, max_age_seconds=CACHE_TTL_SECONDS)
    if hit:
        return {**hit, "cached": True}
"""

from __future__ import annotations

import hashlib
import logging

logger = logging.getLogger(__name__)

# Default TTL: 1 hour.  Tasks completed more than TTL seconds ago are
# not considered cache hits.  Override via TaskRequest.cache_ttl.
CACHE_TTL_SECONDS: int = 3600


def compute_task_hash(agent_type: str, input_text: str) -> str:
    """
    Return a stable SHA-256 hex digest for (agent_type, input_text).

    This is the cache lookup key.  Two calls with identical arguments
    always produce the same hash regardless of order of submission.
    """
    raw = f"{agent_type}:{input_text}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
