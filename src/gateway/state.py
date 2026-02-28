"""
src/gateway/state.py
─────────────────────
Optional Redis-backed state layer for the LegionForge gateway.

Phase 13 adds Redis as an optional store for the three operations that must be
globally consistent across multiple gateway instances:

  ┌──────────────────────────┬─────────────────────────────────────────────┐
  │ Operation                │ Storage                                     │
  ├──────────────────────────┼─────────────────────────────────────────────┤
  │ create_stream_token      │ SETEX stream_token:{tok} 1800 {data}        │
  │ resolve_stream_token     │ GET  stream_token:{tok}                     │
  │ delete_stream_token      │ DEL  stream_token:{tok}                     │
  └──────────────────────────┴─────────────────────────────────────────────┘

When no Redis URL is configured (``settings.gateway.redis_url`` is empty or
the env var ``REDIS_URL`` is not set), the functions delegate transparently
to the existing DB-backed implementations in ``src.database``.  There is
zero performance impact for single-instance deployments.

Activation
──────────
Set ``redis_url`` in your hardware profile YAML::

    gateway:
      redis_url: redis://localhost:6379/0

Or via environment variable::

    export REDIS_URL=redis://localhost:6379/0

Lifecycle
─────────
Call ``init_redis(url)`` during gateway lifespan startup and
``close_redis()`` during shutdown.  Both are no-ops when url is empty.
"""

from __future__ import annotations

import logging
import secrets
from typing import Optional

logger = logging.getLogger(__name__)

# ── Module-level Redis client (None = DB mode) ────────────────────────────────

_redis: "redis.asyncio.Redis | None" = None  # type: ignore[name-defined]

_STREAM_TOKEN_TTL = 30 * 60  # 30 minutes (seconds) — matches auth.py
_KEY_PREFIX = "lf:stream_token:"


# ── Lifecycle ─────────────────────────────────────────────────────────────────


async def init_redis(url: str) -> None:
    """
    Connect to Redis.  No-op when ``url`` is empty.

    Call during gateway lifespan startup before accepting requests.
    """
    global _redis
    if not url:
        logger.info("[state] Redis URL not configured — using DB-backed stream tokens")
        return
    try:
        import redis.asyncio as aioredis

        client = aioredis.from_url(url, decode_responses=True)
        await client.ping()
        _redis = client
        logger.info(f"[state] Redis connected: {url}")
    except Exception as exc:
        logger.error(
            f"[state] Redis connection failed ({exc}) — falling back to DB-backed tokens"
        )
        _redis = None


async def close_redis() -> None:
    """Close the Redis connection.  No-op when Redis is not configured."""
    global _redis
    if _redis is not None:
        try:
            await _redis.aclose()
        except Exception:
            pass
        _redis = None
        logger.info("[state] Redis connection closed")


def get_redis() -> "redis.asyncio.Redis | None":  # type: ignore[name-defined]
    """Return the active Redis client, or None when in DB mode."""
    return _redis


def redis_mode() -> bool:
    """Return True if Redis is active."""
    return _redis is not None


# ── Stream token operations ────────────────────────────────────────────────────


async def create_stream_token(task_id: str, user_id: str) -> str:
    """
    Issue a short-lived stream token for SSE access from browser clients.

    Stores the token in Redis (when configured) or the DB stream_tokens table.
    TTL: 30 minutes.

    Args:
        task_id: Task the token grants streaming access to.
        user_id: User who submitted the task.

    Returns:
        URL-safe random token string (32 bytes of entropy).
    """
    token = secrets.token_urlsafe(32)

    if _redis is not None:
        key = f"{_KEY_PREFIX}{token}"
        value = f"{task_id}:{user_id}"
        await _redis.setex(key, _STREAM_TOKEN_TTL, value)
        logger.debug(f"[state] Stream token created in Redis task={task_id}")
    else:
        from src.database import create_stream_token as _db_create

        await _db_create(token, task_id, user_id, _STREAM_TOKEN_TTL)
        logger.debug(f"[state] Stream token created in DB task={task_id}")

    return token


async def resolve_stream_token(token: str) -> Optional[tuple[str, str]]:
    """
    Resolve a stream token to (task_id, user_id).

    Returns None if the token is unknown or has expired.  Does NOT consume
    (delete) the token so EventSource clients can reconnect within the TTL.

    Args:
        token: Raw stream token string from the query parameter.

    Returns:
        ``(task_id, user_id)`` tuple, or None if invalid/expired.
    """
    if _redis is not None:
        key = f"{_KEY_PREFIX}{token}"
        value: str | None = await _redis.get(key)
        if value is None:
            return None
        parts = value.split(":", 1)
        if len(parts) != 2:
            logger.warning(f"[state] Malformed Redis stream token value: {value!r}")
            return None
        return parts[0], parts[1]
    else:
        from src.database import resolve_stream_token as _db_resolve

        return await _db_resolve(token)


async def delete_stream_token(token: str) -> None:
    """
    Explicitly delete a stream token (e.g. on task cancellation or worker cleanup).

    Args:
        token: Raw stream token string.
    """
    if _redis is not None:
        key = f"{_KEY_PREFIX}{token}"
        await _redis.delete(key)
    else:
        from src.database import delete_stream_token as _db_delete

        await _db_delete(token)
