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
from typing import TYPE_CHECKING, Optional

from src.security.core import _log_safe

if TYPE_CHECKING:
    import redis.asyncio

logger = logging.getLogger(__name__)

# ── Module-level Redis client (None = DB mode) ────────────────────────────────

_redis: redis.asyncio.Redis | None = None

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
        except Exception:  # nosec B110
            pass
        _redis = None
        logger.info("[state] Redis connection closed")


def get_redis() -> redis.asyncio.Redis | None:
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


# ── Per-user daily budget counters (Phase 14) ─────────────────────────────────
#
# When Redis is active, per-user daily token budgets are tracked with a single
# Redis key per user per day:
#
#   lf:budget:{user_id}:{YYYY-MM-DD}   →  int (total reserved tokens today)
#
# INCRBY is used for atomic reservation.  The key auto-expires at midnight UTC
# via EXPIREAT, so no manual cleanup is required.
#
# When Redis is not configured, budget enforcement falls back to the existing
# two-read DB path in per_user_budget_check() (rate_limiter.py).

_BUDGET_KEY_PREFIX = "lf:budget:"


def _tomorrow_midnight_unix() -> int:
    """Return Unix timestamp for tomorrow midnight UTC."""
    from datetime import datetime, timezone, timedelta

    now = datetime.now(tz=timezone.utc)
    tomorrow = (now + timedelta(days=1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    return int(tomorrow.timestamp())


async def redis_budget_check_and_reserve(
    user_id: str,
    estimated_tokens: int,
    daily_limit: int,
) -> None:
    """
    Atomically reserve ``estimated_tokens`` against the user's daily budget.

    Uses Redis INCRBY so all gateway instances share the same counter.
    Sets EXPIREAT to tomorrow midnight UTC on the first reservation of the day.

    Raises:
        RuntimeError: If adding ``estimated_tokens`` would exceed ``daily_limit``.

    No-op when Redis is not configured (DB path handles enforcement instead).
    """
    if _redis is None:
        return

    from datetime import date

    today = date.today().isoformat()
    key = f"{_BUDGET_KEY_PREFIX}{user_id}:{today}"

    new_val: int = await _redis.incrby(key, estimated_tokens)

    # Set expiry on first write (TTL == -1 means the key has no expiry yet).
    ttl: int = await _redis.ttl(key)
    if ttl < 0:
        await _redis.expireat(key, _tomorrow_midnight_unix())

    if new_val > daily_limit:
        # Roll back and reject.
        await _redis.decrby(key, estimated_tokens)
        raise RuntimeError(
            f"Per-user daily token budget exceeded for user '{user_id}' (Redis).\n"
            f"  Would reach: {new_val:,} | Daily limit: {daily_limit:,}"
        )

    logger.debug(
        "[state] Budget reserved: user=%s +%s → %s/%s",
        _log_safe(user_id),
        _log_safe(estimated_tokens),
        _log_safe(new_val),
        _log_safe(daily_limit),
    )


async def redis_budget_release(
    user_id: str,
    estimated_tokens: int,
    actual_tokens: int,
) -> None:
    """
    Correct the Redis budget counter after a task completes.

    Subtracts the reservation and adds actual usage (net adjustment).
    If actual > estimated the counter is incremented by the difference.
    If actual < estimated the counter is decremented (tokens returned).

    No-op when Redis is not configured.
    """
    if _redis is None:
        return

    delta = actual_tokens - estimated_tokens
    if delta == 0:
        return

    from datetime import date

    today = date.today().isoformat()
    key = f"{_BUDGET_KEY_PREFIX}{user_id}:{today}"

    if delta > 0:
        await _redis.incrby(key, delta)
    else:
        # Floor at 0 — never go negative.
        await _redis.decrby(key, abs(delta))

    logger.debug(
        f"[state] Budget released: user={user_id} estimated={estimated_tokens} "
        f"actual={actual_tokens} delta={delta:+}"
    )


async def redis_budget_get(user_id: str) -> int:
    """
    Return the current daily token consumption for a user from Redis.

    Returns 0 if the key does not exist (no usage yet today or not in Redis mode).
    """
    if _redis is None:
        return 0

    from datetime import date

    today = date.today().isoformat()
    key = f"{_BUDGET_KEY_PREFIX}{user_id}:{today}"
    val: str | None = await _redis.get(key)
    return int(val) if val is not None else 0
