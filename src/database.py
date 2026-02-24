"""
src/database.py
───────────────
Async PostgreSQL connection pool, LangGraph checkpointer factory,
and pgvector store. Single entry point for all database operations.

Usage:
    from src.database import get_checkpointer, get_vector_store, init_db

    async with get_checkpointer() as checkpointer:
        graph = base_graph.compile(checkpointer=checkpointer)
        result = await graph.ainvoke(state, config)
"""

from __future__ import annotations

import os
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

import psycopg
from psycopg_pool import AsyncConnectionPool
from psycopg.rows import dict_row
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from pgvector.psycopg import register_vector_async

from config.settings import settings

logger = logging.getLogger(__name__)

# ── Connection helpers ────────────────────────────────────────────────────────


def _get_postgres_password() -> str:
    """
    Return the PostgreSQL password from the environment.
    Raises RuntimeError if not set. Warns if loaded from env var instead of Keychain.
    Never embed this value in a connection URI — pass as a keyword argument only.
    """
    password = os.environ.get("POSTGRES_PASSWORD", "")
    if not password:
        raise RuntimeError(
            "POSTGRES_PASSWORD not set. Store it with:\n"
            "  python -m keyring set postgres api_key\n"
            "Then source ~/.zshrc so POSTGRES_PASSWORD is loaded at startup."
        )
    return password


def _build_conninfo_no_password() -> str:
    """
    Build a PostgreSQL conninfo string WITHOUT the password.
    Password must be passed separately via the 'password' keyword argument
    to avoid it appearing in tracebacks, logs, or error messages.

    Usage:
        pool = AsyncConnectionPool(
            conninfo=_build_conninfo_no_password(),
            kwargs={"password": _get_postgres_password(), ...},
        )
    """
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    db = os.environ.get("POSTGRES_DB", "legionforge")
    user = os.environ.get("POSTGRES_USER", "jpc")
    return f"host={host} port={port} dbname={db} user={user}"


# ── Connection pool (module-level singleton) ──────────────────────────────────

_pool: Optional[AsyncConnectionPool] = None


async def init_db() -> None:
    """
    Initialize the connection pool and set up required extensions/tables.
    Call once at application startup before any agent runs.
    """
    global _pool

    conninfo = _build_conninfo_no_password()
    password = _get_postgres_password()

    logger.info("Initializing PostgreSQL connection pool...")
    _pool = AsyncConnectionPool(
        conninfo=conninfo,
        min_size=1,
        max_size=10,
        kwargs={"password": password, "row_factory": dict_row, "autocommit": True},
    )
    await _pool.wait()

    # Enable pgvector and create LangGraph checkpoint tables
    async with _pool.connection() as conn:
        await conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
        await conn.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")  # fuzzy text
        await register_vector_async(conn)
        logger.info("PostgreSQL extensions verified (vector, pg_trgm)")

    # Set up LangGraph checkpoint tables
    async with get_checkpointer() as checkpointer:
        await checkpointer.setup()
        logger.info("LangGraph checkpoint tables verified")

    # Set up application tables
    async with _pool.connection() as conn:
        await _create_app_tables(conn)

    logger.info("✅ Database initialization complete")


async def _create_app_tables(conn: psycopg.AsyncConnection) -> None:
    """Create application-specific tables if they don't exist."""

    # API usage tracking — for rate limiting and cost monitoring
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS api_usage (
            id            BIGSERIAL PRIMARY KEY,
            ts            TIMESTAMPTZ DEFAULT NOW(),
            provider      TEXT NOT NULL,
            model         TEXT NOT NULL,
            input_tokens  INTEGER DEFAULT 0,
            output_tokens INTEGER DEFAULT 0,
            total_tokens  INTEGER DEFAULT 0,
            run_id        TEXT,
            agent_name    TEXT,
            success       BOOLEAN DEFAULT TRUE,
            latency_ms    INTEGER
        )
    """
    )

    # Index for time-range queries on usage
    await conn.execute(
        """
        CREATE INDEX IF NOT EXISTS api_usage_ts_idx ON api_usage (ts DESC)
    """
    )
    await conn.execute(
        """
        CREATE INDEX IF NOT EXISTS api_usage_provider_idx ON api_usage (provider, ts DESC)
    """
    )

    # Health metrics — persisted snapshots from health checks
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS health_metrics (
            id          BIGSERIAL PRIMARY KEY,
            ts          TIMESTAMPTZ DEFAULT NOW(),
            component   TEXT NOT NULL,
            status      TEXT NOT NULL,
            latency_ms  INTEGER,
            detail      JSONB
        )
    """
    )

    # Vector documents — for RAG
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS documents (
            id          BIGSERIAL PRIMARY KEY,
            created_at  TIMESTAMPTZ DEFAULT NOW(),
            namespace   TEXT NOT NULL DEFAULT 'default',
            content     TEXT NOT NULL,
            metadata    JSONB DEFAULT '{}',
            embedding   vector(768)
        )
    """
    )

    # HNSW index for fast approximate nearest-neighbor search
    await conn.execute(
        """
        CREATE INDEX IF NOT EXISTS documents_embedding_hnsw_idx
        ON documents
        USING hnsw (embedding vector_cosine_ops)
        WITH (m = 16, ef_construction = 64)
    """
    )

    # Security threat events — written by security.py, safeguards.py, and
    # Phase 1 validations. Feeds the Phase 4 Threat Analyst agent.
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_events (
            id           BIGSERIAL PRIMARY KEY,
            ts           TIMESTAMPTZ DEFAULT NOW(),
            agent_id     TEXT NOT NULL,
            run_id       TEXT NOT NULL,
            threat_type  TEXT NOT NULL,
            confidence   FLOAT,
            raw_input    TEXT,
            action_taken TEXT NOT NULL,
            metadata     JSONB DEFAULT '{}'
        )
    """
    )

    await conn.execute(
        """
        CREATE INDEX IF NOT EXISTS threat_events_ts_idx
        ON threat_events (ts DESC)
    """
    )
    await conn.execute(
        """
        CREATE INDEX IF NOT EXISTS threat_events_type_idx
        ON threat_events (threat_type, ts DESC)
    """
    )
    await conn.execute(
        """
        CREATE INDEX IF NOT EXISTS threat_events_run_idx
        ON threat_events (run_id)
    """
    )

    logger.info("Application tables verified")


async def close_db() -> None:
    """Close the connection pool. Call at application shutdown."""
    global _pool
    if _pool:
        await _pool.close()
        _pool = None
        logger.info("PostgreSQL connection pool closed")


def get_pool() -> AsyncConnectionPool:
    """Get the active connection pool. Raises if init_db() hasn't been called."""
    if _pool is None:
        raise RuntimeError("Database not initialized. Call await init_db() first.")
    return _pool


# ── Checkpointer factory ──────────────────────────────────────────────────────


@asynccontextmanager
async def get_checkpointer() -> AsyncGenerator[AsyncPostgresSaver, None]:
    """
    Async context manager that yields an AsyncPostgresSaver backed by the
    existing connection pool. Reuses the pool rather than opening a new
    connection, which keeps the password out of any URI string.

    Usage:
        async with get_checkpointer() as checkpointer:
            graph = my_graph.compile(checkpointer=checkpointer)
    """
    pool = get_pool()
    checkpointer = AsyncPostgresSaver(pool)
    yield checkpointer


# ── Vector store helpers ──────────────────────────────────────────────────────


async def store_document(
    content: str,
    embedding: list[float],
    namespace: str = "default",
    metadata: dict | None = None,
) -> int:
    """Store a document with its embedding. Returns the new document ID."""
    pool = get_pool()
    async with pool.connection() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO documents (content, embedding, namespace, metadata)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            content,
            embedding,
            namespace,
            metadata or {},
        )
    return row["id"]


async def similarity_search(
    query_embedding: list[float],
    namespace: str = "default",
    limit: int = 5,
    min_similarity: float = 0.7,
) -> list[dict]:
    """
    Find documents similar to query_embedding using cosine similarity.
    Returns list of {id, content, metadata, similarity} dicts.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        rows = await conn.fetch(
            """
            SELECT
                id,
                content,
                metadata,
                1 - (embedding <=> %s::vector) AS similarity
            FROM documents
            WHERE namespace = %s
              AND 1 - (embedding <=> %s::vector) >= %s
            ORDER BY embedding <=> %s::vector
            LIMIT %s
            """,
            query_embedding,
            namespace,
            query_embedding,
            min_similarity,
            query_embedding,
            limit,
        )
    return [dict(r) for r in rows]


# ── API usage tracking ────────────────────────────────────────────────────────


async def record_api_usage(
    provider: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    run_id: str | None = None,
    agent_name: str | None = None,
    success: bool = True,
    latency_ms: int | None = None,
) -> None:
    """Record an API call for rate limiting and cost tracking."""
    pool = get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            """
            INSERT INTO api_usage
                (provider, model, input_tokens, output_tokens,
                 total_tokens, run_id, agent_name, success, latency_ms)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            provider,
            model,
            input_tokens,
            output_tokens,
            input_tokens + output_tokens,
            run_id,
            agent_name,
            success,
            latency_ms,
        )


async def get_usage_summary(hours: int = 24) -> dict:
    """Get token usage summary for the last N hours, grouped by provider."""
    if (
        not isinstance(hours, int)
        or isinstance(hours, bool)
        or hours < 1
        or hours > 8760
    ):
        raise ValueError(f"hours must be an integer between 1 and 8760, got {hours!r}")
    pool = get_pool()
    async with pool.connection() as conn:
        rows = await conn.fetch(
            """
            SELECT
                provider,
                COUNT(*)           AS calls,
                SUM(input_tokens)  AS input_tokens,
                SUM(output_tokens) AS output_tokens,
                SUM(total_tokens)  AS total_tokens,
                AVG(latency_ms)    AS avg_latency_ms
            FROM api_usage
            WHERE ts > NOW() - INTERVAL '%s hours'
              AND success = TRUE
            GROUP BY provider
            ORDER BY total_tokens DESC
            """,
            hours,
        )
    return {"hours": hours, "by_provider": [dict(r) for r in rows]}


# ── Security threat event logging ─────────────────────────────────────────────

# Valid threat types — add new ones here as security.py grows
THREAT_TYPES = {
    "INJECTION_DETECTED",  # prompt injection pattern matched
    "TOOL_HASH_MISMATCH",  # tool description/schema changed after registration
    "PREFLIGHT_BUDGET_EXCEEDED",  # pre-execution token estimate over budget
    "PII_REDACTED",  # PII found and removed from input/output
    "LOOP_DETECTED",  # safeguards.py loop detection fired
    "STEP_LIMIT_REACHED",  # safeguards.py step counter hit max
    "TOKEN_BUDGET_EXCEEDED",  # safeguards.py token budget exhausted
}

# Valid action_taken values
THREAT_ACTIONS = {"BLOCKED", "SANDBOX_RETRY", "LOGGED", "REDACTED"}


async def log_threat_event(
    agent_id: str,
    run_id: str,
    threat_type: str,
    action_taken: str,
    confidence: float | None = None,
    raw_input: str | None = None,
    metadata: dict | None = None,
) -> int:
    """
    Log a security threat event. Returns the new event ID.

    Called by security.py, safeguards.py, and Phase 1 validations.
    Feeds the Phase 4 Threat Analyst agent.

    Args:
        agent_id:     Name of the agent that encountered the threat.
        run_id:       UUID of the current run (from SafeguardedState).
        threat_type:  One of THREAT_TYPES. Unknown types are accepted but logged
                      as warnings so new threat types don't silently fail.
        action_taken: One of THREAT_ACTIONS (BLOCKED, SANDBOX_RETRY, LOGGED, REDACTED).
        confidence:   0.0–1.0. None means deterministic (no score needed).
        raw_input:    Sanitized excerpt of the triggering input. Never the full payload.
                      Caller is responsible for truncating/redacting before passing here.
        metadata:     Arbitrary JSON for additional context (tool name, pattern matched, etc).

    Usage:
        from src.database import log_threat_event

        await log_threat_event(
            agent_id="researcher",
            run_id=state["run_id"],
            threat_type="INJECTION_DETECTED",
            action_taken="BLOCKED",
            confidence=0.95,
            raw_input=text[:200],
            metadata={"patterns": matched_patterns},
        )
    """
    if threat_type not in THREAT_TYPES:
        logger.warning(
            f"Unknown threat_type '{threat_type}'. "
            f"Consider adding it to THREAT_TYPES in database.py."
        )
    if action_taken not in THREAT_ACTIONS:
        logger.warning(
            f"Unknown action_taken '{action_taken}'. "
            f"Expected one of: {THREAT_ACTIONS}"
        )

    pool = get_pool()
    async with pool.connection() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO threat_events
                (agent_id, run_id, threat_type, confidence,
                 raw_input, action_taken, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            agent_id,
            run_id,
            threat_type,
            confidence,
            raw_input,
            action_taken,
            metadata or {},
        )
    event_id = row["id"]
    logger.info(
        f"[threat] {threat_type} | agent={agent_id} run={run_id[:8]}... "
        f"action={action_taken} confidence={confidence} id={event_id}"
    )
    return event_id


async def get_threat_summary(hours: int = 24) -> dict:
    """
    Get threat event summary for the last N hours.
    Used by the health server's /threats endpoint (Phase 4).
    """
    if (
        not isinstance(hours, int)
        or isinstance(hours, bool)
        or hours < 1
        or hours > 8760
    ):
        raise ValueError(f"hours must be an integer between 1 and 8760, got {hours!r}")
    pool = get_pool()
    async with pool.connection() as conn:
        rows = await conn.fetch(
            """
            SELECT
                threat_type,
                action_taken,
                COUNT(*)       AS count,
                AVG(confidence) AS avg_confidence
            FROM threat_events
            WHERE ts > NOW() - INTERVAL '%s hours'
            GROUP BY threat_type, action_taken
            ORDER BY count DESC
            """,
            hours,
        )
    return {"hours": hours, "by_type": [dict(r) for r in rows]}
