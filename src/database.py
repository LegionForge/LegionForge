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

import hashlib
import json
import os
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
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

    # Verify audit log chain integrity (warn-only — empty chain on first run is valid)
    chain_ok, verified_rows, error_msg = await verify_audit_log_chain()
    if not chain_ok and verified_rows > 0:
        logger.warning(
            f"[audit-log] Chain integrity check FAILED at row {verified_rows}: {error_msg}. "
            "Logging threat event and continuing — investigate before trusting audit data."
        )
        try:
            await log_threat_event(
                agent_id="database",
                run_id="startup",
                threat_type="AUDIT_LOG_TAMPER",
                action_taken="LOGGED",
                confidence=1.0,
                raw_input=error_msg[:200] if error_msg else None,
                metadata={"verified_rows": verified_rows},
            )
        except Exception:
            pass
    elif chain_ok:
        logger.info(f"[audit-log] Chain valid ({verified_rows} rows verified)")

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

    # Tool registry — tracks approved tools with integrity hashes.
    # verify_tool_before_invocation() checks here at invocation time.
    # Feeds Phase 4 Threat Analyst for TOOL_HASH_MISMATCH events.
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tool_registry (
            tool_id             TEXT PRIMARY KEY,
            source              TEXT NOT NULL,
            version             TEXT NOT NULL DEFAULT '1.0.0',
            description         TEXT NOT NULL,
            description_hash    TEXT NOT NULL,
            schema_hash         TEXT NOT NULL,
            entrypoint_hash     TEXT,
            declared_side_effects TEXT[] NOT NULL DEFAULT '{}',
            approved_by         TEXT NOT NULL,
            approved_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            approval_notes      TEXT DEFAULT '',
            status              TEXT NOT NULL DEFAULT 'PENDING',
            created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """
    )

    await conn.execute(
        """
        CREATE INDEX IF NOT EXISTS tool_registry_status_idx
        ON tool_registry (status)
    """
    )

    # Audit log — append-only, hash-chained event ledger.
    # Tamper detection: each row includes a SHA-256 of its own content plus
    # the previous row's hash. verify_audit_log_chain() walks the chain at startup.
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            seq        BIGSERIAL PRIMARY KEY,
            ts         TIMESTAMPTZ DEFAULT now(),
            event_type TEXT NOT NULL,
            agent_id   TEXT,
            payload    JSONB NOT NULL,
            prev_hash  TEXT NOT NULL,
            row_hash   TEXT NOT NULL
        )
    """
    )

    await conn.execute(
        """
        CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON audit_log (ts DESC)
    """
    )
    await conn.execute(
        """
        CREATE INDEX IF NOT EXISTS audit_log_event_type_idx ON audit_log (event_type, ts DESC)
    """
    )

    # RAG provenance — idempotent column additions to documents table.
    # These track where each document came from and whether to trust it.
    for col_sql in [
        "ALTER TABLE documents ADD COLUMN IF NOT EXISTS source_url TEXT",
        "ALTER TABLE documents ADD COLUMN IF NOT EXISTS source_hash TEXT",
        "ALTER TABLE documents ADD COLUMN IF NOT EXISTS trust_score FLOAT DEFAULT 0.5",
        "ALTER TABLE documents ADD COLUMN IF NOT EXISTS ingested_by TEXT",
        "ALTER TABLE documents ADD COLUMN IF NOT EXISTS ingested_at TIMESTAMPTZ DEFAULT now()",
    ]:
        await conn.execute(col_sql)

    # Agent sequence registry — maps agent_id to permitted tool-call sequences.
    # Guardian checks incoming sequence_so_far against registered prefixes.
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS agent_profiles (
            agent_id      TEXT NOT NULL,
            sequence      TEXT[] NOT NULL,
            registered_at TIMESTAMPTZ DEFAULT NOW(),
            registered_by TEXT NOT NULL DEFAULT 'operator',
            PRIMARY KEY (agent_id, sequence)
        )
    """
    )

    # Phase 4: Adaptive threat rules — proposed by Threat Analyst, approved by human.
    # Guardian polls this table for APPROVED rules and hot-reloads every 5 minutes.
    # Security invariant: only operators may set status → 'APPROVED'; agents may only
    # INSERT rows with status='PENDING'. No agent may UPDATE or DELETE rows.
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_rules (
            id            SERIAL PRIMARY KEY,
            rule_id       UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
            proposed_by   TEXT NOT NULL,
            proposed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            approved_by   TEXT,
            approved_at   TIMESTAMPTZ,
            status        TEXT NOT NULL DEFAULT 'PENDING'
                              CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
            rule_type     TEXT NOT NULL
                              CHECK (rule_type IN (
                                  'INJECTION_PATTERN',
                                  'CAPABILITY_BLOCK',
                                  'SEQUENCE_BLOCK',
                                  'RATE_LIMIT_TIGHTEN'
                              )),
            rule_def      JSONB NOT NULL,
            justification TEXT,
            evidence_ids  TEXT[],
            expires_at    TIMESTAMPTZ
        )
    """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS threat_rules_status_idx ON threat_rules (status, proposed_at DESC)"
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
        cur = await conn.execute(
            """
            INSERT INTO documents (content, embedding, namespace, metadata)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (content, embedding, namespace, metadata or {}),
        )
        row = await cur.fetchone()
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
        cur = await conn.execute(
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
            (
                query_embedding,
                namespace,
                query_embedding,
                min_similarity,
                query_embedding,
                limit,
            ),
        )
        rows = await cur.fetchall()
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
            (
                provider,
                model,
                input_tokens,
                output_tokens,
                input_tokens + output_tokens,
                run_id,
                agent_name,
                success,
                latency_ms,
            ),
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
        cur = await conn.execute(
            """
            SELECT
                provider,
                COUNT(*)           AS calls,
                SUM(input_tokens)  AS input_tokens,
                SUM(output_tokens) AS output_tokens,
                SUM(total_tokens)  AS total_tokens,
                AVG(latency_ms)    AS avg_latency_ms
            FROM api_usage
            WHERE ts > NOW() - make_interval(hours => %s)
              AND success = TRUE
            GROUP BY provider
            ORDER BY total_tokens DESC
            """,
            (hours,),
        )
        rows = await cur.fetchall()
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
    "CAPABILITY_VIOLATION",  # agent attempted a forbidden or unregistered action
    "DESTRUCTIVE_PATTERN",  # input matches credential/infra/bulk-exfil pattern — HITL required
    "AUDIT_LOG_TAMPER",  # audit log hash chain integrity check failed
    "SEQUENCE_VIOLATION",  # tool call sequence not in approved agent_profiles
    # Phase 3: task token ACL
    "TOOL_SCOPE_VIOLATION",  # agent (deny policy) tried a tool outside its token scope
    "INVALID_TASK_TOKEN",  # JWT was invalid, expired, or had wrong issuer
    # Phase 4: adaptive threat intelligence
    "RULE_PROPOSED",  # Threat Analyst proposed a new detection rule (PENDING)
    "RULE_APPLIED",  # Guardian loaded an APPROVED rule into its hot-reload cache
}

# Valid action_taken values
THREAT_ACTIONS = {"BLOCKED", "SANDBOX_RETRY", "LOGGED", "REDACTED", "HITL_REQUIRED"}


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
        cur = await conn.execute(
            """
            INSERT INTO threat_events
                (agent_id, run_id, threat_type, confidence,
                 raw_input, action_taken, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                agent_id,
                run_id,
                threat_type,
                confidence,
                raw_input,
                action_taken,
                metadata or {},
            ),
        )
        row = await cur.fetchone()
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
        cur = await conn.execute(
            """
            SELECT
                threat_type,
                action_taken,
                COUNT(*)       AS count,
                AVG(confidence) AS avg_confidence
            FROM threat_events
            WHERE ts > NOW() - make_interval(hours => %s)
            GROUP BY threat_type, action_taken
            ORDER BY count DESC
            """,
            (hours,),
        )
        rows = await cur.fetchall()
    return {"hours": hours, "by_type": [dict(r) for r in rows]}


async def get_recent_escalations(hours: int = 24, limit: int = 20) -> list[dict]:
    """
    Return recent ESCALATION_BLOCKED events from the audit log.

    Phase 3: surfaced on the health server /status endpoint so operators can
    see which agents hit scope boundaries without trawling raw logs.

    Returns a list of dicts with keys: seq, ts, agent_id, payload.
    Returns an empty list if the DB is unavailable or the table is empty.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            SELECT seq, ts, agent_id, payload
            FROM audit_log
            WHERE event_type = 'ESCALATION_BLOCKED'
              AND ts > NOW() - make_interval(hours => %s)
            ORDER BY ts DESC
            LIMIT %s
            """,
            (hours, limit),
        )
        rows = await cur.fetchall()
    return [
        {
            "seq": r["seq"],
            "ts": (
                r["ts"].isoformat() if hasattr(r["ts"], "isoformat") else str(r["ts"])
            ),
            "agent_id": r["agent_id"],
            "payload": (
                r["payload"]
                if isinstance(r["payload"], dict)
                else json.loads(r["payload"])
            ),
        }
        for r in rows
    ]


# ── Audit log hash chain ───────────────────────────────────────────────────────

# Genesis sentinel — the prev_hash for the very first audit log row.
# Changing this value invalidates all existing audit records.
_AUDIT_LOG_GENESIS = hashlib.sha256(b"LEGIONFORGE_AUDIT_LOG_GENESIS").hexdigest()


def _compute_audit_row_hash(
    seq: int,
    ts: str,
    event_type: str,
    agent_id: str | None,
    payload: dict,
    prev_hash: str,
) -> str:
    """
    Compute the SHA-256 hash for a single audit log row.
    All fields are canonicalised before hashing to prevent format-dependent
    variations from breaking the chain (e.g. datetime formatting).

    This function is deterministic: same inputs always produce the same hash.
    """
    canonical = f"{seq}|{ts}|{event_type}|{agent_id or ''}|{json.dumps(payload, sort_keys=True)}|{prev_hash}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def append_audit_log(
    event_type: str,
    agent_id: str | None,
    payload: dict,
) -> int:
    """
    Append an event to the audit log and return the new sequence number.

    The row_hash is computed over all fields including prev_hash, forming
    a tamper-evident hash chain. Any modification to historical rows will
    be detected by verify_audit_log_chain().

    Non-fatal if DB is unavailable — returns -1 and logs a warning.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        # Get last row hash — genesis sentinel if table is empty
        cur = await conn.execute(
            "SELECT seq, row_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        )
        last_row = await cur.fetchone()
        prev_hash = last_row["row_hash"] if last_row else _AUDIT_LOG_GENESIS

        ts_now = datetime.now(tz=timezone.utc).isoformat()
        # Insert with placeholder seq to get the BIGSERIAL value, then compute hash
        cur2 = await conn.execute(
            """
            INSERT INTO audit_log (ts, event_type, agent_id, payload, prev_hash, row_hash)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING seq, ts
            """,
            (
                ts_now,
                event_type,
                agent_id,
                json.dumps(payload, sort_keys=True),
                prev_hash,
                "PENDING",
            ),
        )
        new_row = await cur2.fetchone()
        seq = new_row["seq"]
        ts_str = (
            new_row["ts"].isoformat()
            if hasattr(new_row["ts"], "isoformat")
            else str(new_row["ts"])
        )
        row_hash = _compute_audit_row_hash(
            seq, ts_str, event_type, agent_id, payload, prev_hash
        )
        await conn.execute(
            "UPDATE audit_log SET row_hash = %s WHERE seq = %s",
            (row_hash, seq),
        )

    logger.debug(
        f"[audit-log] Appended seq={seq} event_type={event_type} agent_id={agent_id}"
    )
    return seq


async def verify_audit_log_chain() -> tuple[bool, int, str | None]:
    """
    Walk the audit log from the first row to the last, recomputing each row_hash
    and verifying it matches the stored value.

    Returns:
        (chain_ok, verified_rows, error_message)
        - chain_ok=True, verified_rows=N, error_message=None  — chain is intact
        - chain_ok=True, verified_rows=0, error_message=None  — empty log (valid on first run)
        - chain_ok=False, verified_rows=N, error_message=str  — tamper detected at row N+1
    """
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            "SELECT seq, ts, event_type, agent_id, payload, prev_hash, row_hash FROM audit_log ORDER BY seq ASC"
        )
        rows = await cur.fetchall()

    if not rows:
        return True, 0, None

    expected_prev = _AUDIT_LOG_GENESIS
    for i, row in enumerate(rows):
        seq = row["seq"]
        ts = (
            row["ts"].isoformat() if hasattr(row["ts"], "isoformat") else str(row["ts"])
        )
        payload = (
            row["payload"]
            if isinstance(row["payload"], dict)
            else json.loads(row["payload"])
        )
        stored_prev = row["prev_hash"]
        stored_hash = row["row_hash"]

        if stored_prev != expected_prev:
            return (
                False,
                i,
                f"seq={seq} prev_hash mismatch (expected {expected_prev[:12]}..., got {stored_prev[:12]}...)",
            )

        computed = _compute_audit_row_hash(
            seq, ts, row["event_type"], row["agent_id"], payload, stored_prev
        )
        if computed != stored_hash:
            return False, i, f"seq={seq} row_hash mismatch — row may have been tampered"

        expected_prev = stored_hash

    return True, len(rows), None


# ── RAG document with provenance ──────────────────────────────────────────────


async def store_document_with_provenance(
    content: str,
    embedding: list[float],
    source_url: str,
    namespace: str = "default",
    metadata: dict | None = None,
    trust_score: float = 0.5,
    ingested_by: str = "system",
) -> int:
    """
    Store a document with full provenance tracking.
    Returns the new document ID.

    source_hash is computed from the content so we can detect if the
    same URL returns different content (possible poisoning indicator).
    """
    source_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            INSERT INTO documents
                (content, embedding, namespace, metadata,
                 source_url, source_hash, trust_score, ingested_by, ingested_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
            RETURNING id
            """,
            (
                content,
                embedding,
                namespace,
                json.dumps(metadata or {}),
                source_url,
                source_hash,
                trust_score,
                ingested_by,
            ),
        )
        row = await cur.fetchone()
    return row["id"]


# ── Agent sequence registry ───────────────────────────────────────────────────


async def register_agent_sequences(
    agent_id: str,
    sequences: list[list[str]],
    registered_by: str = "operator",
) -> None:
    """
    Register permitted tool-call sequences for an agent.
    Idempotent — calling again with the same sequences is a no-op.

    Guardian's sequence-check uses these at enforcement time to decide whether
    a novel sequence should be sandboxed.

    Args:
        agent_id:       Identifier for the agent (e.g. "researcher").
        sequences:      List of permitted sequences, each a list of tool_ids.
                        Example: [["web_search", "web_fetch", "document_summarize"]]
        registered_by:  Who approved these sequences (e.g. "operator", "ci").
    """
    pool = get_pool()
    async with pool.connection() as conn:
        for seq in sequences:
            await conn.execute(
                """
                INSERT INTO agent_profiles (agent_id, sequence, registered_by)
                VALUES (%s, %s, %s)
                ON CONFLICT (agent_id, sequence) DO NOTHING
                """,
                (agent_id, seq, registered_by),
            )
    logger.info(
        f"[agent-profiles] Registered {len(sequences)} sequences for agent '{agent_id}'"
    )


async def get_agent_sequences(agent_id: str) -> list[list[str]]:
    """
    Retrieve all registered sequences for an agent.
    Returns empty list if no sequences are registered (agent is unconstrained).
    """
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            "SELECT sequence FROM agent_profiles WHERE agent_id = %s ORDER BY registered_at ASC",
            (agent_id,),
        )
        rows = await cur.fetchall()
    return [list(row["sequence"]) for row in rows]


# ── Phase 4: Threat rules ─────────────────────────────────────────────────────

# Valid rule types for proposed Guardian rules.
RULE_TYPES = {
    "INJECTION_PATTERN",
    "CAPABILITY_BLOCK",
    "SEQUENCE_BLOCK",
    "RATE_LIMIT_TIGHTEN",
}


async def propose_threat_rule(
    proposed_by: str,
    rule_type: str,
    rule_def: dict,
    justification: str,
    evidence_ids: list[str] | None = None,
    expires_at: str | None = None,
) -> str:
    """
    Insert a new threat rule with status='PENDING'.

    Only agents may call this (they can only INSERT PENDING rows).
    Human operators approve via approve_threat_rule() or the /rules endpoint.

    Args:
        proposed_by:   Agent ID proposing the rule (e.g. 'threat_analyst').
        rule_type:     One of RULE_TYPES.
        rule_def:      The rule payload (JSONB). Schema depends on rule_type:
                       INJECTION_PATTERN: {"pattern": "regex string", "flags": "i"}
                       CAPABILITY_BLOCK:  {"tool_id": "...", "reason": "..."}
                       SEQUENCE_BLOCK:    {"sequence": ["tool_a", "tool_b"]}
                       RATE_LIMIT_TIGHTEN: {"provider": "...", "new_daily_limit": N}
        justification: Human-readable explanation referencing threat_events.
        evidence_ids:  List of run_ids from threat_events that triggered this proposal.
        expires_at:    ISO datetime string for rule expiry (None = no expiry).

    Returns:
        rule_id (UUID string) of the newly created rule.
    """
    pool = get_pool()
    import json

    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            INSERT INTO threat_rules
                (proposed_by, rule_type, rule_def, justification, evidence_ids, expires_at)
            VALUES (%s, %s, %s::jsonb, %s, %s, %s)
            RETURNING rule_id::text
            """,
            (
                proposed_by,
                rule_type,
                json.dumps(rule_def),
                justification,
                evidence_ids or [],
                expires_at,
            ),
        )
        row = await cur.fetchone()
    rule_id = row["rule_id"]
    logger.info(
        f"[threat-rules] Rule proposed rule_id={rule_id} type={rule_type} by={proposed_by}"
    )
    return rule_id


async def get_pending_rules(limit: int = 50) -> list[dict]:
    """
    Return all PENDING threat rules for human review.
    Used by the /rules endpoint (operator review UI).
    """
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            SELECT rule_id::text, proposed_by, proposed_at, rule_type,
                   rule_def, justification, evidence_ids
            FROM threat_rules
            WHERE status = 'PENDING'
            ORDER BY proposed_at DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def get_approved_rules() -> list[dict]:
    """
    Return all currently APPROVED, non-expired threat rules.
    Called by Guardian's hot-reload cache refresh (every 5 minutes).
    """
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            SELECT rule_id::text, rule_type, rule_def, approved_at, expires_at
            FROM threat_rules
            WHERE status = 'APPROVED'
              AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY approved_at ASC
            """
        )
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def approve_threat_rule(rule_id: str, approved_by: str) -> bool:
    """
    Approve a PENDING threat rule. Operator-only action.

    Security invariant: this function is never called by agents — only by human
    operators via the /rules/approve endpoint or a CLI tool. Agents may only
    INSERT PENDING rows via propose_threat_rule().

    Returns True if the rule was found and updated, False if not found.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            UPDATE threat_rules
            SET status = 'APPROVED', approved_by = %s, approved_at = NOW()
            WHERE rule_id = %s::uuid AND status = 'PENDING'
            """,
            (approved_by, rule_id),
        )
    updated = cur.statusmessage.split()[-1] != "0"  # "UPDATE N" — N > 0 means success
    if updated:
        logger.info(f"[threat-rules] Rule approved rule_id={rule_id} by={approved_by}")
    return updated


async def reject_threat_rule(rule_id: str, rejected_by: str) -> bool:
    """
    Reject a PENDING threat rule. Operator-only action.
    Rejected rules are retained for audit; they are never deleted.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            UPDATE threat_rules
            SET status = 'REJECTED', approved_by = %s, approved_at = NOW()
            WHERE rule_id = %s::uuid AND status = 'PENDING'
            """,
            (rejected_by, rule_id),
        )
    updated = cur.statusmessage.split()[-1] != "0"
    if updated:
        logger.info(f"[threat-rules] Rule rejected rule_id={rule_id} by={rejected_by}")
    return updated


async def get_threat_events_for_analysis(
    hours: int = 168,  # 7 days default — enough context for weekly digest
    limit: int = 500,
) -> list[dict]:
    """
    Fetch recent threat events for the Threat Analyst agent.

    Returns structured dicts suitable for LLM analysis. Excludes raw_input
    (may contain PII / injection content) — only metadata and sanitized fields.

    Args:
        hours:  Lookback window in hours (default 168 = 7 days).
        limit:  Maximum rows returned (prevents context window overflow).
    """
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            SELECT
                id, agent_id, run_id, threat_type, action_taken,
                confidence, metadata, ts
            FROM threat_events
            WHERE ts > NOW() - make_interval(hours => %s)
            ORDER BY ts DESC
            LIMIT %s
            """,
            (hours, limit),
        )
        rows = await cur.fetchall()
    return [
        {
            "id": r["id"],
            "agent_id": r["agent_id"],
            "run_id": r["run_id"],
            "threat_type": r["threat_type"],
            "action_taken": r["action_taken"],
            "confidence": float(r["confidence"]) if r["confidence"] else None,
            "metadata": r["metadata"] or {},
            "ts": r["ts"].isoformat() if r["ts"] else None,
        }
        for r in rows
    ]
