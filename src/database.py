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
import secrets
import string
import subprocess
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional

import psycopg
from psycopg import sql as pgsql
from psycopg_pool import AsyncConnectionPool
from psycopg.rows import dict_row
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from pgvector.psycopg import register_vector_async

from config.settings import settings

logger = logging.getLogger(__name__)

# ── Connection helpers ────────────────────────────────────────────────────────


def _get_postgres_password() -> str:
    """
    Return the PostgreSQL password.

    Priority order:
      1. CredentialStore in-memory cache (if initialized — no env access)
      2. POSTGRES_PASSWORD environment variable (legacy / Docker)

    Raises RuntimeError if not set anywhere.
    Never embed this value in a connection URI — pass as a keyword argument only.
    """
    # ── CredentialStore fast path ──────────────────────────────────────────
    try:
        from src.credentials import creds as _creds

        if _creds._initialized:
            pw = _creds.get("postgres")
            if pw:
                return pw
    except ImportError:
        pass

    # ── Environment variable fallback ─────────────────────────────────────
    password = os.environ.get("POSTGRES_PASSWORD", "")
    if not password:
        raise RuntimeError(
            "POSTGRES_PASSWORD not set. Store it with:\n"
            "  python -m keyring set postgres api_key\n"
            "Or: export POSTGRES_PASSWORD=<value>\n"
            "Or: initialize CredentialStore before calling init_db()."
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
    user = os.environ.get("POSTGRES_USER", os.environ.get("USER", "postgres"))
    return f"host={host} port={port} dbname={db} user={user}"


def _build_app_user_conninfo() -> str:
    """
    Build a PostgreSQL conninfo string for the restricted legionforge_app user.
    This user has no DDL, no DELETE on audit/threat tables — used for all
    runtime agent operations after Phase 1 schema setup is complete.
    """
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    db = os.environ.get("POSTGRES_DB", "legionforge")
    user = getattr(settings.security, "db_app_user", "legionforge_app")
    return f"host={host} port={port} dbname={db} user={user}"


def _get_or_generate_app_password() -> str:
    """
    Get the legionforge_app DB user password from CredentialStore / env,
    or generate a fresh one and store it in the macOS Keychain.

    Priority:
      1. CredentialStore in-memory cache (service "legionforge_db_app")
      2. POSTGRES_APP_PASSWORD environment variable
      3. Generate a random 32-char password, store in Keychain, log once

    The generated password is stored via the macOS `security` CLI (same
    pattern as _load_or_create_health_token in health.py). On non-macOS
    or if the CLI fails, the password is printed once to stderr — store it
    manually in your credentials YAML or Keychain.
    """
    service = getattr(
        settings.security, "db_app_password_service", "legionforge_db_app"
    )

    # 1. CredentialStore (only if initialized)
    try:
        from src.credentials import creds as _creds

        if _creds._initialized:
            pw = _creds.get(service)
            if pw:
                return pw
    except ImportError:
        pass

    # 2. Environment variable
    pw = os.environ.get("POSTGRES_APP_PASSWORD", "")
    if pw:
        return pw

    # 3. Generate and persist
    _safe = string.ascii_letters + string.digits + "_-+="
    pw = "".join(secrets.choice(_safe) for _ in range(32))

    # Try to store in macOS Keychain
    try:
        result = subprocess.run(
            [
                "security",
                "add-generic-password",
                "-s",
                service,
                "-a",
                "api_key",
                "-w",
                pw,
                "-U",  # Update if exists
            ],
            capture_output=True,
            timeout=5,
        )
        if result.returncode == 0:
            logger.info(
                f"[db-rbac] Generated legionforge_app password and stored in Keychain "
                f"(service={service!r}). Retrieve with: make setup-db-roles"
            )
        else:
            logger.warning(
                f"[db-rbac] Generated legionforge_app password but could not store in Keychain: "
                f"{result.stderr.decode(errors='replace').strip()}\n"
                f"  Store manually: security add-generic-password -s {service} -a api_key -w '<pw>' -U"
            )
    except Exception as exc:
        logger.warning(
            f"[db-rbac] Generated legionforge_app password but could not store in Keychain: {exc}\n"
            f"  Store manually: security add-generic-password -s {service} -a api_key -w '<pw>' -U"
        )

    return pw


async def _setup_db_roles(admin_conn: psycopg.AsyncConnection) -> None:
    """
    Create the legionforge_app restricted PostgreSQL user and grant minimal privileges.

    Idempotent — safe to run on every startup. Runs as the admin user (POSTGRES_USER).

    Privilege model:
      - CONNECT on database legionforge
      - SELECT on ALL tables (read access for agents)
      - INSERT only on audit_log and threat_events (append-only audit trail)
      - INSERT + UPDATE on mutable app tables (no DELETE, no DDL)
      - Full CRUD on LangGraph checkpoint tables (required by LangGraph internals)
      - USAGE on all sequences (for BIGSERIAL PKs)
    """
    app_user = getattr(settings.security, "db_app_user", "legionforge_app")
    app_pw = _get_or_generate_app_password()
    db_name = os.environ.get("POSTGRES_DB", "legionforge")

    # Create user if not exists (idempotent via DO block)
    # We use psycopg sql module to safely format identifiers and literals.
    await admin_conn.execute(
        pgsql.SQL(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = {user}) THEN
                    CREATE USER {user_id} WITH LOGIN NOINHERIT;
                END IF;
            END
            $$;
            """
        ).format(
            user=pgsql.Literal(app_user),
            user_id=pgsql.Identifier(app_user),
        )
    )

    # Always update the password (idempotent, ensures rotation works)
    await admin_conn.execute(
        pgsql.SQL("ALTER USER {user_id} WITH PASSWORD {pw}").format(
            user_id=pgsql.Identifier(app_user),
            pw=pgsql.Literal(app_pw),
        )
    )

    # CONNECT on the database
    await admin_conn.execute(
        pgsql.SQL("GRANT CONNECT ON DATABASE {db} TO {user_id}").format(
            db=pgsql.Identifier(db_name),
            user_id=pgsql.Identifier(app_user),
        )
    )

    # USAGE on schema
    await admin_conn.execute(
        pgsql.SQL("GRANT USAGE ON SCHEMA public TO {user_id}").format(
            user_id=pgsql.Identifier(app_user),
        )
    )

    # SELECT on all tables
    await admin_conn.execute(
        pgsql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA public TO {user_id}").format(
            user_id=pgsql.Identifier(app_user),
        )
    )

    # Append-only audit tables — INSERT only, no UPDATE/DELETE
    await admin_conn.execute(
        pgsql.SQL("GRANT INSERT ON audit_log, threat_events TO {user_id}").format(
            user_id=pgsql.Identifier(app_user),
        )
    )

    # Mutable app tables — INSERT + UPDATE, no DELETE, no DDL
    for tbl in [
        "api_usage",
        "health_metrics",
        "documents",
        "crystallization_candidates",
        "crystallization_packages",
        "crystallization_analyses",
        "threat_rules",
        "agent_profiles",
        "tool_registry",
        "tasks",  # Phase 8: gateway task queue
        "gateway_users",  # Phase 8: gateway users
        "stream_tokens",  # Phase 10: DB-backed SSE stream tokens
    ]:
        try:
            await admin_conn.execute(
                pgsql.SQL("GRANT INSERT, UPDATE ON {tbl} TO {user_id}").format(
                    tbl=pgsql.Identifier(tbl),
                    user_id=pgsql.Identifier(app_user),
                )
            )
        except Exception as e:
            # Table might not exist yet on very first run — non-fatal
            logger.debug(f"[db-rbac] GRANT on {tbl!r} skipped: {e}")

    # stream_tokens also needs DELETE (purge removes expired rows)
    try:
        await admin_conn.execute(
            pgsql.SQL("GRANT DELETE ON stream_tokens TO {user_id}").format(
                user_id=pgsql.Identifier(app_user),
            )
        )
    except Exception as e:
        logger.debug(f"[db-rbac] GRANT DELETE on stream_tokens skipped: {e}")

    # LangGraph checkpoint tables — full CRUD required by LangGraph internals
    for tbl in [
        "checkpoint_migrations",
        "checkpoints",
        "checkpoint_blobs",
        "checkpoint_writes",
    ]:
        try:
            await admin_conn.execute(
                pgsql.SQL(
                    "GRANT SELECT, INSERT, UPDATE, DELETE ON {tbl} TO {user_id}"
                ).format(
                    tbl=pgsql.Identifier(tbl),
                    user_id=pgsql.Identifier(app_user),
                )
            )
        except Exception as e:
            logger.debug(f"[db-rbac] GRANT on {tbl!r} skipped: {e}")

    # USAGE on all sequences (for BIGSERIAL primary keys)
    await admin_conn.execute(
        pgsql.SQL("GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {user_id}").format(
            user_id=pgsql.Identifier(app_user),
        )
    )

    logger.info(
        f"[db-rbac] Role setup complete for '{app_user}': "
        "SELECT all, INSERT on audit/threat, INSERT+UPDATE on app tables, "
        "full CRUD on checkpoint tables"
    )


# ── Connection pool (module-level singleton) ──────────────────────────────────

_pool: Optional[AsyncConnectionPool] = None


async def init_db() -> None:
    """
    Two-phase database initialization with privilege separation.

    Phase 1 (admin):  Create extensions, LangGraph checkpoint tables, app tables,
                      and the restricted legionforge_app role via _setup_db_roles().
    Phase 2 (app):    Initialize _pool with the restricted legionforge_app user —
                      no DDL, no DELETE on audit tables, no superuser privileges.

    This ensures all runtime agent operations run under the least-privilege DB user.
    Admin credentials are only held during startup schema setup, then discarded.
    """
    global _pool

    # ── Initialize CredentialStore before first secret access ──────────────
    # This loads all credentials into memory once. After this point, no code
    # path in the framework needs to access the Keychain or spawn the
    # `security` CLI subprocess.
    try:
        from src.credentials import creds as _creds

        if not _creds._initialized:
            _creds.initialize(settings.security)
    except ImportError:
        logger.debug("CredentialStore not available — using legacy key access")
    except Exception as exc:
        logger.warning(f"CredentialStore initialization failed: {exc} — continuing")

    # ── Phase 1: Admin pool — schema creation + role setup ─────────────────
    admin_conninfo = _build_conninfo_no_password()
    admin_password = _get_postgres_password()

    logger.info("[db-init] Phase 1: Admin pool — creating schema and roles...")
    admin_pool = AsyncConnectionPool(
        conninfo=admin_conninfo,
        min_size=1,
        max_size=3,  # Small — only used during startup
        kwargs={
            "password": admin_password,
            "row_factory": dict_row,
            "autocommit": True,
        },
    )
    try:
        await admin_pool.wait()

        # Enable pgvector extension (requires superuser)
        async with admin_pool.connection() as conn:
            await conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
            await conn.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
            await register_vector_async(conn)
            logger.info("[db-init] Extensions verified (vector, pg_trgm)")

        # Set up LangGraph checkpoint tables (requires admin / DDL rights)
        admin_checkpointer = AsyncPostgresSaver(admin_pool)
        await admin_checkpointer.setup()
        logger.info("[db-init] LangGraph checkpoint tables verified")

        # Create application tables
        async with admin_pool.connection() as conn:
            await _create_app_tables(conn)

        # Create restricted app role + grant minimal privileges (idempotent)
        async with admin_pool.connection() as conn:
            await _setup_db_roles(conn)

    finally:
        await admin_pool.close()
        logger.info("[db-init] Phase 1 complete — admin pool closed")

    # ── Phase 2: Restricted app pool ────────────────────────────────────────
    # From this point on, ALL database access uses the legionforge_app user:
    # no DDL, no DELETE on audit/threat tables, no superuser privileges.
    logger.info("[db-init] Phase 2: Initializing restricted app user pool...")
    try:
        app_conninfo = _build_app_user_conninfo()
        app_password = _get_or_generate_app_password()
        _pool = AsyncConnectionPool(
            conninfo=app_conninfo,
            min_size=1,
            max_size=10,
            kwargs={
                "password": app_password,
                "row_factory": dict_row,
                "autocommit": True,
            },
        )
        await _pool.wait()
        logger.info(
            f"[db-init] App pool initialized (user={getattr(settings.security, 'db_app_user', 'legionforge_app')!r})"
        )
    except Exception as pool_err:
        # If app user pool fails (e.g., legionforge_app doesn't exist on this DB),
        # fall back to the admin pool for backward compatibility.
        logger.warning(
            f"[db-init] Could not connect as restricted app user: {pool_err}. "
            "Falling back to admin user — run 'make setup-db-roles' to create the role."
        )
        _pool = AsyncConnectionPool(
            conninfo=admin_conninfo,
            min_size=1,
            max_size=10,
            kwargs={
                "password": admin_password,
                "row_factory": dict_row,
                "autocommit": True,
            },
        )
        await _pool.wait()

    # Verify audit log chain integrity. An empty chain is valid on first run.
    # A broken chain (verified_rows > 0 + hash mismatch) means tamper — halt.
    # Continuing with a tampered audit log would make all subsequent forensic
    # data unreliable and could mask an active intrusion.
    chain_ok, verified_rows, error_msg = await verify_audit_log_chain()
    if not chain_ok and verified_rows > 0:
        logger.critical(
            f"[audit-log] Chain integrity check FAILED at row {verified_rows}: {error_msg}. "
            "Audit log has been tampered with — halting startup to protect forensic integrity."
        )
        try:
            await log_threat_event(
                agent_id="database",
                run_id="startup",
                threat_type="AUDIT_LOG_TAMPER",
                action_taken="BLOCKED",
                confidence=1.0,
                raw_input=error_msg[:200] if error_msg else None,
                metadata={"verified_rows": verified_rows},
            )
        except Exception:
            pass
        raise RuntimeError(
            f"[audit-log] AUDIT LOG TAMPER DETECTED at row {verified_rows}: {error_msg}. "
            "Startup halted. Investigate the audit_log table before restarting."
        )
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

    # Phase 5: Crystallization pipeline — Observer → Crystallizer → Pre-HITL Analyzer → HITL.
    # Converts repeated AI tool calls into signed, deterministic artifacts.
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS crystallization_candidates (
            id                    BIGSERIAL PRIMARY KEY,
            candidate_id          TEXT UNIQUE NOT NULL,
            operation_name        TEXT NOT NULL,
            observed_count        INTEGER NOT NULL DEFAULT 0,
            first_seen            TIMESTAMPTZ,
            last_seen             TIMESTAMPTZ,
            example_inputs        JSONB NOT NULL DEFAULT '[]',
            example_outputs       JSONB NOT NULL DEFAULT '[]',
            input_schema          JSONB NOT NULL DEFAULT '{}',
            output_schema         JSONB NOT NULL DEFAULT '{}',
            token_cost_total      INTEGER NOT NULL DEFAULT 0,
            estimated_savings_pct FLOAT NOT NULL DEFAULT 0.0,
            reasoning             TEXT,
            disqualifying_factors JSONB NOT NULL DEFAULT '[]',
            status                TEXT NOT NULL DEFAULT 'NOMINATED'
                                      CHECK (status IN (
                                          'NOMINATED', 'IN_PROGRESS',
                                          'PACKAGED', 'REJECTED'
                                      )),
            nominated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
            nominated_by          TEXT NOT NULL DEFAULT 'observer_agent'
        )
    """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS cryst_candidates_status_idx "
        "ON crystallization_candidates (status, nominated_at DESC)"
    )

    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS crystallization_packages (
            id                    BIGSERIAL PRIMARY KEY,
            package_id            TEXT UNIQUE NOT NULL,
            candidate_id          TEXT REFERENCES crystallization_candidates(candidate_id),
            tool_name             TEXT NOT NULL,
            tool_description      TEXT,
            function_code         TEXT NOT NULL,
            function_signature    TEXT,
            input_schema          JSONB NOT NULL DEFAULT '{}',
            output_schema         JSONB NOT NULL DEFAULT '{}',
            declared_side_effects JSONB NOT NULL DEFAULT '["pure"]',
            test_cases            JSONB NOT NULL DEFAULT '[]',
            edge_cases            JSONB NOT NULL DEFAULT '[]',
            adversarial_cases     JSONB NOT NULL DEFAULT '[]',
            confidence_score      FLOAT NOT NULL DEFAULT 0.0,
            known_limitations     JSONB NOT NULL DEFAULT '[]',
            suggested_fallback    TEXT,
            status                TEXT NOT NULL DEFAULT 'PENDING_ANALYSIS'
                                      CHECK (status IN (
                                          'PENDING_ANALYSIS', 'READY_FOR_REVIEW',
                                          'REJECTED_BY_ANALYSIS', 'APPROVED', 'REJECTED'
                                      )),
            revision_notes        TEXT,
            created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS cryst_packages_status_idx "
        "ON crystallization_packages (status, created_at DESC)"
    )

    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS crystallization_analyses (
            id                       BIGSERIAL PRIMARY KEY,
            package_id               TEXT NOT NULL REFERENCES crystallization_packages(package_id),
            analyzed_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
            forbidden_constructs     JSONB NOT NULL DEFAULT '[]',
            undeclared_dependencies  JSONB NOT NULL DEFAULT '[]',
            undeclared_side_effects  JSONB NOT NULL DEFAULT '[]',
            cyclomatic_complexity    INTEGER,
            lines_of_code            INTEGER,
            test_cases_passed        INTEGER NOT NULL DEFAULT 0,
            test_cases_failed        INTEGER NOT NULL DEFAULT 0,
            failed_case_diffs        JSONB NOT NULL DEFAULT '[]',
            ai_equivalence_rate      FLOAT NOT NULL DEFAULT 0.0,
            adversarial_exceptions   JSONB NOT NULL DEFAULT '[]',
            security_clean           BOOLEAN NOT NULL DEFAULT FALSE,
            security_findings        JSONB NOT NULL DEFAULT '[]',
            recommendation           TEXT,
            recommendation_reasoning TEXT,
            estimated_daily_savings  INTEGER NOT NULL DEFAULT 0,
            risk_flags               JSONB NOT NULL DEFAULT '[]',
            status                   TEXT NOT NULL
                                         CHECK (status IN (
                                             'READY_FOR_REVIEW', 'REJECTED_BY_ANALYSIS'
                                         ))
        )
    """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS cryst_analyses_pkg_idx "
        "ON crystallization_analyses (package_id, analyzed_at DESC)"
    )

    # Phase 5: extend tool_registry with Ed25519 signature columns (idempotent).
    await conn.execute(
        "ALTER TABLE tool_registry ADD COLUMN IF NOT EXISTS signature TEXT"
    )
    await conn.execute(
        "ALTER TABLE tool_registry ADD COLUMN IF NOT EXISTS public_key_fingerprint TEXT"
    )
    await conn.execute(
        "ALTER TABLE tool_registry ADD COLUMN IF NOT EXISTS signed_at TIMESTAMPTZ"
    )

    # Phase 6: extend tool_registry with revocation columns (idempotent).
    # Adds REVOKED status support — Guardian checks this cache and halts revoked tools.
    await conn.execute(
        "ALTER TABLE tool_registry ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ"
    )
    await conn.execute(
        "ALTER TABLE tool_registry ADD COLUMN IF NOT EXISTS revoked_by TEXT"
    )
    await conn.execute(
        "ALTER TABLE tool_registry ADD COLUMN IF NOT EXISTS revocation_reason TEXT"
    )

    # Phase 6: PentestAgent — air-gapped red-team run tracking
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pentest_runs (
            run_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            started_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            finished_at TIMESTAMPTZ,
            mode        TEXT NOT NULL DEFAULT 'verify',
            git_ref     TEXT,
            summary     JSONB,
            status      TEXT NOT NULL DEFAULT 'running'
                            CHECK (status IN ('running','complete','error'))
        )
    """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS pentest_runs_started_idx "
        "ON pentest_runs (started_at DESC)"
    )

    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pentest_findings (
            id              BIGSERIAL PRIMARY KEY,
            run_id          UUID NOT NULL REFERENCES pentest_runs(run_id),
            attack_class    TEXT NOT NULL,
            variant         TEXT NOT NULL,
            severity        TEXT NOT NULL
                                CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','PASS')),
            defense_held    BOOLEAN NOT NULL,
            detail          TEXT,
            payload         TEXT,
            logged_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS pentest_findings_run_idx "
        "ON pentest_findings (run_id, logged_at DESC)"
    )

    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pentest_proposed_rules (
            id              BIGSERIAL PRIMARY KEY,
            run_id          UUID NOT NULL REFERENCES pentest_runs(run_id),
            finding_id      BIGINT REFERENCES pentest_findings(id),
            rule_type       TEXT NOT NULL
                                CHECK (rule_type IN ('REGEX','CAPABILITY','RATE_LIMIT')),
            rule_content    TEXT NOT NULL,
            rationale       TEXT,
            status          TEXT NOT NULL DEFAULT 'PROPOSED'
                                CHECK (status IN ('PROPOSED','APPROVED','REJECTED')),
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """
    )

    # ── Phase 8: Gateway task queue ───────────────────────────────────────────
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tasks (
            task_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id         TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'queued'
                                CHECK (status IN ('queued','running','complete','failed','cancelled')),
            agent_type      TEXT NOT NULL DEFAULT 'orchestrator'
                                CHECK (agent_type IN ('orchestrator','researcher','base_agent')),
            input           TEXT NOT NULL,
            result          TEXT,
            error           TEXT,
            config          JSONB NOT NULL DEFAULT '{}',
            run_id          UUID,
            steps           INTEGER,
            tokens          JSONB,
            stream_events   JSONB NOT NULL DEFAULT '[]',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            completed_at    TIMESTAMPTZ
        )
        """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tasks_user_id    ON tasks (user_id)"
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tasks_status     ON tasks (status)"
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks (created_at DESC)"
    )

    # ── Phase 8: Gateway users ────────────────────────────────────────────────
    # user_id is TEXT (not UUID) so OAuth backends can use "oidc:sub", "github:id",
    # "kerberos:principal", etc. as natural identifiers.  API-key users still get
    # a UUID-formatted string via DEFAULT gen_random_uuid()::text.
    # api_key_hash has no UNIQUE constraint because multiple OAuth users share the
    # same [OAUTH-NO-KEY] sentinel; bcrypt hashes are cryptographically unique.
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS gateway_users (
            user_id         TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            username        TEXT NOT NULL UNIQUE,
            api_key_hash    TEXT NOT NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            is_active       BOOLEAN NOT NULL DEFAULT true
        )
        """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_gateway_users_username ON gateway_users (username)"
    )

    # ── Phase 10: Multi-user schema additions (idempotent) ────────────────────

    # Per-user daily token budget.  Default 100k; overridable per-user via CLI.
    await conn.execute(
        "ALTER TABLE gateway_users "
        "ADD COLUMN IF NOT EXISTS daily_token_limit INTEGER NOT NULL DEFAULT 100000"
    )

    # Estimated token cost recorded at submission time for in-flight TOCTOU safety.
    await conn.execute(
        "ALTER TABLE tasks "
        "ADD COLUMN IF NOT EXISTS estimated_tokens INTEGER NOT NULL DEFAULT 0"
    )

    # User attribution on api_usage — written by the worker after task completion.
    await conn.execute("ALTER TABLE api_usage ADD COLUMN IF NOT EXISTS user_id TEXT")
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_api_usage_user_id ON api_usage (user_id)"
    )

    # ── Phase 13 migration: gateway_users schema corrections ─────────────────
    # Migrate user_id from UUID → TEXT so OAuth backends can store natural IDs
    # like "kerberos:principal", "oidc:sub", "github:id".  Idempotent: postgres
    # ALTER TYPE TEXT on a TEXT column is a no-op.
    await conn.execute(
        "ALTER TABLE gateway_users ALTER COLUMN user_id TYPE TEXT USING user_id::text"
    )
    await conn.execute(
        "ALTER TABLE gateway_users ALTER COLUMN user_id "
        "SET DEFAULT gen_random_uuid()::text"
    )
    # Drop the UNIQUE constraint on api_key_hash.  Multiple OAuth users share the
    # [OAUTH-NO-KEY] sentinel so the constraint would fire on the second OAuth user.
    # bcrypt hashes are cryptographically unique — no DB constraint needed.
    await conn.execute(
        "ALTER TABLE gateway_users "
        "DROP CONSTRAINT IF EXISTS gateway_users_api_key_hash_key"
    )

    # ── Phase 24 migration: add is_admin flag ─────────────────────────────────
    await conn.execute(
        "ALTER TABLE gateway_users "
        "ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT false"
    )

    # ── Phase 26 migration: task completion webhooks ───────────────────────────
    # Optional callback URL: when set, the worker POSTs the result JSON to this
    # URL after the task completes (success or failure).
    await conn.execute("ALTER TABLE tasks ADD COLUMN IF NOT EXISTS callback_url TEXT")

    # Stream tokens — DB-backed so they survive gateway restarts.
    # Low-volume (one row per active SSE session); purged by the worker heartbeat.
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS stream_tokens (
            token       TEXT PRIMARY KEY,
            task_id     TEXT NOT NULL,
            user_id     TEXT NOT NULL,
            expires_at  TIMESTAMPTZ NOT NULL
        )
        """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_stream_tokens_expires "
        "ON stream_tokens (expires_at)"
    )

    # ── Phase 23: Scheduled tasks ─────────────────────────────────────────────
    # cron_expr accepts 5-field cron ("*/15 * * * *"), @shortcuts (@daily), or
    # @every intervals (@every 5m).  Validated by src.scheduler.validate_cron_expr.
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scheduled_tasks (
            id              SERIAL PRIMARY KEY,
            user_id         TEXT NOT NULL,
            name            TEXT NOT NULL,
            task_text       TEXT NOT NULL,
            agent_type      TEXT NOT NULL DEFAULT 'orchestrator',
            cron_expr       TEXT NOT NULL,
            next_run_at     TIMESTAMPTZ NOT NULL,
            last_run_at     TIMESTAMPTZ,
            last_task_id    TEXT,
            enabled         BOOLEAN NOT NULL DEFAULT true,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_sched_tasks_user "
        "ON scheduled_tasks (user_id)"
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_sched_tasks_next_run "
        "ON scheduled_tasks (next_run_at) WHERE enabled = true"
    )

    # ── Phase 27: Task Pipelines ───────────────────────────────────────────────
    # A pipeline is a reusable sequence of steps.  Each step is a task with
    # a task_text template that can reference the initial input ({{input}}) or
    # results of earlier steps ({{step_0.result}}, {{step_1.result}}, …).
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pipelines (
            id          SERIAL PRIMARY KEY,
            user_id     TEXT NOT NULL,
            name        TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            steps       JSONB NOT NULL DEFAULT '[]',
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_pipelines_user " "ON pipelines (user_id)"
    )

    # A pipeline_run tracks one execution of a pipeline.
    # step_results is a JSON array of step outcome dicts written as each
    # step finishes; current_step advances after each step completes.
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pipeline_runs (
            id              SERIAL PRIMARY KEY,
            pipeline_id     INTEGER NOT NULL,
            user_id         TEXT NOT NULL,
            initial_input   TEXT NOT NULL DEFAULT '',
            status          TEXT NOT NULL DEFAULT 'running'
                                CHECK (status IN ('running','complete','failed','cancelled')),
            current_step    INTEGER NOT NULL DEFAULT 0,
            step_results    JSONB NOT NULL DEFAULT '[]',
            started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            completed_at    TIMESTAMPTZ
        )
        """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_pipeline_runs_pipeline "
        "ON pipeline_runs (pipeline_id)"
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_pipeline_runs_user "
        "ON pipeline_runs (user_id)"
    )

    # ── Phase 31: Task tags ────────────────────────────────────────────────────
    # Freeform string tags for filtering and organisation.  Stored as a
    # PostgreSQL TEXT[] so containment queries (@>) use the GIN index.
    await conn.execute(
        "ALTER TABLE tasks ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}'"
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tasks_tags ON tasks USING GIN (tags)"
    )

    # ── Phase 28: Task priority queue ─────────────────────────────────────────
    # priority: 1=low … 5=normal … 10=high.  Worker picks highest priority first,
    # then oldest-first within equal priority (FIFO within tier).
    await conn.execute(
        "ALTER TABLE tasks ADD COLUMN IF NOT EXISTS "
        "priority SMALLINT NOT NULL DEFAULT 5"
    )
    # Composite index: worker scans (status='queued') ordered by (priority DESC, created_at ASC)
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tasks_priority_queue "
        "ON tasks (status, priority DESC, created_at ASC)"
    )

    # ── Phase 29: Task result cache ────────────────────────────────────────────
    # SHA-256 of (agent_type + ":" + input_text).  Stored on every task;
    # lookup_cached_task() queries for a recent completed task with the same hash.
    await conn.execute("ALTER TABLE tasks ADD COLUMN IF NOT EXISTS content_hash TEXT")
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tasks_content_hash "
        "ON tasks (content_hash) WHERE status = 'complete'"
    )

    # ── Phase 32: Task notes ───────────────────────────────────────────────────
    # Users can attach freeform text notes to any of their tasks after submission.
    # Notes are append-only by default; individual notes can be deleted.
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS task_notes (
            id          SERIAL PRIMARY KEY,
            task_id     UUID NOT NULL REFERENCES tasks (task_id) ON DELETE CASCADE,
            user_id     TEXT NOT NULL,
            note        TEXT NOT NULL,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_task_notes_task_id ON task_notes (task_id)"
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_task_notes_user_id ON task_notes (user_id)"
    )

    # ── Phase 34: Task dependencies ────────────────────────────────────────────
    # A task may optionally depend on another task completing first.
    # Worker skips tasks whose dependency is not yet complete.
    # ON DELETE SET NULL: if the dependency task is deleted, the dependent task
    # becomes unconstrained and is immediately eligible for execution.
    await conn.execute(
        "ALTER TABLE tasks ADD COLUMN IF NOT EXISTS "
        "depends_on UUID REFERENCES tasks (task_id) ON DELETE SET NULL"
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tasks_depends_on ON tasks (depends_on) "
        "WHERE depends_on IS NOT NULL"
    )

    # ── Phase 39: Task Timeline ─────────────────────────────────────────────────
    # Lightweight event log: one row per state transition per task.
    # event_type is a short string: 'queued', 'running', 'complete', 'failed',
    # 'cancelled', 'dependency_failed', etc.
    # metadata is a JSONB blob for type-specific detail (run_id, error, steps…).
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS task_events (
            id          BIGSERIAL PRIMARY KEY,
            task_id     UUID NOT NULL REFERENCES tasks (task_id) ON DELETE CASCADE,
            event_type  TEXT NOT NULL,
            metadata    JSONB NOT NULL DEFAULT '{}',
            ts          TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_task_events_task_id "
        "ON task_events (task_id, ts ASC)"
    )

    # ── Phase 40: Task Labels ───────────────────────────────────────────────────
    # Fixed-set system labels (bookmarked, starred, important, archived) stored
    # as TEXT[] with a GIN index — same pattern as tags (Phase 31).
    await conn.execute(
        "ALTER TABLE tasks ADD COLUMN IF NOT EXISTS "
        "labels TEXT[] NOT NULL DEFAULT '{}'"
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tasks_labels ON tasks USING GIN (labels)"
    )

    # ── Phase 45: Full-Text Search ──────────────────────────────────────────────
    # Generated TSVECTOR column (stored, auto-updated on INSERT/UPDATE).
    # Requires PostgreSQL 12+ (available since PG12 GA).
    # ADD COLUMN IF NOT EXISTS silently skips if already present.
    await conn.execute(
        """
        ALTER TABLE tasks
        ADD COLUMN IF NOT EXISTS search_vector TSVECTOR
            GENERATED ALWAYS AS (to_tsvector('english', COALESCE(input, ''))) STORED
        """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tasks_fts ON tasks USING GIN (search_vector)"
    )

    # ── Phase 48: Webhook Registry ───────────────────────────────────────────────
    # Persistent webhook subscriptions per user.  The worker fires these alongside
    # the per-task callback_url (Phase 26) on task complete / failed events.
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS webhooks (
            webhook_id  TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            user_id     TEXT NOT NULL REFERENCES gateway_users(user_id) ON DELETE CASCADE,
            url         TEXT NOT NULL,
            events      TEXT[] NOT NULL DEFAULT '{task_complete,task_failed}',
            secret      TEXT,
            is_active   BOOLEAN NOT NULL DEFAULT true,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_webhooks_user_id ON webhooks (user_id)"
    )

    # ── Phase 49: Task Attachments ───────────────────────────────────────────────
    # Small text blobs (code snippets, file excerpts, structured context) attached
    # to a task.  Max 64 KB per attachment enforced at the API layer.
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS task_attachments (
            attachment_id   TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            task_id         UUID NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
            user_id         TEXT NOT NULL,
            filename        TEXT NOT NULL,
            content_type    TEXT NOT NULL DEFAULT 'text/plain',
            data            TEXT NOT NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_task_attachments_task_id "
        "ON task_attachments (task_id)"
    )

    # ── Phase 50: Task Templates ─────────────────────────────────────────────────
    # Reusable task configurations.  Expanding {var} placeholders in input_template
    # is handled at the API layer (no DB-level string interpolation).
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS task_templates (
            template_id     TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            user_id         TEXT NOT NULL REFERENCES gateway_users(user_id) ON DELETE CASCADE,
            name            TEXT NOT NULL,
            description     TEXT,
            agent_type      TEXT NOT NULL DEFAULT 'base_agent',
            input_template  TEXT NOT NULL,
            default_tags    TEXT[] NOT NULL DEFAULT '{}',
            default_priority INTEGER NOT NULL DEFAULT 5,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (user_id, name)
        )
        """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_task_templates_user_id "
        "ON task_templates (user_id)"
    )

    # ── Phase 51: Task Sharing ────────────────────────────────────────────────────
    # Read-only share tokens for publicly accessible task results.
    # Tokens expire after expires_at (NULL = never expires).
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS task_shares (
            share_token TEXT PRIMARY KEY,
            task_id     UUID NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
            user_id     TEXT NOT NULL,
            expires_at  TIMESTAMPTZ,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_task_shares_task_id ON task_shares (task_id)"
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
    user_id: str | None = None,
) -> None:
    """Record an API call for rate limiting and cost tracking."""
    pool = get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            """
            INSERT INTO api_usage
                (provider, model, input_tokens, output_tokens,
                 total_tokens, run_id, agent_name, success, latency_ms, user_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                user_id,
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
    # Phase 5: crystallization pipeline
    "TOOL_SIGNATURE_MISMATCH",  # Ed25519 signature on a registered tool is invalid
    "TOOL_CRYSTALLIZED",  # crystallized tool approved, signed, and registered
    # Phase 6: comprehensive hardening
    "TOOL_REVOKED",  # tool is in REVOKED status — Guardian halts the call
    "TOOL_RESULT_INJECTION",  # injection pattern detected in a tool's return value
    "MODEL_INTEGRITY_MISMATCH",  # GGUF file SHA256 does not match pinned hash
    # Phase 6: PentestAgent bypass events — logged when a defense is defeated
    "PENTEST_INJECTION_BYPASS",  # prompt injection slipped past detect_injection()
    "PENTEST_RAG_POISONING_BYPASS",  # poisoned doc reached agent context
    "PENTEST_TOOL_POISONING_BYPASS",  # tampered tool hash not caught pre-invocation
    "PENTEST_RESOURCE_BOMB_BYPASS",  # preflight budget or rate limiter not triggered
    "PENTEST_PRIVILEGE_ESCALATION_BYPASS",  # child token exceeded parent scope
    "PENTEST_CRYSTALLIZATION_BYPASS",  # forbidden AST construct passed the analyzer
    "TOOL_ARG_INJECTION",  # injection pattern in LLM-generated tool call args (Phase 8)
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


# ── Phase 5: Crystallization pipeline CRUD ────────────────────────────────────


# Candidate status values — enforced by CHECK constraint in the DB.
CANDIDATE_STATUSES = {"NOMINATED", "IN_PROGRESS", "PACKAGED", "REJECTED"}

# Package status values
PACKAGE_STATUSES = {
    "PENDING_ANALYSIS",
    "READY_FOR_REVIEW",
    "REJECTED_BY_ANALYSIS",
    "APPROVED",
    "REJECTED",
}


async def nominate_candidate(
    candidate_id: str,
    operation_name: str,
    observed_count: int,
    example_inputs: list,
    example_outputs: list,
    input_schema: dict,
    output_schema: dict,
    token_cost_total: int,
    estimated_savings_pct: float,
    reasoning: str,
    disqualifying_factors: list,
    nominated_by: str = "observer_agent",
) -> str | None:
    """
    Write a crystallization candidate nominated by the Observer agent.
    Idempotent — re-nominating the same candidate_id updates observed_count.

    Returns:
        candidate_id on success, None if DB unavailable.
    """
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            await conn.execute(
                """
                INSERT INTO crystallization_candidates
                    (candidate_id, operation_name, observed_count,
                     example_inputs, example_outputs, input_schema, output_schema,
                     token_cost_total, estimated_savings_pct,
                     reasoning, disqualifying_factors, nominated_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (candidate_id) DO UPDATE
                    SET observed_count        = EXCLUDED.observed_count,
                        last_seen             = now(),
                        reasoning             = EXCLUDED.reasoning,
                        disqualifying_factors = EXCLUDED.disqualifying_factors
                """,
                (
                    candidate_id,
                    operation_name,
                    observed_count,
                    json.dumps(example_inputs),
                    json.dumps(example_outputs),
                    json.dumps(input_schema),
                    json.dumps(output_schema),
                    token_cost_total,
                    estimated_savings_pct,
                    reasoning,
                    json.dumps(disqualifying_factors),
                    nominated_by,
                ),
            )
        logger.info(
            f"[crystallization] Candidate nominated: {candidate_id!r} "
            f"operation={operation_name!r} count={observed_count}"
        )
        return candidate_id
    except Exception as e:
        logger.warning(f"[crystallization] nominate_candidate failed: {e}")
        return None


async def get_pending_candidates(limit: int = 20) -> list[dict]:
    """Return NOMINATED candidates, most recent first. Non-fatal."""
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                SELECT candidate_id, operation_name, observed_count, status,
                       token_cost_total, estimated_savings_pct,
                       reasoning, disqualifying_factors, nominated_at, nominated_by
                FROM crystallization_candidates
                WHERE status = 'NOMINATED'
                ORDER BY nominated_at DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = await cur.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.warning(f"[crystallization] get_pending_candidates failed: {e}")
        return []


async def get_candidate(candidate_id: str) -> dict | None:
    """Return full candidate record by ID. Non-fatal."""
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                "SELECT * FROM crystallization_candidates WHERE candidate_id = %s",
                (candidate_id,),
            )
            row = await cur.fetchone()
        return dict(row) if row else None
    except Exception as e:
        logger.warning(f"[crystallization] get_candidate failed: {e}")
        return None


async def create_package(
    package_id: str,
    candidate_id: str,
    tool_name: str,
    tool_description: str,
    function_code: str,
    function_signature: str,
    input_schema: dict,
    output_schema: dict,
    declared_side_effects: list,
    test_cases: list,
    edge_cases: list,
    adversarial_cases: list,
    confidence_score: float,
    known_limitations: list,
    suggested_fallback: str,
) -> str | None:
    """
    Write a crystallization package submitted by the Crystallizer agent.
    Returns package_id on success, None if DB unavailable.
    Also updates the candidate status to IN_PROGRESS.
    """
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            await conn.execute(
                """
                INSERT INTO crystallization_packages
                    (package_id, candidate_id, tool_name, tool_description,
                     function_code, function_signature, input_schema, output_schema,
                     declared_side_effects, test_cases, edge_cases, adversarial_cases,
                     confidence_score, known_limitations, suggested_fallback)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    package_id,
                    candidate_id,
                    tool_name,
                    tool_description,
                    function_code,
                    function_signature,
                    json.dumps(input_schema),
                    json.dumps(output_schema),
                    json.dumps(declared_side_effects),
                    json.dumps(test_cases),
                    json.dumps(edge_cases),
                    json.dumps(adversarial_cases),
                    confidence_score,
                    json.dumps(known_limitations),
                    suggested_fallback,
                ),
            )
            # Mark candidate as in-progress
            await conn.execute(
                "UPDATE crystallization_candidates SET status = 'IN_PROGRESS' "
                "WHERE candidate_id = %s AND status = 'NOMINATED'",
                (candidate_id,),
            )
        logger.info(
            f"[crystallization] Package created: {package_id!r} "
            f"candidate={candidate_id!r} tool={tool_name!r}"
        )
        return package_id
    except Exception as e:
        logger.warning(f"[crystallization] create_package failed: {e}")
        return None


async def get_package(package_id: str) -> dict | None:
    """Return full package record by ID. Non-fatal."""
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                "SELECT * FROM crystallization_packages WHERE package_id = %s",
                (package_id,),
            )
            row = await cur.fetchone()
        return dict(row) if row else None
    except Exception as e:
        logger.warning(f"[crystallization] get_package failed: {e}")
        return None


async def get_packages_ready_for_review() -> list[dict]:
    """
    Return packages at READY_FOR_REVIEW with their latest analysis.
    Most recently analyzed first.
    """
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                SELECT p.*, a.recommendation, a.recommendation_reasoning,
                       a.test_cases_passed, a.test_cases_failed,
                       a.security_clean, a.security_findings,
                       a.estimated_daily_savings, a.risk_flags,
                       a.analyzed_at
                FROM crystallization_packages p
                LEFT JOIN crystallization_analyses a USING (package_id)
                WHERE p.status = 'READY_FOR_REVIEW'
                ORDER BY a.analyzed_at DESC NULLS LAST
                """,
            )
            rows = await cur.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.warning(f"[crystallization] get_packages_ready_for_review failed: {e}")
        return []


async def create_analysis(
    package_id: str,
    forbidden_constructs: list,
    undeclared_dependencies: list,
    undeclared_side_effects: list,
    cyclomatic_complexity: int,
    lines_of_code: int,
    test_cases_passed: int,
    test_cases_failed: int,
    failed_case_diffs: list,
    ai_equivalence_rate: float,
    adversarial_exceptions: list,
    security_clean: bool,
    security_findings: list,
    recommendation: str,
    recommendation_reasoning: str,
    estimated_daily_savings: int,
    risk_flags: list,
    status: str,  # 'READY_FOR_REVIEW' | 'REJECTED_BY_ANALYSIS'
) -> int | None:
    """
    Persist a Pre-HITL analysis report and update package status atomically.
    Returns analysis row id on success, None on failure.
    """
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                INSERT INTO crystallization_analyses
                    (package_id, forbidden_constructs, undeclared_dependencies,
                     undeclared_side_effects, cyclomatic_complexity, lines_of_code,
                     test_cases_passed, test_cases_failed, failed_case_diffs,
                     ai_equivalence_rate, adversarial_exceptions,
                     security_clean, security_findings,
                     recommendation, recommendation_reasoning,
                     estimated_daily_savings, risk_flags, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    package_id,
                    json.dumps(forbidden_constructs),
                    json.dumps(undeclared_dependencies),
                    json.dumps(undeclared_side_effects),
                    cyclomatic_complexity,
                    lines_of_code,
                    test_cases_passed,
                    test_cases_failed,
                    json.dumps(failed_case_diffs),
                    ai_equivalence_rate,
                    json.dumps(adversarial_exceptions),
                    security_clean,
                    json.dumps(security_findings),
                    recommendation,
                    recommendation_reasoning,
                    estimated_daily_savings,
                    json.dumps(risk_flags),
                    status,
                ),
            )
            row = await cur.fetchone()
            analysis_id = row["id"]
            # Atomically update package status
            await conn.execute(
                "UPDATE crystallization_packages SET status = %s WHERE package_id = %s",
                (status, package_id),
            )
        logger.info(
            f"[crystallization] Analysis saved: pkg={package_id!r} "
            f"status={status!r} rec={recommendation!r}"
        )
        return analysis_id
    except Exception as e:
        logger.warning(f"[crystallization] create_analysis failed: {e}")
        return None


async def get_analysis(package_id: str) -> dict | None:
    """Return the most recent analysis report for a package. Non-fatal."""
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                "SELECT * FROM crystallization_analyses WHERE package_id = %s "
                "ORDER BY analyzed_at DESC LIMIT 1",
                (package_id,),
            )
            row = await cur.fetchone()
        return dict(row) if row else None
    except Exception as e:
        logger.warning(f"[crystallization] get_analysis failed: {e}")
        return None


async def approve_package(package_id: str, approved_by: str) -> bool:
    """
    Approve a READY_FOR_REVIEW package. Operator-only action.
    Returns True if the row was updated.
    """
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                UPDATE crystallization_packages
                SET status = 'APPROVED'
                WHERE package_id = %s AND status = 'READY_FOR_REVIEW'
                """,
                (package_id,),
            )
        updated = cur.statusmessage.split()[-1] != "0"
        if updated:
            logger.info(
                f"[crystallization] Package approved: {package_id!r} by={approved_by!r}"
            )
        return updated
    except Exception as e:
        logger.warning(f"[crystallization] approve_package failed: {e}")
        return False


async def reject_package(package_id: str, rejected_by: str, reason: str = "") -> bool:
    """Reject a package at any reviewable status. Returns True if updated."""
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                UPDATE crystallization_packages
                SET status = 'REJECTED', revision_notes = %s
                WHERE package_id = %s
                  AND status IN ('READY_FOR_REVIEW', 'PENDING_ANALYSIS')
                """,
                (reason, package_id),
            )
        updated = cur.statusmessage.split()[-1] != "0"
        if updated:
            logger.info(
                f"[crystallization] Package rejected: {package_id!r} by={rejected_by!r}"
            )
        return updated
    except Exception as e:
        logger.warning(f"[crystallization] reject_package failed: {e}")
        return False


async def revise_package(package_id: str, revision_notes: str) -> bool:
    """
    Send a READY_FOR_REVIEW package back for revision.
    Resets status to PENDING_ANALYSIS so the analyzer runs again after re-submission.
    Returns True if updated.
    """
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                UPDATE crystallization_packages
                SET status = 'PENDING_ANALYSIS', revision_notes = %s
                WHERE package_id = %s AND status = 'READY_FOR_REVIEW'
                """,
                (revision_notes, package_id),
            )
        updated = cur.statusmessage.split()[-1] != "0"
        if updated:
            logger.info(f"[crystallization] Package sent for revision: {package_id!r}")
        return updated
    except Exception as e:
        logger.warning(f"[crystallization] revise_package failed: {e}")
        return False


async def store_tool_signature(
    tool_id: str,
    signature: str,
    public_key_fingerprint: str,
) -> bool:
    """Store Ed25519 signature and public key fingerprint for a registered tool."""
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                UPDATE tool_registry
                SET signature = %s, public_key_fingerprint = %s, signed_at = NOW()
                WHERE tool_id = %s AND status = 'APPROVED'
                """,
                (signature, public_key_fingerprint, tool_id),
            )
        updated = cur.statusmessage.split()[-1] != "0"
        if updated:
            logger.info(f"[signing] Signature stored for tool_id={tool_id!r}")
        return updated
    except Exception as e:
        logger.warning(f"[signing] store_tool_signature failed: {e}")
        return False


async def get_tool_registry_entry(tool_id: str) -> dict | None:
    """Return tool_registry row including signature columns. Non-fatal."""
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                "SELECT * FROM tool_registry WHERE tool_id = %s AND status = 'APPROVED'",
                (tool_id,),
            )
            row = await cur.fetchone()
        return dict(row) if row else None
    except Exception as e:
        logger.warning(f"[crystallization] get_tool_registry_entry failed: {e}")
        return None


# ── Phase 6: Tool revocation ───────────────────────────────────────────────────


async def revoke_tool(
    tool_id: str,
    revoked_by: str,
    reason: str = "Revoked by operator",
) -> bool:
    """
    Revoke a registered tool by setting its status to 'REVOKED'.

    Immediately effective in the next Guardian cache refresh (TTL ≤ 10s).
    The tool will be rejected at invocation time with threat_type='TOOL_REVOKED'.

    Also appends a TOOL_REVOKED event to the audit log for the hash chain.

    Args:
        tool_id:    The tool_id to revoke (must exist in tool_registry).
        revoked_by: Operator identifier (e.g., 'operator', 'ci', 'security_team').
        reason:     Human-readable justification for the revocation.

    Returns:
        True if the tool was found and revoked; False if not found or DB error.
    """
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                UPDATE tool_registry
                SET status             = 'REVOKED',
                    revoked_at         = NOW(),
                    revoked_by         = %s,
                    revocation_reason  = %s
                WHERE tool_id = %s
                  AND status != 'REVOKED'
                """,
                (revoked_by, reason, tool_id),
            )
            rows_affected = int(cur.statusmessage.split()[-1])

        if rows_affected == 0:
            logger.warning(
                f"[revocation] Tool '{tool_id}' not found or already revoked — no-op"
            )
            return False

        logger.info(
            f"[revocation] Tool '{tool_id}' REVOKED by '{revoked_by}': {reason}"
        )

        # Append to audit log (non-fatal if fails)
        try:
            await append_audit_log(
                event_type="TOOL_REVOKED",
                agent_id=revoked_by,
                payload={"tool_id": tool_id, "reason": reason},
            )
        except Exception as audit_err:
            logger.warning(f"[revocation] Audit log append failed: {audit_err}")

        return True

    except Exception as e:
        logger.error(f"[revocation] revoke_tool failed for '{tool_id}': {e}")
        return False


async def get_revoked_tools() -> list[str]:
    """
    Return the list of all REVOKED tool_ids.

    Called by Guardian's cache refresh to populate _revoked_tools set.
    Guardian checks this BEFORE the approval registry — revoked tools halt
    even if they were previously APPROVED.

    Returns:
        List of revoked tool_id strings (empty if none or DB unavailable).
    """
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                "SELECT tool_id FROM tool_registry WHERE status = 'REVOKED'"
            )
            rows = await cur.fetchall()
        return [row["tool_id"] for row in rows]
    except Exception as e:
        logger.warning(f"[revocation] get_revoked_tools failed: {e}")
        return []


# ── Phase 6: PentestAgent — run tracking ─────────────────────────────────────


async def create_pentest_run(mode: str = "verify", git_ref: str | None = None) -> str:
    """
    Insert a new pentest_runs row and return the run_id (UUID string).

    Args:
        mode:    "verify" (stop-at-proof) or "resilience" (measure blast radius).
        git_ref: Optional git SHA or branch name for traceability.

    Returns:
        UUID string for the new run.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        row = await conn.fetchone(
            """
            INSERT INTO pentest_runs (mode, git_ref)
            VALUES (%s, %s)
            RETURNING run_id::text
            """,
            (mode, git_ref),
        )
        run_id = row[0]
        logger.info(f"[pentest] Run created: run_id={run_id} mode={mode}")
        return run_id


async def log_pentest_finding(
    run_id: str,
    attack_class: str,
    variant: str,
    severity: str,
    defense_held: bool,
    detail: str = "",
    payload: str | None = None,
) -> int:
    """
    Insert a finding row into pentest_findings.

    Args:
        run_id:       UUID of the active pentest_runs row.
        attack_class: e.g. "PROMPT_INJECTION", "RAG_POISONING".
        variant:      e.g. "direct_injection", "nested_instruction_override".
        severity:     One of CRITICAL / HIGH / MEDIUM / LOW / PASS.
        defense_held: True if the defense blocked the attack; False = bypass found.
        detail:       Human-readable description of the result.
        payload:      The attack string used (truncated to 4 KB if needed).

    Returns:
        Integer primary key of the new finding row.
    """
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "PASS"}
    if severity not in valid_severities:
        raise ValueError(
            f"severity must be one of {valid_severities}, got {severity!r}"
        )

    if payload and len(payload) > 4096:
        payload = payload[:4096]

    pool = get_pool()
    async with pool.connection() as conn:
        row = await conn.fetchone(
            """
            INSERT INTO pentest_findings
                (run_id, attack_class, variant, severity, defense_held, detail, payload)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (run_id, attack_class, variant, severity, defense_held, detail, payload),
        )
        finding_id = row[0]
        status_icon = "✅" if defense_held else "❌"
        logger.info(
            f"[pentest] {status_icon} {attack_class}/{variant} "
            f"severity={severity} defense_held={defense_held} id={finding_id}"
        )
        return finding_id


async def finish_pentest_run(run_id: str, summary: dict) -> None:
    """
    Mark a pentest run complete and store its summary JSONB.

    Args:
        run_id:  UUID of the run to close.
        summary: Dict with keys: total, passed, bypasses, by_severity, by_class.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            """
            UPDATE pentest_runs
            SET finished_at = NOW(),
                status      = 'complete',
                summary     = %s
            WHERE run_id = %s
            """,
            (json.dumps(summary), run_id),
        )
    logger.info(f"[pentest] Run finished: run_id={run_id} summary={summary}")


async def get_pentest_run(run_id: str) -> dict | None:
    """
    Fetch a single pentest_runs row by run_id.

    Returns:
        Dict with run fields, or None if not found.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        rows = await conn.fetchall(
            "SELECT * FROM pentest_runs WHERE run_id = %s::uuid",
            (run_id,),
        )
    return rows[0] if rows else None


async def list_pentest_findings(run_id: str) -> list[dict]:
    """
    Return all pentest_findings rows for a given run_id, ordered by logged_at.

    Returns:
        List of dicts (empty list if no findings or run not found).
    """
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        return await conn.fetchall(
            """
            SELECT * FROM pentest_findings
            WHERE run_id = %s::uuid
            ORDER BY logged_at ASC
            """,
            (run_id,),
        )


# ── Phase 7: Pentest → Guardian bridge ────────────────────────────────────────

# Maps pentest_proposed_rules.rule_type → threat_rules.rule_type
_PENTEST_RULE_TYPE_MAP: dict[str, str] = {
    "REGEX": "INJECTION_PATTERN",
    "CAPABILITY": "CAPABILITY_BLOCK",
    "RATE_LIMIT": "RATE_LIMIT_TIGHTEN",
}


def _build_threat_rule_def(
    rule_type: str,
    rule_content: str,
    rationale: str | None,
    finding_id: int,
) -> dict:
    """
    Convert a pentest proposed rule into a threat_rules rule_def JSONB payload.

    Args:
        rule_type:    One of 'REGEX', 'CAPABILITY', 'RATE_LIMIT'.
        rule_content: Raw rule content string from pentest_proposed_rules.
        rationale:    Human-readable reason (may be None).
        finding_id:   pentest_findings.id for audit traceability.

    Returns:
        Dict suitable for insertion into threat_rules.rule_def (JSONB).
    """
    base = {
        "source": "pentest",
        "pentest_finding_id": finding_id,
    }
    if rule_type == "REGEX":
        return {
            **base,
            "pattern": rule_content,
            "flags": "i",  # case-insensitive — conservative default
        }
    if rule_type == "CAPABILITY":
        return {
            **base,
            "tool_id": rule_content,
            "reason": rationale or "pentest bypass detected",
        }
    # RATE_LIMIT
    return {
        **base,
        "constraint": rule_content,
    }


async def promote_pentest_rule_to_threat_rule(
    finding_id: int,
    rule_type: str,
    rule_content: str,
    rationale: str | None,
    run_id: str,
) -> str:
    """
    Promote an approved pentest rule into threat_rules so Guardian enforces it.

    This is the Phase 7 Pentest→Guardian bridge. When a human approves a pentest
    proposed rule via ``POST /pentest/rules/{finding_id}/approve``, this function
    converts it to the ``threat_rules`` schema and inserts it with
    status='APPROVED' and approved_by='operator_hitl'.

    The double-step (PENDING → APPROVED) used by the Threat Analyst is bypassed
    here because the human already provided approval at the HITL endpoint — no
    second gate is needed.

    Guardian picks up the new rule within its 10-second cache refresh window via
    ``_check_6_adaptive_rules()``.

    Args:
        finding_id:   pentest_findings.id (for traceability in rule_def).
        rule_type:    One of 'REGEX', 'CAPABILITY', 'RATE_LIMIT'.
        rule_content: Raw content from pentest_proposed_rules.rule_content.
        rationale:    Human-readable rationale (may be None).
        run_id:       UUID of the pentest run (stored as evidence_id).

    Returns:
        rule_id (UUID string) of the newly created threat_rules row.

    Raises:
        ValueError: If rule_type is not in _PENTEST_RULE_TYPE_MAP.
    """
    if rule_type not in _PENTEST_RULE_TYPE_MAP:
        raise ValueError(
            f"Unknown pentest rule_type '{rule_type}'. "
            f"Valid types: {list(_PENTEST_RULE_TYPE_MAP)}"
        )

    threat_rule_type = _PENTEST_RULE_TYPE_MAP[rule_type]
    rule_def = _build_threat_rule_def(rule_type, rule_content, rationale, finding_id)
    justification = (
        rationale or f"Promoted from pentest finding #{finding_id} (run {run_id[:8]})"
    )

    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            INSERT INTO threat_rules
                (proposed_by, rule_type, rule_def, justification, evidence_ids,
                 status, approved_by, approved_at)
            VALUES
                ('pentest_agent', %s, %s::jsonb, %s, %s,
                 'APPROVED', 'operator_hitl', NOW())
            RETURNING rule_id::text
            """,
            (
                threat_rule_type,
                json.dumps(rule_def),
                justification,
                [run_id],
            ),
        )
        row = await cur.fetchone()

    rule_id = row["rule_id"]
    logger.info(
        f"[pentest→guardian] Promoted finding #{finding_id} → threat_rule "
        f"rule_id={rule_id} type={threat_rule_type} (Guardian enforces within 10s)"
    )
    return rule_id


# ── Phase 8: Gateway task queue ───────────────────────────────────────────────


VALID_TASK_STATUSES = {"queued", "running", "complete", "failed", "cancelled"}
VALID_AGENT_TYPES = {"orchestrator", "researcher", "base_agent"}


async def create_task(
    user_id: str,
    input_text: str,
    agent_type: str = "orchestrator",
    config: dict | None = None,
    estimated_tokens: int = 0,
    callback_url: str | None = None,
    priority: int = 5,
    content_hash: str | None = None,
    tags: list[str] | None = None,
    depends_on: str | None = None,
) -> dict:
    """Insert a new task row and return it with task_id and status='queued'.

    priority: 1 (low) … 5 (normal, default) … 10 (high).
    content_hash: SHA-256 of (agent_type:input_text) used for cache lookups.
    tags: freeform string labels (Phase 31).
    depends_on: UUID of a task that must complete before this one runs (Phase 34).
    """
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            INSERT INTO tasks
                (user_id, input, agent_type, config, estimated_tokens,
                 callback_url, priority, content_hash, tags, depends_on)
            VALUES (%s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s,
                    %s::uuid)
            RETURNING task_id::text, status, created_at, agent_type,
                      priority, tags, depends_on::text
            """,
            (
                user_id,
                input_text,
                agent_type,
                json.dumps(config or {}),
                estimated_tokens,
                callback_url,
                max(1, min(10, int(priority))),
                content_hash,
                list(tags) if tags else [],
                depends_on,
            ),
        )
        row = await cur.fetchone()
    task_row = dict(row)
    # Phase 39: record 'queued' timeline event (best-effort, non-blocking)
    try:
        pool2 = get_pool()
        async with pool2.connection() as conn2:
            await conn2.execute(
                "INSERT INTO task_events (task_id, event_type, metadata) "
                "VALUES (%s::uuid, 'queued', %s::jsonb)",
                (
                    task_row["task_id"],
                    json.dumps(
                        {
                            "agent_type": agent_type,
                            "priority": task_row.get("priority", 5),
                        }
                    ),
                ),
            )
    except Exception:
        pass  # timeline is best-effort; never block task creation
    return task_row


async def lookup_cached_task(
    content_hash: str,
    max_age_seconds: int = 3600,
) -> dict | None:
    """
    Return the most recent completed task matching content_hash within
    max_age_seconds, or None if no cache hit exists.

    Phase 29 task result cache.
    """
    from datetime import datetime, timezone, timedelta

    cutoff = datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            SELECT task_id::text, result, completed_at, agent_type
            FROM tasks
            WHERE content_hash = %s
              AND status = 'complete'
              AND completed_at > %s
            ORDER BY completed_at DESC
            LIMIT 1
            """,
            (content_hash, cutoff),
        )
        row = await cur.fetchone()
    return dict(row) if row else None


async def get_task(task_id: str, user_id: str | None = None) -> dict | None:
    """
    Fetch a task by task_id.
    If user_id is provided, returns None if the task belongs to a different user
    (404 semantics — do not reveal task existence to unauthorized callers).
    """
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            "SELECT * FROM tasks WHERE task_id = %s::uuid",
            (task_id,),
        )
        row = await cur.fetchone()

    if row is None:
        return None
    if user_id is not None and row["user_id"] != user_id:
        return None  # 404, not 403 — don't confirm existence
    return dict(row)


# ── Phase 47: Keyset Pagination Cursor Helpers ─────────────────────────────────


def encode_task_cursor(created_at: str, task_id: str) -> str:
    """Encode (created_at, task_id) into an opaque base64 cursor string."""
    import base64

    payload = json.dumps({"ts": created_at, "id": task_id})
    return base64.urlsafe_b64encode(payload.encode()).decode()


def decode_task_cursor(cursor: str) -> tuple[str | None, str | None]:
    """Decode a cursor string back to (created_at, task_id).  Returns (None, None) on error."""
    import base64

    try:
        payload = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
        return payload["ts"], payload["id"]
    except Exception:
        return None, None


async def list_tasks(
    user_id: str,
    limit: int = 20,
    offset: int = 0,
    status: str | None = None,
    q: str | None = None,
    tags: list[str] | None = None,
    label: str | None = None,
    cursor: str | None = None,
) -> dict:
    """Return paginated task list for a user with total count.

    Optional filters (Phase 31 / Phase 40):
        q      — full-text search on task input (Phase 45)
        tags   — return only tasks that contain ALL listed tags
        label  — filter tasks that have a specific label (Phase 40)
        cursor — opaque keyset cursor for efficient deep pagination (Phase 47)
                 When provided, OFFSET is ignored and keyset pagination is used.
    """
    if status is not None and status not in VALID_TASK_STATUSES:
        raise ValueError(f"Invalid status filter: {status!r}")
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row

        # `where` is assembled from hardcoded string fragments only;
        # all user values go into parameterised `params` — no injection risk.
        where = "WHERE user_id = %s"
        params: list = [user_id]
        if status:
            where += " AND status = %s"
            params.append(status)
        if q:
            # Phase 45: prefer full-text search (search_vector GIN index) over
            # ILIKE scan.  plainto_tsquery handles multi-word phrases gracefully.
            where += " AND search_vector @@ plainto_tsquery('english', %s)"
            params.append(q)
        if tags:
            where += " AND tags @> %s"
            params.append(list(tags))
        if label:
            where += " AND labels @> %s"
            params.append([label])

        # Phase 47: keyset cursor pagination.
        # Cursor encodes (created_at ISO string, task_id UUID) as JSON+base64.
        # Uses (created_at, task_id) < (cursor_ts, cursor_id) for stable ordering.
        cursor_ts: str | None = None
        cursor_id: str | None = None
        if cursor:
            cursor_ts, cursor_id = decode_task_cursor(cursor)
        if cursor_ts and cursor_id:
            where += " AND (created_at, task_id::text) < (%s::timestamptz, %s)"
            params.extend([cursor_ts, cursor_id])

        # `where` is assembled from hardcoded string fragments only; all user
        # values go into parameterised `params` — no injection risk.
        _count_q = f"SELECT COUNT(*) AS cnt FROM tasks {where}"  # nosec B608
        cur = await conn.execute(_count_q, params)
        total = (await cur.fetchone())["cnt"]

        _list_q = f"""
            SELECT task_id::text, user_id, status, agent_type, input,
                   result, error, steps, tokens, tags, created_at, updated_at, completed_at
            FROM tasks {where}
            ORDER BY created_at DESC, task_id DESC
            LIMIT %s OFFSET %s
            """  # nosec B608
        # When using cursor pagination, OFFSET is always 0
        effective_offset = 0 if (cursor_ts and cursor_id) else offset
        cur = await conn.execute(_list_q, params + [limit, effective_offset])
        rows = await cur.fetchall()

    task_dicts = [dict(r) for r in rows]

    # Build next_cursor from the last row (None if fewer rows than limit returned)
    next_cursor: str | None = None
    if len(task_dicts) == limit:
        last = task_dicts[-1]
        next_cursor = encode_task_cursor(
            (
                str(last["created_at"].isoformat())
                if hasattr(last["created_at"], "isoformat")
                else str(last["created_at"])
            ),
            str(last["task_id"]),
        )

    return {
        "tasks": task_dicts,
        "total": total,
        "limit": limit,
        "offset": offset,
        "next_cursor": next_cursor,
    }


async def update_task_tags(
    task_id: str,
    user_id: str,
    tags: list[str],
) -> dict | None:
    """
    Replace the tags on a task with the provided list.
    Returns the updated task dict, or None if not found / not owned by user.

    Phase 31.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            UPDATE tasks
            SET tags = %s, updated_at = now()
            WHERE task_id = %s::uuid AND user_id = %s
            RETURNING task_id::text, tags, status, updated_at
            """,
            (list(tags), task_id, user_id),
        )
        row = await cur.fetchone()
    return dict(row) if row else None


# ── Phase 40: Task labels ───────────────────────────────────────────────────────

VALID_TASK_LABELS: frozenset[str] = frozenset(
    {"bookmarked", "starred", "important", "archived"}
)


async def update_task_labels(
    task_id: str,
    user_id: str,
    labels: list[str],
) -> dict | None:
    """
    Replace the labels on a task with the provided list.
    Only labels from VALID_TASK_LABELS are allowed; ValueError on unknown labels.
    Returns the updated task dict, or None if not found / not owned by user.

    Phase 40 — Task Labels.
    """
    unknown = set(labels) - VALID_TASK_LABELS
    if unknown:
        raise ValueError(
            f"Unknown labels: {sorted(unknown)}. "
            f"Allowed: {sorted(VALID_TASK_LABELS)}"
        )
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            UPDATE tasks
            SET labels = %s, updated_at = now()
            WHERE task_id = %s::uuid AND user_id = %s
            RETURNING task_id::text, labels, status, updated_at
            """,
            (list(labels), task_id, user_id),
        )
        row = await cur.fetchone()
    return dict(row) if row else None


# ── Phase 32: Task notes ───────────────────────────────────────────────────────


async def add_task_note(task_id: str, user_id: str, note: str) -> dict | None:
    """
    Append a note to a task.  Returns the new note row, or None if the task
    does not exist / does not belong to user_id (404 semantics).

    Phase 32.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        # Verify ownership first (tasks WHERE task_id AND user_id)
        cur = await conn.execute(
            "SELECT 1 FROM tasks WHERE task_id = %s::uuid AND user_id = %s",
            (task_id, user_id),
        )
        if await cur.fetchone() is None:
            return None
        cur = await conn.execute(
            """
            INSERT INTO task_notes (task_id, user_id, note)
            VALUES (%s::uuid, %s, %s)
            RETURNING id, task_id::text, user_id, note, created_at
            """,
            (task_id, user_id, note),
        )
        row = await cur.fetchone()
    return dict(row) if row else None


async def list_task_notes(task_id: str, user_id: str) -> list[dict]:
    """
    Return all notes for task_id owned by user_id, ordered oldest-first.
    Returns empty list if task not found or not owned by user.

    Phase 32.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        # Ownership check via JOIN
        cur = await conn.execute(
            """
            SELECT n.id, n.task_id::text, n.user_id, n.note, n.created_at
            FROM task_notes n
            JOIN tasks t ON t.task_id = n.task_id
            WHERE n.task_id = %s::uuid
              AND t.user_id = %s
            ORDER BY n.created_at ASC
            """,
            (task_id, user_id),
        )
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def delete_task_note(note_id: int, task_id: str, user_id: str) -> bool:
    """
    Delete a note by ID.  Returns True if deleted, False if not found / not owned.

    Phase 32.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            DELETE FROM task_notes
            WHERE id = %s
              AND task_id = %s::uuid
              AND user_id = %s
            """,
            (note_id, task_id, user_id),
        )
        return cur.rowcount > 0


async def claim_next_queued_task() -> dict | None:
    """
    Atomically claim the oldest queued task by setting status='running'.
    Returns the claimed task row, or None if queue is empty.
    Uses UPDATE ... RETURNING with FOR UPDATE SKIP LOCKED for safe concurrent access.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            UPDATE tasks
            SET status = 'running', updated_at = now()
            WHERE task_id = (
                SELECT t.task_id FROM tasks t
                WHERE t.status = 'queued'
                  AND (
                      t.depends_on IS NULL
                      OR EXISTS (
                          SELECT 1 FROM tasks dep
                          WHERE dep.task_id = t.depends_on
                            AND dep.status = 'complete'
                      )
                  )
                ORDER BY t.priority DESC, t.created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            RETURNING *
            """
        )
        row = await cur.fetchone()
    return dict(row) if row else None


async def mark_task_running(task_id: str, run_id: str) -> None:
    """Record the LangGraph run_id against a task that is already 'running'.

    Phase 39: also inserts a 'running' timeline event.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            """
            UPDATE tasks
            SET run_id = %s::uuid, updated_at = now()
            WHERE task_id = %s::uuid
            """,
            (run_id, task_id),
        )
        # Phase 39: timeline event
        await conn.execute(
            "INSERT INTO task_events (task_id, event_type, metadata) "
            "VALUES (%s::uuid, 'running', %s::jsonb)",
            (task_id, json.dumps({"run_id": run_id})),
        )


async def mark_task_complete(
    task_id: str,
    result: str,
    steps: int | None = None,
    tokens: dict | None = None,
    stream_events: list | None = None,
) -> None:
    pool = get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            """
            UPDATE tasks
            SET status = 'complete', result = %s,
                steps = %s, tokens = %s::jsonb,
                stream_events = %s::jsonb,
                completed_at = now(), updated_at = now()
            WHERE task_id = %s::uuid
            """,
            (
                result,
                steps,
                json.dumps(tokens or {}),
                json.dumps(stream_events or []),
                task_id,
            ),
        )
        # Phase 39: timeline event
        await conn.execute(
            "INSERT INTO task_events (task_id, event_type, metadata) "
            "VALUES (%s::uuid, 'complete', %s::jsonb)",
            (task_id, json.dumps({"steps": steps, "tokens": tokens or {}})),
        )


async def mark_task_failed(task_id: str, error: str) -> None:
    pool = get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            """
            UPDATE tasks
            SET status = 'failed', error = %s,
                completed_at = now(), updated_at = now()
            WHERE task_id = %s::uuid
            """,
            (error, task_id),
        )
        # Phase 39: timeline event
        await conn.execute(
            "INSERT INTO task_events (task_id, event_type, metadata) "
            "VALUES (%s::uuid, 'failed', %s::jsonb)",
            (task_id, json.dumps({"error": error[:500]})),
        )


async def fail_dependent_tasks(failed_task_id: str) -> int:
    """
    Auto-fail queued tasks whose dependency (depends_on) is the given failed task.
    Returns the number of tasks that were auto-failed.

    Phase 34 — Task Dependencies.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            UPDATE tasks
            SET status = 'failed',
                error = 'Dependency task failed or was cancelled',
                completed_at = now(),
                updated_at = now()
            WHERE depends_on = %s::uuid
              AND status = 'queued'
            """,
            (failed_task_id,),
        )
        return cur.rowcount


async def mark_task_cancelled(task_id: str, user_id: str) -> bool:
    """
    Cancel a task if it is still queued and belongs to the requesting user.
    Returns True if a row was updated, False if not found / wrong owner / not queued.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            UPDATE tasks
            SET status = 'cancelled', completed_at = now(), updated_at = now()
            WHERE task_id = %s::uuid AND user_id = %s AND status = 'queued'
            """,
            (task_id, user_id),
        )
        return cur.rowcount == 1


# ── Phase 43: Task Bulk Operations ────────────────────────────────────────────


async def bulk_cancel_tasks(task_ids: list[str], user_id: str) -> int:
    """
    Cancel all queued tasks in task_ids that belong to user_id.
    Running/complete/failed tasks are silently skipped.
    Returns the number of tasks actually cancelled.

    Phase 43 — Task Bulk Operations.
    """
    if not task_ids:
        return 0
    pool = get_pool()
    async with pool.connection() as conn:
        # psycopg ANY(%s) with a list cast to uuid[]
        cur = await conn.execute(
            """
            UPDATE tasks
            SET status = 'cancelled', completed_at = now(), updated_at = now()
            WHERE task_id = ANY(%s::uuid[])
              AND user_id = %s
              AND status = 'queued'
            """,
            (list(task_ids), user_id),
        )
        return cur.rowcount


async def bulk_delete_tasks(task_ids: list[str], user_id: str) -> int:
    """
    Hard-delete tasks in task_ids that belong to user_id.
    Returns the number of tasks actually deleted.
    Cascades to task_notes, task_events, stream_tokens (ON DELETE CASCADE).

    Phase 43 — Task Bulk Operations.
    """
    if not task_ids:
        return 0
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            DELETE FROM tasks
            WHERE task_id = ANY(%s::uuid[])
              AND user_id = %s
            """,
            (list(task_ids), user_id),
        )
        return cur.rowcount


async def bulk_tag_tasks(task_ids: list[str], user_id: str, tags: list[str]) -> int:
    """
    Replace tags on all tasks in task_ids that belong to user_id.
    Returns the number of tasks updated.

    Phase 43 — Task Bulk Operations.
    """
    if not task_ids:
        return 0
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            UPDATE tasks
            SET tags = %s, updated_at = now()
            WHERE task_id = ANY(%s::uuid[])
              AND user_id = %s
            """,
            (list(tags), list(task_ids), user_id),
        )
        return cur.rowcount


# ── Phase 8: Gateway user management ─────────────────────────────────────────


async def create_gateway_user(
    username: str, api_key_hash: str, is_admin: bool = False
) -> dict:
    """
    Insert a new gateway user. api_key_hash must be a bcrypt hash of the raw key.
    Returns the created user row (without the raw key — it is never stored).
    """
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            INSERT INTO gateway_users (username, api_key_hash, is_admin)
            VALUES (%s, %s, %s)
            RETURNING user_id, username, created_at, is_active, is_admin,
                      daily_token_limit
            """,
            (username, api_key_hash, is_admin),
        )
        row = await cur.fetchone()
    return dict(row)


async def get_gateway_user_by_username(username: str) -> dict | None:
    """Fetch a gateway_users row by username (for CLI management)."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            "SELECT * FROM gateway_users WHERE username = %s AND is_active = true",
            (username,),
        )
        row = await cur.fetchone()
    return dict(row) if row else None


async def get_gateway_user_for_auth(username: str) -> dict | None:
    """
    Fetch the api_key_hash for a username so the caller can verify a raw token.
    Returns the full row including api_key_hash and daily_token_limit, or None
    if not found / inactive.  Called only from auth.py — not exposed on any
    API endpoint.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            SELECT user_id, username, api_key_hash, is_active,
                   daily_token_limit, is_admin
            FROM gateway_users
            WHERE is_active = true
            """,
        )
        rows = await cur.fetchall()
    # Return all active users for hash comparison (small table at this scale)
    return [dict(r) for r in rows]


async def deactivate_gateway_user(username: str) -> bool:
    """
    Deactivate a gateway user so they can no longer authenticate.
    Returns True if a row was updated, False if the user was not found.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            UPDATE gateway_users SET is_active = false
            WHERE username = %s AND is_active = true
            """,
            (username,),
        )
        return cur.rowcount == 1


async def set_gateway_user_quota(username: str, daily_token_limit: int) -> bool:
    """
    Update the per-user daily token limit.
    Returns True if a row was updated, False if the user was not found.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            UPDATE gateway_users SET daily_token_limit = %s
            WHERE username = %s AND is_active = true
            """,
            (daily_token_limit, username),
        )
        return cur.rowcount == 1


async def list_gateway_users() -> list[dict]:
    """Return all gateway users (active and inactive) for CLI listing."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            SELECT user_id::text, username, is_active, is_admin,
                   daily_token_limit, created_at
            FROM gateway_users
            ORDER BY created_at ASC
            """
        )
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def promote_gateway_user_to_admin(username: str, is_admin: bool = True) -> bool:
    """
    Grant or revoke admin privilege for a gateway user.
    Returns True if a row was updated, False if the user was not found.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            "UPDATE gateway_users SET is_admin = %s WHERE username = %s",
            (is_admin, username),
        )
        return cur.rowcount == 1


async def get_gateway_user_by_user_id(user_id: str) -> dict | None:
    """Fetch a gateway_users row by user_id (for admin API lookups)."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            SELECT user_id, username, is_active, is_admin, daily_token_limit,
                   created_at
            FROM gateway_users WHERE user_id = %s
            """,
            (user_id,),
        )
        row = await cur.fetchone()
    return dict(row) if row else None


async def rotate_api_key(user_id: str, new_key_hash: str) -> bool:
    """
    Replace the api_key_hash for user_id with new_key_hash.

    Returns True if the row was found and updated, False if user_id not found.
    The new_key_hash must be a bcrypt hash of the new plaintext key.

    Phase 41 — API Key Rotation.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            UPDATE gateway_users
            SET api_key_hash = %s, updated_at = now()
            WHERE user_id = %s
            """,
            (new_key_hash, user_id),
        )
        return cur.rowcount > 0


# ── Phase 10: DB-backed stream tokens ────────────────────────────────────────


async def create_stream_token(
    token: str,
    task_id: str,
    user_id: str,
    ttl_seconds: int = 1800,
) -> None:
    """
    Persist a stream token to the DB with a TTL-based expiry timestamp.

    Stream tokens survive gateway restarts because they are stored in the DB
    rather than an in-memory dict.  The auth.py wrapper generates the token
    string and calls this function to persist it.

    Args:
        token:       URL-safe random token string (generated by auth.py).
        task_id:     The task this token grants access to stream.
        user_id:     The user who submitted the task.
        ttl_seconds: Token lifetime in seconds (default 30 min).
    """
    pool = get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            """
            INSERT INTO stream_tokens (token, task_id, user_id, expires_at)
            VALUES (%s, %s, %s, NOW() + make_interval(secs => %s))
            ON CONFLICT (token) DO NOTHING
            """,
            (token, task_id, user_id, ttl_seconds),
        )


async def resolve_stream_token(token: str) -> tuple[str, str] | None:
    """
    Resolve a stream token to (task_id, user_id).

    Returns None if the token is unknown or has expired.  Does NOT consume
    (delete) the token so EventSource clients can reconnect within the TTL.

    Args:
        token: Raw stream token string from the query param.

    Returns:
        (task_id, user_id) tuple, or None if invalid/expired.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            SELECT task_id, user_id FROM stream_tokens
            WHERE token = %s AND expires_at > NOW()
            """,
            (token,),
        )
        row = await cur.fetchone()
    if row is None:
        return None
    return row["task_id"], row["user_id"]


async def delete_stream_token(token: str) -> None:
    """Delete a specific stream token (call on explicit logout or task cancellation)."""
    pool = get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            "DELETE FROM stream_tokens WHERE token = %s",
            (token,),
        )


async def purge_expired_stream_tokens() -> int:
    """
    Delete all expired stream tokens.  Called opportunistically by the worker
    heartbeat every 10 minutes — not a hot path.

    Returns:
        Number of rows deleted.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute("DELETE FROM stream_tokens WHERE expires_at <= NOW()")
        deleted = cur.rowcount
    if deleted:
        logger.debug(f"[stream-tokens] Purged {deleted} expired token(s)")
    return deleted


# ── Phase 10: Per-user budget queries ─────────────────────────────────────────


async def get_user_actual_usage_today(user_id: str, provider: str) -> int:
    """
    Return total tokens consumed by a user for a provider today.

    Counts only rows where user_id IS NOT NULL (written by the worker after
    task completion) to avoid double-counting agent-internal LLM calls.

    Args:
        user_id:  UUID string of the gateway user.
        provider: LLM provider name (e.g. "ollama", "openai").

    Returns:
        Total token count (0 if none).
    """
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            SELECT COALESCE(SUM(total_tokens), 0) AS total
            FROM api_usage
            WHERE user_id = %s
              AND provider = %s
              AND DATE(ts) = CURRENT_DATE
            """,
            (user_id, provider),
        )
        row = await cur.fetchone()
    return int(row["total"]) if row else 0


async def get_user_inflight_tokens(user_id: str) -> int:
    """
    Return the sum of estimated_tokens for all queued or running tasks for
    a user today.

    This represents the tokens that are reserved but not yet committed to
    api_usage.  Combined with get_user_actual_usage_today, it gives the
    total effective token spend for TOCTOU-safe budget enforcement.

    Args:
        user_id: UUID string of the gateway user.

    Returns:
        Total in-flight token estimate (0 if none).
    """
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            SELECT COALESCE(SUM(estimated_tokens), 0) AS total
            FROM tasks
            WHERE user_id = %s
              AND status IN ('queued', 'running')
              AND DATE(created_at) = CURRENT_DATE
            """,
            (user_id,),
        )
        row = await cur.fetchone()
    return int(row["total"]) if row else 0


async def get_user_usage_summary_today(user_id: str) -> dict:
    """
    Return a per-provider token usage summary for a user today.

    Used by the /usage/me health endpoint.

    Returns:
        Dict with keys: user_id, today (tokens_used, tokens_in_flight), providers.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        # Per-provider breakdown
        cur = await conn.execute(
            """
            SELECT provider, COALESCE(SUM(total_tokens), 0) AS tokens
            FROM api_usage
            WHERE user_id = %s AND DATE(ts) = CURRENT_DATE
            GROUP BY provider
            ORDER BY tokens DESC
            """,
            (user_id,),
        )
        provider_rows = await cur.fetchall()

        # In-flight tokens across all providers
        cur2 = await conn.execute(
            """
            SELECT COALESCE(SUM(estimated_tokens), 0) AS total
            FROM tasks
            WHERE user_id = %s
              AND status IN ('queued', 'running')
              AND DATE(created_at) = CURRENT_DATE
            """,
            (user_id,),
        )
        inflight_row = await cur2.fetchone()

    tokens_used = sum(r["tokens"] for r in provider_rows)
    tokens_in_flight = int(inflight_row["total"]) if inflight_row else 0

    return {
        "user_id": user_id,
        "today": {
            "tokens_used": int(tokens_used),
            "tokens_in_flight": tokens_in_flight,
        },
        "providers": {r["provider"]: int(r["tokens"]) for r in provider_rows},
    }


# ── Phase 23: Scheduled tasks CRUD ────────────────────────────────────────────


def _row_to_schedule(row: dict) -> dict:
    """Serialize a scheduled_tasks row to a JSON-safe dict."""
    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "name": row["name"],
        "task_text": row["task_text"],
        "agent_type": row["agent_type"],
        "cron_expr": row["cron_expr"],
        "next_run_at": row["next_run_at"].isoformat() if row["next_run_at"] else None,
        "last_run_at": row["last_run_at"].isoformat() if row["last_run_at"] else None,
        "last_task_id": row["last_task_id"],
        "enabled": row["enabled"],
        "created_at": row["created_at"].isoformat(),
        "updated_at": row["updated_at"].isoformat(),
    }


async def create_scheduled_task(
    user_id: str,
    name: str,
    task_text: str,
    cron_expr: str,
    agent_type: str = "orchestrator",
) -> dict:
    """
    Insert a new scheduled task.

    ``next_run_at`` is computed from ``cron_expr`` relative to now().
    Raises ``ValueError`` if ``cron_expr`` is invalid.
    """
    from src.scheduler import compute_next_run, validate_cron_expr
    from datetime import datetime, timezone

    validate_cron_expr(cron_expr)
    next_run = compute_next_run(cron_expr, datetime.now(timezone.utc))

    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            INSERT INTO scheduled_tasks
                (user_id, name, task_text, agent_type, cron_expr, next_run_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (user_id, name, task_text, agent_type, cron_expr, next_run),
        )
        row = await cur.fetchone()
    return _row_to_schedule(dict(row))


async def get_scheduled_task(sched_id: int, user_id: str) -> dict | None:
    """Fetch a scheduled task by ID, scoped to user_id (returns None if not found)."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            "SELECT * FROM scheduled_tasks WHERE id = %s AND user_id = %s",
            (sched_id, user_id),
        )
        row = await cur.fetchone()
    return _row_to_schedule(dict(row)) if row else None


async def list_scheduled_tasks(
    user_id: str,
    limit: int = 50,
    offset: int = 0,
    include_disabled: bool = True,
) -> list[dict]:
    """Return scheduled tasks for user_id ordered by next_run_at."""
    pool = get_pool()
    where = "WHERE user_id = %s"
    params: list = [user_id]
    if not include_disabled:
        where += " AND enabled = true"
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            f"SELECT * FROM scheduled_tasks {where} "  # nosec B608
            "ORDER BY next_run_at ASC LIMIT %s OFFSET %s",
            (*params, limit, offset),
        )
        rows = await cur.fetchall()
    return [_row_to_schedule(dict(r)) for r in rows]


async def update_scheduled_task(
    sched_id: int,
    user_id: str,
    *,
    name: str | None = None,
    task_text: str | None = None,
    cron_expr: str | None = None,
    agent_type: str | None = None,
    enabled: bool | None = None,
) -> dict | None:
    """
    Partially update a scheduled task.

    Returns the updated row, or None if not found/not owned by user_id.
    When ``cron_expr`` changes, ``next_run_at`` is recomputed.
    """
    from src.scheduler import compute_next_run, validate_cron_expr
    from datetime import datetime, timezone

    sets: list[str] = ["updated_at = now()"]
    params: list = []

    if name is not None:
        sets.append("name = %s")
        params.append(name)
    if task_text is not None:
        sets.append("task_text = %s")
        params.append(task_text)
    if agent_type is not None:
        sets.append("agent_type = %s")
        params.append(agent_type)
    if enabled is not None:
        sets.append("enabled = %s")
        params.append(enabled)
    if cron_expr is not None:
        validate_cron_expr(cron_expr)
        next_run = compute_next_run(cron_expr, datetime.now(timezone.utc))
        sets.append("cron_expr = %s")
        sets.append("next_run_at = %s")
        params.extend([cron_expr, next_run])

    if len(sets) == 1:  # only updated_at — nothing to change
        return await get_scheduled_task(sched_id, user_id)

    params.extend([sched_id, user_id])
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            f"UPDATE scheduled_tasks SET {', '.join(sets)} "  # nosec B608
            "WHERE id = %s AND user_id = %s RETURNING *",
            params,
        )
        row = await cur.fetchone()
    return _row_to_schedule(dict(row)) if row else None


async def delete_scheduled_task(sched_id: int, user_id: str) -> bool:
    """Delete a scheduled task. Returns True if deleted, False if not found."""
    pool = get_pool()
    async with pool.connection() as conn:
        result = await conn.execute(
            "DELETE FROM scheduled_tasks WHERE id = %s AND user_id = %s",
            (sched_id, user_id),
        )
    deleted = int(result.split()[-1]) if result else 0
    return bool(deleted)


async def get_due_scheduled_tasks() -> list[dict]:
    """Return all enabled scheduled tasks whose next_run_at <= now()."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            "SELECT * FROM scheduled_tasks "
            "WHERE enabled = true AND next_run_at <= now() "
            "ORDER BY next_run_at ASC"
        )
        rows = await cur.fetchall()
    return [_row_to_schedule(dict(r)) for r in rows]


async def record_scheduled_run(
    sched_id: int, task_id: str, next_run_at: "datetime"
) -> None:
    """Update last_run_at, last_task_id, and next_run_at after a job fires."""
    pool = get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            """
            UPDATE scheduled_tasks
            SET last_run_at = now(),
                last_task_id = %s,
                next_run_at = %s,
                updated_at = now()
            WHERE id = %s
            """,
            (task_id, next_run_at, sched_id),
        )


# ── Phase 27: Pipeline CRUD ────────────────────────────────────────────────────


def _row_to_pipeline(row: dict) -> dict:
    d = dict(row)
    for k in ("created_at", "updated_at"):
        if d.get(k) and hasattr(d[k], "isoformat"):
            d[k] = d[k].isoformat()
    return d


def _row_to_run(row: dict) -> dict:
    d = dict(row)
    for k in ("started_at", "completed_at"):
        if d.get(k) and hasattr(d[k], "isoformat"):
            d[k] = d[k].isoformat()
    return d


async def create_pipeline(
    user_id: str,
    name: str,
    steps: list[dict],
    description: str = "",
) -> dict:
    """Create a new pipeline definition. Steps is a list of step dicts."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            INSERT INTO pipelines (user_id, name, description, steps)
            VALUES (%s, %s, %s, %s::jsonb)
            RETURNING *
            """,
            (user_id, name, description, json.dumps(steps)),
        )
        row = await cur.fetchone()
    return _row_to_pipeline(dict(row))


async def get_pipeline(pipeline_id: int, user_id: str) -> dict | None:
    """Fetch a pipeline by ID scoped to user_id."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            "SELECT * FROM pipelines WHERE id = %s AND user_id = %s",
            (pipeline_id, user_id),
        )
        row = await cur.fetchone()
    return _row_to_pipeline(dict(row)) if row else None


async def list_pipelines(user_id: str, limit: int = 50, offset: int = 0) -> list[dict]:
    """List pipelines for user_id ordered by newest first."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            "SELECT * FROM pipelines WHERE user_id = %s "
            "ORDER BY created_at DESC LIMIT %s OFFSET %s",
            (user_id, limit, offset),
        )
        rows = await cur.fetchall()
    return [_row_to_pipeline(dict(r)) for r in rows]


async def update_pipeline(
    pipeline_id: int,
    user_id: str,
    *,
    name: str | None = None,
    description: str | None = None,
    steps: list[dict] | None = None,
) -> dict | None:
    """Partially update a pipeline definition."""
    sets: list[str] = ["updated_at = now()"]
    params: list = []
    if name is not None:
        sets.append("name = %s")
        params.append(name)
    if description is not None:
        sets.append("description = %s")
        params.append(description)
    if steps is not None:
        sets.append("steps = %s::jsonb")
        params.append(json.dumps(steps))
    params.extend([pipeline_id, user_id])
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            f"UPDATE pipelines SET {', '.join(sets)} "  # nosec B608
            "WHERE id = %s AND user_id = %s RETURNING *",
            params,
        )
        row = await cur.fetchone()
    return _row_to_pipeline(dict(row)) if row else None


async def delete_pipeline(pipeline_id: int, user_id: str) -> bool:
    """Delete a pipeline. Returns True if deleted."""
    pool = get_pool()
    async with pool.connection() as conn:
        result = await conn.execute(
            "DELETE FROM pipelines WHERE id = %s AND user_id = %s",
            (pipeline_id, user_id),
        )
    return bool(int(result.split()[-1]) if result else 0)


async def create_pipeline_run(
    pipeline_id: int,
    user_id: str,
    initial_input: str,
) -> dict:
    """Start a new pipeline run record."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            INSERT INTO pipeline_runs (pipeline_id, user_id, initial_input)
            VALUES (%s, %s, %s)
            RETURNING *
            """,
            (pipeline_id, user_id, initial_input),
        )
        row = await cur.fetchone()
    return _row_to_run(dict(row))


async def get_pipeline_run(run_id: int, user_id: str) -> dict | None:
    """Fetch a pipeline run by ID scoped to user_id."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            "SELECT * FROM pipeline_runs WHERE id = %s AND user_id = %s",
            (run_id, user_id),
        )
        row = await cur.fetchone()
    return _row_to_run(dict(row)) if row else None


async def list_pipeline_runs(
    pipeline_id: int, user_id: str, limit: int = 20
) -> list[dict]:
    """List recent runs for a pipeline."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            "SELECT * FROM pipeline_runs WHERE pipeline_id = %s AND user_id = %s "
            "ORDER BY started_at DESC LIMIT %s",
            (pipeline_id, user_id, limit),
        )
        rows = await cur.fetchall()
    return [_row_to_run(dict(r)) for r in rows]


async def update_pipeline_run_step(
    run_id: int,
    current_step: int,
    step_results: list[dict],
) -> None:
    """Update current_step and step_results after a step finishes."""
    pool = get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            "UPDATE pipeline_runs SET current_step = %s, step_results = %s::jsonb "
            "WHERE id = %s",
            (current_step, json.dumps(step_results), run_id),
        )


async def finalize_pipeline_run(
    run_id: int,
    status: str,
    step_results: list[dict],
) -> None:
    """Mark a pipeline run as complete or failed."""
    pool = get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            "UPDATE pipeline_runs SET status = %s, step_results = %s::jsonb, "
            "completed_at = now() WHERE id = %s",
            (status, json.dumps(step_results), run_id),
        )


# ── Phase 39: Task Timeline ────────────────────────────────────────────────────


async def record_task_event(
    task_id: str,
    event_type: str,
    metadata: dict | None = None,
) -> None:
    """
    Insert a timeline event for a task.

    Args:
        task_id:    The task UUID (string).
        event_type: Short label for the transition, e.g. 'queued', 'running',
                    'complete', 'failed', 'cancelled', 'dependency_failed'.
        metadata:   Optional JSONB payload (run_id, steps, error, etc.).
    """
    pool = get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO task_events (task_id, event_type, metadata) "
            "VALUES (%s::uuid, %s, %s::jsonb)",
            (task_id, event_type, json.dumps(metadata or {})),
        )


async def get_task_timeline(task_id: str, user_id: str) -> list[dict]:
    """
    Return the ordered timeline of events for a task, user-scoped.

    Returns an empty list if the task does not exist or belongs to another user.
    Events are ordered oldest-first (ts ASC).

    Args:
        task_id: The task UUID (string).
        user_id: The requesting user's ID — used to enforce ownership.

    Returns:
        List of dicts with keys: id, event_type, metadata, ts.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            SELECT e.id, e.event_type, e.metadata, e.ts
            FROM task_events e
            JOIN tasks t ON t.task_id = e.task_id
            WHERE e.task_id = %s::uuid
              AND t.user_id = %s
            ORDER BY e.ts ASC, e.id ASC
            """,
            (task_id, user_id),
        )
        rows = await cur.fetchall()
    return [
        {
            **dict(r),
            "ts": r["ts"].isoformat() if hasattr(r["ts"], "isoformat") else r["ts"],
        }
        for r in rows
    ]


# ── Phase 44: Task Stats & Analytics ─────────────────────────────────────────


async def get_task_stats(user_id: str) -> dict:
    """
    Return aggregate task statistics for user_id.

    Stats computed:
    - total: total task count
    - by_status: {status: count} dict
    - by_agent_type: {agent_type: count} dict
    - avg_steps: average step count for completed tasks
    - total_input_tokens: sum of input tokens (from tokens JSONB column)
    - total_output_tokens: sum of output tokens
    - top_tags: up to 10 most-used tags with counts
    - last_task_at: timestamp of the most recent task
    - oldest_task_at: timestamp of the oldest task

    Phase 44 — Task Stats & Analytics.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row

        # Counts by status
        cur = await conn.execute(
            """
            SELECT status, COUNT(*) AS cnt
            FROM tasks
            WHERE user_id = %s
            GROUP BY status
            """,
            (user_id,),
        )
        by_status_rows = await cur.fetchall()
        by_status = {r["status"]: r["cnt"] for r in by_status_rows}
        total = sum(by_status.values())

        # Counts by agent_type
        cur = await conn.execute(
            """
            SELECT agent_type, COUNT(*) AS cnt
            FROM tasks
            WHERE user_id = %s
            GROUP BY agent_type
            """,
            (user_id,),
        )
        by_agent_rows = await cur.fetchall()
        by_agent = {r["agent_type"]: r["cnt"] for r in by_agent_rows}

        # Average steps for complete tasks
        cur = await conn.execute(
            """
            SELECT ROUND(AVG(steps)::numeric, 2) AS avg_steps
            FROM tasks
            WHERE user_id = %s AND status = 'complete' AND steps IS NOT NULL
            """,
            (user_id,),
        )
        avg_row = await cur.fetchone()
        avg_steps = (
            float(avg_row["avg_steps"]) if avg_row and avg_row["avg_steps"] else 0.0
        )

        # Token totals (tokens is a JSONB column: {input: N, output: N})
        cur = await conn.execute(
            """
            SELECT
                COALESCE(SUM((tokens->>'input')::bigint), 0)  AS input_tokens,
                COALESCE(SUM((tokens->>'output')::bigint), 0) AS output_tokens
            FROM tasks
            WHERE user_id = %s AND tokens IS NOT NULL AND tokens != '{}'::jsonb
            """,
            (user_id,),
        )
        tok_row = await cur.fetchone()
        input_tokens = int(tok_row["input_tokens"]) if tok_row else 0
        output_tokens = int(tok_row["output_tokens"]) if tok_row else 0

        # Top tags (unnest TEXT[] and count occurrences)
        cur = await conn.execute(
            """
            SELECT tag, COUNT(*) AS cnt
            FROM tasks, UNNEST(tags) AS tag
            WHERE user_id = %s
            GROUP BY tag
            ORDER BY cnt DESC
            LIMIT 10
            """,
            (user_id,),
        )
        tag_rows = await cur.fetchall()
        top_tags = [{"tag": r["tag"], "count": r["cnt"]} for r in tag_rows]

        # First/last task timestamps
        cur = await conn.execute(
            """
            SELECT MIN(created_at) AS oldest, MAX(created_at) AS newest
            FROM tasks WHERE user_id = %s
            """,
            (user_id,),
        )
        ts_row = await cur.fetchone()
        oldest_at = (
            ts_row["oldest"].isoformat() if ts_row and ts_row["oldest"] else None
        )
        newest_at = (
            ts_row["newest"].isoformat() if ts_row and ts_row["newest"] else None
        )

    return {
        "total": total,
        "by_status": by_status,
        "by_agent_type": by_agent,
        "avg_steps_completed": avg_steps,
        "total_input_tokens": input_tokens,
        "total_output_tokens": output_tokens,
        "top_tags": top_tags,
        "oldest_task_at": oldest_at,
        "last_task_at": newest_at,
    }


# ── Phase 46: Task Watchdog ────────────────────────────────────────────────────


async def reap_stuck_tasks(timeout_seconds: int = 1800) -> int:
    """
    Find tasks stuck in 'running' state for longer than timeout_seconds and
    mark them 'failed' with an automated error message.

    Returns the number of tasks reaped.

    A task is considered stuck if its updated_at timestamp is older than
    timeout_seconds ago.  This catches worker crashes mid-task.

    Phase 46 — Task Watchdog.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            UPDATE tasks
            SET status = 'failed',
                error  = 'Task timed out — reaped by watchdog after '
                         || %s || ' seconds',
                completed_at = now(),
                updated_at   = now()
            WHERE status = 'running'
              AND updated_at < now() - (%s || ' seconds')::interval
            RETURNING task_id::text
            """,
            (timeout_seconds, timeout_seconds),
        )
        rows = await cur.fetchall()
        # Record timeline events for each reaped task
        for row in rows:
            try:
                await conn.execute(
                    "INSERT INTO task_events (task_id, event_type, metadata) "
                    "VALUES (%s::uuid, 'failed', %s::jsonb)",
                    (
                        row[0],
                        json.dumps(
                            {"error": f"Watchdog timeout after {timeout_seconds}s"}
                        ),
                    ),
                )
            except Exception:
                pass  # best-effort
        return len(rows)


# ── Phase 48: Webhook Registry ────────────────────────────────────────────────

VALID_WEBHOOK_EVENTS: frozenset[str] = frozenset(
    {"task_complete", "task_failed", "all"}
)


async def create_webhook(
    user_id: str,
    url: str,
    events: list[str],
    secret: str | None = None,
) -> dict:
    """Register a new webhook subscription for a user."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            INSERT INTO webhooks (user_id, url, events, secret)
            VALUES (%s, %s, %s, %s)
            RETURNING webhook_id, user_id, url, events, is_active, created_at
            """,
            (user_id, url, events, secret),
        )
        return dict(await cur.fetchone())


async def list_webhooks(user_id: str) -> list[dict]:
    """Return all webhook subscriptions for a user (secrets omitted)."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            SELECT webhook_id, user_id, url, events, is_active, created_at
            FROM webhooks
            WHERE user_id = %s
            ORDER BY created_at DESC
            """,
            (user_id,),
        )
        return [dict(r) for r in await cur.fetchall()]


async def delete_webhook(webhook_id: str, user_id: str) -> bool:
    """Delete a webhook subscription.  Returns True if deleted, False if not found."""
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            "DELETE FROM webhooks WHERE webhook_id = %s AND user_id = %s RETURNING webhook_id",
            (webhook_id, user_id),
        )
        return (await cur.fetchone()) is not None


async def get_user_webhooks_for_event(user_id: str, event: str) -> list[dict]:
    """Return active webhooks for a user that subscribe to a specific event."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            SELECT webhook_id, url, secret
            FROM webhooks
            WHERE user_id = %s
              AND is_active = true
              AND (events @> %s OR events @> '{all}')
            """,
            (user_id, [event]),
        )
        return [dict(r) for r in await cur.fetchall()]


# ── Phase 49: Task Attachments ────────────────────────────────────────────────

_MAX_ATTACHMENT_BYTES = 65_536  # 64 KB limit enforced here and at API layer


async def add_task_attachment(
    task_id: str,
    user_id: str,
    filename: str,
    data: str,
    content_type: str = "text/plain",
) -> dict:
    """
    Attach a text blob to a task.

    Returns the new attachment row (without ``data`` field to keep responses small).
    Raises ValueError if data exceeds _MAX_ATTACHMENT_BYTES or task not owned by user.
    """
    if len(data.encode()) > _MAX_ATTACHMENT_BYTES:
        raise ValueError(
            f"Attachment data exceeds maximum size of {_MAX_ATTACHMENT_BYTES} bytes"
        )
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        # Verify ownership: task must exist and belong to user
        cur = await conn.execute(
            "SELECT task_id FROM tasks WHERE task_id = %s::uuid AND user_id = %s",
            (task_id, user_id),
        )
        if await cur.fetchone() is None:
            raise ValueError(f"Task {task_id!r} not found or not owned by user")
        cur = await conn.execute(
            """
            INSERT INTO task_attachments (task_id, user_id, filename, content_type, data)
            VALUES (%s::uuid, %s, %s, %s, %s)
            RETURNING attachment_id, task_id::text, user_id, filename, content_type, created_at
            """,
            (task_id, user_id, filename, content_type, data),
        )
        return dict(await cur.fetchone())


async def list_task_attachments(task_id: str, user_id: str) -> list[dict]:
    """List attachments for a task (data field excluded for brevity)."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            SELECT attachment_id, task_id::text, user_id, filename, content_type, created_at
            FROM task_attachments
            WHERE task_id = %s::uuid AND user_id = %s
            ORDER BY created_at ASC
            """,
            (task_id, user_id),
        )
        return [dict(r) for r in await cur.fetchall()]


async def get_task_attachment(
    attachment_id: str, task_id: str, user_id: str
) -> dict | None:
    """Get a single attachment including its data field."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            SELECT attachment_id, task_id::text, user_id, filename, content_type, data, created_at
            FROM task_attachments
            WHERE attachment_id = %s AND task_id = %s::uuid AND user_id = %s
            """,
            (attachment_id, task_id, user_id),
        )
        row = await cur.fetchone()
        return dict(row) if row else None


async def delete_task_attachment(
    attachment_id: str, task_id: str, user_id: str
) -> bool:
    """Delete an attachment.  Returns True if deleted."""
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            "DELETE FROM task_attachments "
            "WHERE attachment_id = %s AND task_id = %s::uuid AND user_id = %s "
            "RETURNING attachment_id",
            (attachment_id, task_id, user_id),
        )
        return (await cur.fetchone()) is not None


# ── Phase 50: Task Templates ───────────────────────────────────────────────────


async def create_task_template(
    user_id: str,
    name: str,
    input_template: str,
    agent_type: str = "base_agent",
    description: str | None = None,
    default_tags: list[str] | None = None,
    default_priority: int = 5,
) -> dict:
    """Create a reusable task template.  Raises ValueError on duplicate name."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        try:
            cur = await conn.execute(
                """
                INSERT INTO task_templates
                    (user_id, name, description, agent_type, input_template,
                     default_tags, default_priority)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING template_id, user_id, name, description, agent_type,
                          input_template, default_tags, default_priority, created_at
                """,
                (
                    user_id,
                    name,
                    description,
                    agent_type,
                    input_template,
                    default_tags or [],
                    default_priority,
                ),
            )
            return dict(await cur.fetchone())
        except Exception as exc:
            if "unique" in str(exc).lower():
                raise ValueError(
                    f"Template name {name!r} already exists for this user"
                ) from exc
            raise


async def list_task_templates(user_id: str) -> list[dict]:
    """List all templates for a user."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            SELECT template_id, user_id, name, description, agent_type,
                   input_template, default_tags, default_priority, created_at
            FROM task_templates
            WHERE user_id = %s
            ORDER BY name ASC
            """,
            (user_id,),
        )
        return [dict(r) for r in await cur.fetchall()]


async def get_task_template(template_id: str, user_id: str) -> dict | None:
    """Get a single template by ID."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            SELECT template_id, user_id, name, description, agent_type,
                   input_template, default_tags, default_priority, created_at
            FROM task_templates
            WHERE template_id = %s AND user_id = %s
            """,
            (template_id, user_id),
        )
        row = await cur.fetchone()
        return dict(row) if row else None


async def delete_task_template(template_id: str, user_id: str) -> bool:
    """Delete a template.  Returns True if deleted."""
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            "DELETE FROM task_templates WHERE template_id = %s AND user_id = %s "
            "RETURNING template_id",
            (template_id, user_id),
        )
        return (await cur.fetchone()) is not None


# ── Phase 51: Task Sharing ─────────────────────────────────────────────────────


async def create_task_share(
    task_id: str,
    user_id: str,
    expires_at: "datetime | None" = None,
) -> dict:
    """
    Create a read-only share token for a task.

    Returns the new share row including the token.
    Raises ValueError if the task does not exist or is not owned by user.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            "SELECT task_id FROM tasks WHERE task_id = %s::uuid AND user_id = %s",
            (task_id, user_id),
        )
        if await cur.fetchone() is None:
            raise ValueError(f"Task {task_id!r} not found or not owned by user")
        token = secrets.token_urlsafe(24)
        cur = await conn.execute(
            """
            INSERT INTO task_shares (share_token, task_id, user_id, expires_at)
            VALUES (%s, %s::uuid, %s, %s)
            RETURNING share_token, task_id::text, user_id, expires_at, created_at
            """,
            (token, task_id, user_id, expires_at),
        )
        return dict(await cur.fetchone())


async def get_shared_task(share_token: str) -> dict | None:
    """
    Look up and return a shared task by its token.

    Returns None if the token is expired or does not exist.
    Only returns: task_id, agent_type, status, result, steps, created_at, completed_at.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            SELECT t.task_id::text, t.agent_type, t.status, t.result,
                   t.steps, t.created_at, t.completed_at
            FROM task_shares s
            JOIN tasks t ON t.task_id = s.task_id
            WHERE s.share_token = %s
              AND (s.expires_at IS NULL OR s.expires_at > now())
            """,
            (share_token,),
        )
        row = await cur.fetchone()
        return dict(row) if row else None


async def list_task_shares(task_id: str, user_id: str) -> list[dict]:
    """List all share tokens for a task owned by user."""
    pool = get_pool()
    async with pool.connection() as conn:
        conn.row_factory = dict_row
        cur = await conn.execute(
            """
            SELECT share_token, task_id::text, user_id, expires_at, created_at
            FROM task_shares
            WHERE task_id = %s::uuid AND user_id = %s
            ORDER BY created_at DESC
            """,
            (task_id, user_id),
        )
        return [dict(r) for r in await cur.fetchall()]


async def revoke_task_share(share_token: str, user_id: str) -> bool:
    """Revoke a share token.  Returns True if deleted."""
    pool = get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            "DELETE FROM task_shares WHERE share_token = %s AND user_id = %s "
            "RETURNING share_token",
            (share_token, user_id),
        )
        return (await cur.fetchone()) is not None
