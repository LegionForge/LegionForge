"""
src/agents/synthetic_env.py
───────────────────────────
Isolated synthetic environment for PentestAgent runs.

The SyntheticEnvironment provides:
  1. A separate PostgreSQL database (`legionforge_pentest`) with the same
     schema as production — but completely isolated from production data.
  2. Three seeded synthetic tools with known hashes — so tool-poisoning
     tests can tamper with them without touching the real tool_registry.
  3. A stub Ollama HTTP server that returns deterministic canned responses —
     attack tests that involve LLM calls get predictable output, no cost.
  4. Stub credentials (fake API keys) — the pentest container NEVER touches
     real Keychain or production secrets.

Usage (async context manager):

    async with SyntheticEnvironment() as env:
        creds = env.get_stub_credentials()
        await env.register_synthetic_tool("fake_web_search", b"fake_body_1")
        # ... run attack tests ...

Air-gap note:
  Network isolation is enforced at the Docker container layer via
  ``--network none``. SyntheticEnvironment itself adds a defence-in-depth
  layer by never requesting real credentials, but the true guarantee is
  the OS-level container isolation — not this class.
"""

from __future__ import annotations

import asyncio
import hashlib
import http.server
import json
import logging
import os
import secrets
import string
import threading
from contextlib import asynccontextmanager
from typing import Any

import psycopg

from config.settings import settings

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_STUB_CREDS: dict[str, str] = {
    "openai": "sk-STUB-" + "x" * 32,
    "anthropic": "sk-ant-STUB-" + "x" * 32,
    "langsmith": "ls__STUB-" + "x" * 32,
}

# Three synthetic tools seeded in the pentest DB.
# Pentest tests that target tool-poisoning use these — never production tools.
_SYNTHETIC_TOOLS: list[dict[str, Any]] = [
    {
        "tool_id": "pt_web_search",
        "tool_name": "Pentest Web Search",
        "description": "Synthetic web search stub for pentest isolation",
        "schema_hash": hashlib.sha256(b"pt_web_search_v1").hexdigest(),
        "status": "APPROVED",
    },
    {
        "tool_id": "pt_code_exec",
        "tool_name": "Pentest Code Executor",
        "description": "Synthetic code execution stub for pentest isolation",
        "schema_hash": hashlib.sha256(b"pt_code_exec_v1").hexdigest(),
        "status": "APPROVED",
    },
    {
        "tool_id": "pt_file_read",
        "tool_name": "Pentest File Reader",
        "description": "Synthetic file read stub for pentest isolation",
        "schema_hash": hashlib.sha256(b"pt_file_read_v1").hexdigest(),
        "status": "APPROVED",
    },
]


# ── Stub Ollama HTTP server ───────────────────────────────────────────────────


class _StubOllamaHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP handler that mimics the Ollama /api/chat endpoint.

    Returns a canned, deterministic response — no real model calls.
    Pentest attack tests that involve LLM inputs use this stub so tests
    are fast, free, and reproducible.
    """

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        _body = self.rfile.read(length)
        response = json.dumps(
            {
                "model": "stub",
                "message": {
                    "role": "assistant",
                    "content": "STUB_RESPONSE: I am a deterministic pentest stub.",
                },
                "done": True,
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *args: Any) -> None:  # noqa: ANN002
        # Suppress access log noise during pentest runs
        pass


# ── SyntheticEnvironment ─────────────────────────────────────────────────────


class SyntheticEnvironment:
    """
    Isolated pentest environment: ephemeral DB + stub Ollama + fake credentials.

    Lifecycle:
        __aenter__  →  create pentest DB → seed tools → start stub Ollama
        __aexit__   →  stop stub Ollama → drop pentest DB

    The synthetic DB is always dropped on exit to prevent state bleed
    between pentest runs.
    """

    def __init__(self) -> None:
        self._db_name: str = settings.pentest.synthetic_db_name
        self._stub_port: int = settings.pentest.stub_ollama_port
        self._stub_server: http.server.HTTPServer | None = None
        self._stub_thread: threading.Thread | None = None
        self._pool: psycopg.AsyncConnection | None = None  # admin connection

    # ── Context manager ───────────────────────────────────────────────────────

    async def __aenter__(self) -> "SyntheticEnvironment":
        logger.info(f"[SyntheticEnv] Setting up: db={self._db_name}")
        await self._init_pentest_db()
        await self._seed_synthetic_tools()
        self._start_stub_ollama()
        logger.info("[SyntheticEnv] Ready")
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        logger.info("[SyntheticEnv] Tearing down")
        self._stop_stub_ollama()
        await self._drop_pentest_db()
        logger.info("[SyntheticEnv] Torn down")

    # ── Database setup ────────────────────────────────────────────────────────

    async def _get_admin_dsn(self) -> str:
        """Build admin DSN (connects to 'postgres' maintenance DB)."""
        host = os.environ.get("POSTGRES_HOST", "localhost")
        port = int(os.environ.get("POSTGRES_PORT", "5432"))
        user = os.environ.get("POSTGRES_USER", os.environ.get("USER", "postgres"))
        password = os.environ.get("POSTGRES_PASSWORD", "")
        return (
            f"host={host} port={port} dbname=postgres "
            f"user={user} password={password}"
        )

    async def _get_pentest_dsn(self) -> str:
        """Build DSN for the synthetic pentest database."""
        host = os.environ.get("POSTGRES_HOST", "localhost")
        port = int(os.environ.get("POSTGRES_PORT", "5432"))
        user = os.environ.get("POSTGRES_USER", os.environ.get("USER", "postgres"))
        password = os.environ.get("POSTGRES_PASSWORD", "")
        return (
            f"host={host} port={port} dbname={self._db_name} "
            f"user={user} password={password}"
        )

    async def _init_pentest_db(self) -> None:
        """Create the synthetic DB and minimal schema for pentest tests."""
        dsn = await self._get_admin_dsn()
        # autocommit required for CREATE DATABASE
        conn = await psycopg.AsyncConnection.connect(dsn, autocommit=True)
        try:
            # Drop and recreate to guarantee a clean slate
            await conn.execute(f"DROP DATABASE IF EXISTS {self._db_name}")  # noqa: S608
            await conn.execute(f"CREATE DATABASE {self._db_name}")
            logger.info(f"[SyntheticEnv] Created database '{self._db_name}'")
        finally:
            await conn.close()

        # Connect to the new DB and create minimal schema
        pentest_dsn = await self._get_pentest_dsn()
        pconn = await psycopg.AsyncConnection.connect(pentest_dsn, autocommit=True)
        try:
            await pconn.execute(
                """
                CREATE TABLE IF NOT EXISTS tool_registry (
                    tool_id     TEXT PRIMARY KEY,
                    tool_name   TEXT NOT NULL,
                    description TEXT,
                    schema_hash TEXT NOT NULL,
                    status      TEXT NOT NULL DEFAULT 'PENDING',
                    created_at  TIMESTAMPTZ DEFAULT NOW(),
                    revoked_at  TIMESTAMPTZ,
                    revoked_by  TEXT,
                    revocation_reason TEXT
                )
                """
            )
            await pconn.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_events (
                    id          BIGSERIAL PRIMARY KEY,
                    ts          TIMESTAMPTZ DEFAULT NOW(),
                    agent_id    TEXT NOT NULL,
                    run_id      TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    confidence  FLOAT,
                    raw_input   TEXT,
                    action_taken TEXT,
                    metadata    JSONB DEFAULT '{}'
                )
                """
            )
            logger.info(f"[SyntheticEnv] Schema created in '{self._db_name}'")
        finally:
            await pconn.close()

    async def _drop_pentest_db(self) -> None:
        """Drop the synthetic DB on teardown."""
        try:
            dsn = await self._get_admin_dsn()
            conn = await psycopg.AsyncConnection.connect(dsn, autocommit=True)
            try:
                # Terminate active connections before dropping
                await conn.execute(
                    f"""
                    SELECT pg_terminate_backend(pid)
                    FROM pg_stat_activity
                    WHERE datname = '{self._db_name}' AND pid <> pg_backend_pid()
                    """
                )
                await conn.execute(
                    f"DROP DATABASE IF EXISTS {self._db_name}"  # noqa: S608
                )
                logger.info(f"[SyntheticEnv] Dropped database '{self._db_name}'")
            finally:
                await conn.close()
        except Exception as e:
            logger.warning(f"[SyntheticEnv] Could not drop DB '{self._db_name}': {e}")

    # ── Tool seeding ──────────────────────────────────────────────────────────

    async def _seed_synthetic_tools(self) -> None:
        """Insert the three synthetic tool stubs into the pentest tool_registry."""
        pentest_dsn = await self._get_pentest_dsn()
        conn = await psycopg.AsyncConnection.connect(pentest_dsn, autocommit=True)
        try:
            for tool in _SYNTHETIC_TOOLS:
                await conn.execute(
                    """
                    INSERT INTO tool_registry (tool_id, tool_name, description, schema_hash, status)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (tool_id) DO UPDATE
                        SET schema_hash = EXCLUDED.schema_hash,
                            status      = EXCLUDED.status
                    """,
                    (
                        tool["tool_id"],
                        tool["tool_name"],
                        tool["description"],
                        tool["schema_hash"],
                        tool["status"],
                    ),
                )
            logger.info(
                f"[SyntheticEnv] Seeded {len(_SYNTHETIC_TOOLS)} synthetic tools"
            )
        finally:
            await conn.close()

    async def register_synthetic_tool(
        self, tool_id: str, body: bytes, status: str = "APPROVED"
    ) -> str:
        """
        Register an additional synthetic tool mid-test.

        Args:
            tool_id: Unique tool identifier.
            body:    Raw bytes whose SHA256 becomes the schema_hash.
            status:  Registry status (APPROVED, PENDING, REJECTED, REVOKED).

        Returns:
            SHA256 hex string of ``body``.
        """
        schema_hash = hashlib.sha256(body).hexdigest()
        pentest_dsn = await self._get_pentest_dsn()
        conn = await psycopg.AsyncConnection.connect(pentest_dsn, autocommit=True)
        try:
            await conn.execute(
                """
                INSERT INTO tool_registry (tool_id, tool_name, description, schema_hash, status)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (tool_id) DO UPDATE
                    SET schema_hash = EXCLUDED.schema_hash,
                        status      = EXCLUDED.status
                """,
                (tool_id, tool_id, f"Synthetic tool: {tool_id}", schema_hash, status),
            )
        finally:
            await conn.close()
        return schema_hash

    async def tamper_tool_hash(self, tool_id: str) -> str:
        """
        Corrupt the schema_hash of a synthetic tool to simulate a rug-pull.

        Returns the corrupted hash string for assertion use in tests.
        """
        corrupted = "CORRUPTED_" + secrets.token_hex(16)
        pentest_dsn = await self._get_pentest_dsn()
        conn = await psycopg.AsyncConnection.connect(pentest_dsn, autocommit=True)
        try:
            await conn.execute(
                "UPDATE tool_registry SET schema_hash = %s WHERE tool_id = %s",
                (corrupted, tool_id),
            )
        finally:
            await conn.close()
        logger.info(f"[SyntheticEnv] Tampered hash for tool '{tool_id}'")
        return corrupted

    async def revoke_synthetic_tool(
        self, tool_id: str, reason: str = "pentest"
    ) -> None:
        """Mark a synthetic tool as REVOKED in the pentest DB."""
        pentest_dsn = await self._get_pentest_dsn()
        conn = await psycopg.AsyncConnection.connect(pentest_dsn, autocommit=True)
        try:
            await conn.execute(
                """
                UPDATE tool_registry
                SET status = 'REVOKED',
                    revoked_at = NOW(),
                    revoked_by = 'pentest',
                    revocation_reason = %s
                WHERE tool_id = %s
                """,
                (reason, tool_id),
            )
        finally:
            await conn.close()
        logger.info(f"[SyntheticEnv] Revoked synthetic tool '{tool_id}'")

    async def get_tool_hash(self, tool_id: str) -> str | None:
        """Return the current schema_hash for a synthetic tool, or None."""
        pentest_dsn = await self._get_pentest_dsn()
        conn = await psycopg.AsyncConnection.connect(pentest_dsn, autocommit=True)
        try:
            row = await conn.fetchone(
                "SELECT schema_hash FROM tool_registry WHERE tool_id = %s",
                (tool_id,),
            )
            return row[0] if row else None
        finally:
            await conn.close()

    # ── Stub Ollama ───────────────────────────────────────────────────────────

    def _start_stub_ollama(self) -> None:
        """Start the deterministic stub Ollama HTTP server in a daemon thread."""
        try:
            self._stub_server = http.server.HTTPServer(
                ("127.0.0.1", self._stub_port), _StubOllamaHandler
            )
            self._stub_thread = threading.Thread(
                target=self._stub_server.serve_forever,
                daemon=True,
                name="stub-ollama",
            )
            self._stub_thread.start()
            logger.info(
                f"[SyntheticEnv] Stub Ollama listening on port {self._stub_port}"
            )
        except OSError as e:
            # Port may already be in use if a previous test didn't clean up.
            logger.warning(
                f"[SyntheticEnv] Could not start stub Ollama on port {self._stub_port}: {e}"
            )
            self._stub_server = None
            self._stub_thread = None

    def _stop_stub_ollama(self) -> None:
        """Shut down the stub Ollama HTTP server."""
        if self._stub_server is not None:
            self._stub_server.shutdown()
            self._stub_server = None
            logger.info("[SyntheticEnv] Stub Ollama stopped")

    @property
    def stub_ollama_url(self) -> str:
        """Base URL for the stub Ollama server."""
        return f"http://127.0.0.1:{self._stub_port}"

    # ── Credentials ───────────────────────────────────────────────────────────

    def get_stub_credentials(self) -> dict[str, str]:
        """
        Return fake API keys for use inside pentest attack functions.

        These are syntactically plausible but are NOT valid keys.
        They are used to verify that the framework properly sanitises /
        redacts credentials without sending anything real to external services.

        Returns:
            Dict with keys: openai, anthropic, langsmith.
        """
        return dict(_STUB_CREDS)

    # ── Threat event query ────────────────────────────────────────────────────

    async def get_threat_events(self, run_id: str | None = None) -> list[dict]:
        """
        Return threat_events logged in the synthetic DB during the pentest run.

        Useful in attack tests to verify that the defense logged the expected
        threat type after an attack attempt.

        Args:
            run_id: Optional run_id filter.

        Returns:
            List of dicts with keys: ts, agent_id, run_id, threat_type,
            confidence, action_taken, metadata.
        """
        pentest_dsn = await self._get_pentest_dsn()
        conn = await psycopg.AsyncConnection.connect(pentest_dsn, autocommit=True)
        try:
            if run_id:
                rows = await conn.fetchall(
                    "SELECT * FROM threat_events WHERE run_id = %s ORDER BY ts ASC",
                    (run_id,),
                )
            else:
                rows = await conn.fetchall(
                    "SELECT * FROM threat_events ORDER BY ts ASC"
                )
            columns = [
                "id",
                "ts",
                "agent_id",
                "run_id",
                "threat_type",
                "confidence",
                "raw_input",
                "action_taken",
                "metadata",
            ]
            return [dict(zip(columns, row)) for row in rows]
        finally:
            await conn.close()
