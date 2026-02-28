"""
tests/conftest.py
─────────────────
Pytest configuration and shared fixtures.

Smoke fixtures: settings (session-scoped, no services required)
Integration fixtures: db, test_user, auth_headers, gateway_client
  (require PostgreSQL — only used by tests/test_integration.py)
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (require running services)"
    )
    config.addinivalue_line("markers", "integration: marks tests requiring PostgreSQL")
    config.addinivalue_line(
        "markers", "ollama: marks tests requiring a live Ollama instance"
    )
    config.addinivalue_line(
        "markers", "unit: marks pure unit tests with no external dependencies"
    )

    # Inject a deterministic test secret for JWT task tokens so smoke tests that
    # exercise ACL/Guardian token validation never hit the macOS Keychain.
    # This is a test-only value — production always reads from Keychain.
    if not os.environ.get("TASK_TOKEN_SECRET"):
        os.environ.setdefault(
            "TASK_TOKEN_SECRET", "smoke-test-secret-for-legionforge-32!!"
        )


@pytest.fixture(scope="session")
def settings():
    from config.settings import settings as s

    return s


# ── Integration fixtures (PostgreSQL required) ────────────────────────────────
# These are only exercised by tests/test_integration.py (@pytest.mark.integration).
# Smoke tests never import these fixtures.


async def _make_admin_conn():
    """
    Create a direct psycopg admin connection for test fixture setup/teardown.

    Why admin, not get_pool()?  legionforge_app has INSERT+UPDATE on tasks and
    gateway_users but NOT DELETE (by RBAC design — runtime code should never bulk-
    delete tasks or users).  Test fixtures need to clean up after themselves, so
    they connect as the admin user instead.

    Reads credentials the same way init_db() does (CredentialStore → env var).
    """
    import psycopg
    from psycopg.rows import dict_row
    from src.database import _get_postgres_password, _build_conninfo_no_password

    return await psycopg.AsyncConnection.connect(
        _build_conninfo_no_password(),
        password=_get_postgres_password(),
        row_factory=dict_row,
        autocommit=True,
    )


try:
    import pytest_asyncio as _pytest_asyncio

    @_pytest_asyncio.fixture(scope="session")
    async def db():
        """Initialize DB pool once per integration test session."""
        from src.database import init_db

        await init_db()
        yield
        # Pool stays open; PostgreSQL service handles shutdown

    @_pytest_asyncio.fixture
    async def test_user(db):
        """Create a throwaway gateway_user row; clean up after each test.

        Uses an admin connection for all DB operations because legionforge_app
        does not have DELETE on tasks, api_usage, or gateway_users by design.
        """
        import secrets
        import uuid
        import bcrypt

        username = f"itest_{secrets.token_hex(4)}"
        raw_key = secrets.token_urlsafe(32)
        hashed = bcrypt.hashpw(raw_key.encode(), bcrypt.gensalt(rounds=4)).decode()
        user_id = str(uuid.uuid4())

        conn = await _make_admin_conn()
        try:
            await conn.execute(
                "INSERT INTO gateway_users"
                " (user_id, username, api_key_hash, daily_token_limit)"
                " VALUES (%s, %s, %s, %s)",
                (user_id, username, hashed, 100000),
            )
        finally:
            await conn.close()

        yield {"username": username, "api_key": raw_key, "user_id": user_id}

        conn = await _make_admin_conn()
        try:
            for tbl in ("stream_tokens", "tasks", "api_usage"):
                await conn.execute(f"DELETE FROM {tbl} WHERE user_id = %s", (user_id,))
            await conn.execute(
                "DELETE FROM gateway_users WHERE user_id = %s", (user_id,)
            )
        finally:
            await conn.close()

    @pytest.fixture
    def auth_headers(test_user):
        """Authorization header dict for the ephemeral test_user."""
        return {"Authorization": f"Bearer {test_user['api_key']}"}

    @_pytest_asyncio.fixture
    async def gateway_client(db):
        """Async HTTPX test client wired to the gateway ASGI app."""
        from httpx import AsyncClient, ASGITransport
        from src.gateway.app import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            yield client

    @_pytest_asyncio.fixture
    async def admin_conn():
        """Admin DB connection for integration tests that need DELETE access."""
        conn = await _make_admin_conn()
        yield conn
        await conn.close()

except ImportError:
    # pytest_asyncio not installed — integration fixtures unavailable (smoke runs fine)
    pass
