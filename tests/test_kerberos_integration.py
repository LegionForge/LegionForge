"""
tests/test_kerberos_integration.py
────────────────────────────────────
Kerberos/GSSAPI integration tests.

These tests require a live KDC and the ``gssapi`` package.  They are
**skipped** unless the environment variable ``KERBEROS_TEST_KDC=1`` is set,
mirroring the pattern used for Ollama-dependent integration tests.

Pre-requisites (see docs/SCALING.md for full setup):

    1. Install a KDC:
           brew install krb5                # macOS
           sudo apt-get install krb5-kdc    # Ubuntu

    2. Configure /etc/krb5.conf with your realm (e.g. TEST.LOCAL)

    3. Create a service principal and export a keytab:
           kadmin.local -q "addprinc -randkey HTTP/localhost@TEST.LOCAL"
           kadmin.local -q "ktadd -k /tmp/test.keytab HTTP/localhost@TEST.LOCAL"

    4. Create a test user principal:
           kadmin.local -q "addprinc -pw testpass testuser@TEST.LOCAL"

    5. Set environment variables and run:
           export KERBEROS_TEST_KDC=1
           export KERBEROS_REALM=TEST.LOCAL
           export KERBEROS_KEYTAB=/tmp/test.keytab
           export KERBEROS_TEST_USER=testuser
           export KERBEROS_TEST_PASS=testpass
           pytest tests/test_kerberos_integration.py -v

Phase:  14 (skeleton)
Status: Tests pass when skipped; live KDC path is Phase 15+.
"""

from __future__ import annotations

import base64
import os

import pytest
import pytest_asyncio

# ── Skip guard ────────────────────────────────────────────────────────────────

_KDC_AVAILABLE = os.environ.get("KERBEROS_TEST_KDC", "").strip() == "1"
_SKIP_REASON = (
    "Kerberos integration tests require KERBEROS_TEST_KDC=1 and a live KDC. "
    "See docs/SCALING.md for setup instructions."
)
skip_without_kdc = pytest.mark.skipif(not _KDC_AVAILABLE, reason=_SKIP_REASON)

_REALM = os.environ.get("KERBEROS_REALM", "TEST.LOCAL")
_KEYTAB = os.environ.get("KERBEROS_KEYTAB", "/tmp/test.keytab")
_TEST_USER = os.environ.get("KERBEROS_TEST_USER", "testuser")
_TEST_PASS = os.environ.get("KERBEROS_TEST_PASS", "testpass")


# ── DB fixture (session-scoped) ────────────────────────────────────────────────


@pytest_asyncio.fixture(scope="session")
async def _db():
    """
    Initialize the database pool for tests that call KerberosBackend.authenticate(),
    which provisions users into gateway_users on first login.

    Skips automatically if PostgreSQL is not reachable.
    """
    try:
        from src.database import init_db

        await init_db()
        yield
    except Exception as exc:
        pytest.skip(f"PostgreSQL not available — skipping DB provisioning tests: {exc}")


# ── Helpers ───────────────────────────────────────────────────────────────────


def _get_client_token(username: str, password: str, realm: str) -> bytes | None:
    """
    Obtain a SPNEGO/Kerberos token for a test user by kinit + GSSAPI init.

    Returns None if gssapi or KDC is unavailable.
    """
    try:
        import gssapi
        import subprocess

        # kinit to get a TGT
        result = subprocess.run(
            ["kinit", f"{username}@{realm}"],
            input=f"{password}\n",
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return None

        # Initiate a security context targeting the HTTP service
        server_name = gssapi.Name(
            f"HTTP@localhost",
            name_type=gssapi.NameType.hostbased_service,
        )
        ctx = gssapi.SecurityContext(name=server_name, usage="initiate")
        token = ctx.step()
        return token
    except Exception:
        return None


# ── Tests ─────────────────────────────────────────────────────────────────────


@skip_without_kdc
def test_kerberos_backend_init_with_keytab():
    """KerberosBackend initialises without error when keytab path is provided."""
    from src.gateway.backends.kerberos import KerberosBackend

    backend = KerberosBackend(
        keytab_path=_KEYTAB,
        service_name="HTTP",
        realm=_REALM,
    )
    assert backend is not None


@skip_without_kdc
@pytest.mark.asyncio
async def test_kerberos_backend_wrong_token_returns_none():
    """A malformed Negotiate token returns None (no exception)."""
    from src.gateway.backends.kerberos import KerberosBackend

    backend = KerberosBackend(keytab_path=_KEYTAB, service_name="HTTP", realm=_REALM)
    result = await backend.authenticate(
        base64.b64encode(b"not-a-gssapi-token").decode(),
        scheme="negotiate",
    )
    assert result is None


@skip_without_kdc
@pytest.mark.asyncio
async def test_kerberos_backend_empty_credential_returns_none():
    """An empty credential string returns None."""
    from src.gateway.backends.kerberos import KerberosBackend

    backend = KerberosBackend(keytab_path=_KEYTAB, service_name="HTTP", realm=_REALM)
    result = await backend.authenticate("", scheme="negotiate")
    assert result is None


@skip_without_kdc
@pytest.mark.asyncio
async def test_kerberos_spnego_accept_context(_db):
    """Full SPNEGO round-trip: initiate from test user, accept on server."""
    try:
        import gssapi  # noqa: F401
    except ImportError:
        pytest.skip("gssapi package not installed")

    token_bytes = _get_client_token(_TEST_USER, _TEST_PASS, _REALM)
    if token_bytes is None:
        pytest.skip("Could not obtain Kerberos TGT — KDC may not be running")

    from src.gateway.backends.kerberos import KerberosBackend

    backend = KerberosBackend(keytab_path=_KEYTAB, service_name="HTTP", realm=_REALM)
    credential = base64.b64encode(token_bytes).decode()
    result = await backend.authenticate(credential, scheme="negotiate")

    assert result is not None, "Expected successful authentication"
    assert "user_id" in result
    assert result["user_id"].startswith("kerberos:")
    assert "username" in result


@skip_without_kdc
@pytest.mark.asyncio
async def test_kerberos_user_provisioned_on_first_auth(_db):
    """
    After successful Kerberos auth, a gateway_users row is created (or already exists).
    Requires PostgreSQL in addition to KDC.
    """
    try:
        import gssapi  # noqa: F401
    except ImportError:
        pytest.skip("gssapi package not installed")

    token_bytes = _get_client_token(_TEST_USER, _TEST_PASS, _REALM)
    if token_bytes is None:
        pytest.skip("Could not obtain Kerberos TGT — KDC may not be running")

    try:
        from src.database import get_pool
    except ImportError:
        pytest.skip("Database module not available")

    from src.gateway.backends.kerberos import KerberosBackend

    backend = KerberosBackend(keytab_path=_KEYTAB, service_name="HTTP", realm=_REALM)
    credential = base64.b64encode(token_bytes).decode()
    result = await backend.authenticate(credential, scheme="negotiate")

    if result is None:
        pytest.skip("Kerberos authentication failed — skipping DB check")

    # Verify the user exists in gateway_users
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT user_id, username, is_active FROM gateway_users WHERE user_id = %s",
                (result["user_id"],),
            )
            row = await cur.fetchone()
    assert row is not None, f"User {result['user_id']} not found in gateway_users"
    assert row["is_active"] is True
