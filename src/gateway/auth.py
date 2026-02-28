"""
src/gateway/auth.py
────────────────────
Bearer-token authentication for the Phase 8 gateway.

Each gateway user has a long-lived API key (random hex string) that is stored
only as a bcrypt hash in gateway_users.api_key_hash.  On every request the raw
key is passed as  Authorization: Bearer <key>, extracted here, and compared
against the stored hashes.

Stream tokens:
  EventSource (browser SSE) cannot set Authorization headers.  After POST /tasks
  the response includes a short-lived stream_token (30-minute TTL).  The SSE
  endpoint accepts either the Bearer token or a stream_token query param.
  Stream tokens are stored in an in-memory dict (sufficient at household scale).

Key API:
    extract_bearer_token(header: str | None) -> str | None
    authenticate(raw_key: str) -> dict | None          # returns user row
    require_user(request) -> dict                      # FastAPI dependency
    create_stream_token(task_id, user_id) -> str
    resolve_stream_token(token) -> tuple[str,str]|None # (task_id, user_id)
"""

from __future__ import annotations

import secrets
import logging
from typing import Optional, Protocol, runtime_checkable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

import bcrypt as _bcrypt

from src.database import (
    get_gateway_user_for_auth,
    create_stream_token as _db_create_stream_token,
    resolve_stream_token as _db_resolve_stream_token,
    delete_stream_token as _db_delete_stream_token,
)

logger = logging.getLogger(__name__)


# ── Auth backend protocol ──────────────────────────────────────────────────────


@runtime_checkable
class AuthBackend(Protocol):
    """
    Auth backend protocol. Implement to add OAuth, LDAP, JWT, or other schemes.
    See docs/SCALING.md for the OAuth integration pattern.

    The returned user dict must include:
        user_id, username, is_active (implicit True), daily_token_limit
    """

    async def authenticate(self, api_key: str) -> dict | None:
        """Verify credentials. Returns user dict or None on failure."""
        ...


class ApiKeyBackend:
    """Default backend: bcrypt-hashed API keys in the gateway_users table."""

    async def authenticate(self, api_key: str) -> dict | None:
        rows = await get_gateway_user_for_auth(api_key)
        for row in rows:
            if verify_api_key(api_key, row["api_key_hash"]):
                return {
                    "user_id": row["user_id"],
                    "username": row["username"],
                    "daily_token_limit": row.get("daily_token_limit", 100000),
                }
        return None


_auth_backend: AuthBackend | None = None


def get_auth_backend() -> AuthBackend:
    """Return the active auth backend (default: ApiKeyBackend)."""
    global _auth_backend
    if _auth_backend is None:
        _auth_backend = ApiKeyBackend()
    return _auth_backend


def set_auth_backend(backend: AuthBackend) -> None:
    """
    Inject a custom auth backend at startup. Example::

        set_auth_backend(GitHubOAuthBackend(client_id=..., client_secret=...))

    See docs/SCALING.md for the OAuth integration pattern.
    """
    global _auth_backend
    _auth_backend = backend


# ── API key hashing (bcrypt, used directly — passlib 1.7 is incompatible with bcrypt 5.x) ───


def hash_api_key(raw_key: str) -> str:
    """Return bcrypt hash of a raw API key (stored in gateway_users.api_key_hash)."""
    return _bcrypt.hashpw(raw_key.encode(), _bcrypt.gensalt()).decode()


def verify_api_key(raw_key: str, hashed: str) -> bool:
    """Constant-time verification of raw key against stored bcrypt hash."""
    try:
        return _bcrypt.checkpw(raw_key.encode(), hashed.encode())
    except Exception:
        return False


# ── Bearer token extraction ───────────────────────────────────────────────────

_bearer_scheme = HTTPBearer(auto_error=False)


def extract_bearer_token(authorization: str | None) -> str | None:
    """
    Extract the raw token from an Authorization header value.

    Returns None for missing or malformed headers.
    Accepted format: "Bearer <token>"
    """
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token if token else None


# ── User lookup ───────────────────────────────────────────────────────────────


async def authenticate(raw_key: str) -> dict | None:
    """
    Verify a raw API key via the active auth backend.

    Delegates to get_auth_backend().authenticate(). The default backend
    (ApiKeyBackend) checks bcrypt-hashed keys in the gateway_users table.
    Swap backends via set_auth_backend() at startup to add OAuth, LDAP, etc.
    """
    return await get_auth_backend().authenticate(raw_key)


# ── FastAPI dependency ────────────────────────────────────────────────────────


async def require_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> dict:
    """
    FastAPI dependency: extract and verify Bearer token.
    Raises 401 on missing/invalid token.
    """
    raw_key: str | None = None

    if credentials:
        raw_key = credentials.credentials
    else:
        # Fallback: check Authorization header manually (handles edge cases)
        raw_key = extract_bearer_token(request.headers.get("authorization"))

    if not raw_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await authenticate(raw_key)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


# ── Stream tokens (DB-backed, 30-minute TTL) ──────────────────────────────────
# Phase 10 migrated stream tokens from an in-memory dict to the stream_tokens
# DB table so they survive gateway restarts.  The worker heartbeat purges
# expired rows every 10 minutes via purge_expired_stream_tokens().

_STREAM_TOKEN_TTL = 30 * 60  # 30 minutes, in seconds


async def create_stream_token(task_id: str, user_id: str) -> str:
    """
    Issue a short-lived stream token for SSE access from browser clients.

    The token is persisted in the stream_tokens DB table so it survives a
    gateway restart.  TTL is enforced by comparing expires_at to NOW() on
    every resolve call.

    Args:
        task_id: The task this token grants access to stream.
        user_id: The user who submitted the task.

    Returns:
        URL-safe random token string (32 bytes of entropy).
    """
    token = secrets.token_urlsafe(32)
    await _db_create_stream_token(token, task_id, user_id, _STREAM_TOKEN_TTL)
    return token


async def resolve_stream_token(token: str) -> tuple[str, str] | None:
    """
    Resolve a DB-backed stream token to (task_id, user_id).

    Returns None if the token is unknown or has expired.  Does NOT consume
    (delete) the token so EventSource clients can reconnect within the TTL.

    Args:
        token: Raw stream token string from the query param.

    Returns:
        (task_id, user_id) tuple, or None if invalid/expired.
    """
    return await _db_resolve_stream_token(token)


async def delete_stream_token(token: str) -> None:
    """Explicitly delete a stream token (e.g. on task cancellation)."""
    await _db_delete_stream_token(token)
