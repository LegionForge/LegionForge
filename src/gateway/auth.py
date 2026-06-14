"""
src/gateway/auth.py
────────────────────
Authentication layer for the LegionForge gateway.

Phase 8–11: Bearer-token (bcrypt API keys) only.
Phase 12:   Multi-scheme: Bearer (api_key / OIDC / GitHub), Basic (LDAP),
            Negotiate (Kerberos scaffold).  The active backend is selected by
            ``settings.gateway.auth_provider`` and wired in the app lifespan.
Phase 13:   Stream token operations delegate to ``src.gateway.state`` which
            uses Redis when configured or the DB table when not.

Stream tokens:
  EventSource (browser SSE) cannot set Authorization headers.  After POST /tasks
  the response includes a short-lived stream_token (30-minute TTL).  The SSE
  endpoint accepts either the Bearer token or a stream_token query param.
  Phase 13: tokens are stored in Redis (multi-instance) or the stream_tokens
  DB table (single-instance fallback).

Public API:
    AuthBackend                          — Protocol (re-exported from backends)
    ApiKeyBackend                        — Default backend (re-exported from backends)
    get_auth_backend() -> AuthBackend    — Return active backend (lazy init)
    set_auth_backend(backend) -> None    — Swap backend at startup
    extract_bearer_token(header) -> str | None
    authenticate(credential, scheme) -> dict | None
    require_user(request) -> dict        — FastAPI dependency (multi-scheme)
    create_stream_token(task_id, user_id) -> str
    resolve_stream_token(token) -> tuple[str,str]|None
"""

from __future__ import annotations

import base64
import logging
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

import bcrypt as _bcrypt


# Phase 13: stream token operations route through state.py (Redis or DB fallback)
from src.gateway.state import (
    create_stream_token as _state_create_stream_token,
    resolve_stream_token as _state_resolve_stream_token,
    delete_stream_token as _state_delete_stream_token,
)

# Re-export from backends package so existing imports continue to work:
#   from src.gateway.auth import AuthBackend, ApiKeyBackend
from src.gateway.backends.base import AuthBackend  # noqa: F401
from src.gateway.backends.api_key import ApiKeyBackend  # noqa: F401

logger = logging.getLogger(__name__)


# ── Active backend singleton ───────────────────────────────────────────────────

_auth_backend: AuthBackend | None = None


def get_auth_backend() -> AuthBackend:
    """Return the active auth backend (default: ApiKeyBackend on lazy init)."""
    global _auth_backend
    if _auth_backend is None:
        _auth_backend = ApiKeyBackend()
    return _auth_backend


def set_auth_backend(backend: AuthBackend) -> None:
    """
    Inject a custom auth backend at startup.

    Called automatically by the gateway lifespan using
    ``load_backend_from_settings(settings)``.  Can also be called directly
    for testing or custom integrations::

        set_auth_backend(GitHubOAuthBackend())

    See docs/SCALING.md for integration examples.
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
    Extract the raw token from a Bearer Authorization header value.

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


async def authenticate(credential: str, scheme: str = "bearer") -> dict | None:
    """
    Verify a credential via the active auth backend.

    Delegates to get_auth_backend().authenticate(credential, scheme=scheme).
    The default backend (ApiKeyBackend) checks bcrypt-hashed keys in the
    gateway_users table.  Swap backends via set_auth_backend() at startup.
    """
    return await get_auth_backend().authenticate(credential, scheme=scheme)


# ── FastAPI dependency ────────────────────────────────────────────────────────


async def require_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> dict:
    """
    FastAPI dependency: extract and verify credentials from the Authorization header.

    Handles three schemes:
      Bearer    — OAuth access tokens, JWT access tokens, or API keys.
                  Authorization: Bearer <token>
      Basic     — LDAP username/password (base64-encoded "user:pass").
                  Authorization: Basic <base64>
      Negotiate — Kerberos/GSSAPI SPNEGO token (scaffold; Phase 13+).
                  Authorization: Negotiate <base64>

    The active auth backend (configured via ``settings.gateway.auth_provider``)
    must accept the presented scheme or it returns None → 401.

    Raises:
        HTTPException 401: Missing/unsupported header or invalid credentials.
    """
    auth_header: str = request.headers.get("authorization", "")
    lower = auth_header.lower()

    if lower.startswith("bearer "):
        credential = auth_header[7:].strip()
        scheme = "bearer"
    elif lower.startswith("basic "):
        try:
            decoded = base64.b64decode(auth_header[6:].strip()).decode(
                "utf-8", errors="replace"
            )
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Malformed Basic authorization header",
                headers={"WWW-Authenticate": "Bearer"},
            )
        credential = decoded
        scheme = "basic"
    elif lower.startswith("negotiate "):
        credential = auth_header[10:].strip()
        scheme = "negotiate"
    else:
        # Legacy fallback: HTTPBearer already extracted a Bearer token
        if credentials:
            credential = credentials.credentials
            scheme = "bearer"
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or unsupported Authorization header",
                headers={"WWW-Authenticate": "Bearer"},
            )

    if not credential:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Empty credential in Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await authenticate(credential, scheme=scheme)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def require_admin(user: dict = Depends(require_user)) -> dict:
    """
    FastAPI dependency: require an authenticated admin user.

    Composes with ``require_user`` — first authenticates the user, then checks
    the ``is_admin`` flag.  Non-admin users receive HTTP 403 (not 401), so
    attackers cannot distinguish admin endpoints from non-existent ones merely by
    probing for 401 vs 403.

    Usage::

        @router.get("/admin/users")
        async def list_users(admin: dict = Depends(require_admin)):
            ...
    """
    if not user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privilege required",
        )
    return user


# ── Stream tokens (Redis or DB-backed, 30-minute TTL) ─────────────────────────
# Phase 10: DB-backed (stream_tokens table, survives restarts).
# Phase 13: Redis-backed when settings.gateway.redis_url is set — enables
#           cross-instance token sharing for multi-gateway deployments.
#           Falls back transparently to DB when Redis is not configured.
#           The worker heartbeat still purges expired DB rows every 10 min
#           (no-op overhead when Redis mode is active).


async def create_stream_token(task_id: str, user_id: str) -> str:
    """
    Issue a short-lived stream token for SSE access from browser clients.

    Phase 13: delegates to state.py which uses Redis (if configured) or the
    stream_tokens DB table (fallback).  TTL is 30 minutes in both modes.

    Args:
        task_id: The task this token grants access to stream.
        user_id: The user who submitted the task.

    Returns:
        URL-safe random token string (32 bytes of entropy).
    """
    return await _state_create_stream_token(task_id, user_id)


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
    return await _state_resolve_stream_token(token)


async def delete_stream_token(token: str) -> None:
    """Explicitly delete a stream token (e.g. on task cancellation)."""
    await _state_delete_stream_token(token)
