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
import time
import logging
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

import bcrypt as _bcrypt

from src.database import get_gateway_user_for_auth

logger = logging.getLogger(__name__)

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
    Verify a raw API key against all active users' stored hashes.

    Fetches all active gateway_users rows (small table — O(users) bcrypt checks).
    Returns the matching user row (without api_key_hash) or None.

    Security: bcrypt verify is constant-time within each comparison.
    We compare against all rows to avoid timing leaks on username.
    """
    rows = await get_gateway_user_for_auth(raw_key)
    for row in rows:
        if verify_api_key(raw_key, row["api_key_hash"]):
            return {"user_id": row["user_id"], "username": row["username"]}
    return None


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


# ── Stream tokens (in-memory, 30-minute TTL) ──────────────────────────────────
# At household scale a dict is sufficient.  Phase 10 moves this to Redis when
# multiple gateway workers are needed.

_stream_tokens: dict[str, tuple[str, str, float]] = (
    {}
)  # token → (task_id, user_id, expiry)

_STREAM_TOKEN_TTL = 30 * 60  # 30 minutes


def create_stream_token(task_id: str, user_id: str) -> str:
    """Issue a short-lived stream token for SSE access from browser clients."""
    token = secrets.token_urlsafe(32)
    expiry = time.monotonic() + _STREAM_TOKEN_TTL
    _stream_tokens[token] = (task_id, user_id, expiry)
    _purge_expired_stream_tokens()
    return token


def resolve_stream_token(token: str) -> tuple[str, str] | None:
    """
    Resolve a stream token to (task_id, user_id).
    Returns None if not found or expired.  Does NOT consume (single-use removed
    for simplicity since SSE clients may reconnect).
    """
    entry = _stream_tokens.get(token)
    if not entry:
        return None
    task_id, user_id, expiry = entry
    if time.monotonic() > expiry:
        del _stream_tokens[token]
        return None
    return task_id, user_id


def _purge_expired_stream_tokens() -> None:
    now = time.monotonic()
    expired = [t for t, (_, _, exp) in _stream_tokens.items() if now > exp]
    for t in expired:
        del _stream_tokens[t]
