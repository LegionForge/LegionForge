"""
src/gateway/backends/api_key.py
────────────────────────────────
Default auth backend: bcrypt-hashed API keys stored in the gateway_users table.

This is the Phase 8–11 implementation, extracted from src/gateway/auth.py into
the Phase 12 backends package.  The old import path (``from src.gateway.auth
import ApiKeyBackend``) continues to work — auth.py re-exports this class.
"""

from __future__ import annotations

import logging

import bcrypt as _bcrypt

from src.database import get_gateway_user_for_auth
from src.gateway.backends.base import AuthBackend, SCHEME_BEARER  # noqa: F401

logger = logging.getLogger(__name__)


def _verify_key(raw: str, hashed: str) -> bool:
    """Constant-time bcrypt verification."""
    try:
        return _bcrypt.checkpw(raw.encode(), hashed.encode())
    except Exception:
        return False


class ApiKeyBackend:
    """
    Default backend: bcrypt-hashed API keys in the gateway_users table.

    Accepts ``scheme="bearer"`` (the default).  Basic and Negotiate credentials
    are silently rejected — a separate backend handles those schemes.

    The sentinel hash ``[OAUTH-NO-KEY]`` is intentionally stored for OAuth-
    provisioned users so that bcrypt verification always fails for them; OAuth
    users can only authenticate via their respective OAuth backend.
    """

    async def authenticate(
        self, credential: str, scheme: str = SCHEME_BEARER
    ) -> dict | None:
        """
        Verify a raw API key.  Returns user dict or None.

        Args:
            credential: Raw API key string from the Authorization Bearer header.
            scheme: Credential scheme; only ``"bearer"`` is accepted.

        Returns:
            User dict with ``user_id``, ``username``, ``daily_token_limit``,
            or ``None`` if authentication fails.
        """
        if scheme != SCHEME_BEARER:
            return None

        rows = await get_gateway_user_for_auth(credential)
        for row in rows:
            hashed = row["api_key_hash"]
            # OAuth-provisioned users carry the sentinel — never match
            if hashed == "[OAUTH-NO-KEY]":
                continue
            if _verify_key(credential, hashed):
                return {
                    "user_id": row["user_id"],
                    "username": row["username"],
                    "daily_token_limit": row.get("daily_token_limit", 100000),
                    "is_admin": row.get("is_admin", False),
                }
        return None
