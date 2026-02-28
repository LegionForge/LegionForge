"""
src/gateway/backends/github.py
────────────────────────────────
GitHub OAuth app auth backend for Phase 12.

GitHub OAuth apps issue opaque access tokens, not JWTs — the OIDC JWKS
flow does not apply.  This backend validates tokens by calling the GitHub
``/user`` API endpoint and auto-provisions a gateway_users row on first login.

Authentication flow
───────────────────
1. GET https://api.github.com/user
   Authorization: token <access_token>
2. If 401 or error → return None.
3. Parse: ``id`` → user_id, ``login`` → username.
4. On first login: INSERT INTO gateway_users … ON CONFLICT DO NOTHING.
5. Return ``{user_id: "github:<id>", username: <login>, daily_token_limit}``.

Config: none (fixed GitHub endpoint).
Keychain: legionforge_github_client_secret (optional — reserved for future
  token verification or webhook signature validation).
"""

from __future__ import annotations

import logging

import httpx

from src.database import get_pool
from src.gateway.backends.base import AuthBackend, SCHEME_BEARER  # noqa: F401

logger = logging.getLogger(__name__)

_GITHUB_USER_URL = "https://api.github.com/user"
_DEFAULT_DAILY_LIMIT = 100_000


class GitHubOAuthBackend:
    """
    GitHub OAuth backend.  Validates opaque GitHub access tokens via the
    ``/user`` API and auto-provisions users on first login.
    """

    async def _provision_user(
        self, user_id: str, username: str, daily_limit: int
    ) -> None:
        """Insert user on first GitHub login; do nothing on subsequent logins."""
        pool = get_pool()
        async with pool.connection() as conn:
            await conn.execute(
                """
                INSERT INTO gateway_users
                    (user_id, username, api_key_hash, daily_token_limit, is_active)
                VALUES (%s, %s, '[OAUTH-NO-KEY]', %s, true)
                ON CONFLICT (user_id) DO NOTHING
                """,
                (user_id, username, daily_limit),
            )

    async def authenticate(
        self, credential: str, scheme: str = SCHEME_BEARER
    ) -> dict | None:
        """
        Validate a GitHub OAuth access token.

        Args:
            credential: Raw GitHub access token from the Authorization Bearer header.
            scheme: Only ``"bearer"`` is accepted.

        Returns:
            User dict with ``user_id``, ``username``, ``daily_token_limit``,
            or ``None`` if authentication fails.
        """
        if scheme != SCHEME_BEARER:
            return None

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    _GITHUB_USER_URL,
                    headers={
                        "Authorization": f"token {credential}",
                        "Accept": "application/vnd.github.v3+json",
                        "User-Agent": "LegionForge-Gateway/1.0",
                    },
                )
            if resp.status_code == 401:
                return None
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.warning(f"[github] /user API call failed: {exc}")
            return None

        github_id = data.get("id")
        login = data.get("login")
        if not github_id or not login:
            logger.warning("[github] /user response missing 'id' or 'login'")
            return None

        user_id = f"github:{github_id}"
        daily_limit = _DEFAULT_DAILY_LIMIT

        try:
            await self._provision_user(user_id, login, daily_limit)
        except Exception as exc:
            logger.error(f"[github] user provisioning failed: {exc}")
            # Non-fatal — user may already exist

        return {
            "user_id": user_id,
            "username": login,
            "daily_token_limit": daily_limit,
        }
