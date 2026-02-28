"""
src/gateway/backends/oidc.py
─────────────────────────────
OIDC auth backend for Phase 12.

Covers any OIDC-compliant identity provider via the standard discovery
document + JWKS flow.  Zero extra code needed for:
  Google, Okta, Auth0, Keycloak, Azure AD, Ping, Cognito, or any OIDC IdP.

Authentication flow
───────────────────
1. Fetch ``<issuer_url>/.well-known/openid-configuration`` (cached 1 h).
2. Fetch ``jwks_uri`` from the discovery doc (cached ``jwks_cache_ttl`` s).
3. Decode + verify the JWT access token using JWKS public keys (PyJWT):
     a. Parse JWT header → get ``kid`` claim.
     b. Find matching JWK in cached JWKS by ``kid``.
     c. Decode + verify with ``jwt.decode()``.
4. Verify ``aud`` claim matches ``settings.gateway.oidc.audience``
   (defaults to ``client_id`` if ``audience`` is empty in config).
5. If JWT decode fails → fall back to a ``userinfo_endpoint`` HTTP call.
6. Extract ``sub`` → ``user_id``, ``preferred_username`` or ``email`` → ``username``.
7. On first login: INSERT INTO gateway_users … ON CONFLICT DO NOTHING.
8. Return ``{user_id: "oidc:<sub>", username, daily_token_limit}``.

Required config (settings.gateway.oidc)
────────────────────────────────────────
  issuer_url   — e.g. https://accounts.google.com
  client_id    — OAuth2 client ID registered with the provider
  audience     — token audience claim (defaults to client_id if empty)
  jwks_cache_ttl    — seconds to cache JWKS keys (default 300)
  userinfo_endpoint — override; empty = read from discovery doc

Keychain: legionforge_oidc_client_secret (loaded but not used in JWKS flow —
  reserved for token introspection or future refresh token support).
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx
import jwt
from jwt.exceptions import PyJWTError

from src.database import get_pool
from src.gateway.backends.base import AuthBackend, SCHEME_BEARER  # noqa: F401

logger = logging.getLogger(__name__)

_DEFAULT_DAILY_LIMIT = 100_000
_DISCOVERY_CACHE_TTL = 3600  # 1 hour


class OIDCBackend:
    """
    OIDC auth backend.  Validates access tokens via JWKS; falls back to
    the userinfo endpoint if JWKS decode fails (e.g. opaque tokens).
    """

    def __init__(self, config: Any) -> None:
        """
        Args:
            config: An ``OIDCConfig`` instance from settings.gateway.oidc.
        """
        self._cfg = config
        self._discovery: dict[str, Any] | None = None
        self._discovery_ts: float = 0.0
        self._jwks: dict[str, Any] | None = None
        self._jwks_ts: float = 0.0

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _get_discovery(self) -> dict[str, Any]:
        now = time.monotonic()
        if self._discovery is None or (now - self._discovery_ts) > _DISCOVERY_CACHE_TTL:
            url = f"{self._cfg.issuer_url.rstrip('/')}/.well-known/openid-configuration"
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                self._discovery = resp.json()
                self._discovery_ts = now
        return self._discovery  # type: ignore[return-value]

    async def _get_jwks(self) -> dict[str, Any]:
        now = time.monotonic()
        ttl = getattr(self._cfg, "jwks_cache_ttl", 300)
        if self._jwks is None or (now - self._jwks_ts) > ttl:
            discovery = await self._get_discovery()
            jwks_uri = discovery["jwks_uri"]
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(jwks_uri)
                resp.raise_for_status()
                self._jwks = resp.json()
                self._jwks_ts = now
        return self._jwks  # type: ignore[return-value]

    def _find_signing_key(self, token: str, jwks_data: dict[str, Any]) -> Any | None:
        """
        Find the correct signing key for ``token`` in a JWKS dict.

        1. Parse the JWT header (unverified) to get the ``kid``.
        2. Match against keys in ``jwks_data["keys"]``.
        3. Return a ``jwt.PyJWK`` object or None if no match found.
        """
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
        except PyJWTError as exc:
            logger.debug(f"[oidc] could not parse JWT header: {exc}")
            return None

        keys = jwks_data.get("keys", [])
        for key_dict in keys:
            if kid is None or key_dict.get("kid") == kid:
                try:
                    return jwt.PyJWK(key_dict)
                except Exception as exc:
                    logger.debug(
                        f"[oidc] PyJWK construction failed for kid={kid}: {exc}"
                    )
                    continue
        return None

    async def _userinfo(self, token: str) -> dict[str, Any] | None:
        """Call the userinfo endpoint as a fallback for opaque tokens."""
        try:
            discovery = await self._get_discovery()
            endpoint = getattr(self._cfg, "userinfo_endpoint", "") or discovery.get(
                "userinfo_endpoint", ""
            )
            if not endpoint:
                return None
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    endpoint, headers={"Authorization": f"Bearer {token}"}
                )
                if resp.status_code != 200:
                    return None
                return resp.json()
        except Exception as exc:
            logger.debug(f"[oidc] userinfo fallback failed: {exc}")
            return None

    async def _provision_user(
        self, user_id: str, username: str, daily_limit: int
    ) -> None:
        """Insert user on first OIDC login; do nothing on subsequent logins."""
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

    # ── Public interface ──────────────────────────────────────────────────────

    async def authenticate(
        self, credential: str, scheme: str = SCHEME_BEARER
    ) -> dict | None:
        """
        Verify an OIDC access token.

        1. Try JWKS JWT decode.
        2. On failure, fall back to userinfo endpoint.
        3. Auto-provision user on first login.

        Returns user dict or None.
        """
        if scheme != SCHEME_BEARER:
            return None
        if not getattr(self._cfg, "issuer_url", "") or not getattr(
            self._cfg, "client_id", ""
        ):
            logger.warning("[oidc] issuer_url or client_id not configured")
            return None

        audience = getattr(self._cfg, "audience", "") or self._cfg.client_id
        claims: dict[str, Any] | None = None

        # ── 1. Try JWKS JWT decode ────────────────────────────────────────────
        try:
            jwks_data = await self._get_jwks()
            signing_key = self._find_signing_key(credential, jwks_data)
            if signing_key is not None:
                claims = jwt.decode(
                    credential,
                    signing_key.key,
                    algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
                    audience=audience,
                    issuer=self._cfg.issuer_url,
                )
        except PyJWTError as exc:
            logger.debug(f"[oidc] JWKS decode failed ({exc}); trying userinfo")
            claims = None
        except Exception as exc:
            logger.debug(f"[oidc] JWKS fetch/decode error ({exc}); trying userinfo")
            claims = None

        # ── 2. Fallback to userinfo ───────────────────────────────────────────
        if claims is None:
            claims = await self._userinfo(credential)
            if claims is None:
                return None

        # ── 3. Extract identity ───────────────────────────────────────────────
        sub = claims.get("sub") or claims.get("id")
        if not sub:
            logger.warning("[oidc] token missing 'sub' claim")
            return None

        username = (
            claims.get("preferred_username")
            or claims.get("email")
            or claims.get("name")
            or str(sub)
        )
        user_id = f"oidc:{sub}"
        daily_limit = _DEFAULT_DAILY_LIMIT

        # ── 4. Auto-provision ─────────────────────────────────────────────────
        try:
            await self._provision_user(user_id, username, daily_limit)
        except Exception as exc:
            logger.error(f"[oidc] user provisioning failed: {exc}")
            # Non-fatal — user may already exist

        return {
            "user_id": user_id,
            "username": username,
            "daily_token_limit": daily_limit,
        }
