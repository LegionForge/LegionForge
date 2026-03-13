"""
src/gateway/backends/ldap_backend.py
──────────────────────────────────────
LDAP / Active Directory auth backend for Phase 12.

Supports OpenLDAP (uid={username}) and Microsoft Active Directory
(sAMAccountName={username}) via a configurable search filter.

Authentication flow
───────────────────
1. Receive ``credential = "username:password"`` (``scheme="basic"``).
2. Split on first ``":"`` → ``(username, password)``.
3. Load bind password from macOS Keychain (service: ``legionforge_ldap_bind_password``).
4. Bind to LDAP as the service account (``settings.gateway.ldap.bind_dn``).
5. Search for the user entry under ``user_search_base`` using
   ``user_search_filter.format(username=username)``.
6. Get user DN from the search result (return None if not found).
7. Rebind as the user DN with the provided password (validates the credential).
8. If rebind fails → return None (wrong password).
9. Extract ``cn`` (or ``displayName``) and ``mail`` from user attributes.
10. On first login: INSERT INTO gateway_users … ON CONFLICT DO NOTHING.
11. Return ``{user_id: "ldap:<dn>", username: <cn>, daily_token_limit}``.

Required config (settings.gateway.ldap)
────────────────────────────────────────
  url              — ldap://ldap.example.com:389 or ldaps://...
  bind_dn          — cn=svc-legionforge,ou=services,dc=example,dc=com
  user_search_base — ou=users,dc=example,dc=com
  user_search_filter — (uid={username})  or  (sAMAccountName={username}) for AD
  daily_token_limit  — default token budget for LDAP-authenticated users

Keychain: legionforge_ldap_bind_password
"""

from __future__ import annotations

import logging

from src.database import get_worker_pool
from src.gateway.backends.base import AuthBackend, SCHEME_BASIC  # noqa: F401

logger = logging.getLogger(__name__)

_ATTRS = ["cn", "displayName", "mail", "dn"]


class LDAPBackend:
    """
    LDAP / Active Directory auth backend.

    Validates Basic auth credentials via LDAP bind + search + rebind.
    Auto-provisions gateway users on first successful login.
    """

    def __init__(self, config: object) -> None:
        """
        Args:
            config: An ``LDAPConfig`` instance from settings.gateway.ldap.
        """
        self._cfg = config

    def _load_bind_password(self) -> str | None:
        """Load the LDAP service account bind password from macOS Keychain."""
        try:
            import keyring

            return keyring.get_password("legionforge_ldap_bind_password", "ldap")
        except Exception as exc:
            logger.warning(f"[ldap] could not load bind password from Keychain: {exc}")
            return None

    async def _provision_user(
        self, user_id: str, username: str, daily_limit: int
    ) -> None:
        pool = get_worker_pool()
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
        self, credential: str, scheme: str = SCHEME_BASIC
    ) -> dict | None:
        """
        Validate LDAP credentials from a Basic auth header.

        Args:
            credential: ``"username:password"`` decoded from the Basic header.
            scheme: Only ``"basic"`` is accepted.

        Returns:
            User dict or None.
        """
        if scheme != SCHEME_BASIC:
            return None

        cfg = self._cfg
        if not getattr(cfg, "url", "") or not getattr(cfg, "bind_dn", ""):
            logger.warning("[ldap] url or bind_dn not configured")
            return None

        # Split on the first colon — passwords may contain colons
        if ":" not in credential:
            return None
        username, password = credential.split(":", 1)
        if not username or not password:
            return None

        bind_password = self._load_bind_password()
        if bind_password is None:
            logger.error("[ldap] bind password unavailable — cannot authenticate")
            return None

        try:
            import ldap3

            server = ldap3.Server(cfg.url, get_info=ldap3.ALL)

            # ── 1. Service-account bind ───────────────────────────────────────
            conn = ldap3.Connection(
                server,
                user=cfg.bind_dn,
                password=bind_password,
                auto_bind=True,
            )

            # ── 2. Search for user ────────────────────────────────────────────
            search_filter = cfg.user_search_filter.format(username=username)
            conn.search(
                search_base=cfg.user_search_base,
                search_filter=search_filter,
                attributes=["cn", "displayName", "mail"],
            )
            if not conn.entries:
                conn.unbind()
                return None

            entry = conn.entries[0]
            user_dn = entry.entry_dn
            conn.unbind()

            # ── 3. Rebind as user (validates password) ────────────────────────
            user_conn = ldap3.Connection(
                server,
                user=user_dn,
                password=password,
                auto_bind=False,
            )
            if not user_conn.bind():
                return None
            user_conn.unbind()

            # ── 4. Extract display name ───────────────────────────────────────
            cn = (
                str(entry.cn.value)
                if hasattr(entry, "cn") and entry.cn
                else (
                    str(entry.displayName.value)
                    if hasattr(entry, "displayName") and entry.displayName
                    else username
                )
            )

        except ImportError:
            logger.error("[ldap] ldap3 package not installed; run: pip install ldap3")
            return None
        except Exception as exc:
            logger.warning(f"[ldap] authentication error: {exc}")
            return None

        user_id = f"ldap:{user_dn}"
        daily_limit = getattr(cfg, "daily_token_limit", 100_000)

        try:
            await self._provision_user(user_id, cn, daily_limit)
        except Exception as exc:
            logger.error(f"[ldap] user provisioning failed: {exc}")

        return {
            "user_id": user_id,
            "username": cn,
            "daily_token_limit": daily_limit,
        }
