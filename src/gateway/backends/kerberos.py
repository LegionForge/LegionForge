"""
src/gateway/backends/kerberos.py
──────────────────────────────────
Kerberos / GSSAPI authentication backend — Phase 13.

This backend accepts HTTP Negotiate (SPNEGO) tokens produced by Kerberos-
authenticated clients.  It validates the GSSAPI token against a service
keytab, extracts the client principal, and returns (or auto-provisions) the
corresponding gateway user.

Prerequisites
─────────────
1. A working KDC with ``/etc/krb5.conf`` configured on every host.
2. A service principal registered in the KDC:
       HTTP/legionforge.example.com@EXAMPLE.COM
3. A keytab file at the path in ``settings.gateway.kerberos.keytab_path``
   (default ``/etc/legionforge/http.keytab``).
4. The ``gssapi`` Python package:
       pip install gssapi
5. HTTP Negotiate at the load-balancer level (NGINX ``auth_gssapi`` module
   or a GSSAPI-aware reverse proxy such as mod_auth_gssapi for Apache).
6. The client browser / tool configured to delegate Kerberos tickets.

Graceful fallback
─────────────────
When the ``gssapi`` package is not installed (the common case for deployments
using api_key, OIDC, GitHub, or LDAP auth), ``authenticate()`` logs a WARNING
once and returns ``None`` — the caller receives a 401, not a 500 crash.
This is a deliberate improvement over the Phase 12 scaffold which raised
``NotImplementedError``.

Integration
───────────
Set ``auth_provider: kerberos`` in your hardware profile YAML and ensure
``settings.gateway.kerberos`` is populated.  The ``require_user`` dependency
in ``auth.py`` already parses the ``Negotiate`` scheme and passes the raw
base64 SPNEGO token to ``authenticate(credential, scheme="negotiate")``.

See docs/SCALING.md for full Kerberos setup and troubleshooting instructions.
"""

from __future__ import annotations

import base64
import logging
from typing import Optional

from src.gateway.backends.base import SCHEME_NEGOTIATE

logger = logging.getLogger(__name__)

# ── Optional gssapi import ────────────────────────────────────────────────────

try:
    import gssapi  # type: ignore[import]
    import gssapi.raw as gss_raw  # type: ignore[import]

    _GSSAPI_AVAILABLE = True
except ImportError:
    _GSSAPI_AVAILABLE = False

_GSSAPI_MISSING_WARNED = False  # log once, not every request

# Sentinel stored in api_key_hash for Kerberos-provisioned users.
# Never passes bcrypt verification, preventing API-key auth for these users.
_KERBEROS_NO_KEY = "[OAUTH-NO-KEY]"


class KerberosBackend:
    """
    Kerberos / GSSAPI authentication backend (Phase 13).

    Validates HTTP Negotiate (SPNEGO) tokens against a service keytab.
    Returns a user dict on success, None on failure.

    When the ``gssapi`` package is not installed, returns None with a
    one-time WARNING log instead of crashing.  This allows the gateway to
    start cleanly even when Kerberos infrastructure is not provisioned.
    """

    def __init__(
        self, keytab_path: str = "", service_name: str = "HTTP", realm: str = ""
    ) -> None:
        """
        Args:
            keytab_path:  Path to the HTTP service keytab file.
                          Loaded from ``settings.gateway.kerberos.keytab_path``
                          by the BackendRegistry factory.
            service_name: GSSAPI service name (default: ``HTTP``).
            realm:        Kerberos realm (e.g. ``EXAMPLE.COM``).
                          Empty string = use the default realm from krb5.conf.
        """
        self._keytab_path = keytab_path or "/etc/legionforge/http.keytab"
        self._service_name = service_name or "HTTP"
        self._realm = realm

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get_server_credentials(self) -> Optional["gssapi.Credentials"]:
        """
        Acquire GSSAPI server credentials from the keytab.

        Returns None (and logs) if the keytab is missing or invalid.
        """
        if not _GSSAPI_AVAILABLE:
            return None
        try:
            server_name = gssapi.Name(
                f"{self._service_name}@",
                name_type=gssapi.NameType.hostbased_service,
            )
            creds = gssapi.Credentials(
                name=server_name,
                usage="accept",
                store={"keytab": self._keytab_path},
            )
            return creds
        except Exception as exc:
            logger.error(
                f"[kerberos] Failed to load keytab {self._keytab_path!r}: {exc}"
            )
            return None

    def _extract_principal(self, ctx: "gssapi.SecurityContext") -> Optional[str]:
        """Extract the client principal name from a completed GSSAPI context."""
        try:
            initiator = ctx.initiator_name
            if initiator is None:
                return None
            return str(initiator)
        except Exception as exc:
            logger.warning(f"[kerberos] Could not extract principal: {exc}")
            return None

    @staticmethod
    def _strip_realm(principal: str) -> str:
        """Strip Kerberos realm from a principal name (alice@EXAMPLE.COM → alice)."""
        return principal.split("@")[0] if "@" in principal else principal

    async def _provision_user(
        self, principal: str, username: str, daily_limit: int
    ) -> dict:
        """
        Upsert a gateway_users row for a Kerberos-authenticated principal.

        Uses ``[OAUTH-NO-KEY]`` as the api_key_hash sentinel so ApiKeyBackend
        cannot authenticate these users.
        """
        from src.database import get_worker_pool

        user_id = f"kerberos:{principal}"
        pool = get_worker_pool()
        try:
            async with pool.connection() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        """
                        INSERT INTO gateway_users
                            (user_id, username, api_key_hash, daily_token_limit, is_active)
                        VALUES (%s, %s, %s, %s, true)
                        ON CONFLICT (user_id) DO NOTHING
                        """,
                        (user_id, username, _KERBEROS_NO_KEY, daily_limit),
                    )
                    # Fetch the row (handles the DO NOTHING case)
                    await cur.execute(
                        "SELECT daily_token_limit FROM gateway_users WHERE user_id = %s",
                        (user_id,),
                    )
                    row = await cur.fetchone()
                    actual_limit = row["daily_token_limit"] if row else daily_limit
        except Exception as exc:
            logger.error(
                f"[kerberos] User provisioning failed for {principal!r}: {exc}"
            )
            actual_limit = daily_limit

        return {
            "user_id": user_id,
            "username": username,
            "daily_token_limit": actual_limit,
        }

    # ── Public interface ──────────────────────────────────────────────────────

    async def authenticate(
        self, credential: str, scheme: str = SCHEME_NEGOTIATE
    ) -> dict | None:
        """
        Validate a base64-encoded SPNEGO token from an HTTP Negotiate header.

        Args:
            credential: Base64-encoded SPNEGO token (the value after "Negotiate ").
            scheme:     Must be ``"negotiate"``; other schemes return None.

        Returns:
            ``{"user_id": "kerberos:{principal}", "username": str,
               "daily_token_limit": int}`` on success, or ``None`` on failure.
        """
        global _GSSAPI_MISSING_WARNED

        if scheme != SCHEME_NEGOTIATE:
            return None

        # ── Graceful fallback when gssapi not installed ───────────────────────
        if not _GSSAPI_AVAILABLE:
            if not _GSSAPI_MISSING_WARNED:
                logger.warning(
                    "[kerberos] authenticate() called but the gssapi package is not "
                    "installed.  Install it with: pip install gssapi  "
                    "Returning None (caller will receive 401).  "
                    "See docs/SCALING.md for full Kerberos setup instructions."
                )
                _GSSAPI_MISSING_WARNED = True
            return None

        # ── Decode SPNEGO token ───────────────────────────────────────────────
        try:
            token_bytes = base64.b64decode(credential)
        except Exception:
            logger.warning("[kerberos] Malformed base64 in Negotiate credential")
            return None

        if not token_bytes:
            logger.warning("[kerberos] Empty SPNEGO token")
            return None

        # ── Acquire server credentials ────────────────────────────────────────
        server_creds = self._get_server_credentials()
        if server_creds is None:
            logger.warning(
                "[kerberos] Cannot acquire server credentials — keytab missing?"
            )
            return None

        # ── Accept security context ───────────────────────────────────────────
        try:
            ctx = gssapi.SecurityContext(creds=server_creds, usage="accept")
            ctx.step(token_bytes)
        except gssapi.exceptions.GSSError as exc:
            logger.warning(f"[kerberos] GSSAPI token validation failed: {exc}")
            return None
        except Exception as exc:
            logger.error(f"[kerberos] Unexpected GSSAPI error: {exc}")
            return None

        # ── Extract principal ─────────────────────────────────────────────────
        principal = self._extract_principal(ctx)
        if not principal:
            logger.warning(
                "[kerberos] Could not extract client principal from GSSAPI context"
            )
            return None

        username = self._strip_realm(principal)
        logger.info(f"[kerberos] Authenticated principal: {principal}")

        # ── Provision / return user ───────────────────────────────────────────
        from config.settings import settings

        daily_limit = settings.gateway.kerberos.daily_token_limit
        return await self._provision_user(principal, username, daily_limit)
