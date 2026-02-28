"""
src/gateway/backends/registry.py
──────────────────────────────────
Backend factory for Phase 12 multi-provider auth registry.

``load_backend_from_settings()`` reads ``settings.gateway.auth_provider`` and
returns the appropriate backend instance.  Called once in the gateway lifespan
(``src/gateway/app.py``) so that the active backend is hot from startup.

Supported ``auth_provider`` values
────────────────────────────────────
  "api_key"   — ApiKeyBackend (default)
                bcrypt-hashed keys stored in gateway_users table.

  "oidc"      — OIDCBackend
                Validates JWT access tokens via JWKS; falls back to
                userinfo endpoint.  Covers Google, Okta, Auth0, Keycloak,
                Azure AD, Cognito, and any OIDC-compliant IdP.
                Requires settings.gateway.oidc to be configured.

  "github"    — GitHubOAuthBackend
                Validates opaque GitHub OAuth tokens via the /user API.
                No extra config needed.

  "ldap"      — LDAPBackend
                LDAP / Active Directory bind + search + rebind.
                Requires settings.gateway.ldap to be configured.
                Uses Basic auth (Authorization: Basic <base64>).

  "kerberos"  — KerberosBackend (scaffold)
                Raises NotImplementedError on every auth call until
                Phase 13 completes the GSSAPI implementation.

Usage (in gateway lifespan)
────────────────────────────
    from src.gateway.backends.registry import load_backend_from_settings
    from src.gateway.auth import set_auth_backend
    from config.settings import settings

    set_auth_backend(load_backend_from_settings(settings))
"""

from __future__ import annotations

from src.gateway.backends.base import AuthBackend
from src.gateway.backends.api_key import ApiKeyBackend
from src.gateway.backends.oidc import OIDCBackend
from src.gateway.backends.github import GitHubOAuthBackend
from src.gateway.backends.ldap_backend import LDAPBackend
from src.gateway.backends.kerberos import KerberosBackend

_VALID_PROVIDERS = frozenset({"api_key", "oidc", "github", "ldap", "kerberos"})


def load_backend_from_settings(settings: object) -> AuthBackend:
    """
    Instantiate the correct auth backend from the hardware profile settings.

    Args:
        settings: A ``HardwareSettings`` instance (from config.settings).

    Returns:
        An ``AuthBackend`` instance ready to authenticate requests.

    Raises:
        ValueError: If ``settings.gateway.auth_provider`` is not a known value.
    """
    provider: str = getattr(
        getattr(settings, "gateway", None), "auth_provider", "api_key"
    )

    match provider:
        case "api_key":
            return ApiKeyBackend()
        case "oidc":
            oidc_cfg = getattr(getattr(settings, "gateway", None), "oidc", None)
            return OIDCBackend(oidc_cfg)
        case "github":
            return GitHubOAuthBackend()
        case "ldap":
            ldap_cfg = getattr(getattr(settings, "gateway", None), "ldap", None)
            return LDAPBackend(ldap_cfg)
        case "kerberos":
            return KerberosBackend()
        case _:
            raise ValueError(
                f"Unknown auth_provider '{provider}'. "
                f"Valid options: {', '.join(sorted(_VALID_PROVIDERS))}"
            )
