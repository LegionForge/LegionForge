"""
src/gateway/backends
─────────────────────
Phase 12 multi-provider auth backend registry.

Public exports:
  AuthBackend        — Protocol (runtime_checkable)
  ApiKeyBackend      — Default: bcrypt API keys in gateway_users
  OIDCBackend        — OIDC/JWKS for Google, Okta, Auth0, Keycloak, Azure AD…
  GitHubOAuthBackend — GitHub opaque OAuth token → /user API
  LDAPBackend        — LDAP / Active Directory bind+search+rebind
  KerberosBackend    — Kerberos/GSSAPI real implementation (Phase 13; graceful fallback)

  load_backend_from_settings — factory: reads settings.gateway.auth_provider
"""

from src.gateway.backends.base import (
    AuthBackend,
    SCHEME_BEARER,
    SCHEME_BASIC,
    SCHEME_NEGOTIATE,
)
from src.gateway.backends.api_key import ApiKeyBackend
from src.gateway.backends.oidc import OIDCBackend
from src.gateway.backends.github import GitHubOAuthBackend
from src.gateway.backends.ldap_backend import LDAPBackend
from src.gateway.backends.kerberos import KerberosBackend
from src.gateway.backends.registry import load_backend_from_settings

__all__ = [
    "AuthBackend",
    "SCHEME_BEARER",
    "SCHEME_BASIC",
    "SCHEME_NEGOTIATE",
    "ApiKeyBackend",
    "OIDCBackend",
    "GitHubOAuthBackend",
    "LDAPBackend",
    "KerberosBackend",
    "load_backend_from_settings",
]
