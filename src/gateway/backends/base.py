"""
src/gateway/backends/base.py
─────────────────────────────
Updated AuthBackend protocol for Phase 12 multi-provider registry.

The ``scheme`` parameter tells a backend what kind of credential it is
receiving so that backends that handle multiple credential types can
dispatch correctly.  Backends that handle only one scheme may ignore it.

Scheme constants
────────────────
``SCHEME_BEARER``     — raw token string (OAuth access token, API key, JWT).
                        HTTP header:  Authorization: Bearer <token>

``SCHEME_BASIC``      — "username:password" decoded from base64 Basic auth.
                        HTTP header:  Authorization: Basic <base64>

``SCHEME_NEGOTIATE``  — base64 GSSAPI token from Kerberos/SPNEGO.
                        HTTP header:  Authorization: Negotiate <base64>

Backward compatibility
──────────────────────
All existing callers that pass only a credential string continue to work —
the ``scheme`` parameter defaults to ``"bearer"``.

See docs/SCALING.md for integration examples.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

# ── Scheme constants ──────────────────────────────────────────────────────────

SCHEME_BEARER = "bearer"
SCHEME_BASIC = "basic"
SCHEME_NEGOTIATE = "negotiate"


# ── Protocol ──────────────────────────────────────────────────────────────────


@runtime_checkable
class AuthBackend(Protocol):
    """
    Auth backend protocol. Implement to add any auth scheme.

    The ``scheme`` parameter tells the backend what kind of credential it
    is receiving:

    - ``"bearer"``    — raw token string (OAuth access token, API key, JWT).
    - ``"basic"``     — "username:password" decoded from a base64 Basic header.
    - ``"negotiate"`` — base64 GSSAPI token from a Negotiate (Kerberos) header.

    Backends that handle only one scheme can ignore the parameter.

    The returned user dict MUST include:
        ``user_id``           — stable unique identifier (str).
        ``username``          — human-readable display name (str).
        ``daily_token_limit`` — integer token budget per day.

    Return ``None`` on any authentication failure (wrong key, expired token,
    user not found, bad password, etc.).  Never raise — callers treat any
    exception as a 500, not a 401.

    See docs/SCALING.md for backend implementation examples.
    """

    async def authenticate(
        self, credential: str, scheme: str = SCHEME_BEARER
    ) -> dict | None:
        """
        Verify credential. Returns user dict or None on failure.
        """
        ...
