"""
src/gateway/backends/kerberos.py
──────────────────────────────────
Kerberos / GSSAPI authentication backend — Phase 13+ scaffold.

This class exists so that ``BackendRegistry`` can map ``auth_provider=kerberos``
to a concrete object at startup.  Authentication calls intentionally raise
``NotImplementedError`` with actionable setup instructions.

What full implementation requires (Phase 13+)
─────────────────────────────────────────────
1. A working Kerberos KDC (``/etc/krb5.conf`` configured on every host).
2. A service principal registered in the KDC:
       HTTP/legionforge.example.com@EXAMPLE.COM
3. A keytab file at (e.g.) ``/etc/legionforge/http.keytab``.
4. The ``gssapi`` Python package:
       pip install gssapi
5. HTTP Negotiate at the load-balancer level (NGINX ``auth_gssapi`` module
   or a GSSAPI-aware reverse proxy).
6. The client browser/tool configured to delegate Kerberos tickets.

See docs/SCALING.md for full Kerberos setup instructions.
"""

from __future__ import annotations

from src.gateway.backends.base import AuthBackend, SCHEME_NEGOTIATE  # noqa: F401


class KerberosBackend:
    """
    Kerberos / GSSAPI authentication scaffold (Phase 13+).

    Instantiating this class is safe.  Any call to ``authenticate()`` raises
    ``NotImplementedError`` with setup instructions until Phase 13 completes
    the implementation.
    """

    async def authenticate(
        self, credential: str, scheme: str = SCHEME_NEGOTIATE
    ) -> dict | None:
        """
        Raises:
            NotImplementedError: Always.  Full implementation is Phase 13+.
        """
        raise NotImplementedError(
            "KerberosBackend requires OS-level KDC setup and the gssapi package. "
            "Steps: (1) configure /etc/krb5.conf, (2) register an HTTP service "
            "principal, (3) pip install gssapi, (4) enable Negotiate at the load "
            "balancer. See docs/SCALING.md for complete setup instructions. "
            "This backend is scaffolded — full implementation is Phase 13+."
        )
