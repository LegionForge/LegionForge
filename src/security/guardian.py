"""
src/security/guardian.py — Phase G2 backward-compatibility shim
────────────────────────────────────────────────────────────────
The canonical Guardian source has moved to:
    packages/guardian/src/legionforge_guardian/app.py

This module injects every name from legionforge_guardian.app into its own
namespace so that all existing LegionForge imports continue to work unchanged
(app, GuardianCheckResponse, _CACHE_TTL_SECONDS, _check_3_destructive_pattern, etc.)
and the Docker entry point `uvicorn src.security.guardian:app` still resolves.

The dynamic update handles both public and private names automatically —
no explicit re-export list required. Adding new names to app.py propagates
here on the next import.

Phase G3 will remove this shim once all call sites are updated to import
from legionforge_guardian.app directly.
"""

import sys as _sys

import legionforge_guardian.app as _app

# Inject all non-dunder names from app.py into this module's namespace.
# Includes private names (_CACHE_TTL_SECONDS, _check_3_destructive_pattern, etc.)
# so existing `from src.security.guardian import _X` imports still resolve.
_sys.modules[__name__].__dict__.update(
    {k: v for k, v in vars(_app).items() if not k.startswith("__")}
)

# Clean up — don't pollute the namespace with the helper names themselves
del _sys, _app
