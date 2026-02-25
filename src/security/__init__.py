"""
src/security/__init__.py
────────────────────────
Backward-compatibility re-export shim.

All code that imported from `src.security` continues to work unchanged
after the module was split into `src/security/core.py` (Phase 2).
Import paths like `from src.security import sanitize_text` still resolve
correctly — Python sees this package and finds the symbols here.

Phase 2 adds `src/security/guardian.py` (FastAPI sidecar).
"""

from src.security.core import (
    # API key management
    get_api_key,
    get_api_key_optional,
    load_all_keys_to_env,
    # Injection detection
    detect_injection,
    _INJECTION_PATTERNS,
    _COMPILED_PATTERNS,
    # Sanitization
    sanitize_text,
    sanitize_for_trace,
    sanitize_output,
    sanitize_messages,
    sanitize_tool_input,
    # Tool registry
    SecurityError,
    ToolManifest,
    register_tool,
    verify_tool_before_invocation,
    _TOOL_REGISTRY,
    _TOOL_HASHES,
    _compute_fast_hash,
    _compute_tool_hash,
    # Capability boundaries
    FORBIDDEN_CAPABILITIES,
    check_capability_boundary,
    # SSRF prevention
    validate_fetch_url,
    _ALLOWED_SCHEMES,
    _BLOCKED_HOSTS,
    _PRIVATE_IP_PATTERNS,
    _is_private_ip,
    # Destructive pattern detection / HITL
    detect_destructive_pattern,
    _DESTRUCTIVE_PATTERNS,
    HITL_HALT_CATEGORIES,
    HITL_LOG_CATEGORIES,
    # Guardian stub (Phase 1 — replaced in Phase 2 but kept for fallback)
    Guardian,
    # PII patterns (used in tests)
    _PII_PATTERNS,
    _MAX_FIELD_LENGTH,
    # Key env fallbacks (used in tests)
    _KEY_ENV_FALLBACKS,
)

__all__ = [
    "get_api_key",
    "get_api_key_optional",
    "load_all_keys_to_env",
    "detect_injection",
    "_INJECTION_PATTERNS",
    "_COMPILED_PATTERNS",
    "sanitize_text",
    "sanitize_for_trace",
    "sanitize_output",
    "sanitize_messages",
    "sanitize_tool_input",
    "SecurityError",
    "ToolManifest",
    "register_tool",
    "verify_tool_before_invocation",
    "_TOOL_REGISTRY",
    "_TOOL_HASHES",
    "_compute_fast_hash",
    "_compute_tool_hash",
    "FORBIDDEN_CAPABILITIES",
    "check_capability_boundary",
    "validate_fetch_url",
    "_ALLOWED_SCHEMES",
    "_BLOCKED_HOSTS",
    "_PRIVATE_IP_PATTERNS",
    "_is_private_ip",
    "detect_destructive_pattern",
    "_DESTRUCTIVE_PATTERNS",
    "HITL_HALT_CATEGORIES",
    "HITL_LOG_CATEGORIES",
    "Guardian",
    "_PII_PATTERNS",
    "_MAX_FIELD_LENGTH",
    "_KEY_ENV_FALLBACKS",
]
