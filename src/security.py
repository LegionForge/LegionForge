"""
src/security.py
───────────────
API key management via macOS Keychain, prompt injection detection,
and input/output sanitization before data reaches agents or LangSmith.

All agent inputs and outputs should pass through sanitize_text()
before being processed or traced.
"""

from __future__ import annotations

import os
import re
import logging
from typing import Any

import subprocess
import time

import keyring

logger = logging.getLogger(__name__)

# ── API Key Management ────────────────────────────────────────────────────────

# Map service names to environment variable fallbacks
_KEY_ENV_FALLBACKS = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "langsmith": "LANGSMITH_API_KEY",
    "postgres": "POSTGRES_PASSWORD",
}


def get_api_key(service: str, _retries: int = 3, _retry_delay: float = 0.5) -> str:
    """
    Retrieve an API key from macOS Keychain, falling back to environment
    variables. Raises RuntimeError if the key cannot be found.

    Retries the Keychain lookup up to _retries times with a short delay
    between attempts — the Keychain can be transiently unavailable at
    shell startup or right after login.

    Usage:
        key = get_api_key("anthropic")
    """
    # Try Keychain first, with retries for transient unavailability
    key = None
    for attempt in range(_retries):
        try:
            key = keyring.get_password(service, "api_key")
            if key:
                break
        except Exception:
            if attempt < _retries - 1:
                time.sleep(_retry_delay)
    if key:
        return key

    # Try macOS security CLI fallback — handles cases where the Python
    # keyring library is blocked by code-signing restrictions
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", "api_key", "-w"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass

    # Try environment variable fallback
    env_var = _KEY_ENV_FALLBACKS.get(service, f"{service.upper()}_API_KEY")
    key = os.environ.get(env_var)
    if key:
        logger.warning(
            f"API key for '{service}' loaded from environment variable "
            f"'{env_var}'. Prefer storing in macOS Keychain."
        )
        return key

    raise RuntimeError(
        f"API key for '{service}' not found.\n"
        f"Store it with: python -m keyring set {service} api_key\n"
        f"Or set environment variable: {env_var}"
    )


def get_api_key_optional(service: str) -> str | None:
    """Like get_api_key but returns None instead of raising if not found."""
    try:
        return get_api_key(service)
    except RuntimeError:
        return None


def load_all_keys_to_env() -> None:
    """
    Load all available API keys from Keychain into environment variables
    so downstream libraries (LangChain, LangSmith) can find them.
    Call once at startup.
    """
    mappings = {
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "langsmith": "LANGSMITH_API_KEY",
    }
    loaded = []
    for service, env_var in mappings.items():
        if env_var not in os.environ:
            key = get_api_key_optional(service)
            if key:
                os.environ[env_var] = key
                loaded.append(service)

    if loaded:
        logger.info(f"Loaded API keys from Keychain: {', '.join(loaded)}")


# ── Prompt Injection Detection ────────────────────────────────────────────────

# Patterns that indicate potential prompt injection attempts.
# Minimum count is enforced by test_injection_pattern_count_regression.
_INJECTION_PATTERNS = [
    # Classic override attempts
    r"ignore\s+(all\s+)?previous\s+instructions?",
    r"disregard\s+(all\s+)?previous",
    r"forget\s+(all\s+)?previous\s+instructions?",
    r"override\s+(all\s+)?(previous\s+)?instructions?",
    # Role hijacking
    r"you\s+are\s+now\s+['\"]?(?!a\s+helpful|an\s+AI)[a-z\s]{3,}",
    r"act\s+as\s+(if\s+you\s+(are|were)|a\s+)",
    r"pretend\s+(you\s+are|to\s+be)",
    r"roleplay\s+as",
    r"simulate\s+(being|a)",
    # Jailbreak attempts
    r"jailbreak",
    r"dan\s+mode",
    r"developer\s+mode",
    r"god\s+mode",
    r"unrestricted\s+mode",
    # System prompt exfiltration
    r"(reveal|show|print|output|display)\s+(your\s+)?(system\s+)?prompt",
    r"(what\s+(are|were)\s+your\s+instructions)",
    r"repeat\s+(everything|all)\s+(above|before)",
    # Instruction injection from external content
    r"<\s*(?:system|instruction|prompt)\s*>",
    r"\[INST\]|\[\/INST\]",
    r"<\|im_start\|>|<\|im_end\|>",
    # DAN / numbered jailbreak variants (DAN 2.0, DAN 11.0, etc.)
    r"dan\s*\d+\.?\d*",
    r"(enable|activate|unlock)\s+(dan|developer|god|unrestricted|jailbreak)\s+mode",
    # Persistent instruction override
    r"from\s+now\s+on[,\s]+(you\s+(are|must|will|should)|act\s+as|respond\s+as)",
    r"in\s+(your\s+next|the\s+next)\s+(message|response|reply|output|turn)",
    # Encoding / obfuscation bypass
    r"(decode|translate|interpret|convert)\s+(this\s+)?(from\s+)?(base64|hex|rot13|morse|caesar\s+cipher)",
    r"base64\s*[=:]\s*[A-Za-z0-9+/]{10,}={0,2}",
    # Hypothetical / academic framing (common jailbreak preambles)
    r"for\s+(educational|academic|research|hypothetical|illustrative)\s+purposes",
    r"hypothetically\s+(speaking|,|if\b)",
    r"imagine\s+(you\s+(are|were|could|can)|being\s+a\s+)",
]

_COMPILED_PATTERNS = [
    re.compile(p, re.IGNORECASE | re.MULTILINE) for p in _INJECTION_PATTERNS
]


def detect_injection(text: str) -> tuple[bool, list[str]]:
    """
    Check text for prompt injection patterns.

    Returns:
        (is_suspicious, list_of_matched_patterns)
    """
    matches = []
    for pattern in _COMPILED_PATTERNS:
        if pattern.search(text):
            matches.append(pattern.pattern)

    return bool(matches), matches


# ── Input / Output Sanitization ───────────────────────────────────────────────

# PII patterns to redact before sending to LangSmith traces
_PII_PATTERNS = [
    # Email addresses
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "[EMAIL]"),
    # Phone numbers (US formats)
    (re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[PHONE]"),
    # Social Security Numbers
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    # Credit card numbers (basic pattern)
    (re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"), "[CARD]"),
    # API keys / tokens (long hex/base64 strings that look like secrets)
    (re.compile(r"\b(?:sk-|ls__|pk_|rk_|Bearer\s+)[A-Za-z0-9_\-]{16,}\b"), "[API_KEY]"),
]

# Maximum length for a single field before truncation
_MAX_FIELD_LENGTH = 10_000


def sanitize_text(
    text: str,
    redact_pii: bool = True,
    check_injection: bool = True,
    truncate: bool = True,
) -> tuple[str, dict[str, Any]]:
    """
    Sanitize text before passing to agents or sending to LangSmith.

    Returns:
        (sanitized_text, metadata)
        metadata includes: pii_redacted (bool), injection_detected (bool),
                           injection_patterns (list), truncated (bool)
    """
    meta: dict[str, Any] = {
        "pii_redacted": False,
        "injection_detected": False,
        "injection_patterns": [],
        "truncated": False,
        "original_length": len(text),
    }

    if not isinstance(text, str):
        text = str(text)

    # 1. Check for injection BEFORE any modifications
    if check_injection:
        is_suspicious, patterns = detect_injection(text)
        if is_suspicious:
            meta["injection_detected"] = True
            meta["injection_patterns"] = patterns
            logger.warning(
                f"⚠️  Potential prompt injection detected. " f"Patterns: {patterns[:3]}"
            )

    # 2. Redact PII
    if redact_pii:
        original = text
        for pattern, replacement in _PII_PATTERNS:
            text = pattern.sub(replacement, text)
        if text != original:
            meta["pii_redacted"] = True

    # 3. Truncate if needed
    if truncate and len(text) > _MAX_FIELD_LENGTH:
        text = (
            text[:_MAX_FIELD_LENGTH]
            + f"... [truncated, original: {meta['original_length']} chars]"
        )
        meta["truncated"] = True

    return text, meta


def sanitize_messages(messages: list[dict]) -> list[dict]:
    """
    Sanitize a list of message dicts (LangChain format).
    Modifies content in place without altering structure.
    """
    sanitized = []
    for msg in messages:
        msg = dict(msg)
        if isinstance(msg.get("content"), str):
            msg["content"], _ = sanitize_text(msg["content"])
        sanitized.append(msg)
    return sanitized


def sanitize_for_trace(data: Any) -> Any:
    """
    Recursively sanitize arbitrary data before it goes into a LangSmith trace.
    Handles dicts, lists, and strings.
    """
    if isinstance(data, str):
        sanitized, _ = sanitize_text(data, check_injection=False)
        return sanitized
    elif isinstance(data, dict):
        return {k: sanitize_for_trace(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_for_trace(item) for item in data]
    return data
