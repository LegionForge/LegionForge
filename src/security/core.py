"""
src/security.py
───────────────
API key management via macOS Keychain, prompt injection detection,
and input/output sanitization before data reaches agents or LangSmith.

All agent inputs and outputs should pass through sanitize_text()
before being processed or traced.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import unicodedata
import logging
from dataclasses import dataclass, field
from typing import Any

import subprocess
import threading
import time

try:
    import keyring as _keyring  # unavailable in Linux containers
except ImportError:
    _keyring = None  # type: ignore[assignment]


def _keyring_get(service: str, account: str, timeout: float = 1.0) -> str | None:
    """
    Call keyring.get_password with a hard timeout.

    On macOS, keyring.get_password can hang indefinitely when the calling process
    does not have Keychain authorization (e.g. sandboxed tools, first-run dialogs).
    We run the call in a daemon thread and join with a timeout so the caller is
    never blocked longer than `timeout` seconds.
    """
    if _keyring is None:
        return None
    result: list[str | None] = [None]

    def _fetch() -> None:
        try:
            result[0] = _keyring.get_password(service, account)
        except Exception:
            pass

    thread = threading.Thread(target=_fetch, daemon=True)
    thread.start()
    thread.join(timeout=timeout)
    return result[0]


logger = logging.getLogger(__name__)

# ── API Key Management ────────────────────────────────────────────────────────

# Map service names to environment variable fallbacks
_KEY_ENV_FALLBACKS = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "langsmith": "LANGSMITH_API_KEY",
    "postgres": "POSTGRES_PASSWORD",
    "legionforge_inceptionlabs_api_key": "INCEPTIONLABS_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "legionforge_tavily_api_key": "TAVILY_API_KEY",
    "legionforge_brave_api_key": "BRAVE_API_KEY",
}


def get_api_key(service: str, _retries: int = 3, _retry_delay: float = 0.5) -> str:
    """
    Retrieve an API key by service name.

    Priority order:
      1. CredentialStore in-memory cache (if initialized — zero Keychain calls)
      2. macOS Keychain via keyring library (with timeout)
      3. macOS security CLI (handles code-signing restriction edge cases)
      4. Environment variable fallback

    Raises RuntimeError if the key cannot be found anywhere.

    Usage:
        key = get_api_key("anthropic")
    """
    # ── 1. CredentialStore fast path (after initialization) ──────────────────
    # After creds.initialize() has been called, all secrets are in-memory.
    # This path never touches the Keychain, CLI, or environment — no popups,
    # no subprocess spawns, no timing attacks via secret lookup timing.
    try:
        from src.credentials import creds as _creds

        if _creds._initialized:
            value = _creds.get(service)
            if value:
                return value
            # Service not in store — fall through to legacy path so callers
            # requesting one-off services not in the default map still work.
    except ImportError:
        pass  # credentials module not yet available (bootstrap phase)

    # ── 2. Keychain via keyring library ──────────────────────────────────────
    # Only retry on exceptions (transient Keychain unavailability at startup).
    # If the lookup returns None (key absent or timeout), retrying won't help.
    key = None
    for attempt in range(_retries):
        try:
            key = _keyring_get(service, "api_key")
            break  # got a result (key or None) — no point retrying
        except Exception:
            if attempt < _retries - 1:
                time.sleep(_retry_delay)
    if key:
        return key

    # ── 3. macOS security CLI fallback ───────────────────────────────────────
    # Handles cases where the Python keyring library is blocked by
    # code-signing restrictions (e.g., inside a sandboxed process).
    # timeout=5: prevent indefinite hang when Keychain triggers an auth dialog.
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", "api_key", "-w"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass

    # ── 4. Environment variable fallback ─────────────────────────────────────
    env_var = _KEY_ENV_FALLBACKS.get(service, f"{service.upper()}_API_KEY")
    key = os.environ.get(env_var)
    if key:
        logger.warning(
            f"API key for '{service}' loaded from environment variable "
            f"'{env_var}'. Prefer storing in macOS Keychain or CredentialStore."
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
    Load all available API keys into environment variables so downstream
    libraries (LangChain, LangSmith) can find them. Call once at startup.

    If CredentialStore is initialized, reads from the in-memory cache.
    Otherwise falls back to the legacy Keychain / env-var path.
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
        logger.info(
            f"Loaded API keys from Keychain/CredentialStore: {', '.join(loaded)}"
        )


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
    r"repeat\s+(verbatim|exactly|word[\s\-]for[\s\-]word)",
    r"(in|from)\s+your\s+system\s+prompt",
    r"instructions?\s+given\s+to\s+you\s+by\s+(the\s+)?(operator|developer|system|admin)",
    # Extended exfiltration verbs (leak, dump, expose) applied to system prompt
    r"(leak|dump|expose|exfiltrate|disclose)\s+(?:(?:the|your|my|this|our)\s+)?(system\s+)(prompt|message|instructions?)",
    # System prompt synonym nouns (system message, initial instructions, operator prompt, preprompt)
    r"(reveal|show|print|output|display|repeat|share)\s+(?:(?:the|your|my|this|our)\s+)?(system\s+message|initial\s+(instructions?|prompt)|operator\s+(prompt|instructions?)|pre[\s\-]?prompt)",
    # Conversational indirect exfiltration ("what were you told/instructed [to do]")
    r"what\s+were\s+you\s+(told|instructed)",
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

# ── Unicode normalization for injection detection ─────────────────────────────
# Attackers can split keywords with zero-width characters (U+200B ZWSP, U+200C ZWNJ,
# U+200D ZWJ, U+200E/F LRM/RLM, U+2060 WJ, U+FEFF BOM) or use fullwidth Unicode
# equivalents (Ａ→A) to evade regex matching.  NFKC normalization collapses fullwidth
# and compatibility forms; the zero-width strip removes invisible splitters.
# Known limitation: Cyrillic homoglyphs (е, р, с) and Unicode small-caps are NOT
# collapsed by NFKC — a full homoglyph map would be needed for those vectors.
_ZERO_WIDTH_RE = re.compile(r"[\u200B\u200C\u200D\u200E\u200F\u2060\uFEFF]")


def _normalize_for_detection(text: str) -> str:
    """NFKC-normalize and strip zero-width characters before injection detection."""
    text = unicodedata.normalize("NFKC", text)
    return _ZERO_WIDTH_RE.sub("", text)


# ── Injection pattern tiering ─────────────────────────────────────────────────
# Tier 1 (HALT-WORTHY): Unambiguous injection; essentially zero legitimate use in
# tool arguments. SecureToolNode halts the run immediately on a Tier 1 match.
# Tier 2 (LOG-ONLY): Real injection signals that also appear in legitimate research
# or educational content. SecureToolNode logs a LOGGED threat event and continues.
# See SECURITY.md §"Injection Detection Architecture" for the full decision record.
_HALT_ON_INJECTION_PATTERNS: frozenset[str] = frozenset(
    p
    for p in _INJECTION_PATTERNS
    if p
    in {
        r"ignore\s+(all\s+)?previous\s+instructions?",
        r"disregard\s+(all\s+)?previous",
        r"forget\s+(all\s+)?previous\s+instructions?",
        r"override\s+(all\s+)?(previous\s+)?instructions?",
        r"jailbreak",
        r"dan\s+mode",
        r"dan\s*\d+\.?\d*",
        r"(enable|activate|unlock)\s+(dan|developer|god|unrestricted|jailbreak)\s+mode",
        r"(reveal|show|print|output|display)\s+(your\s+)?(system\s+)?prompt",
        r"(what\s+(are|were)\s+your\s+instructions)",
        r"<\s*(?:system|instruction|prompt)\s*>",
        r"\[INST\]|\[\/INST\]",
        r"<\|im_start\|>|<\|im_end\|>",
        # Extended exfiltration — synonymous with existing Tier-1 patterns above
        r"(leak|dump|expose|exfiltrate|disclose)\s+(?:(?:the|your|my|this|our)\s+)?(system\s+)(prompt|message|instructions?)",
        r"(reveal|show|print|output|display|repeat|share)\s+(?:(?:the|your|my|this|our)\s+)?(system\s+message|initial\s+(instructions?|prompt)|operator\s+(prompt|instructions?)|pre[\s\-]?prompt)",
    }
)


def has_halt_worthy_injection(matched_patterns: list[str]) -> bool:
    """
    Return True if any matched injection pattern is Tier 1 (halt-worthy).

    Tier 1 = unambiguous injection attempts that have no legitimate use in tool
    arguments. Tier 2 patterns (educational framing, hypothetical, etc.) are real
    injection signals but also appear in legitimate research queries, so they are
    logged without halting.

    See SECURITY.md §"Injection Detection Architecture" for the full decision record.
    """
    return bool(set(matched_patterns) & _HALT_ON_INJECTION_PATTERNS)


def detect_injection(text: str) -> tuple[bool, list[str]]:
    """
    Check text for prompt injection patterns.

    Input is NFKC-normalized and zero-width characters are stripped before matching
    so that fullwidth Unicode and invisible-splitter obfuscation are caught.

    Returns:
        (is_suspicious, list_of_matched_patterns)
    """
    normalized = _normalize_for_detection(text)
    matches = []
    for pattern in _COMPILED_PATTERNS:
        if pattern.search(normalized):
            matches.append(pattern.pattern)

    return bool(matches), matches


# ── Input / Output Sanitization ───────────────────────────────────────────────

# PII patterns to redact before sending to LangSmith traces or external APIs.
# Ordered from most specific to least to minimise false positives.
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
    # Database connection strings (postgresql://, mysql://, mongodb://, redis://)
    # Matched before the IP pattern so credentials embedded in DSNs are caught first.
    (
        re.compile(
            r"(?:postgresql|postgres|mysql|mongodb|redis|sqlite)://"
            r"[A-Za-z0-9_.%+\-]*(?::[^@\s]{1,64})?@[^\s\"'`]+"
        ),
        "[DB_DSN]",
    ),
    # Private IPv4 addresses (RFC 1918 + loopback + link-local).
    # Internal infrastructure IPs must not appear in traces or external API calls.
    #   10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16
    #
    # (?<!://) negative lookbehind: skip IPs that are URL hosts (immediately
    # following "://").  The SSRF guard (validate_fetch_url) already blocks
    # those before any network activity; redacting the host here would corrupt
    # the URL before the guard runs and produce an "invalid URL" error instead
    # of the intended "URL blocked" SSRF message.
    # IPs in plain text, query strings, and auth credentials ARE still redacted.
    (
        re.compile(
            r"(?<!://)\b(?:"
            r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|169\.254\.\d{1,3}\.\d{1,3}"
            r")\b"
        ),
        "[PRIVATE_IP]",
    ),
    # Unix home directory paths that expose usernames.
    # Matches /Users/<name>/... (macOS) and /home/<name>/... (Linux).
    (
        re.compile(r"(?:/(?:Users|home)/)[A-Za-z0-9._\-]+(?:/[^\s\"'`]*)?"),
        "[HOME_PATH]",
    ),
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


def sanitize_output(text: str) -> tuple[str, dict]:
    """
    Sanitize external tool output before it enters agent context.
    Applies PII redaction and injection detection — same as sanitize_text()
    but named distinctly so call sites are unambiguous about direction.
    """
    return sanitize_text(text, redact_pii=True, check_injection=True)


# ── Log injection prevention ───────────────────────────────────────────────────
# User-controlled strings logged verbatim can smuggle fake log lines (log
# injection) or ANSI escape sequences that manipulate terminals and log viewers.

_ANSI_RE: re.Pattern = re.compile(r"\x1b\[[0-9;]*[mGKHF]|\x1b[()][AB]")
_CTRL_RE: re.Pattern = re.compile(r"[\r\n\t\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_log_value(value: object, max_len: int = 200) -> str:
    """Strip ANSI codes and control chars from user-controlled log values.

    Prevents log injection (fake log lines) and terminal escape attacks.
    Call on any user-supplied string before it reaches logger.*().

    Args:
        value:   The value to sanitize (any type — converted via str()).
        max_len: Maximum length of the returned string (default 200).
                 Longer values are truncated with a trailing '…'.

    Returns:
        A clean, printable string safe for use in log messages.
    """
    s = value if isinstance(value, str) else str(value)
    s = _ANSI_RE.sub("", s)
    s = _CTRL_RE.sub(" ", s)
    if len(s) > max_len:
        s = s[:max_len] + "…"
    return s


def sanitize_messages(messages: list) -> list:
    """
    Sanitize a list of messages before outbound LLM calls (PII redaction on send).
    Handles both LangChain BaseMessage objects and plain dicts.
    Returns the same type as received (messages are NOT converted).
    """
    sanitized = []
    for msg in messages:
        if hasattr(msg, "content") and isinstance(msg.content, str):
            clean, _ = sanitize_text(msg.content)
            try:
                msg = msg.model_copy(update={"content": clean})
            except AttributeError:
                try:
                    msg = msg.copy(update={"content": clean})
                except Exception:
                    pass  # If copy fails, use original msg
        elif isinstance(msg, dict) and isinstance(msg.get("content"), str):
            msg = dict(msg)
            msg["content"], _ = sanitize_text(msg["content"])
        sanitized.append(msg)
    return sanitized


# ── Tool Registry ─────────────────────────────────────────────────────────────


class SecurityError(Exception):
    """Raised when a security invariant is violated (unregistered tool, hash mismatch)."""


@dataclass
class ToolManifest:
    """Describes a tool at registration time. Immutable after registration."""

    tool_id: str
    description: str
    input_schema: dict  # JSON-serialisable dict
    declared_side_effects: list[
        str
    ]  # e.g. ["reads_web", "calls_external_api:duckduckgo.com"]
    source: str  # "local" | "langchain" | "custom"
    version: str = "0.7.1-alpha"
    entrypoint_func: Any = field(
        default=None, repr=False
    )  # callable; used for source hash


# In-memory registries — populated by register_tool() at startup
_TOOL_REGISTRY: dict[str, ToolManifest] = {}
_TOOL_HASHES: dict[str, dict[str, str]] = (
    {}
)  # tool_id → {description_hash, schema_hash, entrypoint_hash}


def _compute_fast_hash(manifest: ToolManifest) -> dict[str, str]:
    """
    Fast in-memory integrity hash — description and schema only. No disk I/O.

    Used in the per-invocation hot path (verify_tool_before_invocation).
    Both inputs live in memory so this is microseconds, not milliseconds.
    """
    description_hash = hashlib.sha256(manifest.description.encode("utf-8")).hexdigest()
    schema_json = json.dumps(manifest.input_schema, sort_keys=True, ensure_ascii=True)
    schema_hash = hashlib.sha256(schema_json.encode("utf-8")).hexdigest()
    return {"description_hash": description_hash, "schema_hash": schema_hash}


def _compute_tool_hash(manifest: ToolManifest) -> dict[str, str]:
    """
    Full integrity hash — description, schema, AND entrypoint source via
    inspect.getsource(). Reads from disk; use only at registration time and
    in the `make verify-tool-registry` startup check, NOT on every invocation.

    Returns dict with keys: description_hash, schema_hash, entrypoint_hash.
    entrypoint_hash is None if the function source cannot be retrieved
    (built-ins, lambdas, dynamically created functions).
    """
    hashes = _compute_fast_hash(manifest)

    entrypoint_hash: str | None = None
    if manifest.entrypoint_func is not None:
        try:
            source = inspect.getsource(manifest.entrypoint_func)
            entrypoint_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
        except (OSError, TypeError):
            entrypoint_hash = None

    hashes["entrypoint_hash"] = entrypoint_hash
    return hashes


async def register_tool(
    manifest: ToolManifest,
    approved_by: str = "operator",
    approval_notes: str = "",
) -> None:
    """
    Register a tool in the in-memory registry and persist to DB.
    Idempotent — calling again with the same tool_id updates the record.

    Args:
        manifest:       ToolManifest describing the tool.
        approved_by:    Identifier of the approver (e.g. "operator", "ci").
        approval_notes: Free-text rationale for approval.
    """
    hashes = _compute_tool_hash(manifest)

    # Always update in-memory registry first (works even without DB)
    _TOOL_REGISTRY[manifest.tool_id] = manifest
    _TOOL_HASHES[manifest.tool_id] = hashes

    logger.info(
        f"[tool-registry] Registered '{manifest.tool_id}' (source={manifest.source} "
        f"version={manifest.version} approved_by={approved_by})"
    )

    # Persist to DB — non-fatal if DB not available (smoke tests run without DB)
    #
    # Security note: input_schema is stored alongside schema_hash so that
    # verify_tool_before_invocation can reconstruct a valid manifest on lazy-load.
    # This makes the lazy-load hash check self-referential (both sides come from
    # the same DB row), so it cannot detect DB-level tampering on the lazy path.
    # The primary integrity guarantee is in-memory registration at gateway startup
    # (register_researcher_tools / register_orchestrator_tools), which is the hot
    # path.  Lazy-load is only a fallback for tools registered out-of-process.
    try:
        from src.database import get_worker_pool

        pool = get_worker_pool()
        async with pool.connection() as conn:
            await conn.execute(
                """
                INSERT INTO tool_registry
                    (tool_id, source, version, description, description_hash,
                     schema_hash, entrypoint_hash, declared_side_effects,
                     approved_by, approval_notes, status, input_schema)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'APPROVED', %s)
                ON CONFLICT (tool_id) DO UPDATE SET
                    source            = EXCLUDED.source,
                    version           = EXCLUDED.version,
                    description       = EXCLUDED.description,
                    description_hash  = EXCLUDED.description_hash,
                    schema_hash       = EXCLUDED.schema_hash,
                    entrypoint_hash   = EXCLUDED.entrypoint_hash,
                    declared_side_effects = EXCLUDED.declared_side_effects,
                    approved_by       = EXCLUDED.approved_by,
                    approval_notes    = EXCLUDED.approval_notes,
                    input_schema      = EXCLUDED.input_schema,
                    status            = 'APPROVED',
                    approved_at       = NOW()
                """,
                (
                    manifest.tool_id,
                    manifest.source,
                    manifest.version,
                    manifest.description,
                    hashes["description_hash"],
                    hashes["schema_hash"],
                    hashes["entrypoint_hash"],
                    manifest.declared_side_effects,
                    approved_by,
                    approval_notes,
                    json.dumps(manifest.input_schema),
                ),
            )
    except RuntimeError:
        logger.debug(
            f"[tool-registry] DB not initialized — '{manifest.tool_id}' "
            "registered in memory only."
        )
    except Exception as e:
        logger.warning(
            f"[tool-registry] DB persist failed for '{manifest.tool_id}': {e} "
            "— registered in memory only."
        )

    # Phase 5: Ed25519-sign the manifest and store in tool_registry.
    # Non-fatal — signing unavailability is expected before setup-signing-key runs.
    try:
        from config.settings import settings as _settings

        if _settings.security.tool_signing_enabled:
            from src.tools.signing import sign_tool_manifest, get_public_key_fingerprint
            from src.database import store_tool_signature

            sig = sign_tool_manifest(
                tool_id=manifest.tool_id,
                description=manifest.description,
                input_schema=manifest.input_schema,
                declared_side_effects=manifest.declared_side_effects,
                version=manifest.version,
            )
            fingerprint = get_public_key_fingerprint()
            await store_tool_signature(manifest.tool_id, sig, fingerprint)
            logger.debug(
                f"[tool-registry] Manifest signed for '{manifest.tool_id}' "
                f"fingerprint={fingerprint!r}"
            )
    except RuntimeError:
        logger.debug(
            f"[tool-registry] Signing key not configured — "
            f"'{manifest.tool_id}' registered without signature. "
            "Run: make setup-signing-key"
        )
    except Exception as e:
        logger.warning(f"[tool-registry] Signing failed for '{manifest.tool_id}': {e}")


async def verify_tool_before_invocation(tool_id: str) -> bool:
    """
    Check that a tool is registered and its hashes have not changed since registration.

    Returns True if the tool is approved and integrity checks pass.
    Returns False (and logs a threat event) on hash mismatch or unregistered tool.
    Raises SecurityError only when the violation is severe enough to halt the run.
    """
    if tool_id not in _TOOL_REGISTRY:
        # Lazy-load from DB — tools registered via `make register-*` in a separate
        # process (e.g. the gateway startup context) are in the DB but not yet in the
        # in-memory registry of this process.  Reconstruct a minimal ToolManifest from
        # the stored description + input_schema and populate _TOOL_HASHES from the
        # stored hashes so the subsequent hash check can proceed normally.
        loaded = False
        try:
            from src.database import get_tool_registry_entry

            row = await get_tool_registry_entry(tool_id)
            if row is not None:
                raw_schema = row.get("input_schema", {})
                if isinstance(raw_schema, str):
                    try:
                        raw_schema = json.loads(raw_schema)
                    except (json.JSONDecodeError, ValueError):
                        raw_schema = {}
                elif not isinstance(raw_schema, dict):
                    raw_schema = {}
                manifest = ToolManifest(
                    tool_id=tool_id,
                    description=row["description"],
                    input_schema=raw_schema,
                    declared_side_effects=[],
                    source=row.get("source", "local"),
                )
                _TOOL_REGISTRY[tool_id] = manifest
                _TOOL_HASHES[tool_id] = {
                    "description_hash": row["description_hash"],
                    "schema_hash": row["schema_hash"],
                    "entrypoint_hash": row.get("entrypoint_hash"),
                }
                logger.info(
                    f"[tool-registry] Lazy-loaded '{tool_id}' from DB into in-memory registry."
                )
                loaded = True
        except Exception as e:
            logger.warning(f"[tool-registry] DB fallback failed for '{tool_id}': {e}")

        if not loaded:
            # Defensive alias fallback: SecureToolNode normalises dropped-underscore
            # names before this point, but guard against any bypass path (issue #276).
            # If tool_id matches the underscore-stripped form of a registered tool,
            # delegate to the canonical name rather than blocking.
            _canonical = next(
                (k for k in _TOOL_REGISTRY if k.replace("_", "") == tool_id),
                None,
            )
            if _canonical:
                logger.warning(
                    f"[tool-registry] Alias fallback: '{tool_id}' resolved to "
                    f"'{_canonical}' — SecureToolNode normalisation was bypassed."
                )
                return await verify_tool_before_invocation(_canonical)
            logger.error(
                f"[tool-registry] CAPABILITY_VIOLATION — tool '{tool_id}' not registered."
            )
            try:
                from src.database import log_threat_event

                await log_threat_event(
                    agent_id="security",
                    run_id="unknown",
                    threat_type="CAPABILITY_VIOLATION",
                    action_taken="BLOCKED",
                    confidence=1.0,
                    raw_input=tool_id[:200],
                    metadata={"tool_id": tool_id},
                )
            except Exception:
                pass
            return False

    manifest = _TOOL_REGISTRY[tool_id]
    stored_hashes = _TOOL_HASHES[tool_id]

    # Fast path: only check description + schema (pure in-memory, no disk I/O).
    # Entrypoint source hash is verified at startup via make verify-tool-registry,
    # not on every call — inspect.getsource() reads from disk and is expensive
    # when called hundreds of times per session.
    current_hashes = _compute_fast_hash(manifest)

    mismatches = {
        k: (stored_hashes.get(k), current_hashes.get(k))
        for k in ("description_hash", "schema_hash")
        if stored_hashes.get(k) and stored_hashes.get(k) != current_hashes.get(k)
    }

    if mismatches:
        logger.error(
            f"[tool-registry] TOOL_HASH_MISMATCH for '{tool_id}'. "
            f"Fields changed: {list(mismatches.keys())}"
        )
        try:
            from src.database import log_threat_event

            await log_threat_event(
                agent_id="security",
                run_id="unknown",
                threat_type="TOOL_HASH_MISMATCH",
                action_taken="BLOCKED",
                confidence=1.0,
                raw_input=tool_id[:200],
                metadata={"tool_id": tool_id, "mismatches": list(mismatches.keys())},
            )
        except Exception:
            pass
        return False

    return True


# ── Capability Boundary ───────────────────────────────────────────────────────

FORBIDDEN_CAPABILITIES: frozenset[str] = frozenset(
    {
        "register_tool",
        "write_executable",
        "invoke_unregistered",
        "modify_registry",
        "escalate_scope",
        "spawn_agent_direct",
        "modify_own_state",
    }
)


def check_capability_boundary(action: str) -> bool:
    """
    Phase 1 stub. Blocks actions in FORBIDDEN_CAPABILITIES.
    Full Guardian enforcement is wired in Phase 2 as a sidecar service.

    Returns True if action is permitted, False if forbidden.
    """
    if action in FORBIDDEN_CAPABILITIES:
        logger.error(f"[guardian-stub] CAPABILITY_VIOLATION blocked: {action}")
        return False
    return True


# ── SSRF Prevention ───────────────────────────────────────────────────────────
# Blocks Server-Side Request Forgery: an injected prompt instructing the agent
# to fetch internal services (postgres port, cloud metadata, localhost, etc.)

_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

_BLOCKED_HOSTS: frozenset[str] = frozenset(
    {
        "localhost",
        "metadata.google.internal",  # GCP metadata
        "169.254.169.254",  # AWS/Azure/GCP IMDS — cloud credentials endpoint
        "100.100.100.200",  # Alibaba Cloud metadata
    }
)

# Private / non-routable IP prefixes (string-level fast check before DNS)
_PRIVATE_IP_PATTERNS: list[re.Pattern] = [
    re.compile(r"^127\."),  # loopback (127.0.0.0/8)
    re.compile(r"^10\."),  # RFC 1918 (10.0.0.0/8)
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),  # RFC 1918 (172.16-31.x)
    re.compile(r"^192\.168\."),  # RFC 1918 (192.168.0.0/16)
    re.compile(r"^169\.254\."),  # link-local / IMDS (169.254.0.0/16)
    re.compile(r"^0\."),  # 0.0.0.0/8 — unspecified
    re.compile(r"^::1$"),  # IPv6 loopback
    re.compile(r"^fc[0-9a-f]{2}:", re.I),  # IPv6 unique local (fc00::/7)
    re.compile(r"^fd[0-9a-f]{2}:", re.I),  # IPv6 unique local (fd00::/8)
    re.compile(r"^fe80:", re.I),  # IPv6 link-local
]


def _is_private_ip(ip: str) -> bool:
    """Return True if ip string matches any private/reserved range."""
    for pattern in _PRIVATE_IP_PATTERNS:
        if pattern.match(ip):
            return True
    return False


def validate_fetch_url(url: str) -> None:
    """
    Validate a URL before making an outbound HTTP request.

    Raises SecurityError for:
    - Non-HTTP/HTTPS schemes  (file://, ftp://, gopher://, etc.)
    - Localhost and known metadata endpoints
    - Private / RFC 1918 / link-local IP addresses (SSRF prevention)
    - .local domains (mDNS — resolves to internal hosts)
    - DNS rebinding: resolves the hostname and checks the resulting IPs

    Call this inside every tool that makes outbound HTTP requests, BEFORE
    the request is made. SecureToolNode also calls this as belt-and-suspenders.

    Adversarial scenarios blocked:
      - web_fetch("http://localhost:5432")        — DB port
      - web_fetch("http://192.168.1.1/admin")    — internal router
      - web_fetch("http://169.254.169.254/...")  — cloud credentials
      - web_fetch("file:///etc/passwd")           — local file read
      - DNS rebinding: evil.com → 127.0.0.1 after TTL
    """
    import socket
    from urllib.parse import urlparse

    if not url or not isinstance(url, str):
        raise SecurityError(f"Invalid URL: {url!r}")

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise SecurityError(f"Malformed URL {url!r}: {e}") from e

    # 1. Scheme check
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise SecurityError(
            f"[SSRF] Forbidden URL scheme {scheme!r}. Only http/https are allowed."
        )

    host = (parsed.hostname or "").lower()
    if not host:
        raise SecurityError(f"[SSRF] URL has no hostname: {url!r}")

    # 2. Blocked hostname list
    if host in _BLOCKED_HOSTS:
        raise SecurityError(
            f"[SSRF] Blocked host {host!r} (known metadata/internal endpoint)."
        )

    # 3. .local domain (mDNS — resolves to internal hosts on the LAN)
    if host.endswith(".local"):
        raise SecurityError(f"[SSRF] .local domains are not permitted: {host!r}")

    # 4. String-level private IP check (fast path — catches literal IPs in URL)
    if _is_private_ip(host):
        raise SecurityError(f"[SSRF] Private IP address in URL: {host!r}")

    # 5. DNS resolution check — catches DNS rebinding and CNAMEs to internal IPs
    try:
        addrs = socket.getaddrinfo(host, None)
        for _, _, _, _, addr in addrs:
            resolved_ip = addr[0]
            if _is_private_ip(resolved_ip):
                raise SecurityError(
                    f"[SSRF] {host!r} resolves to private IP {resolved_ip!r}. "
                    "Possible DNS rebinding attack."
                )
    except SecurityError:
        raise
    except OSError:
        pass  # DNS resolution failed — let httpx handle that gracefully

    logger.debug(f"[ssrf-check] URL validated: {url!r}")


def is_ssrf_url(url: str) -> bool:
    """Return True if *url* targets a private/internal address (SSRF risk).

    Lightweight boolean wrapper around validate_fetch_url().  Use this when
    you want to gate on SSRF without raising an exception — e.g. webhook
    callback_url validation where we log-and-skip rather than 500.

    Returns:
        True  — URL should be BLOCKED (private/internal target detected).
        False — URL appears safe (public address, passes all checks).
    """
    try:
        validate_fetch_url(url)
        return False  # passed all checks — not an SSRF target
    except (SecurityError, ValueError):
        return True  # blocked
    except Exception:
        return True  # fail-safe: block on unexpected errors


# ── Outbound Tool Input Sanitization ─────────────────────────────────────────
# Symmetric counterpart to sanitize_output(). Sanitize BEFORE sending to any
# external API — prevents PII from leaking into third-party search queries,
# and detects injection attempts that may have crept into tool arguments.


def sanitize_tool_input(text: str, tool_id: str = "") -> tuple[str, dict]:
    """
    Sanitize a tool input value before it leaves the process.

    Applies PII redaction and injection detection — same pipeline as
    sanitize_text() but named distinctly so call sites are unambiguous
    about direction (outbound vs inbound).

    Call this on every argument that will be sent to an external API
    (search queries, fetch URLs, summarization inputs, etc.)
    """
    result, meta = sanitize_text(text, redact_pii=True, check_injection=True)
    if meta.get("pii_redacted") or meta.get("injection_detected"):
        logger.warning(
            f"[tool-input] sanitize_tool_input on tool='{tool_id}': "
            f"pii_redacted={meta['pii_redacted']} "
            f"injection_detected={meta['injection_detected']}"
        )
    return result, meta


# ── Destructive Pattern Detection (HITL trigger) ──────────────────────────────
# Patterns that are either adversarial OR legitimately risky enough to require
# human approval before the agent proceeds.
#
# These are NOT all malicious — a security researcher legitimately needs to query
# for "password policy". The point is: a HUMAN should decide, not the agent alone.

_DESTRUCTIVE_PATTERNS: list[tuple[re.Pattern, str]] = [
    # ── Credential probing ────────────────────────────────────────────────────
    # Searching for or extracting secrets, keys, or auth material.
    # May be legitimate security research — but always needs human review.
    (
        re.compile(
            r"\b(password|passwd|api[_\-\s]?key|secret[_\-\s]?key|private[_\-\s]?key"
            r"|access[_\-\s]?token|auth[_\-\s]?token|bearer[_\-\s]?token|credentials?"
            r"|keychain|vault\s+secret|pgp\s+key|ssh\s+key|client[_\-\s]?secret)\b",
            re.I,
        ),
        "CREDENTIAL_PROBE",
    ),
    # ── Internal infrastructure probing ──────────────────────────────────────
    # Attempts to discover or interact with internal services, admin panels,
    # or network topology. Classic lateral-movement reconnaissance pattern.
    (
        re.compile(
            r"\b(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.\d+\.\d+"
            r"|internal[_\-\s]?(api|service|host|network|endpoint)"
            r"|intranet|admin[_\-\s]?(panel|console|interface|login|portal)"
            r"|management[_\-\s]?(console|interface|portal)"
            r"|corp(orate)?\s+network|vpn\s+(gateway|server|config))\b",
            re.I,
        ),
        "INTERNAL_PROBE",
    ),
    # ── System file / path probing ────────────────────────────────────────────
    # Attempts to read system credentials, configs, or sensitive files.
    # Covers Unix, macOS, and Windows common targets.
    (
        re.compile(
            r"(/etc/(passwd|shadow|hosts|sudoers|crontab|ssh|ssl)"
            r"|/root/|/home/\w+/\.(ssh|aws|gnupg|config)"
            r"|~/\.(ssh|aws|gnupg|config|env|bashrc|zshrc)"
            r"|\\\\HKLM\\\\|\\\\HKCU\\\\|%APPDATA%|%SYSTEMROOT%|%LOCALAPPDATA%"
            r"|C:\\\\Windows\\\\System32|C:\\\\Users\\\\[^/\\\\]+\\\\AppData)",
            re.I,
        ),
        "SYSTEM_PATH_PROBE",
    ),
    # ── Bulk data exfiltration ────────────────────────────────────────────────
    # Mass extraction framing: dumps, full exports, scraping everything.
    # Also catches encrypt/overwrite/destroy patterns (ransomware-adjacent).
    (
        re.compile(
            r"\b(exfil(trat)?e?"
            r"|dump\s+(all|the\s+(database|db|tables?|data|users?|records?))"
            r"|export\s+(all|every|complete|full|entire)"
            r"|scrape\s+(all|every|the\s+(site|web|pages?|content))"
            r"|harvest\s+(all|data|credentials?|emails?|records?)"
            # Bulk destroy/overwrite (ransomware / destructive patterns)
            r"|encrypt\s+(all|every|the)\s+(files?|data|disks?|volumes?|backups?)"
            r"|overwrite\s+(all|every|the)\s+(files?|data|disks?|records?)"
            r"|wipe\s+(all|the|disks?|drives?|volumes?|database)"
            r"|delete\s+(all|every|the)\s+(files?|data|records?|users?|backups?)"
            r"|shred\s+(all|every|the)\s+(files?|data|disks?))\b",
            re.I,
        ),
        "BULK_DESTRUCTIVE",
    ),
    # ── Self-probe ────────────────────────────────────────────────────────────
    # Agent attempting to learn its own config, identity, or secrets.
    # A key early indicator of a successful prompt injection.
    (
        re.compile(
            r"\b(your\s+(system\s+)?prompt|your\s+instructions?"
            r"|your\s+(api\s+)?key|your\s+(initial|current)\s+(instructions?|context)"
            r"|legionforge\s+(config|secret|key|prompt)"
            r"|agent[_\-\s]?(config|settings|state|key|identity)"
            r"|what\s+are\s+your\s+instructions?)\b",
            re.I,
        ),
        "SELF_PROBE",
    ),
    # ── Command / shell injection ─────────────────────────────────────────────
    # Shell metacharacters or command sequences in tool arguments.
    # Indicates attempt to escape tool boundaries and run system commands.
    (
        re.compile(
            r"[|;&`]\s*(cat|ls|ps|id|whoami|wget|curl|nc|netcat|bash|sh|zsh|dash"
            r"|python\d*|perl|ruby|node|php|powershell|cmd\.exe)\b"
            r"|\$\([^)]+\)"  # $(command) subshell
            r"|`[^`]{3,}`"  # `command` backtick execution
            r"|\beval\s*\(",  # eval( calls
            re.I,
        ),
        "CMD_INJECTION",
    ),
    # ── Prompt-level privilege escalation ────────────────────────────────────
    # Agent being instructed to escalate its own permissions or bypass controls.
    (
        re.compile(
            r"\b(sudo|run\s+as\s+(root|admin|administrator|superuser)"
            r"|escalate\s+(privileges?|permissions?|access|scope)"
            r"|bypass\s+(the\s+)?(security|auth\w*|authorization|check|filter|guard)"
            r"|disable\s+(the\s+|a\s+)?(security|safeguards?|checks?|filters?|guards?|monitoring|logging)"
            r"|grant\s+(yourself|itself|the\s+agent)(\s+\w+)?\s+(access|permissions?|privileges?))\b",
            re.I,
        ),
        "PRIVILEGE_ESCALATION",
    ),
    # ── Data staging / covert channel setup ──────────────────────────────────
    # Patterns that suggest setting up infrastructure for exfiltration:
    # posting data to webhooks, encoding for transmission, dead-drop patterns.
    (
        re.compile(
            r"\b(send\s+(this|the|all)\s+(data|output|result|content)\s+to"
            r"|post\s+(this|the|all)\s+(data|output|result)\s+to"
            r"|webhook\.site|requestbin|pipedream|ngrok\.(io|com)"
            r"|pastebin\.com|hastebin|ghostbin"  # common data dead-drops
            r"|base64\s+(encode|encod)\s+(and\s+)?(send|post|upload)"
            r"|encode\s+(and\s+)?(exfil|send|transmit|upload))\b",
            re.I,
        ),
        "DATA_STAGING",
    ),
    # ── Reconnaissance patterns ───────────────────────────────────────────────
    # Systematic enumeration of users, services, network topology, or software
    # versions — standard first phase of an attack chain.
    (
        re.compile(
            r"\b(enumerate\s+(all\s+)?(users?|accounts?|services?|hosts?|ports?|subnets?|domains?)"
            r"|list\s+all\s+(users?|accounts?|services?|processes?|ports?|connections?)"
            r"|network\s+(scan|map|topology|enumeration)"
            r"|port\s+(scan|sweep|probe)"
            r"|service\s+(discovery|enumeration|fingerprint)"
            r"|os\s+(detection|fingerprint|version\s+scan))\b",
            re.I,
        ),
        "RECONNAISSANCE",
    ),
]


# ── Destructive pattern tier classification ───────────────────────────────────
# FORCE-END tier: high-confidence, unambiguously adversarial in any tool-call
# context. Guardian (sidecar) intercepts these first and returns force_end=True.
# SecureToolNode also force-ends as a fallback if Guardian is unavailable.
# No legitimate task should ever produce these in a tool argument.
# No human gate — there is no valid approve path for these categories.
FORCE_END_CATEGORIES: frozenset[str] = frozenset(
    {
        "CMD_INJECTION",  # Shell metacharacters — clear attempt to escape tool sandbox
        "SELF_PROBE",  # Agent learning its own config — sign of successful injection
        "DATA_STAGING",  # Webhook dead-drops, encode-and-send — exfiltration setup
        "PRIVILEGE_ESCALATION",  # "bypass security check" — unambiguously adversarial
    }
)

# HITL-REVIEW tier: ambiguous — may be adversarial OR legitimate research.
# In "team" / "enterprise" hitl_mode: task pauses for operator approval.
# In "permissive" hitl_mode: event is logged and run continues (see #264).
# Examples of legitimate triggers:
#   CREDENTIAL_PROBE:  "best practices for API key rotation"
#   RECONNAISSANCE:    "how to enumerate Python package dependencies"
#   INTERNAL_PROBE:    article mentioning "localhost" in a Docker tutorial
#   BULK_DESTRUCTIVE:  "delete all old log records" (legitimate admin task)
HITL_REVIEW_CATEGORIES: frozenset[str] = frozenset(
    {
        "CREDENTIAL_PROBE",
        "RECONNAISSANCE",
        "INTERNAL_PROBE",
        "BULK_DESTRUCTIVE",
        "SYSTEM_PATH_PROBE",
    }
)


def detect_destructive_pattern(text: str) -> tuple[bool, list[str]]:
    """
    Scan text for patterns that require human-in-the-loop review or immediate halt.
    Returns (any_matched, list_of_matched_categories).

    Callers should check each category against FORCE_END_CATEGORIES to decide
    whether to force-end or review. check_hitl_required() does this
    automatically.

    FORCE-END categories (force_end=True — Guardian hard stop, no human gate):
      CMD_INJECTION        — shell metacharacters in tool arguments
      SELF_PROBE           — agent probing its own config or identity
      DATA_STAGING         — webhook dead-drops, encode-and-send setup
      PRIVILEGE_ESCALATION — bypass/disable security controls

    HITL-REVIEW categories (operator review — log+continue until #266 UI lands):
      CREDENTIAL_PROBE     — queries containing password/key/token vocabulary
      RECONNAISSANCE       — systematic enumeration requests
      INTERNAL_PROBE       — localhost, admin panels, internal service refs
      BULK_DESTRUCTIVE     — mass encrypt/wipe/delete framing
      SYSTEM_PATH_PROBE    — /etc/passwd, ~/.ssh, registry path refs
    """
    matched: list[str] = []
    for pattern, category in _DESTRUCTIVE_PATTERNS:
        if pattern.search(text):
            matched.append(category)
    return bool(matched), matched


class Guardian:
    """
    Phase 1 stub. Real Guardian implemented in Phase 2 as a sidecar service.
    All methods return permissive results past the capability check,
    and log every call to build the Phase 2 baseline.
    """

    @staticmethod
    def check(tool_id: str, action: str, state: dict) -> bool:
        """
        Returns True if the tool invocation is permitted.
        Blocks immediately on FORBIDDEN_CAPABILITIES; otherwise permits.
        """
        logger.debug(f"[guardian-stub] check(tool_id={tool_id!r}, action={action!r})")
        if not check_capability_boundary(action):
            return False
        return True  # stub: allow everything past capability check
