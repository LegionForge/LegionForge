"""
src/security/acl.py
───────────────────
Phase 3: Task-scoped JWT access control.

Every agent run can be issued a TaskToken that declares exactly which tools
and data classes are allowed. Sub-agents receive derived (narrower) tokens —
a child token can never exceed its parent's scope (privilege cannot escalate).

Key functions:
    issue_task_token()    — create a new signed JWT for an agent run
    validate_task_token() — decode and verify a JWT; returns TaskToken | None
    derive_task_token()   — narrow a parent token (child ⊆ parent scope enforced)

Signing:
    Algorithm: HS256 (symmetric — one shared secret, no PKI complexity at this scale)
    Secret load order:
      1. Keychain service "legionforge_task_tokens" (native macOS path)
      2. TASK_TOKEN_SECRET environment variable (Docker / CI path)
    Raises RuntimeError at issue/validate time if neither source is available.

Setup (one-time):
    python -c "import secrets; print(secrets.token_hex(32))"  # generate secret
    security add-generic-password -s legionforge_task_tokens -a api_key -w '<secret>'
"""

from __future__ import annotations

import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any

import jwt

from config.settings import settings

logger = logging.getLogger(__name__)


# ── Custom exceptions ─────────────────────────────────────────────────────────


class PrivilegeEscalationError(ValueError):
    """Raised when a derived token attempts to exceed its parent's scope."""

    pass


# ── Data models ───────────────────────────────────────────────────────────────


@dataclass
class TaskToken:
    """
    Decoded representation of a task-scoped JWT.

    Fields mirror the JWT payload claims so callers don't need to parse JWT
    directly — validate_task_token() returns this, not a raw dict.
    """

    token_id: str
    agent_id: str
    run_id: str
    granted_tools: list[str]
    granted_tables: list[str]
    granted_data_classes: list[str]
    expires_at: datetime
    parent_token_id: str | None
    escalation_policy: str  # "deny" | "alert"


@dataclass
class EscalationRequest:
    """
    Represents a runtime escalation attempt — recorded when an agent calls a
    tool outside its token scope.

    Policy semantics (both halt the run — behaviour difference is logging only):
      "deny"  — suspicious; logged to threat_events as TOOL_SCOPE_VIOLATION.
                Use for sub-agents that should NEVER need to exceed their scope.
      "alert" — operational under-scoping; logged to audit_log as ESCALATION_BLOCKED.
                Use for experimental agents where scope may need tuning.

    Phase 3: halt + write to threat_events / audit_log + surface on /status.
    Phase 4: structured escalation via agent output (never implicit tool calls).

    Security invariant: escalation approvals are always run-scoped and single-use.
    Approving an escalation NEVER modifies roles.yaml, the tool registry, or
    grants capability to future runs. The only legitimate way to expand an agent's
    baseline permissions is a human editing roles.yaml and committing it.
    """

    token_id: str
    agent_id: str
    requested_tool: str
    reason: str
    escalation_policy: str


# ── Secret management ─────────────────────────────────────────────────────────


def _get_signing_secret() -> str:
    """
    Return the JWT signing secret.

    Load order:
      1. TASK_TOKEN_SECRET environment variable (Docker / CI / test path)
      2. Keychain service "legionforge_task_tokens" (native macOS production path)

    Env var is checked first so that tests and Docker containers can inject a
    secret without touching the Keychain — and to avoid triggering a Keychain
    auth dialog when running inside sandboxed processes (e.g. Claude Code).

    Raises RuntimeError if neither source yields a value.
    """
    # Check env var first — Docker, CI, and test environments set this explicitly.
    secret = os.environ.get("TASK_TOKEN_SECRET", "")
    if secret:
        return secret

    # Production path: Keychain (import guard: core may not be importable in all contexts)
    try:
        from src.security.core import get_api_key_optional

        secret = get_api_key_optional(settings.security.task_token_secret_service)
        if secret:
            return secret
    except Exception as e:
        # The RuntimeError below will surface the missing-secret case loudly;
        # debug-log the underlying Keychain failure so it's diagnosable.
        logger.debug("[acl] task-token secret lookup failed: %s", e)

    raise RuntimeError(
        f"Task token signing secret not found.\n"
        f"Store it in Keychain:\n"
        f"  security add-generic-password "
        f"-s {settings.security.task_token_secret_service} -a api_key -w '<secret>'\n"
        f"Or set the TASK_TOKEN_SECRET environment variable (Docker/CI path)."
    )


# ── Core functions ────────────────────────────────────────────────────────────


def issue_task_token(
    agent_id: str,
    run_id: str,
    granted_tools: list[str],
    granted_tables: list[str] | None = None,
    granted_data_classes: list[str] | None = None,
    ttl_seconds: int | None = None,
    parent_token_id: str | None = None,
    escalation_policy: str = "deny",
) -> str:
    """
    Issue a new task-scoped JWT for an agent run.

    Args:
        agent_id:             Agent identifier (e.g. "researcher", "orchestrator").
        run_id:               Unique run UUID for traceability.
        granted_tools:        Tool IDs this token authorises.
        granted_tables:       Database tables this token may access (default: []).
        granted_data_classes: Data sensitivity classes (public, internal, security).
        ttl_seconds:          Token lifetime in seconds (default: settings value).
        parent_token_id:      Token ID of the parent (for derived tokens).
        escalation_policy:    "deny" (suspicious — threat_events) |
                              "alert" (operational — audit_log) on out-of-scope call.

    Returns:
        Signed JWT string (str). Store in AgentState.task_token.

    Raises:
        RuntimeError: if signing secret is not available.
    """
    secret = _get_signing_secret()
    token_id = str(uuid.uuid4())

    if ttl_seconds is None:
        ttl_seconds = settings.security.task_token_ttl_seconds

    now = datetime.now(tz=timezone.utc)
    expires_at = now + timedelta(seconds=ttl_seconds)

    payload: dict[str, Any] = {
        "jti": token_id,
        "sub": agent_id,
        "iss": settings.security.task_token_issuer,
        "iat": now,
        "exp": expires_at,
        "run_id": run_id,
        "granted_tools": granted_tools,
        "granted_tables": granted_tables or [],
        "granted_data_classes": granted_data_classes or [],
        "parent_token_id": parent_token_id,
        "escalation_policy": escalation_policy,
    }

    token_str: str = jwt.encode(payload, secret, algorithm="HS256")

    logger.debug(
        f"[acl] Token issued jti={token_id[:8]}... agent={agent_id} "
        f"tools={granted_tools} ttl={ttl_seconds}s"
    )
    return token_str


def validate_task_token(token_str: str) -> TaskToken | None:
    """
    Decode and validate a task token JWT.

    Returns TaskToken on success. Returns None on any failure:
      - Expired signature
      - Invalid signature / tampered payload
      - Missing required claims
      - Issuer mismatch
      - Signing secret unavailable

    Never raises — callers must treat None as a halt condition.
    """
    try:
        secret = _get_signing_secret()
    except RuntimeError as e:
        logger.error(f"[acl] Cannot validate token — signing secret unavailable: {e}")
        return None

    try:
        payload = jwt.decode(
            token_str,
            secret,
            algorithms=["HS256"],
            options={"require": ["exp", "iat", "jti", "sub", "iss"]},
        )
    except jwt.ExpiredSignatureError:
        logger.warning("[acl] Task token has expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"[acl] Invalid task token: {e}")
        return None
    except Exception as e:
        logger.error(f"[acl] Unexpected error decoding token: {e}")
        return None

    # Verify issuer
    if payload.get("iss") != settings.security.task_token_issuer:
        logger.warning(
            f"[acl] Token issuer mismatch: expected "
            f"{settings.security.task_token_issuer!r}, got {payload.get('iss')!r}"
        )
        return None

    return TaskToken(
        token_id=payload["jti"],
        agent_id=payload["sub"],
        run_id=payload.get("run_id", ""),
        granted_tools=payload.get("granted_tools", []),
        granted_tables=payload.get("granted_tables", []),
        granted_data_classes=payload.get("granted_data_classes", []),
        expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
        parent_token_id=payload.get("parent_token_id"),
        escalation_policy=payload.get("escalation_policy", "deny"),
    )


def derive_task_token(
    parent_jwt: str,
    granted_tools: list[str],
    granted_data_classes: list[str],
    ttl_seconds: int | None = None,
) -> str:
    """
    Derive a narrower sub-agent token from a parent token.

    Enforces that child scope ⊆ parent scope — privilege cannot escalate.
    Child token expires at min(parent.expires_at, now + ttl_seconds).
    Child inherits parent's granted_tables and escalation_policy.

    Args:
        parent_jwt:           Signed JWT string of the parent token.
        granted_tools:        Tool IDs for the child (must be ⊆ parent's tools).
        granted_data_classes: Data classes for the child (must be ⊆ parent's).
        ttl_seconds:          Child TTL; capped at parent's remaining lifetime.

    Returns:
        Signed JWT string for the child token.

    Raises:
        PrivilegeEscalationError: if child requests tools/data_classes outside parent scope.
        ValueError: if parent token is invalid/expired or TTL is non-positive.
    """
    parent = validate_task_token(parent_jwt)
    if parent is None:
        raise ValueError("Cannot derive from invalid or expired parent token")

    # Enforce: child tools ⊆ parent tools
    child_tools_set = set(granted_tools)
    parent_tools_set = set(parent.granted_tools)
    extra_tools = child_tools_set - parent_tools_set
    if extra_tools:
        raise PrivilegeEscalationError(
            f"Cannot derive token: child requests tools outside parent scope: "
            f"{sorted(extra_tools)}"
        )

    # Enforce: child data_classes ⊆ parent data_classes
    child_dc_set = set(granted_data_classes)
    parent_dc_set = set(parent.granted_data_classes)
    extra_dc = child_dc_set - parent_dc_set
    if extra_dc:
        raise PrivilegeEscalationError(
            f"Cannot derive token: child requests data_classes outside parent scope: "
            f"{sorted(extra_dc)}"
        )

    # Child expires_at = min(parent.expires_at, now + ttl)
    now = datetime.now(tz=timezone.utc)
    if ttl_seconds is None:
        ttl_seconds = settings.security.task_token_ttl_seconds
    child_candidate_expires = now + timedelta(seconds=ttl_seconds)
    child_expires = min(parent.expires_at, child_candidate_expires)
    child_ttl = int((child_expires - now).total_seconds())

    if child_ttl <= 0:
        raise ValueError(
            "Cannot derive token: parent has expired or remaining lifetime is zero"
        )

    derived = issue_task_token(
        agent_id=parent.agent_id,
        run_id=parent.run_id,
        granted_tools=granted_tools,
        granted_tables=parent.granted_tables,  # inherit table access
        granted_data_classes=granted_data_classes,
        ttl_seconds=child_ttl,
        parent_token_id=parent.token_id,
        escalation_policy=parent.escalation_policy,
    )

    logger.info(
        f"[acl] Token derived from parent={parent.token_id[:8]}... "
        f"tools={granted_tools} ttl={child_ttl}s"
    )
    return derived
