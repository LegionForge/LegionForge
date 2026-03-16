"""
src/credentials.py
──────────────────
Modular credential store — abstracts all secret access behind a unified
interface. Three backends are supported:

  keychain  — macOS Keychain via keyring + security CLI (default for dev)
  env_var   — pure environment variable lookup (Docker/CI)
  file      — YAML credentials file at ~/.config/legionforge/credentials.yaml
              (air-gapped or non-macOS environments)

Security properties:
  • Credentials are loaded ONCE at initialization into an in-memory dict.
    Subsequent calls to get() never touch the Keychain, filesystem, or env.
  • get_safe_subprocess_env() returns an os.environ copy with ALL secrets
    stripped — use this for EVERY subprocess.run() call in the framework.
  • Credentials file must be chmod 0600; CredentialStore refuses to load
    from a world-readable or group-readable file (fail-safe).
  • After initialization, the macOS Keychain and security CLI are never
    accessed again. No user-triggered code path causes a Keychain popup.

Usage:
    from src.credentials import creds
    creds.initialize(settings.security)  # call once at startup

    # Retrieve a secret (from in-memory cache after init)
    api_key = creds.get("anthropic")

    # Get a subprocess-safe env (no secrets)
    proc = subprocess.run(cmd, env=creds.get_safe_subprocess_env(), ...)

File backend format (~/.config/legionforge/credentials.yaml, chmod 0600):
    openai: sk-...
    anthropic: sk-ant-...
    postgres: my_password
    legionforge_health: tok_...
    legionforge_task_tokens: secret_...
    legionforge_tool_signer: <hex_private_key>
    legionforge_db_app: <restricted-db-user-password>
"""

from __future__ import annotations

import logging
import os
import stat
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

# Default location for file-backend credentials.
# This file MUST be chmod 0600 — world/group readable files are rejected.
DEFAULT_CREDENTIALS_FILE = Path.home() / ".config" / "legionforge" / "credentials.yaml"

# Mapping: service name → environment variable name.
# Used by env_var backend and as fallback for keychain/file backends.
_SERVICE_TO_ENV: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "langsmith": "LANGSMITH_API_KEY",
    "postgres": "POSTGRES_PASSWORD",
    "legionforge_health": "LEGIONFORGE_HEALTH_TOKEN",
    "legionforge_task_tokens": "TASK_TOKEN_SECRET",
    "legionforge_tool_signer": "TOOL_SIGNING_PRIVATE_KEY",
    # Phase 6: DB RBAC — restricted runtime DB user (no DDL, no DELETE on audit tables)
    "legionforge_db_app": "POSTGRES_APP_PASSWORD",
    # Phase 56: Search provider API keys
    "legionforge_tavily_api_key": "TAVILY_API_KEY",
    "legionforge_brave_api_key": "BRAVE_API_KEY",
    "legionforge_exa_api_key": "EXA_API_KEY",
    "legionforge_perplexity_api_key": "PERPLEXITY_API_KEY",
    "legionforge_firecrawl_api_key": "FIRECRAWL_API_KEY",
    # InceptionLabs cloud LLM provider (mercury-2, OpenAI-compatible)
    "legionforge_inceptionlabs_api_key": "INCEPTIONLABS_API_KEY",
}

# All environment variable names that contain secrets.
# Used to build the set of keys to strip from subprocess environments.
_SECRET_ENV_VARS: frozenset[str] = frozenset(_SERVICE_TO_ENV.values()) | frozenset(
    {
        # Common secret env var names not in _SERVICE_TO_ENV
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "LANGSMITH_API_KEY",
        "LANGCHAIN_API_KEY",
        "POSTGRES_PASSWORD",
        "POSTGRES_APP_PASSWORD",
        "DATABASE_URL",
        "SECRET_KEY",
        "SIGNING_KEY",
        "PRIVATE_KEY",
        "LEGIONFORGE_HEALTH_TOKEN",
        "TASK_TOKEN_SECRET",
        "TOOL_SIGNING_PRIVATE_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "NPM_TOKEN",
        "PYPI_TOKEN",
        "HUGGINGFACE_TOKEN",
        "HF_TOKEN",
        # LangChain / LangSmith variants
        "LANGCHAIN_TRACING_V2",  # not a secret but controls tracing
        "LANGCHAIN_PROJECT",
    }
)

# Allowlist of environment variable keys that are SAFE to pass to subprocesses.
# This is a WHITELIST — any key not in this set is excluded.
# Secrets (API keys, passwords, tokens) are never on this list.
_SAFE_SUBPROCESS_ENV_KEYS: frozenset[str] = frozenset(
    {
        # Process essentials
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "TMPDIR",
        "TEMP",
        "TMP",
        "PWD",
        "OLDPWD",
        # Locale / encoding
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LC_MESSAGES",
        "LC_NUMERIC",
        "LC_TIME",
        "TZ",
        # Python runtime
        "PYTHONPATH",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONNOUSERSITE",
        "PYTHONUNBUFFERED",
        "VIRTUAL_ENV",
        # macOS dynamic linking
        "DYLD_LIBRARY_PATH",
        # Linux dynamic linking
        "LD_LIBRARY_PATH",
        # Terminal / color
        "TERM",
        "COLORTERM",
        "NO_COLOR",
        # CI marker (not a secret)
        "CI",
        # Ollama model path (not a secret)
        "OLLAMA_MODELS",
    }
)

# ── keyring import (optional — Linux containers may not have it) ───────────────

try:
    import keyring as _keyring
except ImportError:
    _keyring = None  # type: ignore[assignment]


def _keyring_get(service: str, account: str, timeout: float = 2.0) -> str | None:
    """
    Call keyring.get_password with a hard timeout.

    On macOS, keyring.get_password can hang indefinitely when the calling
    process does not have Keychain authorization. We run it in a daemon thread
    and join with a timeout so the caller is never blocked longer than
    `timeout` seconds.
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


# ── CredentialStore ────────────────────────────────────────────────────────────


class CredentialStore:
    """
    Unified credential store with pluggable backends.

    Initialization pattern (call once at application startup):
        from src.credentials import creds
        creds.initialize(settings.security)

    After initialize(), ALL get() calls read from an in-memory dict.
    The Keychain, filesystem, and environment are never accessed again
    for secret retrieval. This prevents any user-triggered code path
    from causing a Keychain popup, a file read, or env sniffing.

    For subprocess safety:
        Use get_safe_subprocess_env() for EVERY subprocess.run() call.
        This returns a sanitized copy of os.environ with no secrets.
    """

    def __init__(self) -> None:
        self._store: dict[str, str] = {}
        self._initialized = False
        self._backend: str = "env_var"
        self._credentials_file: Path = DEFAULT_CREDENTIALS_FILE
        self._purge_env_after_load: bool = False
        self._keychain_access_allowed: bool = True
        # Cache the safe subprocess env at init time (snapshot of os.environ)
        self._safe_env_snapshot: dict[str, str] | None = None

    # ── Initialization ──────────────────────────────────────────────────────

    def initialize(self, security_config: object) -> None:
        """
        Load all known credentials into memory from the configured backend.

        Must be called once at startup (e.g., in init_db() or main()).
        Subsequent calls are no-ops.

        Args:
            security_config: A SecurityConfig instance from config.settings.
                             Expected attributes (all have defaults for forward-compat):
                               secret_backend: "keychain" | "env_var" | "file"
                               purge_env_after_load: bool
                               keychain_access_allowed: bool
                               credentials_file_path: str
        """
        if self._initialized:
            logger.debug("CredentialStore already initialized — skipping")
            return

        # Read config with graceful defaults for any missing fields
        self._backend = getattr(security_config, "secret_backend", "env_var")
        self._purge_env_after_load = getattr(
            security_config, "purge_env_after_load", False
        )
        self._keychain_access_allowed = getattr(
            security_config, "keychain_access_allowed", True
        )
        creds_path = getattr(security_config, "credentials_file_path", "")
        if creds_path:
            self._credentials_file = Path(creds_path).expanduser()

        # Load all known services into memory
        loaded: list[str] = []
        not_found: list[str] = []
        for service in _SERVICE_TO_ENV:
            value = self._load_one(service)
            if value:
                self._store[service] = value
                loaded.append(service)
            else:
                not_found.append(service)

        self._initialized = True
        logger.info(
            f"CredentialStore initialized (backend={self._backend}): "
            f"loaded={loaded}, not_found={not_found}"
        )

        # Snapshot the safe subprocess env NOW, before any purge.
        # This gives subprocesses a consistent PATH/HOME/etc even if we later
        # purge secrets from os.environ.
        self._safe_env_snapshot = {
            k: v for k, v in os.environ.items() if k in _SAFE_SUBPROCESS_ENV_KEYS
        }

        # Optional: purge secrets from os.environ after loading into memory.
        # WARNING: This breaks LangChain / LangSmith which require API keys in
        # os.environ. Only enable if you use a fully store-aware LLM client.
        if self._purge_env_after_load:
            self._purge_secrets_from_env()

    def _load_one(self, service: str) -> str | None:
        """Load a single credential from the configured backend."""
        if self._backend == "keychain":
            return self._load_from_keychain(service)
        elif self._backend == "file":
            return self._load_from_file(service)
        else:
            # env_var (default) or unknown backend
            if self._backend not in ("keychain", "env_var", "file"):
                logger.warning(
                    f"Unknown backend '{self._backend}' — falling back to env_var"
                )
            return self._load_from_env(service)

    def _load_from_keychain(self, service: str) -> str | None:
        """
        Load from macOS Keychain. Falls back to env_var if not found.

        Uses both the Python keyring library and the macOS security CLI as
        a fallback, since code-signing restrictions can block keyring on
        some configurations.
        """
        if not self._keychain_access_allowed:
            logger.debug(
                f"Keychain access disabled by config — skipping for '{service}'"
            )
            return self._load_from_env(service)

        # Try Python keyring (with timeout to prevent Keychain UI hangs)
        key = _keyring_get(service, "api_key", timeout=2.0)
        if key:
            return key

        # Try macOS security CLI (handles code-signing restriction edge cases)
        try:
            result = subprocess.run(
                [
                    "security",
                    "find-generic-password",
                    "-s",
                    service,
                    "-a",
                    "api_key",
                    "-w",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass

        # Fall through to env var
        return self._load_from_env(service)

    def _load_from_env(self, service: str) -> str | None:
        """Load from environment variable."""
        env_var = _SERVICE_TO_ENV.get(service, f"{service.upper()}_API_KEY")
        return os.environ.get(env_var)

    def _load_from_file(self, service: str) -> str | None:
        """
        Load from credentials YAML file.

        Security requirements:
          - File must exist and be chmod 0600 (owner read/write only).
          - World-readable or group-readable files raise PermissionError.
          - Falls back to env_var if file doesn't exist or key not in file.
        """
        if not self._credentials_file.exists():
            return self._load_from_env(service)

        # Reject world-readable or group-readable files
        file_stat = self._credentials_file.stat()
        permissions = stat.S_IMODE(file_stat.st_mode)
        if permissions & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
            raise PermissionError(
                f"Credentials file {self._credentials_file} is group/world accessible.\n"
                f"Fix with: chmod 0600 {self._credentials_file}"
            )

        try:
            with open(self._credentials_file, "r") as f:
                data = yaml.safe_load(f) or {}
        except Exception as exc:
            logger.error(f"Failed to read credentials file: {exc}")
            return self._load_from_env(service)

        value = data.get(service)
        if value:
            return str(value)

        # Fall back to env var
        return self._load_from_env(service)

    def _purge_secrets_from_env(self) -> None:
        """Remove all known secret environment variables from os.environ."""
        purged: list[str] = []
        for env_var in _SECRET_ENV_VARS:
            if env_var in os.environ:
                del os.environ[env_var]
                purged.append(env_var)
        if purged:
            logger.info(
                f"Purged {len(purged)} secret env vars from os.environ: {purged}"
            )

    # ── Secret Access ────────────────────────────────────────────────────────

    def get(self, service: str, default: Optional[str] = None) -> Optional[str]:
        """
        Retrieve a credential by service name.

        After initialize(), reads exclusively from the in-memory cache.
        Before initialize() (e.g., in test environments), falls back to
        env var lookup with a debug log warning.

        Args:
            service: Service name (e.g. "anthropic", "postgres",
                     "legionforge_health", "legionforge_task_tokens")
            default: Return value if service not found (default: None)

        Returns:
            The credential value, or default if not found.
        """
        if not self._initialized:
            logger.debug(
                f"CredentialStore.get('{service}') called before initialize() "
                f"— falling back to env var"
            )
            return self._load_from_env(service) or default

        return self._store.get(service, default)

    def require(self, service: str) -> str:
        """
        Retrieve a credential, raising RuntimeError if not found.

        Use this for required credentials where absence should halt startup.
        """
        value = self.get(service)
        if not value:
            env_var = _SERVICE_TO_ENV.get(service, f"{service.upper()}_API_KEY")
            raise RuntimeError(
                f"Required credential '{service}' not found.\n"
                f"  Backend: {self._backend}\n"
                f"  Env var: export {env_var}=<value>\n"
                f"  Keychain: python -m keyring set {service} api_key\n"
                f"  File: add '{service}: <value>' to {DEFAULT_CREDENTIALS_FILE}"
            )
        return value

    def is_available(self, service: str) -> bool:
        """Return True if the credential for the given service is loaded."""
        return bool(self.get(service))

    def set_runtime(self, service: str, value: str) -> None:
        """
        Store a credential in the in-memory cache at runtime.

        This does NOT persist to Keychain, file, or environment.
        Use for credentials generated at runtime (e.g., short-lived tokens).
        """
        self._store[service] = value

    # ── Subprocess Safety ────────────────────────────────────────────────────

    def get_safe_subprocess_env(self) -> dict[str, str]:
        """
        Return a copy of os.environ with ALL secrets stripped.

        Use this for EVERY subprocess.run() call in the framework.
        Prevents secrets from leaking into untrusted code (e.g., AI-generated
        functions under test in the crystallization analyzer).

        Only keys in _SAFE_SUBPROCESS_ENV_KEYS are included. Any key not on
        the allowlist is excluded, regardless of whether it is a known secret.

        Returns:
            A fresh dict (not a reference to os.environ) with only safe keys.
            If initialized, returns the snapshot taken at init time (preferred).
            Otherwise, computes from current os.environ.
        """
        if self._safe_env_snapshot is not None:
            # Return a copy of the snapshot — prevents callers from mutating it
            return dict(self._safe_env_snapshot)
        # Before initialization: compute from current os.environ
        return {k: v for k, v in os.environ.items() if k in _SAFE_SUBPROCESS_ENV_KEYS}

    # ── Diagnostics ──────────────────────────────────────────────────────────

    def status(self) -> dict:
        """
        Return a summary of credential availability (no secret values).

        Safe to include in health check responses.
        """
        return {
            "initialized": self._initialized,
            "backend": self._backend,
            "purge_env_after_load": self._purge_env_after_load,
            "keychain_access_allowed": self._keychain_access_allowed,
            "services": {
                service: (self._initialized and service in self._store)
                for service in _SERVICE_TO_ENV
            },
        }


# ── Module-level singleton ─────────────────────────────────────────────────────

#: Global CredentialStore singleton.
#:
#: Call ``creds.initialize(settings.security)`` once at application startup
#: (typically in ``init_db()`` or the top-level ``main()``).
#:
#: Thereafter, all secret access is in-memory only. No Keychain popups,
#: no file reads, no environment scans on hot paths.
creds: CredentialStore = CredentialStore()
