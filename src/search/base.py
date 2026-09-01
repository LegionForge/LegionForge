"""
src/search/base.py
──────────────────
Abstract base for all search providers (Phase 56).

SearchResult is a normalized TypedDict shared across every provider so
researcher.py and any future consumer can treat results uniformly regardless
of which backend answered the query.

SearchProvider is a simple ABC with three requirements:
  • name      — unique string identifier used in settings + logs
  • requires_key — True if the provider needs an API key to operate
  • is_available() — lightweight check; False means the provider should be
                     skipped (key missing, service unreachable, etc.)
  • search()  — synchronous; runs inside the sync @tool wrapper
"""

from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from typing import Optional, TypedDict

logger = logging.getLogger(__name__)


# ── Result contract ────────────────────────────────────────────────────────────


class SearchResult(TypedDict, total=False):
    """Normalized search result returned by every provider."""

    title: str
    url: str
    snippet: str
    # error key is set (and others may be absent) when the provider failed.
    error: str


# ── Credential helper ──────────────────────────────────────────────────────────


def _get_cred(service_name: str, env_fallback: str) -> Optional[str]:
    """
    Retrieve a credential from the LegionForge CredentialStore (loaded at
    startup) or fall back to a plain environment variable.

    Returns None if neither source has the value — callers use this to gate
    ``is_available()`` checks without raising.
    """
    try:
        from src.credentials import creds

        val = creds.get(service_name)
        if val:
            return val
    except Exception as e:
        # Caller falls through to env-var fallback; surface the broken-Keychain
        # case at debug so operators can spot it without spamming production.
        logger.debug("[search] creds lookup failed for %s: %s", service_name, e)
    return os.environ.get(env_fallback) or None


# ── Abstract base ──────────────────────────────────────────────────────────────


class SearchProvider(ABC):
    """Abstract base class for all pluggable search providers."""

    # Override in subclasses
    name: str = ""
    requires_key: bool = True

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this provider is ready to serve requests."""
        ...

    @abstractmethod
    def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
        """
        Execute a search and return normalized results.

        Must never raise — return a single-item list with ``error`` key on
        failure so callers (including the LLM) get a clear signal.
        """
        ...
