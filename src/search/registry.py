"""
src/search/registry.py
──────────────────────
Provider registry for Phase 56 configurable search.

Maintains a lazy-import mapping from provider name → class.  Providers are
only imported when first used; importing an unused provider (e.g. Exa when
the exa_py package isn't installed) never causes an ImportError at startup.

Public API
──────────
    get_provider(name: str) -> SearchProvider
        Return an instantiated provider.  Raises KeyError for unknown names.

    list_providers() -> list[str]
        Return all registered provider names.

    provider_status() -> dict[str, dict]
        Return a dict of {name: {available, requires_key}} for the health
        endpoint and the TestLab admin UI.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.search.base import SearchProvider

logger = logging.getLogger(__name__)

# ── Lazy-import registry ───────────────────────────────────────────────────────
# Each entry is a (module_path, class_name) tuple; the class is imported and
# cached on first access to avoid unnecessary imports at startup.

_REGISTRY: dict[str, tuple[str, str]] = {
    "ddg": ("src.search.providers.ddg", "DDGProvider"),
    "tavily": ("src.search.providers.tavily", "TavilyProvider"),
    "brave": ("src.search.providers.brave", "BraveProvider"),
    "exa": ("src.search.providers.exa", "ExaProvider"),
    "perplexity": ("src.search.providers.perplexity", "PerplexityProvider"),
    "searxng": ("src.search.providers.searxng", "SearXNGProvider"),
}

# Instantiated provider cache — one instance per provider name per process.
_instances: dict[str, "SearchProvider"] = {}


def get_provider(name: str) -> "SearchProvider":
    """
    Return the instantiated provider for ``name``.

    Raises:
        KeyError  — unknown provider name
        ImportError — provider module is missing (optional dependency not installed)
    """
    if name not in _REGISTRY:
        raise KeyError(
            f"Unknown search provider: {name!r}. " f"Available: {list(_REGISTRY)}"
        )
    if name not in _instances:
        module_path, class_name = _REGISTRY[name]
        import importlib

        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        _instances[name] = cls()
    return _instances[name]


def list_providers() -> list[str]:
    """Return all registered provider names."""
    return list(_REGISTRY)


def provider_status() -> dict[str, dict]:
    """
    Return availability status for every registered provider.
    Used by the /agents and TestLab admin UI.
    """
    status: dict[str, dict] = {}
    for name in _REGISTRY:
        try:
            p = get_provider(name)
            available = p.is_available()
            requires_key = p.requires_key
        except Exception as exc:
            available = False
            requires_key = True
            logger.debug("[search/registry] status check failed for %s: %s", name, exc)
        status[name] = {"available": available, "requires_key": requires_key}
    return status
