"""
src/search/__init__.py
──────────────────────
Public search API for Phase 56 — Configurable Search Providers.

Single entry point: ``search_web(query, max_results)``

Routing logic:
  1. Try the configured primary provider (settings.search.provider).
  2. If it is unavailable or returns only error results, try the fallback
     provider (settings.search.fallback), if different from primary.
  3. If both fail, return the error result from the primary attempt.

Usage (inside a LangChain @tool):
    from src.search import search_web
    results = search_web(query, max_results=5)

The module also re-exports SearchResult and list_providers / provider_status
for callers that need the TypedDict or registry info.
"""

from __future__ import annotations

import logging

from src.search.base import SearchResult  # noqa: F401 — re-export
from src.search.registry import (
    get_provider,
    list_providers,
    provider_status,
)  # noqa: F401 — re-export

logger = logging.getLogger(__name__)


def search_web(query: str, max_results: int = 5) -> list[SearchResult]:
    """
    Search the web using the configured provider with automatic fallback.

    Returns a list of SearchResult TypedDicts.  On total failure returns a
    single-item list with an ``error`` key — never raises.
    """
    from config.settings import settings

    primary_name: str = settings.search.provider
    fallback_name: str = settings.search.fallback

    # ── Primary attempt ────────────────────────────────────────────────────────
    primary_results = _try_provider(primary_name, query, max_results)
    if _has_real_results(primary_results):
        return primary_results

    # ── Fallback attempt (only if different from primary) ──────────────────────
    if fallback_name and fallback_name != primary_name:
        logger.info(
            "[search] Primary provider %r failed/empty — trying fallback %r",
            primary_name,
            fallback_name,
        )
        fallback_results = _try_provider(fallback_name, query, max_results)
        if _has_real_results(fallback_results):
            return fallback_results

    # Both failed — return whatever the primary gave us (structured error dict)
    return primary_results


# ── Internal helpers ───────────────────────────────────────────────────────────


def _try_provider(name: str, query: str, max_results: int) -> list[SearchResult]:
    """Attempt a search with one named provider; return error list on failure."""
    try:
        provider = get_provider(name)
        if not provider.is_available():
            logger.warning("[search] Provider %r reports unavailable", name)
            return [
                SearchResult(
                    error="provider_unavailable",
                    title=f"{name} unavailable",
                    snippet=(
                        f"The {name} search provider is not available "
                        "(check API key or service reachability)."
                    ),
                    url="",
                )
            ]
        return provider.search(query, max_results=max_results)
    except Exception as exc:
        logger.error("[search] Provider %r raised: %s", name, exc)
        return [
            SearchResult(
                error=type(exc).__name__,
                title=f"{name} error",
                snippet=str(exc),
                url="",
            )
        ]


def _has_real_results(results: list[SearchResult]) -> bool:
    """Return True if results contain at least one non-error entry."""
    return any("error" not in r for r in results)
