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
    Search the web using the configured provider with automatic fallback chain.

    Tries providers in order: primary → fallback_chain (or legacy fallback).
    Returns the first successful result set.  On total failure returns a
    single-item list with an ``error`` key — never raises.
    """
    from config.settings import settings

    primary_name: str = settings.search.provider

    # Build ordered provider list (deduplicated, primary always first).
    chain: list[str] = [primary_name]
    if settings.search.fallback_chain:
        for name in settings.search.fallback_chain:
            if name not in chain:
                chain.append(name)
    elif settings.search.fallback and settings.search.fallback != primary_name:
        chain.append(settings.search.fallback)

    primary_results: list[SearchResult] | None = None
    for name in chain:
        results = _try_provider(name, query, max_results)
        if primary_results is None:
            primary_results = results
        if _has_real_results(results):
            if name != primary_name:
                logger.info("[search] Using fallback provider %r", name)
            return results
        logger.info("[search] Provider %r failed/empty — trying next in chain", name)

    # All providers exhausted — return primary error result
    return primary_results or []


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
