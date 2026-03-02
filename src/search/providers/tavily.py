"""
src/search/providers/tavily.py
───────────────────────────────
Tavily search provider (Phase 56).

Tavily is an LLM-optimised search API that returns clean, AI-ready excerpts.
Requires a Tavily API key stored in macOS Keychain as "legionforge_tavily_api_key"
or environment variable TAVILY_API_KEY.

pip install tavily-python  (add to requirements.txt when activating this provider)
"""

from __future__ import annotations

import logging

from config.settings import settings
from src.search.base import SearchProvider, SearchResult, _get_cred

logger = logging.getLogger(__name__)

_SERVICE = "legionforge_tavily_api_key"
_ENV = "TAVILY_API_KEY"


class TavilyProvider(SearchProvider):
    name = "tavily"
    requires_key = True

    def __init__(self) -> None:
        cfg = settings.search.tavily
        self._search_depth: str = cfg.search_depth
        self._max_tokens: int = cfg.max_tokens

    def _key(self) -> str | None:
        return _get_cred(_SERVICE, _ENV)

    def is_available(self) -> bool:
        if not self._key():
            return False
        try:
            from tavily import TavilyClient  # noqa: F401

            return True
        except ImportError:
            logger.debug("[search/tavily] tavily-python not installed")
            return False

    def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
        key = self._key()
        if not key:
            return [
                SearchResult(
                    error="no_api_key",
                    title="Tavily unavailable",
                    snippet="No Tavily API key configured.",
                    url="",
                )
            ]
        try:
            from tavily import TavilyClient

            client = TavilyClient(api_key=key)
            resp = client.search(
                query=query,
                search_depth=self._search_depth,
                max_results=max_results,
            )
            results: list[SearchResult] = []
            for r in resp.get("results", []):
                results.append(
                    SearchResult(
                        title=r.get("title", ""),
                        url=r.get("url", ""),
                        snippet=r.get("content", r.get("snippet", "")),
                    )
                )
            return results or [
                SearchResult(
                    error="empty",
                    title="No results",
                    snippet="Tavily returned no results.",
                    url="",
                )
            ]
        except Exception as exc:
            exc_name = type(exc).__name__
            logger.warning("[search/tavily] Error (%s) for query=%r", exc_name, query)
            return [
                SearchResult(
                    error=exc_name,
                    title="Tavily search failed",
                    snippet=f"Tavily error: {exc}",
                    url="",
                )
            ]
