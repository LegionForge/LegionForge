"""
src/search/providers/ddg.py
───────────────────────────
DuckDuckGo search provider — default, no API key required.

Uses the unofficial duckduckgo_search library (already a project dependency).
Catches RatelimitException and all other DDG errors, returning a structured
error result so the LLM gets a clear "unavailable" signal rather than a
Python traceback.
"""

from __future__ import annotations

import logging

from config.settings import settings
from src.search.base import SearchProvider, SearchResult

logger = logging.getLogger(__name__)


class DDGProvider(SearchProvider):
    name = "ddg"
    requires_key = False

    def __init__(self) -> None:
        cfg = settings.search.ddg
        self._region: str = cfg.region
        self._safe_search: str = cfg.safe_search

    def is_available(self) -> bool:
        try:
            from duckduckgo_search import DDGS  # noqa: F401

            return True
        except ImportError:
            return False

    def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
        try:
            from duckduckgo_search import DDGS

            with DDGS() as ddgs:
                raw = list(
                    ddgs.text(
                        query,
                        max_results=max_results,
                        region=self._region,
                        safesearch=self._safe_search,
                    )
                )
            # DDG returns dicts with keys: title, href, body
            # Normalize to SearchResult
            results: list[SearchResult] = []
            for r in raw:
                results.append(
                    SearchResult(
                        title=r.get("title", ""),
                        url=r.get("href", r.get("url", "")),
                        snippet=r.get("body", r.get("snippet", "")),
                    )
                )
            return results

        except Exception as exc:
            exc_name = type(exc).__name__
            if "Ratelimit" in exc_name or "ratelimit" in str(exc).lower():
                msg = (
                    "DuckDuckGo rate limit reached. "
                    "Do NOT retry the same query. "
                    "Tell the user you cannot retrieve live search results right now."
                )
            else:
                msg = (
                    f"DuckDuckGo search failed ({exc_name}). "
                    "Tell the user you cannot retrieve live results right now."
                )
            logger.warning("[search/ddg] Error (%s) for query=%r", exc_name, query)
            return [
                SearchResult(
                    error=exc_name, title="Search unavailable", snippet=msg, url=""
                )
            ]
