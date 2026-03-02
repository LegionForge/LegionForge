"""
src/search/providers/brave.py
──────────────────────────────
Brave Search API provider (Phase 56).

Brave Search offers a privacy-respecting, independent search index.
Requires an API key from https://brave.com/search/api/
Keychain: "legionforge_brave_api_key" | env: BRAVE_API_KEY

No additional pip install required — uses httpx (already a dependency).
"""

from __future__ import annotations

import logging

import httpx

from config.settings import settings
from src.search.base import SearchProvider, SearchResult, _get_cred

logger = logging.getLogger(__name__)

_SERVICE = "legionforge_brave_api_key"
_ENV = "BRAVE_API_KEY"
_API_URL = "https://api.search.brave.com/res/v1/web/search"


class BraveProvider(SearchProvider):
    name = "brave"
    requires_key = True

    def __init__(self) -> None:
        cfg = settings.search.brave
        self._country: str = cfg.country
        self._search_lang: str = cfg.search_lang

    def _key(self) -> str | None:
        return _get_cred(_SERVICE, _ENV)

    def is_available(self) -> bool:
        return bool(self._key())

    def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
        key = self._key()
        if not key:
            return [
                SearchResult(
                    error="no_api_key",
                    title="Brave Search unavailable",
                    snippet="No Brave API key configured.",
                    url="",
                )
            ]
        try:
            resp = httpx.get(
                _API_URL,
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "gzip",
                    "X-Subscription-Token": key,
                },
                params={
                    "q": query,
                    "count": min(max_results, 20),
                    "country": self._country,
                    "search_lang": self._search_lang,
                },
                timeout=settings.search.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            web_results = data.get("web", {}).get("results", [])
            results: list[SearchResult] = []
            for r in web_results:
                results.append(
                    SearchResult(
                        title=r.get("title", ""),
                        url=r.get("url", ""),
                        snippet=r.get("description", ""),
                    )
                )
            return results or [
                SearchResult(
                    error="empty",
                    title="No results",
                    snippet="Brave Search returned no results.",
                    url="",
                )
            ]
        except Exception as exc:
            exc_name = type(exc).__name__
            logger.warning("[search/brave] Error (%s) for query=%r", exc_name, query)
            return [
                SearchResult(
                    error=exc_name,
                    title="Brave Search failed",
                    snippet=f"Brave error: {exc}",
                    url="",
                )
            ]
