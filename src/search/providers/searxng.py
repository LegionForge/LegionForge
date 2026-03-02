"""
src/search/providers/searxng.py
─────────────────────────────────
SearXNG (self-hosted meta-search) provider (Phase 56).

SearXNG aggregates results from Google, Bing, DuckDuckGo, and others through
a self-hosted instance — no API key required, full query privacy, no rate
limits from third-party APIs.

Recommended local setup (Docker):
    docker run -d -p 8888:8080 --name searxng searxng/searxng

Config: settings.search.searxng.url  (default http://localhost:8888)
No API key required — does not call _get_cred().
"""

from __future__ import annotations

import logging

import httpx

from config.settings import settings
from src.search.base import SearchProvider, SearchResult

logger = logging.getLogger(__name__)


class SearXNGProvider(SearchProvider):
    name = "searxng"
    requires_key = False

    def __init__(self) -> None:
        cfg = settings.search.searxng
        self._url: str = cfg.url.rstrip("/")
        self._engines: list[str] = cfg.engines

    def is_available(self) -> bool:
        try:
            resp = httpx.get(f"{self._url}/healthz", timeout=2.0)
            return resp.status_code == 200
        except Exception:
            # Try the root path as a fallback health check
            try:
                resp = httpx.get(self._url, timeout=2.0)
                return resp.status_code < 500
            except Exception:
                return False

    def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
        try:
            params: dict = {
                "q": query,
                "format": "json",
                "pageno": 1,
            }
            if self._engines:
                params["engines"] = ",".join(self._engines)

            resp = httpx.get(
                f"{self._url}/search",
                params=params,
                timeout=settings.search.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            raw_results = data.get("results", [])[:max_results]
            results: list[SearchResult] = []
            for r in raw_results:
                results.append(
                    SearchResult(
                        title=r.get("title", ""),
                        url=r.get("url", ""),
                        snippet=r.get("content", ""),
                    )
                )
            return results or [
                SearchResult(
                    error="empty",
                    title="No results",
                    snippet="SearXNG returned no results.",
                    url="",
                )
            ]
        except Exception as exc:
            exc_name = type(exc).__name__
            logger.warning("[search/searxng] Error (%s) for query=%r", exc_name, query)
            return [
                SearchResult(
                    error=exc_name,
                    title="SearXNG search failed",
                    snippet=f"SearXNG error: {exc}",
                    url="",
                )
            ]
