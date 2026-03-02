"""
src/search/providers/exa.py
────────────────────────────
Exa (formerly Metaphor) search provider (Phase 56).

Exa is a neural search engine that understands meaning rather than keywords.
Excellent for research tasks that need semantically similar documents.
Requires an API key from https://exa.ai
Keychain: "legionforge_exa_api_key" | env: EXA_API_KEY

pip install exa_py  (add to requirements.txt when activating this provider)
"""

from __future__ import annotations

import logging

from config.settings import settings
from src.search.base import SearchProvider, SearchResult, _get_cred

logger = logging.getLogger(__name__)

_SERVICE = "legionforge_exa_api_key"
_ENV = "EXA_API_KEY"


class ExaProvider(SearchProvider):
    name = "exa"
    requires_key = True

    def __init__(self) -> None:
        cfg = settings.search.exa
        self._use_autoprompt: bool = cfg.use_autoprompt
        self._type: str = cfg.type

    def _key(self) -> str | None:
        return _get_cred(_SERVICE, _ENV)

    def is_available(self) -> bool:
        if not self._key():
            return False
        try:
            import exa_py  # noqa: F401

            return True
        except ImportError:
            logger.debug("[search/exa] exa_py not installed")
            return False

    def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
        key = self._key()
        if not key:
            return [
                SearchResult(
                    error="no_api_key",
                    title="Exa unavailable",
                    snippet="No Exa API key configured.",
                    url="",
                )
            ]
        try:
            from exa_py import Exa

            client = Exa(api_key=key)
            resp = client.search_and_contents(
                query,
                num_results=max_results,
                use_autoprompt=self._use_autoprompt,
                type=self._type,
                text={"max_characters": 500},
            )
            results: list[SearchResult] = []
            for r in resp.results:
                results.append(
                    SearchResult(
                        title=r.title or "",
                        url=r.url or "",
                        snippet=(r.text or "")[:500],
                    )
                )
            return results or [
                SearchResult(
                    error="empty",
                    title="No results",
                    snippet="Exa returned no results.",
                    url="",
                )
            ]
        except Exception as exc:
            exc_name = type(exc).__name__
            logger.warning("[search/exa] Error (%s) for query=%r", exc_name, query)
            return [
                SearchResult(
                    error=exc_name,
                    title="Exa search failed",
                    snippet=f"Exa error: {exc}",
                    url="",
                )
            ]
