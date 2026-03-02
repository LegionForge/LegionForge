"""
src/search/providers/perplexity.py
────────────────────────────────────
Perplexity AI search provider (Phase 56).

Perplexity's Sonar API returns LLM-synthesised answers with citations, making
it ideal for factual research questions that need a concise answer plus sources.
Requires an API key from https://www.perplexity.ai/settings/api
Keychain: "legionforge_perplexity_api_key" | env: PERPLEXITY_API_KEY

Uses the OpenAI-compatible Perplexity endpoint via httpx (no extra pip install).
"""

from __future__ import annotations

import logging

import httpx

from config.settings import settings
from src.search.base import SearchProvider, SearchResult, _get_cred

logger = logging.getLogger(__name__)

_SERVICE = "legionforge_perplexity_api_key"
_ENV = "PERPLEXITY_API_KEY"
_API_URL = "https://api.perplexity.ai/chat/completions"


class PerplexityProvider(SearchProvider):
    name = "perplexity"
    requires_key = True

    def __init__(self) -> None:
        cfg = settings.search.perplexity
        self._model: str = cfg.model

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
                    title="Perplexity unavailable",
                    snippet="No Perplexity API key configured.",
                    url="",
                )
            ]
        try:
            resp = httpx.post(
                _API_URL,
                headers={
                    "Authorization": f"Bearer {key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self._model,
                    "messages": [{"role": "user", "content": query}],
                    "max_tokens": 1024,
                },
                timeout=settings.search.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            citations = data.get("citations", [])

            # Build a single synthesised result with Perplexity's answer.
            # Then add individual citation URLs as additional results if present.
            results: list[SearchResult] = [
                SearchResult(
                    title=f"Perplexity answer for: {query[:60]}",
                    url=citations[0] if citations else "",
                    snippet=content[:1000],
                )
            ]
            for cite_url in citations[1:max_results]:
                results.append(SearchResult(title="", url=cite_url, snippet=""))
            return results
        except Exception as exc:
            exc_name = type(exc).__name__
            logger.warning(
                "[search/perplexity] Error (%s) for query=%r", exc_name, query
            )
            return [
                SearchResult(
                    error=exc_name,
                    title="Perplexity search failed",
                    snippet=f"Perplexity error: {exc}",
                    url="",
                )
            ]
