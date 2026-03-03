"""
tests/tool_accuracy/test_web_search.py
────────────────────────────────────────
9 tests for the `web_search` tool.

Group A — Error handling (mocked DDG, no network)
Group B — Input sanitization (no network, mock DDG)
Group C — Result structure (mocked results)
Group D — Live tests (skipped when CI=true)

Run with: make test-tool-accuracy
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

pytestmark = pytest.mark.tool_accuracy

# Fake DDG results for structure tests
_FAKE_RESULTS = [
    {"href": "https://example.com/1", "body": "Example body 1", "title": "Example 1"},
    {"href": "https://example.com/2", "body": "Example body 2", "title": "Example 2"},
]


# ── Group A — Error handling ───────────────────────────────────────────────────


def test_web_search_rate_limit_returns_error_struct():
    """Rate-limit error → returns a list with one error-dict, no exception raised."""
    from src.agents.researcher import web_search

    with patch("duckduckgo_search.DDGS") as mock_ddgs_cls:
        mock_ddgs_cls.return_value.__enter__ = lambda s: s
        mock_ddgs_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_ddgs_cls.return_value.text.side_effect = Exception("ratelimit")

        result = web_search.invoke({"query": "test"})

    assert isinstance(result, list), f"Expected list, got {type(result)}"
    assert len(result) == 1, f"Expected 1 error entry, got {len(result)}"
    assert "error" in result[0], f"Expected 'error' key in result, got: {result[0]}"


def test_web_search_rate_limit_snippet_no_hallucination_hint():
    """Rate-limit error snippet must NOT suggest using training knowledge."""
    from src.agents.researcher import web_search

    with patch("duckduckgo_search.DDGS") as mock_ddgs_cls:
        mock_ddgs_cls.return_value.__enter__ = lambda s: s
        mock_ddgs_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_ddgs_cls.return_value.text.side_effect = Exception("ratelimit")

        result = web_search.invoke({"query": "test"})

    snippet = result[0].get("snippet", "")
    assert (
        "training" not in snippet.lower()
    ), f"Snippet must not mention 'training': {snippet!r}"
    assert (
        "training knowledge" not in snippet.lower()
    ), f"Snippet must not suggest using training knowledge: {snippet!r}"


def test_web_search_generic_error_no_exception_raised():
    """Any DDG exception must be caught — web_search must not propagate it."""
    from src.agents.researcher import web_search

    with patch("duckduckgo_search.DDGS") as mock_ddgs_cls:
        mock_ddgs_cls.return_value.__enter__ = lambda s: s
        mock_ddgs_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_ddgs_cls.return_value.text.side_effect = RuntimeError("network error")

        # Must not raise
        result = web_search.invoke({"query": "test query"})

    assert isinstance(result, list)


def test_web_search_error_result_has_error_key():
    """Any error path must produce a result[0] dict with an 'error' key."""
    from src.agents.researcher import web_search

    with patch("duckduckgo_search.DDGS") as mock_ddgs_cls:
        mock_ddgs_cls.return_value.__enter__ = lambda s: s
        mock_ddgs_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_ddgs_cls.return_value.text.side_effect = ConnectionError("timeout")

        result = web_search.invoke({"query": "test"})

    assert "error" in result[0], f"'error' key missing from result: {result[0]}"


# ── Group B — Input sanitization ──────────────────────────────────────────────


def test_web_search_pii_redacted_before_ddg():
    """SSN in query must be redacted before the query reaches DDG."""
    from src.agents.researcher import web_search

    captured_query: list[str] = []

    def _capture_text(query, max_results=5, **kwargs):
        captured_query.append(query)
        return _FAKE_RESULTS

    with patch("duckduckgo_search.DDGS") as mock_ddgs_cls:
        mock_ddgs_cls.return_value.__enter__ = lambda s: s
        mock_ddgs_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_ddgs_cls.return_value.text.side_effect = _capture_text

        web_search.invoke({"query": "find 123-45-6789 news"})

    assert captured_query, "DDG was never called"
    assert (
        "123-45-6789" not in captured_query[0]
    ), f"SSN must be redacted before DDG call, got query: {captured_query[0]!r}"


def test_web_search_max_results_passed_to_ddg():
    """max_results=3 must be forwarded to DDGS.text as a kwarg."""
    from src.agents.researcher import web_search

    captured_kwargs: list[dict] = []

    def _capture_text(query, max_results=5, **kwargs):
        captured_kwargs.append({"query": query, "max_results": max_results})
        return _FAKE_RESULTS

    with patch("duckduckgo_search.DDGS") as mock_ddgs_cls:
        mock_ddgs_cls.return_value.__enter__ = lambda s: s
        mock_ddgs_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_ddgs_cls.return_value.text.side_effect = _capture_text

        web_search.invoke({"query": "test", "max_results": 3})

    assert captured_kwargs, "DDG was never called"
    assert (
        captured_kwargs[0]["max_results"] == 3
    ), f"Expected max_results=3, got: {captured_kwargs[0]}"


# ── Group C — Result structure ─────────────────────────────────────────────────


def test_web_search_result_list_is_list_of_dicts():
    """Successful DDG results are returned as a list of dicts."""
    from src.agents.researcher import web_search

    with patch("duckduckgo_search.DDGS") as mock_ddgs_cls:
        mock_ddgs_cls.return_value.__enter__ = lambda s: s
        mock_ddgs_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_ddgs_cls.return_value.text.return_value = _FAKE_RESULTS

        result = web_search.invoke({"query": "python pytest"})

    assert isinstance(result, list), f"Expected list, got {type(result)}"
    assert len(result) > 0, "Expected at least one result"
    assert isinstance(result[0], dict), f"Expected dict entries, got {type(result[0])}"


# ── Group D — Live tests (skipped in CI) ──────────────────────────────────────


@pytest.mark.skipif(
    os.environ.get("CI") == "true",
    reason="Live DDG tests skipped in CI (network + rate-limit risk)",
)
def test_web_search_live_returns_nonempty_list():
    """Live DDG search returns a non-empty list of results."""
    from src.agents.researcher import web_search

    result = web_search.invoke({"query": "python pytest asyncio", "max_results": 3})

    assert isinstance(result, list), f"Expected list, got {type(result)}"
    assert len(result) > 0, "Live search returned no results"


@pytest.mark.skipif(
    os.environ.get("CI") == "true",
    reason="Live DDG tests skipped in CI (network + rate-limit risk)",
)
def test_web_search_live_result_has_required_fields():
    """Live DDG results have at least one expected field per entry."""
    from src.agents.researcher import web_search

    result = web_search.invoke({"query": "python pytest asyncio", "max_results": 3})

    known_fields = {"title", "href", "url", "body", "snippet"}
    for entry in result:
        present = known_fields & set(entry.keys())
        assert (
            present
        ), f"Result entry has none of the expected fields {known_fields}: {entry}"
