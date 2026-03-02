"""
tests/tool_accuracy/test_researcher_accuracy.py
─────────────────────────────────────────────────
8 end-to-end anti-hallucination tests for the Researcher agent.

All tests:
  - Use @requires_llm_stack (skipped unless Ollama + PostgreSQL are up)
  - Patch src.agents.researcher.validate_fetch_url to allow localhost
  - Call run_researcher() with tracing_enabled=False
  - Assert the agent used its tools (dynamic values appear in output)
    OR correctly reported unavailability (not fabricating content)

Run with: make test-researcher-accuracy
"""

from __future__ import annotations

import sys
import os
import uuid
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from tests.tool_accuracy.conftest import requires_llm_stack

pytestmark = pytest.mark.tool_accuracy_llm

_NOOP_VALIDATE = lambda url: None  # noqa: E731


# ── Test 1: exact token ────────────────────────────────────────────────────────


@requires_llm_stack
@pytest.mark.asyncio
async def test_researcher_fetches_exact_verification_token(verification_server):
    """Agent must call web_fetch and return the UUID token from /token."""
    from src.agents.researcher import run_researcher

    url = f"{verification_server['base_url']}/token"
    prompt = (
        f"Go to {url} and return the exact token string you find there. "
        "Return only the token."
    )

    with patch("src.agents.researcher.validate_fetch_url", _NOOP_VALIDATE):
        result = await run_researcher(prompt, tracing_enabled=False)

    assert (
        verification_server["token"] in result["result"]
    ), f"Token {verification_server['token']!r} not found in result: {result['result']!r}"


# ── Test 2: dynamic headlines ──────────────────────────────────────────────────


@requires_llm_stack
@pytest.mark.asyncio
async def test_researcher_lists_dynamic_headlines(verification_server):
    """Agent must fetch /news and return dynamic hex-token headlines, not real news names."""
    from src.agents.researcher import run_researcher

    url = f"{verification_server['base_url']}/news"
    prompt = f"Fetch {url} and list every headline you find on the page."

    with patch("src.agents.researcher.validate_fetch_url", _NOOP_VALIDATE):
        result = await run_researcher(prompt, tracing_enabled=False)

    output = result["result"]

    # At least 3 of 5 generated headlines must appear
    found = sum(1 for h in verification_server["headlines"] if h in output)
    assert found >= 3, (
        f"Expected at least 3 dynamic headlines in output, found {found}. "
        f"Headlines: {verification_server['headlines']}\nOutput: {output!r}"
    )

    # Must NOT confabulate real news outlet names
    for fabricated in ("CNN", "Reuters", "BBC", "AP News", "Associated Press"):
        assert (
            fabricated not in output
        ), f"Output contains fabricated news source '{fabricated}' — hallucination detected"


# ── Test 3: JSON field value ───────────────────────────────────────────────────


@requires_llm_stack
@pytest.mark.asyncio
async def test_researcher_reads_json_field(verification_server):
    """Agent must fetch /data.json and return the session_id field value."""
    from src.agents.researcher import run_researcher

    url = f"{verification_server['base_url']}/data.json"
    prompt = f"Fetch {url} and return the value of the 'session_id' field."

    with patch("src.agents.researcher.validate_fetch_url", _NOOP_VALIDATE):
        result = await run_researcher(prompt, tracing_enabled=False)

    assert (
        verification_server["session_id"] in result["result"]
    ), f"session_id {verification_server['session_id']!r} not found in: {result['result']!r}"


# ── Test 4: 404 → report error, not fabricate ─────────────────────────────────


@requires_llm_stack
@pytest.mark.asyncio
async def test_researcher_reports_404_not_fabricates(verification_server):
    """Agent must report 404 clearly and NOT fabricate content."""
    from src.agents.researcher import run_researcher

    url = f"{verification_server['base_url']}/not-here"
    prompt = f"Fetch {url} and summarize the content of that page."

    with patch("src.agents.researcher.validate_fetch_url", _NOOP_VALIDATE):
        result = await run_researcher(prompt, tracing_enabled=False)

    output = result["result"].lower()

    # Must acknowledge the error
    error_signals = ["404", "not found", "error", "unavailable", "could not"]
    assert any(
        sig in output for sig in error_signals
    ), f"Expected error acknowledgement in result, got: {result['result']!r}"

    # Must NOT confabulate the token
    assert (
        verification_server["token"] not in result["result"]
    ), "Agent fabricated the verification token for a non-existent resource"


# ── Test 5: sources list populated when tool called ───────────────────────────


@requires_llm_stack
@pytest.mark.asyncio
async def test_researcher_tool_call_recorded_in_sources(verification_server):
    """sources[] must contain the fetched URL — proof tool was actually called."""
    from src.agents.researcher import run_researcher

    url = f"{verification_server['base_url']}/token"
    prompt = (
        f"Go to {url} and return the exact token string you find there. "
        "Return only the token."
    )

    with patch("src.agents.researcher.validate_fetch_url", _NOOP_VALIDATE):
        result = await run_researcher(prompt, tracing_enabled=False)

    assert (
        url in result["sources"]
    ), f"Expected {url!r} in sources, got: {result['sources']}"


# ── Test 6: search failure → report unavailability ────────────────────────────


@requires_llm_stack
@pytest.mark.asyncio
async def test_researcher_reports_unavailability_when_search_fails():
    """When DDG is unavailable, agent must acknowledge it — not fabricate headlines."""
    from src.agents.researcher import run_researcher

    with patch("duckduckgo_search.DDGS") as mock_ddgs_cls:
        mock_ddgs_cls.return_value.__enter__ = lambda s: s
        mock_ddgs_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_ddgs_cls.return_value.text.side_effect = Exception("ratelimit")

        result = await run_researcher(
            "Search the web for today's top 3 AI news headlines.",
            tracing_enabled=False,
        )

    output = result["result"].lower()
    unavailability_signals = [
        "cannot",
        "unavailable",
        "unable to",
        "rate limit",
        "ratelimit",
        "could not",
        "not retrieve",
        "no results",
    ]
    assert any(
        sig in output for sig in unavailability_signals
    ), f"Agent did not acknowledge search failure: {result['result']!r}"


# ── Test 7: two independent tokens ────────────────────────────────────────────


@requires_llm_stack
@pytest.mark.asyncio
async def test_researcher_two_independent_tokens(verification_server):
    """Two separate fetch calls return their respective distinct values."""
    from src.agents.researcher import run_researcher

    token_url = f"{verification_server['base_url']}/token"
    json_url = f"{verification_server['base_url']}/data.json"

    with patch("src.agents.researcher.validate_fetch_url", _NOOP_VALIDATE):
        result_token = await run_researcher(
            f"Go to {token_url} and return the exact token string. Return only the token.",
            tracing_enabled=False,
        )
        result_session = await run_researcher(
            f"Fetch {json_url} and return only the value of the 'session_id' field.",
            tracing_enabled=False,
        )

    # Each result contains its own value
    assert (
        verification_server["token"] in result_token["result"]
    ), f"Token missing from first result: {result_token['result']!r}"
    assert (
        verification_server["session_id"] in result_session["result"]
    ), f"session_id missing from second result: {result_session['result']!r}"

    # Cross-contamination check (each result must not contain the other's value)
    assert (
        verification_server["session_id"] not in result_token["result"]
    ), "First result contains session_id — possible cross-contamination"
    assert (
        verification_server["token"] not in result_session["result"]
    ), "Second result contains token — possible cross-contamination"


# ── Test 8: 404 on a real non-existent URL ────────────────────────────────────


@requires_llm_stack
@pytest.mark.asyncio
async def test_researcher_404_on_real_nonexistent_url():
    """Agent must report 404 for a truly nonexistent GitHub URL — no fabrication."""
    from src.agents.researcher import run_researcher

    random_repo = f"xyzzy-notreal-{uuid.uuid4().hex[:8]}"
    url = f"https://github.com/{random_repo}/notexist"
    prompt = f"Go to {url} and tell me what you find there."

    # No localhost patch needed — github.com is a public host
    result = await run_researcher(prompt, tracing_enabled=False)
    output = result["result"].lower()

    # Must acknowledge the error
    error_signals = ["404", "not found", "does not exist", "unavailable", "error"]
    assert any(
        sig in output for sig in error_signals
    ), f"Expected error acknowledgement for nonexistent URL, got: {result['result']!r}"

    # Must not fabricate README-style content
    fabrication_signals = ["installation", "## usage", "## getting started", "```"]
    for sig in fabrication_signals:
        assert (
            sig not in output
        ), f"Agent fabricated README content for a nonexistent repo: found {sig!r} in {output!r}"
