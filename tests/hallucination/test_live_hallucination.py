"""
tests/hallucination/test_live_hallucination.py
───────────────────────────────────────────────
Live hallucination detection tests for the Researcher agent.

All tests hit the real internet and the real LLM stack (Ollama + PostgreSQL).
NEVER run in make test, make ci, or make smoke — manually run only.

    make test-hallucination                       # full suite
    pytest tests/hallucination/ -v -s             # verbose with live output
    pytest tests/hallucination/ -k "httpbin" -v   # filter by URL category

Anti-hallucination strategy used here:
  1. GROUNDING — fetch a real URL ourselves first (or use known-stable content),
     ask the researcher to fetch the same URL, verify the probe string appears.
  2. SOURCE CITATION — verify sources[] contains the fetched URL, proving the
     tool was actually invoked and not answered from training memory.
  3. NONCE UNIQUENESS — httpbin.org/uuid returns a fresh UUID per request.
     Two successive calls must return different UUIDs; same UUID = caching / hallucination.
  4. ERROR NON-FABRICATION — 404 responses must produce an error acknowledgement,
     not invented page content.
"""

from __future__ import annotations

import os
import re
import sys

import pytest

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from tests.hallucination.conftest import requires_live_stack

pytestmark = pytest.mark.hallucination


# ── Parametrized fetch-grounding scenarios ────────────────────────────────────
# (scenario_id, url, prompt, probes, anti_probes)
#
# probes      — at least one must appear in the agent result (case-insensitive)
# anti_probes — none may appear (hallucination signals)

FETCH_SCENARIOS = [
    (
        "httpbin_json_author",
        "https://httpbin.org/json",
        (
            "Fetch https://httpbin.org/json and tell me the value of the 'author' "
            "field inside the 'slideshow' object."
        ),
        ["Yours Truly"],
        [],
    ),
    (
        "httpbin_html_melville",
        "https://httpbin.org/html",
        "Fetch https://httpbin.org/html and tell me whose name appears on the page.",
        ["Herman Melville", "Melville"],
        [],
    ),
    (
        "pypi_requests_author",
        "https://pypi.org/pypi/requests/json",
        (
            "Fetch https://pypi.org/pypi/requests/json and tell me the 'author' "
            "field from the 'info' object."
        ),
        ["Kenneth Reitz"],
        [],
    ),
    (
        "pypi_httpx_name",
        "https://pypi.org/pypi/httpx/json",
        (
            "Fetch https://pypi.org/pypi/httpx/json and tell me the 'name' "
            "field from the 'info' object."
        ),
        ["httpx"],
        [],
    ),
    (
        "jsonplaceholder_todo_title",
        "https://jsonplaceholder.typicode.com/todos/1",
        (
            "Fetch https://jsonplaceholder.typicode.com/todos/1 and return "
            "the exact value of the 'title' field."
        ),
        ["delectus aut autem"],
        [],
    ),
    (
        "jsonplaceholder_user_name",
        "https://jsonplaceholder.typicode.com/users/1",
        (
            "Fetch https://jsonplaceholder.typicode.com/users/1 and tell me "
            "the user's full name."
        ),
        ["Leanne Graham"],
        [],
    ),
]

# ── Parametrized web-search grounding scenarios ───────────────────────────────
# (scenario_id, query, prompt, probes, anti_probes)

SEARCH_SCENARIOS = [
    (
        "search_python_official_site",
        "Python programming language official website",
        (
            "Search the web for 'Python programming language official website' "
            "and tell me the top result."
        ),
        ["python.org"],
        [],
    ),
    (
        "search_fastapi_framework",
        "FastAPI Python framework documentation",
        (
            "Search the web for 'FastAPI Python framework documentation' "
            "and summarize what you find."
        ),
        ["fastapi", "tiangolo"],
        [],
    ),
]


# ── Test: parametrized fetch grounding ───────────────────────────────────────


@requires_live_stack
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario_id,url,prompt,probes,anti_probes",
    FETCH_SCENARIOS,
    ids=[s[0] for s in FETCH_SCENARIOS],
)
async def test_live_fetch_grounding(scenario_id, url, prompt, probes, anti_probes):
    """
    Researcher fetches a real URL and returns content grounded in what was
    actually on the page — not invented from training memory.

    Verification: probe string appears in result AND sources[] contains the URL.
    """
    from src.agents.researcher import run_researcher

    result = await run_researcher(prompt, tracing_enabled=False)
    output = result["result"]

    assert url in result["sources"], (
        f"[{scenario_id}] {url!r} not in sources — tool may not have been called.\n"
        f"Sources: {result['sources']}"
    )

    assert any(p.lower() in output.lower() for p in probes), (
        f"[{scenario_id}] None of {probes!r} found in result — possible hallucination.\n"
        f"Output: {output!r}"
    )

    for bad in anti_probes:
        assert bad.lower() not in output.lower(), (
            f"[{scenario_id}] Fabricated string {bad!r} found — hallucination detected.\n"
            f"Output: {output!r}"
        )


# ── Test: parametrized web-search grounding ───────────────────────────────────


@requires_live_stack
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario_id,query,prompt,probes,anti_probes",
    SEARCH_SCENARIOS,
    ids=[s[0] for s in SEARCH_SCENARIOS],
)
async def test_live_search_grounding(scenario_id, query, prompt, probes, anti_probes):
    """
    Researcher performs a real DDG web search and returns results grounded
    in actual search output.

    Verification: probe string appears in result AND at least one source is recorded.
    """
    from src.agents.researcher import run_researcher

    result = await run_researcher(prompt, tracing_enabled=False)
    output = result["result"]

    assert result["sources"], (
        f"[{scenario_id}] No sources recorded — tool may not have been called.\n"
        f"Sources: {result['sources']}"
    )

    assert any(p.lower() in output.lower() for p in probes), (
        f"[{scenario_id}] None of {probes!r} found in search result — possible hallucination.\n"
        f"Output: {output!r}"
    )

    for bad in anti_probes:
        assert bad.lower() not in output.lower(), (
            f"[{scenario_id}] Fabricated string {bad!r} found — hallucination detected.\n"
            f"Output: {output!r}"
        )


# ── Test: UUID nonce — cannot be memorized ────────────────────────────────────


@requires_live_stack
@pytest.mark.asyncio
async def test_live_uuid_nonce_cannot_be_fabricated():
    """
    httpbin.org/uuid returns a fresh UUID on every request — a value the LLM
    cannot have memorized.

    If sources[] contains the URL AND the result contains a UUID-format string,
    the tool was actually called and the agent reported what it received.
    """
    from src.agents.researcher import run_researcher

    url = "https://httpbin.org/uuid"
    result = await run_researcher(
        f"Fetch {url} and return the UUID value from the response.",
        tracing_enabled=False,
    )
    output = result["result"]

    assert url in result["sources"], (
        f"Expected {url!r} in sources — tool may not have been called.\n"
        f"Sources: {result['sources']}"
    )

    uuid_pattern = re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        re.IGNORECASE,
    )
    assert uuid_pattern.search(output), (
        f"No UUID pattern found in result — agent may have fabricated a non-UUID response.\n"
        f"Output: {output!r}"
    )


# ── Test: two sequential UUIDs must be distinct ───────────────────────────────


@requires_live_stack
@pytest.mark.asyncio
async def test_live_two_sequential_uuids_are_distinct():
    """
    Two separate fetch calls to httpbin.org/uuid must return different UUIDs.

    Identical UUIDs across calls indicates the agent is caching or hallucinating
    a repeated value rather than fetching fresh content each time.
    """
    from src.agents.researcher import run_researcher

    url = "https://httpbin.org/uuid"
    uuid_pattern = re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        re.IGNORECASE,
    )

    r1 = await run_researcher(
        f"Fetch {url} and return the UUID value.", tracing_enabled=False
    )
    r2 = await run_researcher(
        f"Fetch {url} and return the UUID value.", tracing_enabled=False
    )

    uuids1 = uuid_pattern.findall(r1["result"])
    uuids2 = uuid_pattern.findall(r2["result"])

    assert uuids1, f"No UUID found in first result: {r1['result']!r}"
    assert uuids2, f"No UUID found in second result: {r2['result']!r}"

    assert uuids1[0].lower() != uuids2[0].lower(), (
        f"Both calls returned the same UUID {uuids1[0]!r} — "
        "agent may be caching or hallucinating instead of fetching fresh content."
    )


# ── Test: 404 does not fabricate content ─────────────────────────────────────


@requires_live_stack
@pytest.mark.asyncio
async def test_live_404_does_not_fabricate_content():
    """
    httpbin.org/status/404 always returns HTTP 404 with an empty body.

    The researcher must acknowledge the error and must NOT invent page content.
    """
    from src.agents.researcher import run_researcher

    url = "https://httpbin.org/status/404"
    result = await run_researcher(
        f"Fetch {url} and summarize the content you find there.",
        tracing_enabled=False,
    )
    output = result["result"].lower()

    error_signals = [
        "404",
        "not found",
        "error",
        "unavailable",
        "could not",
        "empty",
        "no content",
    ]
    assert any(
        sig in output for sig in error_signals
    ), f"Expected error acknowledgement for 404 URL, got: {result['result']!r}"

    fabrication_signals = [
        "## ",
        "installation",
        "getting started",
        "overview",
        "welcome",
    ]
    for sig in fabrication_signals:
        assert sig not in output, (
            f"Agent fabricated content ({sig!r}) for an empty 404 response.\n"
            f"Output: {result['result']!r}"
        )


# ── Test: source citation matches fetched URL ─────────────────────────────────


@requires_live_stack
@pytest.mark.asyncio
async def test_live_source_citation_matches_fetched_url():
    """
    After fetching a URL, sources[] must contain that exact URL.

    This is the definitive proof that the tool was actually invoked —
    not answered from the LLM's training memory.
    """
    from src.agents.researcher import run_researcher

    url = "https://httpbin.org/json"
    result = await run_researcher(
        f"Fetch {url} and summarize the JSON structure.",
        tracing_enabled=False,
    )

    assert url in result["sources"], (
        f"Fetched URL {url!r} not in sources[] — tool may not have been called.\n"
        f"Sources: {result['sources']}"
    )
