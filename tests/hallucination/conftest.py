"""
tests/hallucination/conftest.py
────────────────────────────────
Markers and availability checks for the live hallucination test suite.

These tests hit the real internet AND the real LLM stack (Ollama + PostgreSQL).
Never included in make test, make ci, or make smoke — manually run only.

    make test-hallucination
    pytest tests/hallucination/ -v -s
"""

import pytest


def _ollama_available() -> bool:
    try:
        import os

        import httpx

        url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
        return httpx.get(f"{url}/api/tags", timeout=2.0).status_code == 200
    except Exception:
        return False


def _postgres_available() -> bool:
    try:
        import subprocess

        r = subprocess.run(
            ["psql", "-U", "legionforge", "-d", "legionforge", "-c", "SELECT 1"],
            capture_output=True,
            timeout=3,
        )
        return r.returncode == 0
    except Exception:
        return False


def _internet_available() -> bool:
    try:
        import httpx

        return (
            httpx.get("https://httpbin.org/status/200", timeout=5.0).status_code == 200
        )
    except Exception:
        return False


_stack_ok = _ollama_available() and _postgres_available()
_net_ok = _internet_available()

requires_llm_stack = pytest.mark.skipif(
    not _stack_ok,
    reason="Requires Ollama (localhost:11434) + PostgreSQL (legionforge DB)",
)

requires_live_stack = pytest.mark.skipif(
    not (_stack_ok and _net_ok),
    reason="Requires Ollama + PostgreSQL + internet access (httpbin.org unreachable)",
)
