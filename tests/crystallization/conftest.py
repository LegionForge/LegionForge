"""
tests/crystallization/conftest.py
──────────────────────────────────
Shared fixtures for the crystallization pipeline test suite.

All fixtures are no-services-required (no PostgreSQL, no Ollama).
"""

import pytest


# ── Candidate fixtures ────────────────────────────────────────────────────────


@pytest.fixture()
def sample_candidate() -> dict:
    """A complete CrystallizationCandidate dict (format_currency example)."""
    return {
        "candidate_id": "cand_test000001",
        "operation_name": "format_currency",
        "observed_count": 47,
        "example_inputs": [
            {"amount": 1234.5, "currency": "USD"},
            {"amount": 0.99, "currency": "EUR"},
            {"amount": 1000000.0, "currency": "GBP"},
        ],
        "example_outputs": ["$1,234.50", "€0.99", "£1,000,000.00"],
        "input_schema": {"amount": "float", "currency": "str"},
        "output_schema": {"formatted": "str"},
        "token_cost_total": 4700,
        "estimated_savings_pct": 95.0,
        "reasoning": (
            "1. Same logical operation 47 times. "
            "2. Inputs always amount+currency. "
            "3. Outputs deterministic given same inputs. "
            "4. No ambiguity — pure arithmetic + string formatting. "
            "5. Simple algorithm: locale-aware format. "
            "6. ~100 tokens per call vs ~0 for deterministic."
        ),
        "disqualifying_factors": [],
        "status": "NOMINATED",
    }


# ── Function code fixtures ─────────────────────────────────────────────────────


@pytest.fixture()
def valid_function_code() -> str:
    """A pure Python function that should pass all analyzer checks."""
    return '''
def format_currency(amount: float, currency: str) -> str:
    """
    Format a numeric amount as a currency string.

    Args:
        amount:   The numeric value to format.
        currency: ISO 4217 currency code (USD, EUR, GBP, JPY).

    Returns:
        Formatted string e.g. '$1,234.50'.
    """
    symbols = {"USD": "$", "EUR": "\\u20ac", "GBP": "\\u00a3", "JPY": "\\u00a5"}
    symbol = symbols.get(currency, currency + " ")
    if currency == "JPY":
        return f"{symbol}{amount:,.0f}"
    return f"{symbol}{amount:,.2f}"
'''.strip()


@pytest.fixture()
def malicious_function_codes() -> list[tuple[str, str]]:
    """
    List of (name, code) tuples covering forbidden constructs.

    Each entry represents a distinct bypass/attack category that the analyzer
    must reject via static analysis before any execution occurs.
    """
    return [
        (
            "exec_call",
            "def evil(x): exec(\"import os; os.system('id')\")\n",
        ),
        (
            "eval_call",
            "def evil(x): return eval(x)\n",
        ),
        (
            "dunder_import",
            "def evil(x): m = __import__('os'); return m.getcwd()\n",
        ),
        (
            "subprocess_import",
            "import subprocess\ndef evil(x): return subprocess.check_output(['id'])\n",
        ),
        (
            "socket_import",
            "import socket\ndef evil(host): return socket.gethostbyname(host)\n",
        ),
        (
            "open_write",
            "def evil(data): open('/tmp/pwned', 'w').write(data)\n",
        ),
        (
            "subclass_escape",
            "def evil(): return ().__class__.__bases__[0].__subclasses__()\n",
        ),
        (
            "globals_subscript",
            "def evil(): return globals()['__builtins__']\n",
        ),
    ]


# ── Test case fixtures ─────────────────────────────────────────────────────────


@pytest.fixture()
def sample_test_cases() -> list[dict]:
    """Five test cases in the format the Crystallizer produces."""
    return [
        {
            "input": {"amount": 1234.5, "currency": "USD"},
            "expected_output": "$1,234.50",
        },
        {"input": {"amount": 0.99, "currency": "EUR"}, "expected_output": "\u20ac0.99"},
        {
            "input": {"amount": 100.0, "currency": "GBP"},
            "expected_output": "\u00a3100.00",
        },
        {"input": {"amount": 0.0, "currency": "USD"}, "expected_output": "$0.00"},
        {
            "input": {"amount": 9999.99, "currency": "USD"},
            "expected_output": "$9,999.99",
        },
    ]


@pytest.fixture()
def sample_package(sample_test_cases, valid_function_code) -> dict:
    """A complete crystallization package dict ready for analysis."""
    return {
        "package_id": "pkg_test000001",
        "candidate_id": "cand_test000001",
        "tool_name": "format_currency",
        "tool_description": "Format a numeric amount as a locale-aware currency string.",
        "function_code": valid_function_code,
        "function_signature": "def format_currency(amount: float, currency: str) -> str:",
        "input_schema": {"amount": "float", "currency": "str"},
        "output_schema": {"result": "str"},
        "declared_side_effects": ["pure"],
        "test_cases": sample_test_cases,
        "edge_cases": [
            {"input": {"amount": 0.0, "currency": "USD"}, "expected_output": "$0.00"},
        ],
        "adversarial_cases": [
            {
                "input": {"amount": 10**15, "currency": "USD"},
                "expected_behavior": "handles large numbers without crash",
            }
        ],
        "confidence_score": 0.95,
        "known_limitations": ["Does not handle all ISO 4217 codes"],
        "suggested_fallback": "Return raw amount as string",
        "status": "PENDING_ANALYSIS",
    }
