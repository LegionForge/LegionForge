"""
tests/crystallization/test_crystallizer.py
──────────────────────────────────────────
Tests for the submit_crystallization_package tool function — validation logic
only, no database calls.

The tool's validation runs synchronously inside the async function before
any DB interaction, so we can test it by mocking out the DB path.
"""

import json
import pytest
import asyncio
from unittest.mock import AsyncMock, patch

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_package_args(**overrides) -> dict:
    """Return a valid set of keyword arguments for submit_crystallization_package."""
    defaults = {
        "candidate_id": "cand_test000001",
        "tool_name": "format_currency",
        "tool_description": "Format a numeric amount as a currency string.",
        "function_code": (
            "def format_currency(amount: float, currency: str) -> str:\n"
            "    symbols = {'USD': '$', 'EUR': '\u20ac'}\n"
            '    return f"{symbols.get(currency, currency)}{amount:.2f}"\n'
        ),
        "function_signature": "def format_currency(amount: float, currency: str) -> str:",
        "input_schema": json.dumps({"amount": "float", "currency": "str"}),
        "output_schema": json.dumps({"result": "str"}),
        "declared_side_effects": json.dumps(["pure"]),
        "test_cases": json.dumps(
            [
                {
                    "input": {"amount": 1.0, "currency": "USD"},
                    "expected_output": "$1.00",
                },
                {
                    "input": {"amount": 2.0, "currency": "EUR"},
                    "expected_output": "\u20ac2.00",
                },
                {
                    "input": {"amount": 3.0, "currency": "USD"},
                    "expected_output": "$3.00",
                },
            ]
        ),
        "edge_cases": json.dumps([]),
        "adversarial_cases": json.dumps([]),
        "confidence_score": 0.9,
        "known_limitations": json.dumps([]),
        "suggested_fallback": "Return raw amount as string",
    }
    defaults.update(overrides)
    return defaults


async def _call_submit(**kwargs) -> dict:
    """Invoke submit_crystallization_package with a mocked DB and return parsed result."""
    from src.agents.crystallizer import submit_crystallization_package

    # Mock both DB write and analyzer trigger so no external services are needed
    with (
        patch("src.database.create_package", new=AsyncMock(return_value="pkg_mock001")),
        patch(
            "src.tools.crystallization_analyzer.analyze_package",
            new=AsyncMock(return_value={}),
        ),
    ):
        raw = await submit_crystallization_package.ainvoke(kwargs)
    return json.loads(raw)


# ── Test cases ────────────────────────────────────────────────────────────────


class TestSubmitCrystallizationPackage:
    """Validation tests for submit_crystallization_package (no DB required)."""

    def test_valid_package_accepted(self):
        result = asyncio.run(_call_submit(**_make_package_args()))
        assert result.get("status") == "submitted", f"Expected submitted, got: {result}"
        assert "package_id" in result

    def test_zero_test_cases_rejected(self):
        args = _make_package_args(test_cases=json.dumps([]))
        result = asyncio.run(_call_submit(**args))
        assert "error" in result
        assert "test cases" in result["error"].lower() or "0" in result["error"]

    def test_one_test_case_rejected(self):
        args = _make_package_args(
            test_cases=json.dumps(
                [
                    {
                        "input": {"amount": 1.0, "currency": "USD"},
                        "expected_output": "$1.00",
                    }
                ]
            )
        )
        result = asyncio.run(_call_submit(**args))
        assert "error" in result

    def test_two_test_cases_rejected(self):
        args = _make_package_args(
            test_cases=json.dumps(
                [
                    {
                        "input": {"amount": 1.0, "currency": "USD"},
                        "expected_output": "$1.00",
                    },
                    {
                        "input": {"amount": 2.0, "currency": "USD"},
                        "expected_output": "$2.00",
                    },
                ]
            )
        )
        result = asyncio.run(_call_submit(**args))
        assert "error" in result
        assert "3" in result["error"] or "test cases" in result["error"].lower()

    def test_three_test_cases_accepted(self):
        # Exactly at the minimum — should succeed
        result = asyncio.run(_call_submit(**_make_package_args()))
        assert result.get("status") == "submitted"
        assert result.get("test_cases") == 3

    def test_exec_in_function_code_rejected(self):
        args = _make_package_args(
            function_code="def evil(x):\n    exec(x)\n    return x\n"
        )
        result = asyncio.run(_call_submit(**args))
        assert "error" in result
        assert "exec(" in result["error"] or "forbidden" in result["error"].lower()

    def test_eval_in_function_code_rejected(self):
        args = _make_package_args(function_code="def evil(x):\n    return eval(x)\n")
        result = asyncio.run(_call_submit(**args))
        assert "error" in result
        assert "eval(" in result["error"] or "forbidden" in result["error"].lower()

    def test_import_subprocess_in_function_code_rejected(self):
        args = _make_package_args(
            function_code="import subprocess\ndef evil(cmd):\n    return subprocess.check_output(cmd)\n"
        )
        result = asyncio.run(_call_submit(**args))
        assert "error" in result
        assert "subprocess" in result["error"] or "forbidden" in result["error"].lower()

    def test_os_system_in_function_code_rejected(self):
        args = _make_package_args(
            function_code="import os\ndef evil(cmd):\n    os.system(cmd)\n"
        )
        result = asyncio.run(_call_submit(**args))
        assert "error" in result
        assert "os.system" in result["error"] or "forbidden" in result["error"].lower()

    def test_invalid_json_in_test_cases_rejected(self):
        args = _make_package_args(test_cases="{not valid json}")
        result = asyncio.run(_call_submit(**args))
        assert "error" in result
        assert "JSON" in result["error"] or "json" in result["error"].lower()

    def test_result_contains_expected_fields(self):
        result = asyncio.run(_call_submit(**_make_package_args()))
        assert "package_id" in result
        assert "tool_name" in result
        assert result["tool_name"] == "format_currency"

    def test_confidence_score_returned_in_result(self):
        result = asyncio.run(_call_submit(**_make_package_args(confidence_score=0.75)))
        assert result.get("confidence_score") == 0.75

    def test_socket_dot_pattern_rejected(self):
        # 'socket.' is in the forbidden list in crystallizer.py
        args = _make_package_args(
            function_code="import socket\ndef evil(h):\n    s = socket.socket()\n    return s\n"
        )
        result = asyncio.run(_call_submit(**args))
        assert "error" in result
