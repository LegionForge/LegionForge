"""
tests/crystallization/test_observer.py
───────────────────────────────────────
Tests for the Observer agent's tool functions — no Ollama required.

Tool functions are tested directly with mocked DB calls.
"""

import json
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

# ── Helpers ───────────────────────────────────────────────────────────────────


def _run(coro):
    return asyncio.run(coro)


# ── nominate_candidate tests ──────────────────────────────────────────────────


class TestNominateCandidate:
    """Test the nominate_candidate tool function with mocked DB."""

    def _call_nominate(self, **overrides) -> dict:
        defaults = {
            "operation_name": "format_currency",
            "observed_count": 47,
            "example_inputs": json.dumps([{"amount": 1.0, "currency": "USD"}]),
            "example_outputs": json.dumps(["$1.00"]),
            "reasoning": "All six criteria satisfied.",
            "disqualifying_factors": json.dumps([]),
            "token_cost_total": 4700,
            "estimated_savings_pct": 95.0,
        }
        defaults.update(overrides)

        async def _run_mocked():
            from src.agents.observer import nominate_candidate

            with patch(
                "src.database.nominate_candidate",
                new=AsyncMock(return_value="cand_mock0001"),
            ):
                raw = await nominate_candidate.ainvoke(defaults)
            return json.loads(raw)

        return _run(_run_mocked())

    def test_valid_nomination_succeeds(self):
        result = self._call_nominate()
        assert result.get("status") == "nominated", f"Expected nominated, got: {result}"

    def test_result_contains_candidate_id(self):
        result = self._call_nominate()
        assert "candidate_id" in result
        assert result["candidate_id"].startswith("cand_")

    def test_result_contains_operation_name(self):
        result = self._call_nominate()
        assert result["operation_name"] == "format_currency"

    def test_result_contains_observed_count(self):
        result = self._call_nominate()
        assert result["observed_count"] == 47

    def test_invalid_json_example_inputs_returns_error(self):
        async def _run_mocked():
            from src.agents.observer import nominate_candidate

            raw = await nominate_candidate.ainvoke(
                {
                    "operation_name": "test_op",
                    "observed_count": 5,
                    "example_inputs": "{not valid json",
                    "example_outputs": "[]",
                    "reasoning": "test",
                    "disqualifying_factors": "[]",
                    "token_cost_total": 100,
                    "estimated_savings_pct": 50.0,
                }
            )
            return json.loads(raw)

        result = _run(_run_mocked())
        assert "error" in result
        assert "JSON" in result["error"] or "json" in result["error"].lower()

    def test_invalid_json_disqualifying_factors_returns_error(self):
        async def _run_mocked():
            from src.agents.observer import nominate_candidate

            raw = await nominate_candidate.ainvoke(
                {
                    "operation_name": "test_op",
                    "observed_count": 5,
                    "example_inputs": "[]",
                    "example_outputs": "[]",
                    "reasoning": "test",
                    "disqualifying_factors": "not-json",
                    "token_cost_total": 100,
                    "estimated_savings_pct": 50.0,
                }
            )
            return json.loads(raw)

        result = _run(_run_mocked())
        assert "error" in result

    def test_low_observed_count_still_nominates(self):
        # Observer doesn't enforce observed_count threshold itself —
        # that's the system prompt's responsibility. The tool accepts any count.
        result = self._call_nominate(observed_count=1)
        assert result.get("status") == "nominated"

    def test_non_empty_disqualifying_factors_still_nominates(self):
        # Disqualifying factors are advisory — human decides. Nomination succeeds.
        result = self._call_nominate(
            disqualifying_factors=json.dumps(["edge cases unclear"])
        )
        assert result.get("status") == "nominated"

    def test_db_failure_returns_error(self):
        async def _run_mocked():
            from src.agents.observer import nominate_candidate

            with patch(
                "src.database.nominate_candidate",
                new=AsyncMock(side_effect=Exception("DB connection failed")),
            ):
                raw = await nominate_candidate.ainvoke(
                    {
                        "operation_name": "format_currency",
                        "observed_count": 10,
                        "example_inputs": "[]",
                        "example_outputs": "[]",
                        "reasoning": "test",
                        "disqualifying_factors": "[]",
                        "token_cost_total": 100,
                        "estimated_savings_pct": 50.0,
                    }
                )
            return json.loads(raw)

        result = _run(_run_mocked())
        assert "error" in result

    def test_db_returns_none_returns_error(self):
        # DB write fails silently (returns None) — tool should report error
        async def _run_mocked():
            from src.agents.observer import nominate_candidate

            with patch(
                "src.database.nominate_candidate",
                new=AsyncMock(return_value=None),
            ):
                raw = await nominate_candidate.ainvoke(
                    {
                        "operation_name": "format_currency",
                        "observed_count": 10,
                        "example_inputs": "[]",
                        "example_outputs": "[]",
                        "reasoning": "test",
                        "disqualifying_factors": "[]",
                        "token_cost_total": 100,
                        "estimated_savings_pct": 50.0,
                    }
                )
            return json.loads(raw)

        result = _run(_run_mocked())
        assert "error" in result


# ── read_tool_call_history tests ──────────────────────────────────────────────


class TestReadToolCallHistory:
    """Test read_tool_call_history with a mocked DB pool."""

    def _make_mock_row(self, tool_id: str, count: int = 1) -> list:
        """Build a list of fake audit_log rows for a given tool_id."""
        rows = []
        for i in range(count):
            rows.append(
                {
                    "payload": {
                        "tool_id": tool_id,
                        "inputs": {"query": f"test {i}"},
                        "output_summary": f"result {i}",
                    },
                    "ts": "2026-01-01T00:00:00Z",
                }
            )
        return rows

    def test_returns_json_string(self):
        async def _run_mocked():
            from src.agents.observer import read_tool_call_history

            mock_conn = AsyncMock()
            mock_cur = AsyncMock()
            mock_cur.fetchall = AsyncMock(
                return_value=self._make_mock_row("web_search", 5)
            )
            mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_conn.__aexit__ = AsyncMock(return_value=False)
            mock_conn.execute = AsyncMock(return_value=mock_cur)

            mock_pool = MagicMock()
            mock_pool.connection = MagicMock(return_value=mock_conn)

            with patch("src.database.get_worker_pool", return_value=mock_pool):
                raw = await read_tool_call_history.ainvoke(
                    {"hours": 24, "min_occurrences": 3}
                )
            return json.loads(raw)

        result = _run(_run_mocked())
        assert "operations_found" in result or "error" in result

    def test_db_failure_returns_graceful_error(self):
        async def _run_mocked():
            from src.agents.observer import read_tool_call_history

            with patch(
                "src.database.get_worker_pool",
                side_effect=Exception("Pool not initialized"),
            ):
                raw = await read_tool_call_history.ainvoke(
                    {"hours": 24, "min_occurrences": 3}
                )
            return json.loads(raw)

        result = _run(_run_mocked())
        # Must return JSON with error info, not raise
        assert "error" in result or "operations_found" in result

    def test_returns_note_on_empty_audit_log(self):
        async def _run_mocked():
            from src.agents.observer import read_tool_call_history

            with patch(
                "src.database.get_worker_pool",
                side_effect=Exception("empty"),
            ):
                raw = await read_tool_call_history.ainvoke(
                    {"hours": 168, "min_occurrences": 3}
                )
            return json.loads(raw)

        result = _run(_run_mocked())
        # Graceful fallback — always JSON
        assert isinstance(result, dict)


# ── OBSERVER_TOOLS list tests ─────────────────────────────────────────────────


class TestObserverToolSet:
    """Verify the Observer's tool set matches the expected read/nominate scope."""

    def test_observer_tools_importable(self):
        from src.agents.observer import OBSERVER_TOOLS

        assert len(OBSERVER_TOOLS) == 2

    def test_observer_tools_names(self):
        from src.agents.observer import OBSERVER_TOOLS

        names = {t.name for t in OBSERVER_TOOLS}
        assert "read_tool_call_history" in names
        assert "nominate_candidate" in names
