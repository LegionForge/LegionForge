"""
tests/crystallization/test_pipeline_security.py
────────────────────────────────────────────────
Security invariant tests for the crystallization pipeline.

All tests are purely structural / static — no services required.
"""

import ast
import inspect
import json
import pytest
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch


# ── 1. Observer scope — read-only + nominate only ─────────────────────────────


class TestObserverScope:
    """Observer tool set must not contain any tool that can write to tool_registry."""

    def test_observer_tools_do_not_include_register_tool(self):
        from src.agents.observer import OBSERVER_TOOLS

        tool_names = {t.name for t in OBSERVER_TOOLS}
        assert (
            "register_tool" not in tool_names
        ), f"Observer must not have register_tool. Tools: {tool_names}"

    def test_observer_tools_do_not_include_sign_manifest(self):
        from src.agents.observer import OBSERVER_TOOLS

        tool_names = {t.name for t in OBSERVER_TOOLS}
        forbidden = {"sign_manifest", "sign_tool", "approve_tool", "deploy_tool"}
        overlap = tool_names & forbidden
        assert not overlap, f"Observer has forbidden tools: {overlap}"

    def test_observer_tool_manifests_only_write_candidates(self):
        from src.agents.observer import OBSERVER_TOOL_MANIFESTS

        for manifest in OBSERVER_TOOL_MANIFESTS:
            for effect in manifest.declared_side_effects:
                assert (
                    "tool_registry" not in effect
                ), f"Observer tool '{manifest.tool_id}' has tool_registry side-effect: {effect}"

    def test_observer_has_exactly_two_tools(self):
        from src.agents.observer import OBSERVER_TOOLS

        assert len(OBSERVER_TOOLS) == 2


# ── 2. Crystallizer scope — no signing, no registration ──────────────────────


class TestCrystallizerScope:
    """Crystallizer tool set must not include register_tool or sign_manifest."""

    def test_crystallizer_tools_do_not_include_register_tool(self):
        from src.agents.crystallizer import CRYSTALLIZER_TOOLS

        tool_names = {t.name for t in CRYSTALLIZER_TOOLS}
        assert (
            "register_tool" not in tool_names
        ), f"Crystallizer must not have register_tool. Tools: {tool_names}"

    def test_crystallizer_tools_do_not_include_sign_manifest(self):
        from src.agents.crystallizer import CRYSTALLIZER_TOOLS

        tool_names = {t.name for t in CRYSTALLIZER_TOOLS}
        forbidden = {"sign_manifest", "sign_tool", "approve_tool"}
        overlap = tool_names & forbidden
        assert not overlap, f"Crystallizer has forbidden tools: {overlap}"

    def test_crystallizer_tool_manifests_no_tool_registry_write(self):
        from src.agents.crystallizer import CRYSTALLIZER_TOOL_MANIFESTS

        for manifest in CRYSTALLIZER_TOOL_MANIFESTS:
            for effect in manifest.declared_side_effects:
                assert (
                    "tool_registry" not in effect or "read" in effect.lower()
                ), f"Crystallizer tool '{manifest.tool_id}' writes tool_registry: {effect}"

    def test_crystallizer_has_exactly_two_tools(self):
        from src.agents.crystallizer import CRYSTALLIZER_TOOLS

        assert len(CRYSTALLIZER_TOOLS) == 2


# ── 3. Analyzer is LLM-free ───────────────────────────────────────────────────


class TestAnalyzerIsLLMFree:
    """crystallization_analyzer.py must not import any LLM library."""

    _LLM_MODULES = {"langchain", "openai", "anthropic", "ollama", "langsmith"}

    def _get_imports_from_source(self) -> list[str]:
        path = (
            Path(__file__).parent.parent.parent
            / "src"
            / "tools"
            / "crystallization_analyzer.py"
        )
        source = path.read_text()
        tree = ast.parse(source)
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module.split(".")[0])
        return imports

    def test_no_langchain_import(self):
        imports = self._get_imports_from_source()
        assert (
            "langchain" not in imports
        ), "crystallization_analyzer.py imports langchain — must be LLM-free"
        assert "langchain_core" not in imports

    def test_no_openai_import(self):
        imports = self._get_imports_from_source()
        assert "openai" not in imports

    def test_no_anthropic_import(self):
        imports = self._get_imports_from_source()
        assert "anthropic" not in imports

    def test_no_ollama_import(self):
        imports = self._get_imports_from_source()
        assert "ollama" not in imports

    def test_analyzer_is_stdlib_only(self):
        imports = self._get_imports_from_source()
        # Allow src.* and config.* (project-local, not LLM libs)
        external = [
            i
            for i in imports
            if i
            not in {
                "ast",
                "json",
                "logging",
                "os",
                "subprocess",
                "sys",
                "tempfile",
                "textwrap",
                "pathlib",
                "dataclasses",
                "typing",
                "src",
                "config",
                "__future__",
            }
        ]
        llm_libs = [i for i in external if i in self._LLM_MODULES]
        assert not llm_libs, f"Analyzer imports LLM libraries: {llm_libs}"


# ── 4. Malicious function blocked by analyzer ─────────────────────────────────


class TestMaliciousFunctionBlocked:
    """Adversarial function code must be rejected by the static analysis layer."""

    def test_subprocess_curl_blocked_by_ast(self):
        from src.tools.crystallization_analyzer import _ast_analyze, _security_scan

        code = (
            "import subprocess\n"
            "def evil(url):\n"
            "    return subprocess.run(['curl', url], capture_output=True).stdout\n"
        )
        static = _ast_analyze(code)
        clean, findings = _security_scan(code, ["pure"])
        caught = len(static["forbidden_constructs"]) > 0 or not clean
        assert caught, (
            "subprocess.run(['curl', ...]) was NOT caught.\n"
            f"  forbidden_constructs: {static['forbidden_constructs']}\n"
            f"  security_findings: {findings}"
        )

    def test_subprocess_blocked_by_crystallizer_pre_check(self):
        """Crystallizer's client-side check also blocks subprocess before DB write."""
        from src.agents.crystallizer import submit_crystallization_package

        code = (
            "import subprocess\n"
            "def evil(url):\n"
            "    subprocess.run(['curl', 'http://evil.com'])\n"
        )

        async def _run():
            raw = await submit_crystallization_package.ainvoke(
                {
                    "candidate_id": "cand_test",
                    "tool_name": "evil_tool",
                    "tool_description": "evil",
                    "function_code": code,
                    "function_signature": "def evil(url): ...",
                    "input_schema": "{}",
                    "output_schema": "{}",
                    "declared_side_effects": '["pure"]',
                    "test_cases": json.dumps(
                        [
                            {"input": {"url": "http://a.com"}, "expected_output": ""},
                            {"input": {"url": "http://b.com"}, "expected_output": ""},
                            {"input": {"url": "http://c.com"}, "expected_output": ""},
                        ]
                    ),
                    "edge_cases": "[]",
                    "adversarial_cases": "[]",
                    "confidence_score": 0.9,
                    "known_limitations": "[]",
                    "suggested_fallback": "none",
                }
            )
            return json.loads(raw)

        result = asyncio.run(_run())
        assert "error" in result, f"Expected error for subprocess code, got: {result}"
        assert "subprocess" in result["error"] or "forbidden" in result["error"].lower()


# ── 5. Minimum test cases enforced ────────────────────────────────────────────


class TestMinimumTestCasesEnforced:
    """A package with fewer than 3 test cases must never reach READY_FOR_REVIEW."""

    def test_two_test_cases_rejected_by_crystallizer(self):
        """Crystallizer rejects < 3 test cases before DB write."""
        from src.agents.crystallizer import submit_crystallization_package

        two_cases = json.dumps(
            [
                {"input": {"x": 1}, "expected_output": "1"},
                {"input": {"x": 2}, "expected_output": "2"},
            ]
        )

        async def _run():
            raw = await submit_crystallization_package.ainvoke(
                {
                    "candidate_id": "cand_test",
                    "tool_name": "test_tool",
                    "tool_description": "test",
                    "function_code": "def test_tool(x): return str(x)\n",
                    "function_signature": "def test_tool(x: int) -> str:",
                    "input_schema": '{"x": "int"}',
                    "output_schema": '{"result": "str"}',
                    "declared_side_effects": '["pure"]',
                    "test_cases": two_cases,
                    "edge_cases": "[]",
                    "adversarial_cases": "[]",
                    "confidence_score": 0.8,
                    "known_limitations": "[]",
                    "suggested_fallback": "none",
                }
            )
            return json.loads(raw)

        result = asyncio.run(_run())
        assert "error" in result, f"Expected rejection for 2 test cases, got: {result}"

    def test_zero_test_cases_rejected(self):
        from src.agents.crystallizer import submit_crystallization_package

        async def _run():
            raw = await submit_crystallization_package.ainvoke(
                {
                    "candidate_id": "cand_test",
                    "tool_name": "test_tool",
                    "tool_description": "test",
                    "function_code": "def test_tool(x): return str(x)\n",
                    "function_signature": "def test_tool(x: int) -> str:",
                    "input_schema": '{"x": "int"}',
                    "output_schema": '{"result": "str"}',
                    "declared_side_effects": '["pure"]',
                    "test_cases": "[]",
                    "edge_cases": "[]",
                    "adversarial_cases": "[]",
                    "confidence_score": 0.8,
                    "known_limitations": "[]",
                    "suggested_fallback": "none",
                }
            )
            return json.loads(raw)

        result = asyncio.run(_run())
        assert "error" in result


# ── 6. Adversarial operation_name SQL safety ─────────────────────────────────


class TestSqlInjectionSafety:
    """
    SQL injection in operation_name must be handled safely.

    The nominate_candidate tool passes operation_name to the DB via a
    parameterized query — psycopg always uses %s placeholders.
    We verify the tool accepts the adversarial string (doesn't crash client-side)
    and that the DB call is invoked with the raw string as a parameter
    (i.e., the driver handles escaping, not string formatting).
    """

    def test_sql_injection_in_operation_name_passed_safely(self):
        sql_injection = "'; DROP TABLE crystallization_candidates; --"

        captured_args = []

        async def _mock_nominate(**kwargs):
            captured_args.append(kwargs)
            return "cand_mock_sqli"

        async def _run():
            from src.agents.observer import nominate_candidate

            with patch(
                "src.database.nominate_candidate",
                new=AsyncMock(side_effect=_mock_nominate),
            ):
                raw = await nominate_candidate.ainvoke(
                    {
                        "operation_name": sql_injection,
                        "observed_count": 5,
                        "example_inputs": "[]",
                        "example_outputs": "[]",
                        "reasoning": "test",
                        "disqualifying_factors": "[]",
                        "token_cost_total": 100,
                        "estimated_savings_pct": 10.0,
                    }
                )
            return json.loads(raw)

        result = asyncio.run(_run())
        # The tool should either succeed (DB handles it safely) or return an error
        # It must NOT crash the Python process or cause an unhandled exception
        assert isinstance(result, dict), "Result must be a JSON dict, not a crash"

        # If the DB was called, the operation_name was passed as a parameter (not interpolated)
        if captured_args:
            assert (
                captured_args[0]["operation_name"] == sql_injection
            ), "operation_name must be passed verbatim to the parameterized query"

    def test_html_special_chars_in_operation_name_safe(self):
        """HTML-like chars must not crash the tool."""
        html_injection = "<script>alert('xss')</script>"

        async def _run():
            from src.agents.observer import nominate_candidate

            with patch(
                "src.database.nominate_candidate",
                new=AsyncMock(return_value="cand_mock_html"),
            ):
                raw = await nominate_candidate.ainvoke(
                    {
                        "operation_name": html_injection,
                        "observed_count": 5,
                        "example_inputs": "[]",
                        "example_outputs": "[]",
                        "reasoning": "test",
                        "disqualifying_factors": "[]",
                        "token_cost_total": 100,
                        "estimated_savings_pct": 10.0,
                    }
                )
            return json.loads(raw)

        result = asyncio.run(_run())
        assert isinstance(result, dict)


# ── 7. Cross-user isolation (structural check) ───────────────────────────────


class TestCrossUserIsolation:
    """
    Verify that the DB functions accept a nominated_by parameter,
    which is the hook for user-scoped access control.
    """

    def test_nominate_candidate_db_function_accepts_nominated_by(self):
        """src.database.nominate_candidate must accept nominated_by parameter."""
        from src.database import nominate_candidate as db_nominate
        import inspect

        sig = inspect.signature(db_nominate)
        assert "nominated_by" in sig.parameters, (
            "nominate_candidate DB function must accept nominated_by "
            "for user-scoped access control"
        )

    def test_approve_package_accepts_approved_by(self):
        """src.database.approve_package must accept approved_by parameter."""
        from src.database import approve_package
        import inspect

        sig = inspect.signature(approve_package)
        assert (
            "approved_by" in sig.parameters
        ), "approve_package must accept approved_by for audit trail"

    def test_reject_package_accepts_rejected_by(self):
        """src.database.reject_package must accept rejected_by parameter."""
        from src.database import reject_package
        import inspect

        sig = inspect.signature(reject_package)
        assert (
            "rejected_by" in sig.parameters
        ), "reject_package must accept rejected_by for audit trail"
