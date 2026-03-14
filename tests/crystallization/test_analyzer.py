"""
tests/crystallization/test_analyzer.py
───────────────────────────────────────
Pre-HITL Analyzer tests — 100% deterministic, no LLM, no database.

Imports the internal functions of crystallization_analyzer directly and
tests them with synthetic inputs.  All tests are synchronous (the internal
helpers _ast_analyze, _security_scan, _run_test_in_subprocess are sync).
"""

import pytest

from src.tools.crystallization_analyzer import (
    _ast_analyze,
    _extract_function_name,
    _run_test_in_subprocess,
    _security_scan,
)

# ── AST / static analysis tests ───────────────────────────────────────────────


class TestAstAnalyze:
    """Tests for _ast_analyze() — pure AST walking, no subprocess."""

    def test_valid_pure_function_no_forbidden(self, valid_function_code):
        result = _ast_analyze(valid_function_code)
        assert (
            result["forbidden_constructs"] == []
        ), f"Expected no forbidden constructs, got: {result['forbidden_constructs']}"
        assert result["undeclared_dependencies"] == []
        assert result["parse_error"] is None

    def test_exec_call_rejected(self):
        code = "def evil(x):\n    exec(x)\n"
        result = _ast_analyze(code)
        assert any(
            "exec" in s for s in result["forbidden_constructs"]
        ), f"exec() not flagged in: {result['forbidden_constructs']}"

    def test_eval_call_rejected(self):
        code = "def evil(x):\n    return eval(x)\n"
        result = _ast_analyze(code)
        assert any("eval" in s for s in result["forbidden_constructs"])

    def test_dunder_import_rejected(self):
        code = "def evil(x):\n    m = __import__('os')\n    return m.getcwd()\n"
        result = _ast_analyze(code)
        assert any("__import__" in s for s in result["forbidden_constructs"])

    def test_subprocess_import_rejected(self):
        code = (
            "import subprocess\ndef evil(x):\n    return subprocess.check_output(x)\n"
        )
        result = _ast_analyze(code)
        assert any("subprocess" in s for s in result["forbidden_constructs"])

    def test_socket_import_rejected(self):
        code = "import socket\ndef evil(host):\n    return socket.gethostbyname(host)\n"
        result = _ast_analyze(code)
        assert any("socket" in s for s in result["forbidden_constructs"])

    def test_open_write_rejected(self):
        # open() is in _FORBIDDEN_NAMES — the call is rejected regardless of mode
        code = "def evil(data):\n    open('/tmp/pwned', 'w').write(data)\n"
        result = _ast_analyze(code)
        assert any("open" in s for s in result["forbidden_constructs"])

    def test_subclass_escape_rejected(self):
        # ().__class__.__bases__[0].__subclasses__() — MRO traversal
        code = "def evil():\n    return ().__class__.__bases__[0].__subclasses__()\n"
        result = _ast_analyze(code)
        # __bases__ and __subclasses__ are in _FORBIDDEN_ATTRS
        constructs_str = " ".join(result["forbidden_constructs"])
        assert (
            "__bases__" in constructs_str or "__subclasses__" in constructs_str
        ), f"Subclass escape not flagged. Got: {result['forbidden_constructs']}"

    def test_globals_subscript_rejected(self):
        # globals()['exec'] — dynamic builtin access via subscript
        code = "def evil():\n    return globals()['exec']('os.getcwd()')\n"
        result = _ast_analyze(code)
        assert any(
            "globals" in s or "Dynamic builtin" in s
            for s in result["forbidden_constructs"]
        ), f"globals subscript not flagged. Got: {result['forbidden_constructs']}"

    def test_stdlib_imports_allowed(self):
        code = (
            "import json\nimport re\nimport datetime\nimport math\nimport hashlib\n"
            "def f(x): return json.dumps({'a': x})\n"
        )
        result = _ast_analyze(code)
        assert (
            result["undeclared_dependencies"] == []
        ), f"Clean stdlib imports flagged as undeclared: {result['undeclared_dependencies']}"
        assert result["forbidden_constructs"] == []

    def test_third_party_import_flagged_as_undeclared(self):
        code = "import requests\ndef f(url): return requests.get(url).text\n"
        result = _ast_analyze(code)
        assert "requests" in result["undeclared_dependencies"]

    def test_os_system_attr_rejected(self):
        code = "import os\ndef evil(cmd):\n    os.system(cmd)\n"
        result = _ast_analyze(code)
        assert any("system" in s for s in result["forbidden_constructs"])

    def test_os_popen_attr_rejected(self):
        code = "import os\ndef evil(cmd):\n    return os.popen(cmd).read()\n"
        result = _ast_analyze(code)
        assert any("popen" in s for s in result["forbidden_constructs"])

    def test_cyclomatic_complexity_linear_function(self):
        # A linear function with no branches → complexity = 1
        code = "def f(x):\n    return x * 2\n"
        result = _ast_analyze(code)
        assert result["cyclomatic_complexity"] == 1

    def test_cyclomatic_complexity_with_branches(self):
        # Three if-statements → 1 + 3 = 4
        code = (
            "def f(x):\n"
            "    if x > 0:\n        return 1\n"
            "    elif x < 0:\n        return -1\n"
            "    else:\n        pass\n"
            "    if x == 42:\n        return 42\n"
            "    return 0\n"
        )
        result = _ast_analyze(code)
        assert (
            result["cyclomatic_complexity"] >= 3
        ), f"Expected >= 3 for 3-branch function, got {result['cyclomatic_complexity']}"

    def test_lines_of_code_counted(self, valid_function_code):
        result = _ast_analyze(valid_function_code)
        expected_lines = len(valid_function_code.splitlines())
        assert result["lines_of_code"] == expected_lines

    def test_long_function_lines_flagged(self):
        # Build a 60-line function body (above the recommended 50-line limit)
        lines = ["def long_func(x):"]
        for i in range(60):
            lines.append(f"    x = x + {i}")
        lines.append("    return x")
        code = "\n".join(lines)
        result = _ast_analyze(code)
        assert result["lines_of_code"] > 50

    def test_syntax_error_captured(self):
        code = "def broken(\n    return 1\n"
        result = _ast_analyze(code)
        assert result["parse_error"] is not None
        assert len(result["forbidden_constructs"]) > 0

    def test_getattr_bypass_rejected(self):
        # getattr(os, 'system') — getattr bypass of forbidden attribute
        code = "import os\ndef evil(cmd):\n    return getattr(os, 'system')(cmd)\n"
        result = _ast_analyze(code)
        assert any(
            "getattr" in s for s in result["forbidden_constructs"]
        ), f"getattr bypass not flagged. Got: {result['forbidden_constructs']}"

    def test_sys_modules_subscript_rejected(self):
        # sys.modules['subprocess'] — import bypass via sys.modules
        code = (
            "import sys\n"
            "def evil():\n"
            "    sp = sys.modules['subprocess']\n"
            "    return sp.check_output(['id'])\n"
        )
        result = _ast_analyze(code)
        assert any(
            "modules" in s or "sys.modules" in s for s in result["forbidden_constructs"]
        ), f"sys.modules bypass not flagged. Got: {result['forbidden_constructs']}"


# ── Security scan tests ───────────────────────────────────────────────────────


class TestSecurityScan:
    """Tests for _security_scan() — pattern-based scan, no subprocess."""

    def test_clean_function_is_clean(self, valid_function_code):
        clean, findings = _security_scan(valid_function_code, ["pure"])
        assert clean is True
        assert findings == []

    def test_exec_in_code_flagged(self):
        code = "def evil(x): exec(x)\n"
        clean, findings = _security_scan(code, ["pure"])
        assert clean is False
        assert any("exec" in f for f in findings)

    def test_eval_in_code_flagged(self):
        code = "def evil(x): return eval(x)\n"
        clean, findings = _security_scan(code, ["pure"])
        assert clean is False
        assert any("eval" in f for f in findings)

    def test_subprocess_in_code_flagged(self):
        code = "import subprocess\ndef evil(): subprocess.run(['id'])\n"
        clean, findings = _security_scan(code, ["pure"])
        assert clean is False
        assert any("subprocess" in f for f in findings)

    def test_socket_in_code_flagged(self):
        code = "import socket\ndef evil(h): return socket.gethostbyname(h)\n"
        clean, findings = _security_scan(code, ["pure"])
        assert clean is False
        assert any("socket" in f for f in findings)

    def test_open_write_flagged(self):
        code = "def evil(data): open('/tmp/x', 'w').write(data)\n"
        clean, findings = _security_scan(code, ["pure"])
        assert clean is False

    def test_import_in_pure_function_flagged(self):
        # A function claiming to be pure but containing an import statement
        code = "def f():\n    import os\n    return os.getcwd()\n"
        clean, findings = _security_scan(code, ["pure"])
        # Security scan flags 'import ' in a pure function
        assert clean is False

    def test_os_system_flagged(self):
        code = "def evil(cmd):\n    import os\n    os.system(cmd)\n"
        clean, findings = _security_scan(code, ["pure"])
        assert clean is False
        assert any("os.system" in f for f in findings)


# ── Subprocess test execution tests ──────────────────────────────────────────
#
# The analyzer uses _build_sandboxed_cmd() to pick the best sandbox:
#   1. Docker deny-default container (legionforge-analyzer:latest) — ideal
#   2. macOS sandbox-exec — fallback
#   3. Bare subprocess — last resort (test environments)
#
# When Docker is running with the legionforge-analyzer image, it wraps Python
# calls inside the container, which cannot access the local venv Python binary.
# Tests that exercise actual subprocess execution must bypass the sandbox so
# the local Python executable is used.  We do this by patching
# _build_sandboxed_cmd to return the bare command, matching the "last resort"
# branch that the analyzer itself uses in CI / Linux environments.


import sys
from unittest.mock import patch as _patch


def _run_unsandboxed(function_code, function_name, test_input, timeout=5):
    """Run _run_test_in_subprocess with sandbox bypassed (bare subprocess)."""
    with _patch(
        "src.tools.crystallization_analyzer._build_sandboxed_cmd",
        side_effect=lambda cmd: cmd,
    ):
        return _run_test_in_subprocess(
            function_code, function_name, test_input, timeout=timeout
        )


class TestRunTestInSubprocess:
    """Tests for _run_test_in_subprocess() — sandboxed subprocess execution.

    All tests in this class use _run_unsandboxed() which patches
    _build_sandboxed_cmd to return the bare command.  This ensures the local
    venv Python is used regardless of whether Docker / sandbox-exec is
    available in the current environment.
    """

    def test_passing_test_case(self, valid_function_code):
        ok, actual, err = _run_unsandboxed(
            valid_function_code,
            "format_currency",
            {"amount": 1234.5, "currency": "USD"},
        )
        assert ok is True, f"Expected success, got err={err!r}"
        assert actual == "$1,234.50"
        assert err is None

    def test_passing_eur_test_case(self, valid_function_code):
        ok, actual, err = _run_unsandboxed(
            valid_function_code,
            "format_currency",
            {"amount": 0.99, "currency": "EUR"},
        )
        assert ok is True, f"Expected success, got err={err!r}"
        assert actual == "\u20ac0.99"

    def test_wrong_expected_is_detected(self, valid_function_code):
        # Run the function and check result doesn't match wrong expectation
        ok, actual, err = _run_unsandboxed(
            valid_function_code,
            "format_currency",
            {"amount": 5.0, "currency": "USD"},
        )
        assert ok is True, f"Expected success, got err={err!r}"
        # Result is $5.00, not $999.00
        assert str(actual) != "$999.00"

    def test_type_error_is_captured(self):
        code = "def boom(x): return x['nonexistent_key']\n"
        ok, actual, err = _run_unsandboxed(
            code,
            "boom",
            {"x": "not_a_dict"},
        )
        assert ok is False
        assert err is not None

    def test_always_raises_counts_as_failure(self):
        code = "def always_fail(x): raise ValueError('intentional failure')\n"
        ok, actual, err = _run_unsandboxed(
            code,
            "always_fail",
            {"x": 1},
        )
        assert ok is False
        assert err is not None

    def test_multiple_test_cases_tracked(self, valid_function_code):
        # Run 5 test cases and assert all pass
        test_inputs = [
            ({"amount": 1.0, "currency": "USD"}, "$1.00"),
            ({"amount": 2.5, "currency": "USD"}, "$2.50"),
            ({"amount": 100.0, "currency": "GBP"}, "\u00a3100.00"),
            ({"amount": 0.0, "currency": "USD"}, "$0.00"),
            ({"amount": 9999.99, "currency": "USD"}, "$9,999.99"),
        ]
        passed = 0
        failed = 0
        for inp, expected in test_inputs:
            ok, actual, err = _run_unsandboxed(
                valid_function_code, "format_currency", inp
            )
            if ok and str(actual) == str(expected):
                passed += 1
            else:
                failed += 1
        assert passed == 5, f"Expected 5 passes, got {passed} pass / {failed} fail"

    def test_pass_rate_below_threshold_would_auto_reject(self):
        # A function that returns the wrong answer 4 out of 5 times
        wrong_code = "def always_wrong(x): return 'WRONG'\n"
        failures = 0
        for i in range(5):
            ok, actual, err = _run_unsandboxed(wrong_code, "always_wrong", {"x": i})
            if str(actual) != str(i):
                failures += 1
        pass_rate = (5 - failures) / 5
        # A function returning 'WRONG' for all inputs should have < 80% pass rate
        assert pass_rate < 0.80


# ── Function name extraction ──────────────────────────────────────────────────


class TestExtractFunctionName:
    """Tests for _extract_function_name()."""

    def test_extracts_function_name(self, valid_function_code):
        name = _extract_function_name(valid_function_code)
        assert name == "format_currency"

    def test_extracts_first_function_name(self):
        code = "def first(): pass\ndef second(): pass\n"
        name = _extract_function_name(code)
        assert name == "first"

    def test_syntax_error_returns_none(self):
        code = "def broken(\n    return 1\n"
        name = _extract_function_name(code)
        assert name is None

    def test_no_function_returns_none(self):
        code = "x = 1 + 2\n"
        name = _extract_function_name(code)
        assert name is None


# ── Auto-rejection decision logic tests ──────────────────────────────────────


class TestAutoRejectionLogic:
    """
    Test the auto-rejection gate logic as expressed through the internal
    functions.  These tests assert the invariants that analyze_package()
    relies on when building the report.
    """

    def test_forbidden_construct_triggers_rejection_path(self):
        """Any forbidden construct in static analysis → auto-reject."""
        code = "def evil(x): return eval(x)\n"
        static = _ast_analyze(code)
        assert (
            len(static["forbidden_constructs"]) > 0
        ), "Expected at least one forbidden construct for eval()"

    def test_undeclared_dep_triggers_rejection_path(self):
        """Non-stdlib import → undeclared dependency → auto-reject."""
        code = "import requests\ndef f(url): return requests.get(url).text\n"
        static = _ast_analyze(code)
        assert "requests" in static["undeclared_dependencies"]

    def test_security_violation_triggers_rejection_path(self):
        """Security scan finding → auto-reject."""
        code = "def evil(): subprocess.run(['id'])\n"
        clean, findings = _security_scan(code, ["pure"])
        assert clean is False
        assert len(findings) > 0

    def test_clean_function_no_rejection_triggers(self, valid_function_code):
        """Clean function: no forbidden constructs, no undeclared deps, security clean."""
        static = _ast_analyze(valid_function_code)
        clean, findings = _security_scan(valid_function_code, ["pure"])
        assert static["forbidden_constructs"] == []
        assert static["undeclared_dependencies"] == []
        assert clean is True

    def test_all_malicious_codes_have_forbidden_constructs(
        self, malicious_function_codes
    ):
        """Every entry in malicious_function_codes should be caught by AST or security scan."""
        for name, code in malicious_function_codes:
            static = _ast_analyze(code)
            clean, findings = _security_scan(code, ["pure"])
            caught = len(static["forbidden_constructs"]) > 0 or not clean
            assert caught, (
                f"Malicious code '{name}' was NOT caught by analyzer.\n"
                f"  forbidden_constructs: {static['forbidden_constructs']}\n"
                f"  security_findings: {findings}"
            )
