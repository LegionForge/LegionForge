"""
src/tools/crystallization_analyzer.py
──────────────────────────────────────
Pre-HITL Analyzer — Phase 5 Crystallization Pipeline.

Deterministic analysis pipeline triggered automatically after a
CrystallizationPackage is submitted. No LLM involved — pure logic.

Checks (in order):
  1. Static analysis (AST) — forbidden constructs, undeclared imports
  2. Test case execution — subprocess-sandboxed, time-limited
  3. Behavioral equivalence — function outputs vs. stored Observer examples
  4. Adversarial testing — edge cases and adversarial inputs
  5. Security scan — purity / side-effect enforcement
  6. Auto-rejection decision — if any hard gates fail

Auto-rejected (no human review) if:
  - Any forbidden AST construct found
  - Any undeclared non-stdlib dependency
  - Security scan violation
  - Test case pass rate < 80%

Everything else goes to human review with a full report.

Usage:
    from src.tools.crystallization_analyzer import analyze_package
    await analyze_package("pkg_abc123def456")
"""

from __future__ import annotations

import ast
import json
import logging
import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ── Sandbox configuration ──────────────────────────────────────────────────────

# Path to sandbox-exec binary (macOS only)
_SANDBOX_EXEC = "/usr/bin/sandbox-exec"

# Template sandbox profile — contains PROJECT_ROOT_PLACEHOLDER, not a real path.
# Use _get_resolved_sandbox_profile() to get a usable file.
_SANDBOX_PROFILE_TEMPLATE = (
    Path(__file__).parent.parent.parent / "config" / "sandbox_profiles" / "analyzer.sb"
)
_SANDBOX_PROFILE_PLACEHOLDER = "PROJECT_ROOT_PLACEHOLDER"
_PROJECT_ROOT = str(Path(__file__).parent.parent.parent.resolve())

# Module-level cache: resolved profile written to a tempfile once per process.
_resolved_sandbox_profile_path: str | None = None


def _get_resolved_sandbox_profile() -> Path | None:
    """Return path to a sandbox profile with PROJECT_ROOT_PLACEHOLDER substituted.

    Reads the template once, writes a resolved copy to a tempfile, and caches the
    path for the lifetime of the process.  Returns None if the template is missing.
    """
    global _resolved_sandbox_profile_path
    if _resolved_sandbox_profile_path is not None:
        return Path(_resolved_sandbox_profile_path)
    if not _SANDBOX_PROFILE_TEMPLATE.exists():
        return None
    content = _SANDBOX_PROFILE_TEMPLATE.read_text()
    content = content.replace(_SANDBOX_PROFILE_PLACEHOLDER, _PROJECT_ROOT)
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".sb", prefix="legionforge-analyzer-", delete=False
    )
    tmp.write(content)
    tmp.close()
    _resolved_sandbox_profile_path = tmp.name
    logger.debug("Resolved sandbox profile written to %s", tmp.name)
    return Path(tmp.name)


# ── Constants ─────────────────────────────────────────────────────────────────

# AST node types that are unconditionally forbidden in crystallized functions.
# These represent dynamic code execution or dangerous system access.
_FORBIDDEN_NAMES = frozenset(
    {
        "exec",
        "eval",
        "compile",
        "__import__",
        "breakpoint",
        "input",
        # File I/O: crystallized pure functions must not touch the filesystem
        "open",
        # Introspection that can reveal runtime state or bypass restrictions
        "vars",
        "dir",
        # Phase 6: dynamic namespace access — globals()['eval'](), locals()['exec']()
        "globals",
        "locals",
        # Phase 6: MRO traversal entry point — type(obj).__mro__ chain pivoting
        "type",
    }
)

_FORBIDDEN_ATTRS = frozenset(
    {
        # Process spawning via os / subprocess
        "system",  # os.system
        "popen",  # os.popen / subprocess.Popen
        "Popen",  # subprocess.Popen
        "call",  # subprocess.call
        "run",  # subprocess.run (checked via module context)
        # os.exec* family — replaces the current process image
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        # os.spawn* family
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        # os.fork* — process duplication
        "fork",
        "forkpty",
        # os credential / privilege escalation
        "setuid",
        "setgid",
        "seteuid",
        "setegid",
        # Phase 6: MRO traversal — ().__class__.__bases__[0].__subclasses__()
        "__bases__",
        "__subclasses__",
        "__mro__",
        # Phase 6: object introspection bypass
        "__class__",
        "__dict__",
        # Phase 6: sys.modules['subprocess'] subscript bypass
        "modules",
    }
)

# Stdlib modules that are unconditionally banned from crystallized functions.
# These modules provide OS-level access that pure functions must never use.
# Note: they ARE stdlib — we flag imports of these specifically.
_BANNED_STDLIB_MODULES = frozenset(
    {
        "subprocess",
        "multiprocessing",
        "socket",
        "socketserver",
        "signal",
        "smtplib",
        "ftplib",
        "imaplib",
        "poplib",
        "telnetlib",
        "ssl",
        "xmlrpc",
        "http",
        "urllib",
        "email",
        "ctypes",
        "cffi",
        "pty",
        "tty",
        "termios",
        "grp",
        "pwd",
        "spwd",
        "crypt",
        "sqlite3",
        "dbm",
        "shelve",
        "pickle",
        "pickletools",
        "marshal",
        "mmap",
        "msvcrt",
        "winreg",
        "winsound",
        "posix",
        "nt",
        "resource",
        "syslog",
    }
)

# Modules that are in the Python standard library and are allowed in
# crystallized functions (pure, computation-only modules).
_STDLIB_MODULES = frozenset(
    {
        "abc",
        "ast",
        "base64",
        "binascii",
        "bisect",
        "calendar",
        "cmath",
        "collections",
        "contextlib",
        "copy",
        "csv",
        "dataclasses",
        "datetime",
        "decimal",
        "difflib",
        "enum",
        "fnmatch",
        "fractions",
        "functools",
        "gc",
        "glob",
        "gzip",
        "hashlib",
        "heapq",
        "hmac",
        "html",
        "inspect",
        "io",
        "ipaddress",
        "itertools",
        "json",
        "keyword",
        "linecache",
        "locale",
        "logging",
        "math",
        "mimetypes",
        "numbers",
        "operator",
        "os",
        "os.path",
        "pathlib",
        "platform",
        "pprint",
        "queue",
        "random",
        "re",
        "shlex",
        "shutil",
        "stat",
        "statistics",
        "string",
        "struct",
        "sys",
        "tarfile",
        "tempfile",
        "textwrap",
        "threading",
        "time",
        "timeit",
        "traceback",
        "typing",
        "unicodedata",
        "unittest",
        "uuid",
        "warnings",
        "weakref",
        "xml",
        "zipfile",
        "zipimport",
        "zlib",
        "__future__",
    }
)

# Execution sandbox timeout in seconds
_EXEC_TIMEOUT_SECONDS = 5

# Minimum test pass rate for READY_FOR_REVIEW
_MIN_PASS_RATE = 0.80

# Auto-reject gates (checked before sending to human review)
_AUTO_REJECT_GATES = [
    "forbidden_constructs",  # any forbidden AST nodes
    "undeclared_dependencies",  # non-stdlib imports
    "security_findings",  # security scan findings
]


# ── AST analysis ──────────────────────────────────────────────────────────────


def _ast_analyze(function_code: str) -> dict[str, Any]:
    """
    Parse the function_code with ast.parse() and check for:
    - Forbidden function calls / attribute accesses
    - Non-stdlib import statements
    - Approximate cyclomatic complexity (branching nodes)
    - Line count

    Returns a dict with findings.
    """
    result: dict[str, Any] = {
        "forbidden_constructs": [],
        "undeclared_dependencies": [],
        "undeclared_side_effects": [],
        "cyclomatic_complexity": 1,
        "lines_of_code": len(function_code.splitlines()),
        "parse_error": None,
    }

    try:
        tree = ast.parse(function_code)
    except SyntaxError as e:
        result["parse_error"] = str(e)
        result["forbidden_constructs"].append(f"SyntaxError: {e}")
        return result

    # Walk AST for forbidden constructs
    for node in ast.walk(tree):
        # Forbidden function names called directly: exec(), eval(), open(), etc.
        if isinstance(node, ast.Call):
            func = node.func

            # Direct call: exec(), eval(), open(), etc.
            if isinstance(func, ast.Name) and func.id in _FORBIDDEN_NAMES:
                result["forbidden_constructs"].append(
                    f"Forbidden call: {func.id}() at line {node.lineno}"
                )

            # Attribute call: os.system(), subprocess.Popen(), os.execvp(), etc.
            elif isinstance(func, ast.Attribute) and func.attr in _FORBIDDEN_ATTRS:
                result["forbidden_constructs"].append(
                    f"Forbidden call: .{func.attr}() at line {node.lineno}"
                )

            # getattr() bypass detection: getattr(os, 'system') / getattr(os, 'execvp')
            # This is the most common AST-check bypass technique.
            elif isinstance(func, ast.Name) and func.id == "getattr":
                # Check if the second argument is a string literal matching a forbidden attr
                if len(node.args) >= 2:
                    attr_arg = node.args[1]
                    if isinstance(attr_arg, ast.Constant) and isinstance(
                        attr_arg.value, str
                    ):
                        if attr_arg.value in _FORBIDDEN_ATTRS:
                            result["forbidden_constructs"].append(
                                f"getattr bypass detected: getattr(..., {attr_arg.value!r}) "
                                f"at line {node.lineno}"
                            )
                        elif attr_arg.value in _FORBIDDEN_NAMES:
                            result["forbidden_constructs"].append(
                                f"getattr bypass detected: getattr(..., {attr_arg.value!r}) "
                                f"at line {node.lineno}"
                            )
                    else:
                        # Non-literal second arg — dynamic getattr is a risk flag
                        # (can't statically determine the attribute name)
                        result.setdefault("risk_flags", []).append(
                            f"Dynamic getattr: second argument is not a string literal "
                            f"at line {node.lineno} — cannot statically verify attribute"
                        )

        # Phase 6: Subscript-based bypass detection.
        # These patterns circumvent import checks without using import statements.
        elif isinstance(node, ast.Subscript):
            # sys.modules['subprocess'] — access restricted modules without import
            if isinstance(node.value, ast.Attribute) and node.value.attr in {"modules"}:
                result["forbidden_constructs"].append(
                    f"sys.modules subscript access at line {node.lineno} — "
                    "imports restricted module without import statement"
                )
            # __builtins__['eval'] — access builtins dict directly
            elif isinstance(node.value, ast.Name) and node.value.id == "__builtins__":
                result["forbidden_constructs"].append(
                    f"__builtins__ subscript access at line {node.lineno} — "
                    "bypasses forbidden-name check via dict access"
                )
            # globals()['exec'] or locals()['eval'] — dynamic builtin access
            elif isinstance(node.value, ast.Call):
                call_func = node.value.func
                if isinstance(call_func, ast.Name) and call_func.id in {
                    "globals",
                    "locals",
                    "vars",
                }:
                    result["forbidden_constructs"].append(
                        f"Dynamic builtin access via {call_func.id}()[...] "
                        f"at line {node.lineno} — bypasses forbidden-name check"
                    )

        # Import statements — check against stdlib allowlist and banned list
        elif isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in _BANNED_STDLIB_MODULES:
                    result["forbidden_constructs"].append(
                        f"Banned stdlib module import: {alias.name!r} "
                        f"(network/process/IO access not permitted)"
                    )
                elif top not in _STDLIB_MODULES:
                    result["undeclared_dependencies"].append(alias.name)

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top = node.module.split(".")[0]
                if top in _BANNED_STDLIB_MODULES:
                    result["forbidden_constructs"].append(
                        f"Banned stdlib module import: {node.module!r} "
                        f"(network/process/IO access not permitted)"
                    )
                elif top not in _STDLIB_MODULES:
                    result["undeclared_dependencies"].append(node.module)

        # Complexity approximation: count branching nodes
        elif isinstance(
            node,
            (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With, ast.Assert),
        ):
            result["cyclomatic_complexity"] += 1

    return result


# ── Security scan ─────────────────────────────────────────────────────────────


def _security_scan(
    function_code: str, declared_side_effects: list[str]
) -> tuple[bool, list[str]]:
    """
    Pattern-based security scan.

    Returns (security_clean: bool, findings: list[str]).
    """
    findings: list[str] = []

    # Hard patterns that are always forbidden
    hard_patterns = [
        ("exec(", "Dynamic code execution (exec)"),
        ("eval(", "Dynamic code evaluation (eval)"),
        ("__import__", "Dynamic import (__import__)"),
        ("os.system", "Shell command execution (os.system)"),
        ("subprocess.", "Subprocess spawning"),
        ("socket.", "Network socket access"),
        (".write(", "File write operation"),
        ("open(", "File open"),  # open() for reading could be legitimate but we flag it
    ]

    for pattern, description in hard_patterns:
        if pattern in function_code:
            findings.append(f"{description}: found {pattern!r} in code")

    # Check purity claim vs actual code
    if declared_side_effects == ["pure"]:
        # Function claims to be pure — additional checks
        suspicious = ["import ", "global ", "nonlocal "]
        for s in suspicious:
            if s in function_code:
                findings.append(
                    f"Purity violation claim: {s.strip()!r} found in code "
                    "but declared_side_effects=['pure']"
                )

    return len(findings) == 0, findings


# ── Subprocess-sandboxed test execution ──────────────────────────────────────


def _get_safe_env() -> dict[str, str]:
    """
    Return a secret-stripped environment for subprocess execution.

    Tries to use the initialized CredentialStore singleton (preferred).
    Falls back to a manual allowlist filter if CredentialStore is not yet
    initialized (e.g., in unit tests or CLI usage).
    """
    try:
        from src.credentials import creds

        return creds.get_safe_subprocess_env()
    except ImportError:
        pass
    # Fallback: manual allowlist — same keys as CredentialStore._SAFE_SUBPROCESS_ENV_KEYS
    _safe_keys = frozenset(
        {
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "SHELL",
            "TMPDIR",
            "TEMP",
            "TMP",
            "PWD",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "TZ",
            "PYTHONPATH",
            "PYTHONDONTWRITEBYTECODE",
            "PYTHONNOUSERSITE",
            "PYTHONUNBUFFERED",
            "VIRTUAL_ENV",
            "DYLD_LIBRARY_PATH",
            "LD_LIBRARY_PATH",
            "TERM",
        }
    )
    return {k: v for k, v in os.environ.items() if k in _safe_keys}


def _build_container_cmd(python_args: list[str]) -> list[str] | None:
    """
    Try to build a Docker deny-default container command for the analyzer.

    Requires the legionforge-analyzer:latest image to be pre-built.
    Returns None if Docker is unavailable or the image doesn't exist.

    Container security properties (deny-default, unlike sandbox-exec allow-default):
      --network none          → no network access at all
      --read-only             → filesystem is read-only
      --tmpfs /tmp:size=10m   → only /tmp is writable
      --memory 128m           → OOM kill at 128MB
      --cpus 0.5              → max 0.5 CPU cores
      --security-opt no-new-privileges → no setuid/setgid
      --pids-limit 20         → prevents fork bomb
      --user analyzer         → non-root user
    """
    try:
        from config.settings import settings as _settings

        if not getattr(_settings.security, "analyzer_container_enabled", True):
            return None
    except Exception:
        pass

    try:
        r = subprocess.run(
            ["docker", "image", "inspect", "legionforge-analyzer:latest"],
            capture_output=True,
            timeout=2,
        )
        if r.returncode != 0:
            return None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None

    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:size=10m",  # nosec B108 — Docker tmpfs mount arg, not a Python tempfile path
        "--memory",
        "128m",
        "--cpus",
        "0.5",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "20",
        "--user",
        "analyzer",
        "legionforge-analyzer:latest",
    ] + python_args


def _build_sandboxed_cmd(python_cmd: list[str]) -> list[str]:
    """
    Wrap a Python subprocess command with the best available sandbox.

    Priority (strongest isolation first):
      1. Docker deny-default container (legionforge-analyzer:latest) — ideal
      2. macOS sandbox-exec allow-default+targeted-deny — fallback
      3. Bare subprocess — last resort (test environments / Linux without Docker)

    Docker is preferred because it uses deny-default isolation, whereas
    sandbox-exec uses allow-default + targeted deny (less strict but simpler
    to configure for Python's broad dylib requirements).
    """
    # Priority 1: Docker deny-default container
    container_cmd = _build_container_cmd(python_cmd)
    if container_cmd is not None:
        return container_cmd

    # Priority 2: macOS sandbox-exec (allow-default + targeted deny)
    sandbox_profile = _get_resolved_sandbox_profile()
    if (
        sys.platform == "darwin"
        and os.path.isfile(_SANDBOX_EXEC)
        and sandbox_profile is not None
    ):
        return [_SANDBOX_EXEC, "-f", str(sandbox_profile)] + python_cmd

    # Priority 3: Bare subprocess (test environments / Linux without Docker)
    return python_cmd


def _run_test_in_subprocess(
    function_code: str,
    function_name: str,
    test_input: dict,
    timeout: float = _EXEC_TIMEOUT_SECONDS,
) -> tuple[bool, Any, str | None]:
    """
    Execute a single test case in a sandboxed subprocess.

    Security properties:
      - The generated code is NEVER exec()d in the main process.
      - The subprocess environment is stripped of ALL secrets
        (API keys, passwords, tokens) via CredentialStore.get_safe_subprocess_env().
      - On macOS, the subprocess is wrapped with sandbox-exec using the
        analyzer seatbelt profile (deny network, deny Keychain, deny writes).
      - A hard timeout prevents infinite loops from stalling the analyzer.

    Returns:
        (success: bool, output: Any, error: str | None)
    """
    # Build a self-contained runner script
    runner = textwrap.dedent(
        f"""
import json
import sys

{function_code}

try:
    inputs = json.loads(sys.argv[1])
    result = {function_name}(**inputs)
    print(json.dumps({{"output": result, "error": None}}, default=str))
except Exception as e:
    print(json.dumps({{"output": None, "error": str(e)}}))
"""
    )

    # Build the command — sandbox-exec wraps on macOS if available
    base_cmd = [sys.executable, "-c", runner, json.dumps(test_input)]
    cmd = _build_sandboxed_cmd(base_cmd)

    # Use secret-stripped environment — NEVER pass the full os.environ
    safe_env = _get_safe_env()

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=safe_env,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            result = json.loads(proc.stdout.strip())
            if result.get("error"):
                return False, None, result["error"]
            return True, result.get("output"), None
        else:
            stderr = proc.stderr.strip()[:500]
            return False, None, f"Exit {proc.returncode}: {stderr}"
    except subprocess.TimeoutExpired:
        return False, None, f"Timeout after {timeout}s"
    except Exception as e:
        return False, None, str(e)


def _extract_function_name(function_code: str) -> str | None:
    """Extract the function name from the first def statement."""
    try:
        tree = ast.parse(function_code)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                return node.name
    except SyntaxError:
        pass
    return None


# ── Main analysis entry point ─────────────────────────────────────────────────


async def analyze_package(package_id: str) -> dict[str, Any]:
    """
    Run the full Pre-HITL analysis on a crystallization package.

    Fetches the package from DB, runs all checks, writes an analysis
    report to crystallization_analyses, and updates the package status.

    Returns the analysis report as a dict (same structure as the DB row).
    Raises no exceptions — failures are captured in the report.
    """
    try:
        from src.database import (
            create_analysis,
            get_package,
        )

        package = await get_package(package_id)
        if not package:
            logger.warning(f"[analyzer] Package {package_id!r} not found — skipping")
            return {"error": f"Package {package_id!r} not found"}

        function_code: str = package.get("function_code", "")
        declared_side_effects: list = package.get("declared_side_effects") or ["pure"]
        test_cases: list = package.get("test_cases") or []
        edge_cases: list = package.get("edge_cases") or []
        adversarial_cases: list = package.get("adversarial_cases") or []
        example_inputs: list = []  # from candidate — used for equivalence
        example_outputs: list = []

        # Try to get candidate examples for equivalence check
        candidate_id = package.get("candidate_id")
        if candidate_id:
            try:
                from src.database import get_candidate

                candidate = await get_candidate(candidate_id)
                if candidate:
                    example_inputs = candidate.get("example_inputs") or []
                    example_outputs = candidate.get("example_outputs") or []
            except Exception:
                pass

    except Exception as e:
        logger.warning(f"[analyzer] DB fetch failed for {package_id!r}: {e}")
        return {"error": str(e)}

    # ── 1. Static analysis ────────────────────────────────────────────────────
    static = _ast_analyze(function_code)
    forbidden_constructs = static["forbidden_constructs"]
    undeclared_dependencies = static["undeclared_dependencies"]
    cyclomatic_complexity = static["cyclomatic_complexity"]
    lines_of_code = static["lines_of_code"]

    # ── 2 + 4. Test case + adversarial execution ──────────────────────────────
    function_name = _extract_function_name(function_code) or "unknown_function"
    passed = 0
    failed = 0
    failed_diffs: list[dict] = []
    adversarial_exceptions: list[dict] = []

    # Run standard test cases
    for tc in test_cases:
        inp = tc.get("input", {})
        expected = tc.get("expected_output")
        ok, actual, err = _run_test_in_subprocess(function_code, function_name, inp)
        if ok and str(actual) == str(expected):
            passed += 1
        else:
            failed += 1
            failed_diffs.append(
                {
                    "input": inp,
                    "expected": expected,
                    "actual": actual,
                    "error": err,
                }
            )

    # Run adversarial cases
    for ac in adversarial_cases:
        inp = ac.get("input", {})
        ok, actual, err = _run_test_in_subprocess(function_code, function_name, inp)
        if err and "Timeout" not in err:
            adversarial_exceptions.append({"input": inp, "error": err})

    # Standard edge inputs regardless of declared edge_cases
    standard_adversarial = [
        {},  # empty
        {"__proto__": "exploit"},  # prototype pollution attempt
    ]
    for inp in standard_adversarial:
        ok, actual, err = _run_test_in_subprocess(function_code, function_name, inp)
        if err and "Timeout" not in err and "unexpected keyword" not in str(err):
            adversarial_exceptions.append({"input": inp, "error": err})

    # ── 3. Behavioral equivalence vs. Observer examples ──────────────────────
    equivalence_matches = 0
    equivalence_total = 0
    for inp, expected_out in zip(example_inputs[:5], example_outputs[:5]):
        if not isinstance(inp, dict):
            continue
        ok, actual, err = _run_test_in_subprocess(function_code, function_name, inp)
        equivalence_total += 1
        if ok and str(actual) == str(expected_out):
            equivalence_matches += 1

    ai_equivalence_rate = (
        equivalence_matches / equivalence_total if equivalence_total > 0 else 1.0
    )

    # ── 5. Security scan ──────────────────────────────────────────────────────
    security_clean, security_findings = _security_scan(
        function_code, declared_side_effects
    )

    # ── 6. Auto-rejection decision ────────────────────────────────────────────
    total_tests = passed + failed
    pass_rate = passed / total_tests if total_tests > 0 else 0.0

    auto_reject_reasons: list[str] = []
    if forbidden_constructs:
        auto_reject_reasons.append(f"Forbidden AST constructs: {forbidden_constructs}")
    if undeclared_dependencies:
        auto_reject_reasons.append(
            f"Undeclared non-stdlib dependencies: {undeclared_dependencies}"
        )
    if security_findings:
        auto_reject_reasons.append(f"Security violations: {security_findings}")
    if total_tests > 0 and pass_rate < _MIN_PASS_RATE:
        auto_reject_reasons.append(
            f"Test pass rate too low: {pass_rate:.0%} (minimum {_MIN_PASS_RATE:.0%})"
        )

    if auto_reject_reasons:
        status = "REJECTED_BY_ANALYSIS"
        recommendation = "REJECT"
        recommendation_reasoning = "Auto-rejected by Pre-HITL Analyzer. " + "; ".join(
            auto_reject_reasons
        )
    else:
        status = "READY_FOR_REVIEW"
        recommendation = (
            "APPROVE" if pass_rate >= 0.95 and security_clean else "NEEDS_REVISION"
        )
        recommendation_reasoning = (
            f"Test pass rate: {pass_rate:.0%} ({passed}/{total_tests}). "
            f"Security: {'clean' if security_clean else 'issues found'}. "
            f"Complexity: {cyclomatic_complexity} (lines: {lines_of_code}). "
            f"AI equivalence: {ai_equivalence_rate:.0%}."
        )

    # Risk flags for human reviewer
    risk_flags: list[str] = []
    if cyclomatic_complexity > 10:
        risk_flags.append(f"High cyclomatic complexity: {cyclomatic_complexity}")
    if lines_of_code > 50:
        risk_flags.append(f"Function is longer than recommended: {lines_of_code} lines")
    if ai_equivalence_rate < 0.7 and equivalence_total > 0:
        risk_flags.append(
            f"Low AI equivalence rate: {ai_equivalence_rate:.0%} — "
            "function may not match observed behavior"
        )
    if adversarial_exceptions:
        risk_flags.append(
            f"{len(adversarial_exceptions)} adversarial input(s) caused exceptions"
        )

    # Estimated daily savings (rough: observed_count * avg_tokens_per_call)
    estimated_daily_savings = 0
    try:
        from src.database import get_candidate

        candidate = await get_candidate(package.get("candidate_id", ""))
        if candidate:
            token_total = candidate.get("token_cost_total", 0)
            count = candidate.get("observed_count", 1)
            # Rough extrapolation to daily savings
            estimated_daily_savings = int(token_total / max(count, 1) * 10)
    except Exception:
        pass

    # ── Persist analysis ──────────────────────────────────────────────────────
    report = {
        "package_id": package_id,
        "forbidden_constructs": forbidden_constructs,
        "undeclared_dependencies": undeclared_dependencies,
        "undeclared_side_effects": [],
        "cyclomatic_complexity": cyclomatic_complexity,
        "lines_of_code": lines_of_code,
        "test_cases_passed": passed,
        "test_cases_failed": failed,
        "failed_case_diffs": failed_diffs,
        "ai_equivalence_rate": ai_equivalence_rate,
        "adversarial_exceptions": adversarial_exceptions,
        "security_clean": security_clean,
        "security_findings": security_findings,
        "recommendation": recommendation,
        "recommendation_reasoning": recommendation_reasoning,
        "estimated_daily_savings": estimated_daily_savings,
        "risk_flags": risk_flags,
        "status": status,
    }

    try:
        await create_analysis(**report)
        logger.info(
            f"[analyzer] Analysis complete for {package_id!r}: "
            f"status={status!r} rec={recommendation!r} "
            f"pass={passed}/{total_tests}"
        )
    except Exception as e:
        logger.warning(f"[analyzer] Failed to persist analysis for {package_id!r}: {e}")

    return report
