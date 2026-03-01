"""
tests/testlab_suite/test_novel_security.py
────────────────────────────────────────────
LLM-generated novel security tests — 10 parametrized slots.

The LLM generates 10 security-focused tests each run, covering:
  - Auth bypass attempts
  - Data leak probes
  - Token forgery
  - Injection variants
  - DoS patterns

Findings (failures) are saved to novel_findings.json for promotion.
Skips gracefully if Ollama is not available.

Mark: novel_security
Count: 10 tests (parametrized slots)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests.testlab_suite.novel_findings import append_finding

pytestmark = [pytest.mark.novel_security]

_NOVEL_SEC_TMP = Path(__file__).parent / ".novel_security.py"
_SLOT_COUNT = 10


# ── Shared LLM helper (mirrors test_novel_llm.py) ────────────────────────────


def _ollama_available() -> bool:
    base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    try:
        import urllib.request

        urllib.request.urlopen(f"{base}/api/tags", timeout=3)
        return True
    except Exception:
        return False


def _ollama_generate(prompt: str, model: str = "qwen2.5:3b") -> str:
    import urllib.request

    base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    payload = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.8},
        }
    ).encode()
    req = urllib.request.Request(
        f"{base}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read())
    return data.get("response", "").strip()


def _generate_security_tests(gateway_url: str) -> str:
    """Ask LLM for 10 novel security tests."""
    prompt = textwrap.dedent(
        f"""\
        You are a security test engineer specializing in API penetration testing.
        Write 10 novel security test functions for a FastAPI gateway.

        Gateway: {gateway_url}
        Tech stack: FastAPI + PostgreSQL + JWT Bearer auth + SSE streaming
        Valid API key: "test-api-key"
        Endpoints:
          POST /tasks {{task: str}} (auth required) → 202
          GET /tasks (auth required) → {{tasks, total}}
          GET /tasks/{{id}} (auth required) → task or 404
          DELETE /tasks/{{id}} (auth required) → {{status: cancelled}}
          GET /health (public) → {{status: ok}}
          GET /tasks/{{id}}/stream?token=st-{{id}} (stream token required) → SSE

        Generate exactly 10 test functions named:
          test_security_slot_0 through test_security_slot_9

        Include at least one test for each of:
          - Auth bypass attempt
          - Data leak probe
          - Token forgery
          - Injection variant
          - DoS/resource exhaustion pattern

        Rules:
        - Use httpx.Client (sync) — NOT async
        - base_url = "{gateway_url}"
        - Each test MUST assert that attacks are BLOCKED (4xx) or cause no 5xx
        - Tests must be self-contained with all imports inside each function
        - Security tests should be grey-hat/adversarial — creative attack vectors
        - Output ONLY valid Python code — no markdown, no explanations

        Begin:
    """
    )
    return _ollama_generate(prompt)


# ── Module-level generation ───────────────────────────────────────────────────

_generated_code: str | None = None
_generation_error: str | None = None


@pytest.fixture(scope="module", autouse=True)
def generate_security_file(gateway_server):
    """Generate security tests once per module."""
    global _generated_code, _generation_error

    if not _ollama_available():
        _generation_error = "Ollama not available"
        yield
        return

    gateway_url = gateway_server.base_url

    try:
        code = _generate_security_tests(gateway_url)
        code = re.sub(r"^```(?:python)?\n?", "", code, flags=re.MULTILINE)
        code = re.sub(r"\n?```$", "", code, flags=re.MULTILINE)
        code = code.strip()
        _NOVEL_SEC_TMP.write_text(code, encoding="utf-8")
        _generated_code = code
    except Exception as exc:
        _generation_error = str(exc)

    yield

    if _NOVEL_SEC_TMP.exists():
        try:
            _NOVEL_SEC_TMP.unlink()
        except Exception:
            pass


# ── Parametrized security slots ───────────────────────────────────────────────


@pytest.mark.parametrize("slot", range(_SLOT_COUNT))
def test_security_slot(slot: int, generate_security_file):
    """Run generated security test slot N via subprocess."""
    if _generation_error:
        pytest.skip(f"Security test generation skipped: {_generation_error}")

    if not _NOVEL_SEC_TMP.exists():
        pytest.skip("Security tests file not generated")

    test_name = f"test_security_slot_{slot}"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(_NOVEL_SEC_TMP),
            f"::{test_name}",
            "-v",
            "--tb=short",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(Path(__file__).parent.parent.parent),
    )

    if result.returncode != 0:
        failure_output = (result.stdout + result.stderr)[-2000:]
        try:
            code = (
                _NOVEL_SEC_TMP.read_text(encoding="utf-8")
                if _NOVEL_SEC_TMP.exists()
                else ""
            )
        except Exception:
            code = ""

        append_finding(
            category="security",
            test_name=test_name,
            source_code=code,
            failure_reason=failure_output,
        )
        pytest.fail(f"Novel security test slot {slot} FAILED:\n{failure_output[:1000]}")
