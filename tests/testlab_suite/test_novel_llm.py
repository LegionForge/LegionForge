"""
tests/testlab_suite/test_novel_llm.py
──────────────────────────────────────
LLM-generated general tests — 5 parametrized test slots.

At module load, if an LLM (Ollama) is available, generates 5 novel test
functions targeting the mock gateway, writes them to a temp file, and runs
each as a subprocess. Findings (failures) are saved to novel_findings.json.

Skips gracefully if OLLAMA_BASE_URL is not available.

Mark: novel
Count: 5 tests (parametrized slots)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

from tests.testlab_suite.novel_findings import append_finding

pytestmark = [pytest.mark.novel]

_SLOT_COUNT = 5

# ── LLM availability check ────────────────────────────────────────────────────


def _ollama_available() -> bool:
    """Return True if OLLAMA_BASE_URL is set and Ollama responds."""
    base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    try:
        import urllib.request

        urllib.request.urlopen(f"{base}/api/tags", timeout=3)
        return True
    except Exception:
        return False


def _ollama_generate(prompt: str, model: str = "qwen2.5:3b") -> str:
    """Call Ollama generate API and return the response text."""
    import urllib.request

    base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    payload = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.7},
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


# ── Generate novel tests ──────────────────────────────────────────────────────


def _generate_novel_tests(gateway_url: str) -> str:
    """Ask the LLM to generate 5 novel test functions and return Python code."""
    prompt = textwrap.dedent(
        f"""\
        You are a Python test engineer writing pytest tests for a FastAPI gateway.

        The gateway is at {gateway_url}. It:
        - Requires Bearer token auth (valid key: "test-api-key")
        - POST /tasks {{task: str}} → 202 {{task_id, status, stream_token}}
        - GET /tasks → 200 {{tasks: list, total: int}}
        - GET /tasks/{{id}} → 200 task object or 404
        - DELETE /tasks/{{id}} → 200 {{task_id, status: "cancelled"}}
        - GET /health → 200 {{status: "ok"}}
        - GET /usage/me → 200 {{daily_token_limit, tokens_used_today, remaining}}

        Generate exactly 5 pytest test functions named:
          test_novel_slot_0, test_novel_slot_1, test_novel_slot_2,
          test_novel_slot_3, test_novel_slot_4

        Rules:
        - Import httpx and use httpx.Client (sync, not async)
        - Use base_url = "{gateway_url}"
        - Valid API key = "test-api-key"
        - Each test must be self-contained
        - Cover interesting edge cases not in the standard test suite
        - Do NOT import pytest-asyncio; use regular sync functions
        - Output ONLY valid Python code — no markdown, no explanations

        Begin:
    """
    )
    return _ollama_generate(prompt)


# ── Module-level generation (runs once) ──────────────────────────────────────

_generated_code: str | None = None
_generation_error: str | None = None
_novel_tmp_path: str | None = None


@pytest.fixture(scope="module", autouse=True)
def generate_novel_file(gateway_server):
    """Generate novel tests once per module and write to a system temp file."""
    global _generated_code, _generation_error, _novel_tmp_path
    import re

    if not _ollama_available():
        _generation_error = "Ollama not available"
        yield
        return

    gateway_url = gateway_server.base_url
    tmp_path: str | None = None
    try:
        code = _generate_novel_tests(gateway_url)
        # Strip markdown fences if LLM adds them
        code = re.sub(r"^```(?:python)?\n?", "", code, flags=re.MULTILINE)
        code = re.sub(r"\n?```$", "", code, flags=re.MULTILINE)
        code = code.strip()

        # Write to a system temp directory (not inside the project) so pytest
        # subprocess does not pick up the project conftest.py.
        fd, tmp_path = tempfile.mkstemp(suffix="_novel_general.py", prefix="lf_")
        os.close(fd)
        Path(tmp_path).write_text(code, encoding="utf-8")
        _novel_tmp_path = tmp_path
        _generated_code = code
    except Exception as exc:
        _generation_error = str(exc)

    yield

    # Cleanup
    if tmp_path and Path(tmp_path).exists():
        try:
            Path(tmp_path).unlink()
        except Exception:
            pass


# ── Parametrized test slots ───────────────────────────────────────────────────


@pytest.mark.parametrize("slot", range(_SLOT_COUNT))
def test_novel_slot(slot: int, generate_novel_file):
    """Run generated novel test slot N via subprocess."""
    if _generation_error:
        pytest.skip(f"Novel test generation skipped: {_generation_error}")

    if not _novel_tmp_path or not Path(_novel_tmp_path).exists():
        pytest.skip("Novel tests file not generated")

    test_name = f"test_novel_slot_{slot}"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            f"{_novel_tmp_path}::{test_name}",
            "-v",
            "--tb=short",
            "--override-ini=asyncio_mode=auto",
            "-p",
            "no:cacheprovider",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )

    if result.returncode != 0:
        # Save as a finding
        failure_output = (result.stdout + result.stderr)[-2000:]
        try:
            code = (
                Path(_novel_tmp_path).read_text(encoding="utf-8")
                if _novel_tmp_path and Path(_novel_tmp_path).exists()
                else ""
            )
        except Exception:
            code = ""

        finding_id = append_finding(
            category="general",
            test_name=test_name,
            source_code=code,
            failure_reason=failure_output,
        )
        pytest.skip(
            f"Novel test slot {slot}: finding saved (id={finding_id}). "
            f"Review via GET /novel or novel_findings.json. "
            f"Output snippet: {failure_output[:300]}"
        )
