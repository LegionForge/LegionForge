"""
tests/testlab_suite/test_cve.py
────────────────────────────────
CVE-based security tests.

Workflow:
  1. Fetch CVEs from NVD NIST API for relevant keywords
     (fastapi, langchain, psycopg, pyjwt, starlette)
  2. Feed each CVE to the LLM to generate a pytest function verifying
     LegionForge is NOT vulnerable to that CVE
  3. Run each generated test via subprocess
  4. Save failures to novel_findings.json

Requires:
  - Network access (for NVD API)
  - Ollama running (OLLAMA_BASE_URL)

Both are optional — test gracefully skips if either is missing.

Mark: cve
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
import time
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from tests.testlab_suite.novel_findings import append_finding

pytestmark = [pytest.mark.cve]

_CVE_TMP_DIR = Path(__file__).parent / ".cve_tests"
_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_KEYWORDS = ["fastapi", "langchain", "psycopg", "pyjwt", "starlette"]
_LOOKBACK_DAYS = 365

# ── Helpers ───────────────────────────────────────────────────────────────────


def _network_available() -> bool:
    try:
        urllib.request.urlopen("https://services.nvd.nist.gov", timeout=5)
        return True
    except Exception:
        return False


def _ollama_available() -> bool:
    base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    try:
        urllib.request.urlopen(f"{base}/api/tags", timeout=3)
        return True
    except Exception:
        return False


def _fetch_cves(keyword: str, max_results: int = 3) -> list[dict[str, Any]]:
    """Fetch recent CVEs for a keyword from NVD NIST API."""
    import datetime

    end_date = datetime.datetime.utcnow()
    start_date = end_date - datetime.timedelta(days=_LOOKBACK_DAYS)
    params = (
        f"keywordSearch={keyword}"
        f"&pubStartDate={start_date.strftime('%Y-%m-%dT%H:%M:%S.000')}"
        f"&pubEndDate={end_date.strftime('%Y-%m-%dT%H:%M:%S.000')}"
        f"&resultsPerPage={max_results}"
    )
    url = f"{_NVD_BASE}?{params}"
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "LegionForge-TestLab/1.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        vulnerabilities = data.get("vulnerabilities", [])
        result = []
        for v in vulnerabilities:
            cve = v.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")
            descs = cve.get("descriptions", [])
            desc = next(
                (d["value"] for d in descs if d.get("lang") == "en"),
                "No description available",
            )
            result.append({"id": cve_id, "description": desc[:1000]})
        return result
    except Exception:
        return []


def _ollama_generate(prompt: str, model: str = "qwen2.5:3b") -> str:
    base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    payload = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.5},
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


def _generate_cve_test(cve: dict, gateway_url: str, fn_name: str) -> str:
    """Ask LLM to generate a test verifying we're not vulnerable to a CVE."""
    prompt = textwrap.dedent(
        f"""\
        You are a security test engineer.

        Write a single pytest test function named `{fn_name}` that verifies
        the LegionForge gateway at {gateway_url} is NOT vulnerable to:

        {cve['id']}: {cve['description']}

        Rules:
        - Use httpx.Client (sync) with base_url="{gateway_url}"
        - Valid API key: "test-api-key" (Bearer auth)
        - The test should probe the specific vulnerability vector described
        - Assert that the attack fails (4xx response) or server behaves safely
        - Include all imports inside the function
        - Output ONLY the Python function — no markdown, no imports at module level

        Begin:
    """
    )
    return _ollama_generate(prompt)


# ── Collection and generation fixture ────────────────────────────────────────

_cve_tests: list[dict] = []  # {cve_id, fn_name, file_path}
_skip_reason: str | None = None


@pytest.fixture(scope="module", autouse=True)
def collect_cve_tests(gateway_server):
    """Fetch CVEs, generate tests, write to temp files."""
    global _cve_tests, _skip_reason

    if not _network_available():
        _skip_reason = "NVD API not reachable (no network)"
        yield
        return

    if not _ollama_available():
        _skip_reason = "Ollama not available"
        yield
        return

    _CVE_TMP_DIR.mkdir(exist_ok=True)
    gateway_url = gateway_server.base_url

    all_cves: list[dict] = []
    for keyword in _CVE_KEYWORDS:
        fetched = _fetch_cves(keyword, max_results=2)
        all_cves.extend(fetched)
        time.sleep(0.5)  # NVD rate limit: 5 req/30s without API key

    if not all_cves:
        _skip_reason = "No CVEs fetched from NVD"
        yield
        return

    # Deduplicate by CVE ID
    seen: set[str] = set()
    unique_cves = []
    for cve in all_cves:
        if cve["id"] not in seen:
            seen.add(cve["id"])
            unique_cves.append(cve)

    for i, cve in enumerate(unique_cves[:10]):  # Cap at 10 CVEs
        fn_name = f"test_cve_{cve['id'].replace('-', '_').lower()}"
        file_path = _CVE_TMP_DIR / f"test_cve_{i:02d}.py"

        try:
            code = _generate_cve_test(cve, gateway_url, fn_name)
            code = re.sub(r"^```(?:python)?\n?", "", code, flags=re.MULTILINE)
            code = re.sub(r"\n?```$", "", code, flags=re.MULTILINE)
            code = code.strip()
            file_path.write_text(code, encoding="utf-8")
            _cve_tests.append(
                {"cve_id": cve["id"], "fn_name": fn_name, "file_path": str(file_path)}
            )
        except Exception:
            continue  # Skip CVEs where generation fails

    yield

    # Cleanup
    try:
        import shutil

        shutil.rmtree(_CVE_TMP_DIR, ignore_errors=True)
    except Exception:
        pass


# ── Dynamic CVE test runner ───────────────────────────────────────────────────


def pytest_generate_tests(metafunc):
    """Dynamically parametrize test_cve_vulnerability with collected CVE tests."""
    if "cve_entry" in metafunc.fixturenames:
        if _cve_tests:
            metafunc.parametrize(
                "cve_entry",
                _cve_tests,
                ids=[c["cve_id"] for c in _cve_tests],
            )
        else:
            metafunc.parametrize("cve_entry", [None], ids=["no-cves"])


def test_cve_vulnerability(cve_entry, collect_cve_tests):
    """Run CVE-specific generated test via subprocess."""
    if _skip_reason:
        pytest.skip(_skip_reason)

    if cve_entry is None:
        pytest.skip("No CVE tests generated")

    fn_name = cve_entry["fn_name"]
    file_path = cve_entry["file_path"]
    cve_id = cve_entry["cve_id"]

    if not Path(file_path).exists():
        pytest.skip(f"Test file not found for {cve_id}")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            file_path,
            f"::{fn_name}",
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
            code = Path(file_path).read_text(encoding="utf-8")
        except Exception:
            code = ""

        append_finding(
            category="cve",
            test_name=fn_name,
            source_code=code,
            failure_reason=f"CVE: {cve_id}\n{failure_output}",
        )
        pytest.fail(f"CVE test FAILED for {cve_id}:\n{failure_output[:1000]}")
