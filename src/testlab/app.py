"""
src/testlab/app.py
──────────────────
LegionForge TestLab — an admin-gated web interface for running, editing,
and AI-generating tests against the full LegionForge test suite.

Features
────────
  • Run any test suite (smoke, integration, UI, security, pentest) in real-time
    with SSE-streamed pytest output
  • Browse and edit test files through a Monaco-powered code editor
  • Use the configured LLM to generate new tests for any module and auto-append
    them to the appropriate test file
  • JWT-gated — only users with the admin API key (legionforge_health Keychain
    item) can access this service
  • Runs standalone on :8090 (separate from the main gateway on :8080)

Endpoints
─────────
  GET  /             → TestLab web UI
  GET  /health       → {"status": "ok"}
  GET  /suites       → list of available test suites
  POST /run          → start a test run (SSE stream of pytest output)
  GET  /files        → list of test files
  GET  /files/{path} → read a test file
  PUT  /files/{path} → write a test file
  POST /generate     → ask LLM to generate new tests for a given module
  GET  /history      → list of past runs (last 50, in-process only)
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

# Novel findings support
_NOVEL_FINDINGS_FILE = _TESTS_DIR / "testlab_suite" / "novel_findings.json"

# ── Project root (two levels up from this file) ───────────────────────────────
_ROOT = Path(__file__).parent.parent.parent
_TESTS_DIR = _ROOT / "tests"
_STATIC = Path(__file__).parent / "static"

# ── Auth ──────────────────────────────────────────────────────────────────────
_ADMIN_KEY: str | None = None


def _load_admin_key() -> str:
    """Load admin key from Keychain or TESTLAB_ADMIN_KEY env var."""
    global _ADMIN_KEY
    if _ADMIN_KEY:
        return _ADMIN_KEY
    # Try env var first (Docker / CI)
    env_key = os.environ.get("TESTLAB_ADMIN_KEY", "").strip()
    if env_key:
        _ADMIN_KEY = env_key
        return _ADMIN_KEY
    # Try Keychain
    try:
        import keyring

        key = keyring.get_password("legionforge_health", "api_key") or ""
        if key:
            _ADMIN_KEY = key
            return _ADMIN_KEY
    except Exception:
        pass
    raise RuntimeError(
        "No admin key found. Set TESTLAB_ADMIN_KEY env var or populate "
        "'legionforge_health' Keychain item."
    )


_bearer = HTTPBearer(auto_error=False)


async def require_admin(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> None:
    try:
        admin_key = _load_admin_key()
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    if creds is None or creds.credentials != admin_key:
        raise HTTPException(status_code=401, detail="Admin key required")


# ── In-process run history (last 50) ─────────────────────────────────────────
_run_history: list[dict] = []
_MAX_HISTORY = 50


def _record_run(run_id: str, suite: str, status: str, output: str, elapsed: float):
    _run_history.insert(
        0,
        {
            "run_id": run_id,
            "suite": suite,
            "status": status,
            "output_tail": output[-2000:],
            "elapsed_seconds": round(elapsed, 2),
            "ts": datetime.now(timezone.utc).isoformat(),
        },
    )
    if len(_run_history) > _MAX_HISTORY:
        _run_history.pop()


# ── Test suite definitions ────────────────────────────────────────────────────
SUITES: dict[str, dict] = {
    "smoke": {
        "label": "Smoke Tests",
        "description": "497 fast tests, no services required (~21s)",
        "cmd": ["python", "-m", "pytest", "tests/test_smoke.py", "-v", "--tb=short"],
    },
    "ui": {
        "label": "UI Tests",
        "description": "40 Playwright browser tests, no services required (~6s)",
        "cmd": [
            "python",
            "-m",
            "pytest",
            "tests/ui/",
            "-v",
            "-m",
            "ui",
            "--tb=short",
        ],
    },
    "integration": {
        "label": "Integration Tests",
        "description": "38 tests requiring PostgreSQL",
        "cmd": [
            "python",
            "-m",
            "pytest",
            "tests/test_integration.py",
            "-v",
            "-m",
            "integration",
            "--tb=short",
        ],
    },
    "security": {
        "label": "Security Audit",
        "description": "Smoke tests + bandit static analysis + URI scan",
        "cmd": ["make", "-C", str(_ROOT), "security-audit"],
    },
    "pentest": {
        "label": "Pentest Suite",
        "description": "PentestAgent red-team (stop-at-proof mode, requires Docker + PostgreSQL)",
        "cmd": ["make", "-C", str(_ROOT), "pentest"],
    },
    "all": {
        "label": "Full Suite",
        "description": "Smoke + UI tests (fast, no services)",
        "cmd": [
            "python",
            "-m",
            "pytest",
            "tests/test_smoke.py",
            "tests/ui/",
            "-v",
            "--tb=short",
        ],
    },
    # ── TestLab Attack Suite (Phase 19) ───────────────────────────
    "functional": {
        "label": "Functional Tests",
        "description": "25 standard usage tests — mock gateway, no services",
        "cmd": [
            "python",
            "-m",
            "pytest",
            "tests/testlab_suite/test_functional.py",
            "-v",
            "-m",
            "functional",
            "--tb=short",
        ],
    },
    "security_attacks": {
        "label": "Security Attacks",
        "description": "35 attack tests — injection, session, MITM, protocol",
        "cmd": [
            "python",
            "-m",
            "pytest",
            "tests/testlab_suite/test_security_attacks.py",
            "-v",
            "-m",
            "security",
            "--tb=short",
        ],
    },
    "dos": {
        "label": "DOS Resilience",
        "description": "15 denial-of-service resilience tests",
        "cmd": [
            "python",
            "-m",
            "pytest",
            "tests/testlab_suite/test_dos.py",
            "-v",
            "-m",
            "dos",
            "--tb=short",
        ],
    },
    "auth_attacks": {
        "label": "Auth Attacks",
        "description": "20 authentication attack tests",
        "cmd": [
            "python",
            "-m",
            "pytest",
            "tests/testlab_suite/test_auth_attacks.py",
            "-v",
            "-m",
            "auth_attack",
            "--tb=short",
        ],
    },
    "data_attacks": {
        "label": "Data Attacks",
        "description": "15 data exfiltration and PII leak tests",
        "cmd": [
            "python",
            "-m",
            "pytest",
            "tests/testlab_suite/test_data_attacks.py",
            "-v",
            "-m",
            "data_attack",
            "--tb=short",
        ],
    },
    "novel_general": {
        "label": "Novel (LLM General)",
        "description": "5 LLM-generated general tests — requires Ollama",
        "cmd": [
            "python",
            "-m",
            "pytest",
            "tests/testlab_suite/test_novel_llm.py",
            "-v",
            "-m",
            "novel",
            "--tb=short",
        ],
    },
    "novel_security": {
        "label": "Novel (LLM Security)",
        "description": "10 LLM-generated security tests — requires Ollama",
        "cmd": [
            "python",
            "-m",
            "pytest",
            "tests/testlab_suite/test_novel_security.py",
            "-v",
            "-m",
            "novel_security",
            "--tb=short",
        ],
    },
    "cve": {
        "label": "CVE Tests",
        "description": "NVD CVE-based tests — requires network + Ollama",
        "cmd": [
            "python",
            "-m",
            "pytest",
            "tests/testlab_suite/test_cve.py",
            "-v",
            "-m",
            "cve",
            "--tb=short",
        ],
    },
    "testlab_all": {
        "label": "All Attack Suites",
        "description": "All 110+ testlab_suite tests (functional + attacks + resilience)",
        "cmd": [
            "python",
            "-m",
            "pytest",
            "tests/testlab_suite/",
            "-v",
            "--tb=short",
            "--ignore=tests/testlab_suite/test_novel_llm.py",
            "--ignore=tests/testlab_suite/test_novel_security.py",
            "--ignore=tests/testlab_suite/test_cve.py",
        ],
    },
}

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(title="LegionForge TestLab", version="1.0.0")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "testlab"}


@app.get("/")
async def index():
    return FileResponse(str(_STATIC / "index.html"), media_type="text/html")


# ── Suite list ────────────────────────────────────────────────────────────────


@app.get("/suites", dependencies=[Depends(require_admin)])
async def list_suites():
    return [
        {"id": k, "label": v["label"], "description": v["description"]}
        for k, v in SUITES.items()
    ]


# ── Run a test suite ──────────────────────────────────────────────────────────


class RunRequest(BaseModel):
    suite: str
    extra_args: list[str] = []


@app.post("/run", dependencies=[Depends(require_admin)])
async def run_suite(req: RunRequest, request: Request):
    if req.suite not in SUITES:
        raise HTTPException(status_code=400, detail=f"Unknown suite: {req.suite}")

    suite_def = SUITES[req.suite]
    cmd = suite_def["cmd"] + req.extra_args
    run_id = str(uuid.uuid4())[:8]

    async def event_generator():
        yield {
            "event": "run_start",
            "data": json.dumps(
                {
                    "run_id": run_id,
                    "suite": req.suite,
                    "cmd": " ".join(cmd),
                }
            ),
        }

        t0 = time.monotonic()
        full_output: list[str] = []

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(_ROOT),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, "PYTHONUNBUFFERED": "1", "FORCE_COLOR": "0"},
        )

        assert proc.stdout is not None
        async for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace")
            full_output.append(line)
            yield {"event": "output", "data": json.dumps({"line": line})}
            # Respect client disconnect
            if await request.is_disconnected():
                proc.kill()
                break

        await proc.wait()
        elapsed = time.monotonic() - t0
        status = "passed" if proc.returncode == 0 else "failed"
        _record_run(run_id, req.suite, status, "".join(full_output), elapsed)

        yield {
            "event": "run_end",
            "data": json.dumps(
                {
                    "run_id": run_id,
                    "returncode": proc.returncode,
                    "status": status,
                    "elapsed_seconds": round(elapsed, 2),
                }
            ),
        }

    return EventSourceResponse(event_generator())


# ── File browser ──────────────────────────────────────────────────────────────

_ALLOWED_DIRS = [_TESTS_DIR]
_ALLOWED_EXTENSIONS = {".py"}


def _safe_path(rel: str) -> Path:
    """Resolve a relative path under tests/ and validate it's safe."""
    try:
        p = (_TESTS_DIR / rel).resolve()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid path")
    # Must stay inside tests/
    if not str(p).startswith(str(_TESTS_DIR)):
        raise HTTPException(status_code=403, detail="Path outside tests/")
    if p.suffix not in _ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Only .py files are allowed")
    return p


@app.get("/files", dependencies=[Depends(require_admin)])
async def list_files():
    """Return a tree of all .py test files."""
    files = []
    for f in sorted(_TESTS_DIR.rglob("*.py")):
        rel = str(f.relative_to(_TESTS_DIR))
        files.append({"path": rel, "size": f.stat().st_size})
    return files


@app.get("/files/{file_path:path}", dependencies=[Depends(require_admin)])
async def read_file(file_path: str):
    p = _safe_path(file_path)
    if not p.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return {"path": file_path, "content": p.read_text(encoding="utf-8")}


class WriteRequest(BaseModel):
    content: str


@app.put("/files/{file_path:path}", dependencies=[Depends(require_admin)])
async def write_file(file_path: str, req: WriteRequest):
    p = _safe_path(file_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(req.content, encoding="utf-8")
    return {"path": file_path, "size": p.stat().st_size, "status": "saved"}


# ── LLM test generation ───────────────────────────────────────────────────────


class GenerateRequest(BaseModel):
    module_path: str  # e.g. "src.gateway.events"
    description: str  # natural-language description of what to test
    target_file: str  # relative path under tests/ (e.g. "test_smoke.py")
    append: bool = True  # if True, append to target_file; else return only


@app.post("/generate", dependencies=[Depends(require_admin)])
async def generate_tests(req: GenerateRequest):
    """Use the LLM to generate pytest tests for a given module."""
    try:
        from src.llm_factory import get_llm
        from langchain_core.messages import HumanMessage
    except ImportError as e:
        raise HTTPException(status_code=503, detail=f"LLM not available: {e}")

    # Build a focused prompt
    src_path = _ROOT / req.module_path.replace(".", "/")
    for ext in [".py", "/__init__.py"]:
        candidate = Path(str(src_path) + ext)
        if candidate.exists():
            source_snippet = candidate.read_text()[:4000]
            break
    else:
        source_snippet = "(source not found — generate based on module description)"

    prompt = f"""You are a Python test engineer for LegionForge, a security-native AI agent framework.

Generate 3–5 pytest test functions for the module `{req.module_path}`.

Requirement: {req.description}

Module source (truncated to 4000 chars):
```python
{source_snippet}
```

Rules:
- Use `pytest` only (no unittest)
- Tests must be self-contained — no external services required unless marked @pytest.mark.integration
- Import directly from `{req.module_path}`
- Each function name must start with `test_`
- Include a one-line docstring per test
- For security controls: always include BOTH a positive (attack succeeds) and negative (defense holds) test
- Output ONLY the Python test code — no markdown fences, no explanation

Begin:"""

    try:
        llm = get_llm("base_agent")
        response = await llm.ainvoke([HumanMessage(content=prompt)])
        generated = response.content.strip()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM error: {e}")

    # Strip any markdown fences if LLM added them anyway
    generated = re.sub(r"^```(?:python)?\n?", "", generated, flags=re.MULTILINE)
    generated = re.sub(r"\n?```$", "", generated, flags=re.MULTILINE)
    generated = generated.strip()

    result: dict[str, Any] = {
        "module": req.module_path,
        "generated": generated,
        "appended": False,
        "target_file": req.target_file,
    }

    if req.append and req.target_file:
        target = _safe_path(req.target_file)
        if target.exists():
            existing = target.read_text(encoding="utf-8")
            separator = (
                f"\n\n\n# ── LLM-generated tests for {req.module_path}"
                f" ({datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}) ──\n\n"
            )
            target.write_text(existing + separator + generated + "\n", encoding="utf-8")
            result["appended"] = True

    return result


# ── Run history ───────────────────────────────────────────────────────────────


@app.get("/history", dependencies=[Depends(require_admin)])
async def run_history():
    return _run_history


# ── Test collection & individual run ─────────────────────────────────────────


@app.get("/tests", dependencies=[Depends(require_admin)])
async def list_tests():
    """List all collected tests grouped by category, using pytest --collect-only."""
    categories = {
        "functional": "tests/testlab_suite/test_functional.py",
        "security_attacks": "tests/testlab_suite/test_security_attacks.py",
        "dos": "tests/testlab_suite/test_dos.py",
        "auth_attacks": "tests/testlab_suite/test_auth_attacks.py",
        "data_attacks": "tests/testlab_suite/test_data_attacks.py",
    }
    result: dict[str, list[str]] = {}
    for category, path in categories.items():
        proc = await asyncio.create_subprocess_exec(
            "python",
            "-m",
            "pytest",
            path,
            "--collect-only",
            "-q",
            "--no-header",
            cwd=str(_ROOT),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        lines = stdout.decode("utf-8", errors="replace").splitlines()
        tests = [
            line.strip()
            for line in lines
            if "::" in line and not line.startswith("ERROR")
        ]
        result[category] = tests
    return result


class SingleTestRequest(BaseModel):
    test_node: (
        str  # e.g. "tests/testlab_suite/test_security_attacks.py::test_sql_injection"
    )


@app.post("/run/test", dependencies=[Depends(require_admin)])
async def run_single_test(req: SingleTestRequest, request: Request):
    """Run a single test by its pytest node ID (SSE stream of output)."""
    # Validate node path is within tests/testlab_suite/
    node = req.test_node
    if not node.startswith("tests/testlab_suite/") and not node.startswith("tests/"):
        raise HTTPException(status_code=400, detail="test_node must be within tests/")

    cmd = ["python", "-m", "pytest", node, "-v", "--tb=short"]
    run_id = str(uuid.uuid4())[:8]

    async def event_generator():
        yield {
            "event": "run_start",
            "data": json.dumps({"run_id": run_id, "test_node": node}),
        }
        t0 = time.monotonic()
        full_output: list[str] = []

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(_ROOT),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, "PYTHONUNBUFFERED": "1", "FORCE_COLOR": "0"},
        )
        assert proc.stdout is not None
        async for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace")
            full_output.append(line)
            yield {"event": "output", "data": json.dumps({"line": line})}
            if await request.is_disconnected():
                proc.kill()
                break

        await proc.wait()
        elapsed = time.monotonic() - t0
        status = "passed" if proc.returncode == 0 else "failed"
        _record_run(run_id, node, status, "".join(full_output), elapsed)
        yield {
            "event": "run_end",
            "data": json.dumps(
                {
                    "run_id": run_id,
                    "returncode": proc.returncode,
                    "status": status,
                    "elapsed_seconds": round(elapsed, 2),
                }
            ),
        }

    return EventSourceResponse(event_generator())


class CategoryRunRequest(BaseModel):
    category: str
    filter: str = ""  # optional substring filter on test names


@app.post("/run/category", dependencies=[Depends(require_admin)])
async def run_category(req: CategoryRunRequest, request: Request):
    """Run a test category with optional keyword filter."""
    if req.category not in SUITES:
        raise HTTPException(status_code=400, detail=f"Unknown category: {req.category}")

    cmd = list(SUITES[req.category]["cmd"])
    if req.filter:
        cmd += ["-k", req.filter]

    run_id = str(uuid.uuid4())[:8]

    async def event_generator():
        yield {
            "event": "run_start",
            "data": json.dumps(
                {"run_id": run_id, "category": req.category, "filter": req.filter}
            ),
        }
        t0 = time.monotonic()
        full_output: list[str] = []

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(_ROOT),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, "PYTHONUNBUFFERED": "1", "FORCE_COLOR": "0"},
        )
        assert proc.stdout is not None
        async for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace")
            full_output.append(line)
            yield {"event": "output", "data": json.dumps({"line": line})}
            if await request.is_disconnected():
                proc.kill()
                break

        await proc.wait()
        elapsed = time.monotonic() - t0
        status = "passed" if proc.returncode == 0 else "failed"
        _record_run(run_id, req.category, status, "".join(full_output), elapsed)
        yield {
            "event": "run_end",
            "data": json.dumps(
                {
                    "run_id": run_id,
                    "returncode": proc.returncode,
                    "status": status,
                    "elapsed_seconds": round(elapsed, 2),
                }
            ),
        }

    return EventSourceResponse(event_generator())


# ── Novel LLM test generation triggers ───────────────────────────────────────


@app.post("/generate/llm-general", dependencies=[Depends(require_admin)])
async def generate_llm_general(request: Request):
    """Trigger generation of 5 LLM general tests (SSE streamed run)."""
    cmd = [
        "python",
        "-m",
        "pytest",
        "tests/testlab_suite/test_novel_llm.py",
        "-v",
        "--tb=short",
    ]
    run_id = str(uuid.uuid4())[:8]

    async def event_generator():
        yield {
            "event": "run_start",
            "data": json.dumps({"run_id": run_id, "type": "llm-general"}),
        }
        t0 = time.monotonic()
        full_output: list[str] = []
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(_ROOT),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, "PYTHONUNBUFFERED": "1", "FORCE_COLOR": "0"},
        )
        assert proc.stdout is not None
        async for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace")
            full_output.append(line)
            yield {"event": "output", "data": json.dumps({"line": line})}
            if await request.is_disconnected():
                proc.kill()
                break
        await proc.wait()
        elapsed = time.monotonic() - t0
        status = "passed" if proc.returncode == 0 else "failed"
        _record_run(run_id, "novel_general", status, "".join(full_output), elapsed)
        yield {
            "event": "run_end",
            "data": json.dumps(
                {
                    "run_id": run_id,
                    "status": status,
                    "elapsed_seconds": round(elapsed, 2),
                }
            ),
        }

    return EventSourceResponse(event_generator())


@app.post("/generate/llm-security", dependencies=[Depends(require_admin)])
async def generate_llm_security(request: Request):
    """Trigger generation of 10 LLM security tests (SSE streamed run)."""
    cmd = [
        "python",
        "-m",
        "pytest",
        "tests/testlab_suite/test_novel_security.py",
        "-v",
        "--tb=short",
    ]
    run_id = str(uuid.uuid4())[:8]

    async def event_generator():
        yield {
            "event": "run_start",
            "data": json.dumps({"run_id": run_id, "type": "llm-security"}),
        }
        t0 = time.monotonic()
        full_output: list[str] = []
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(_ROOT),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, "PYTHONUNBUFFERED": "1", "FORCE_COLOR": "0"},
        )
        assert proc.stdout is not None
        async for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace")
            full_output.append(line)
            yield {"event": "output", "data": json.dumps({"line": line})}
            if await request.is_disconnected():
                proc.kill()
                break
        await proc.wait()
        elapsed = time.monotonic() - t0
        status = "passed" if proc.returncode == 0 else "failed"
        _record_run(run_id, "novel_security", status, "".join(full_output), elapsed)
        yield {
            "event": "run_end",
            "data": json.dumps(
                {
                    "run_id": run_id,
                    "status": status,
                    "elapsed_seconds": round(elapsed, 2),
                }
            ),
        }

    return EventSourceResponse(event_generator())


@app.post("/generate/cve", dependencies=[Depends(require_admin)])
async def generate_cve_tests(request: Request):
    """Fetch CVEs and generate CVE-based tests (SSE streamed run)."""
    cmd = [
        "python",
        "-m",
        "pytest",
        "tests/testlab_suite/test_cve.py",
        "-v",
        "--tb=short",
    ]
    run_id = str(uuid.uuid4())[:8]

    async def event_generator():
        yield {
            "event": "run_start",
            "data": json.dumps({"run_id": run_id, "type": "cve"}),
        }
        t0 = time.monotonic()
        full_output: list[str] = []
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(_ROOT),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, "PYTHONUNBUFFERED": "1", "FORCE_COLOR": "0"},
        )
        assert proc.stdout is not None
        async for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace")
            full_output.append(line)
            yield {"event": "output", "data": json.dumps({"line": line})}
            if await request.is_disconnected():
                proc.kill()
                break
        await proc.wait()
        elapsed = time.monotonic() - t0
        status = "passed" if proc.returncode == 0 else "failed"
        _record_run(run_id, "cve", status, "".join(full_output), elapsed)
        yield {
            "event": "run_end",
            "data": json.dumps(
                {
                    "run_id": run_id,
                    "status": status,
                    "elapsed_seconds": round(elapsed, 2),
                }
            ),
        }

    return EventSourceResponse(event_generator())


# ── Novel findings ────────────────────────────────────────────────────────────


@app.get("/novel", dependencies=[Depends(require_admin)])
async def list_novel_findings():
    """List all novel findings from novel_findings.json."""
    if not _NOVEL_FINDINGS_FILE.exists():
        return []
    try:
        return json.loads(_NOVEL_FINDINGS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


class PromoteRequest(BaseModel):
    target_file: str  # relative path under tests/ (e.g. "testlab_suite/test_security_attacks.py")


@app.put("/novel/{finding_id}/promote", dependencies=[Depends(require_admin)])
async def promote_novel_finding(finding_id: str, req: PromoteRequest):
    """Copy a novel finding's source code into a permanent test file."""
    target = _safe_path(req.target_file)
    if not _NOVEL_FINDINGS_FILE.exists():
        raise HTTPException(status_code=404, detail="No findings file")

    try:
        findings = json.loads(_NOVEL_FINDINGS_FILE.read_text(encoding="utf-8"))
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to read findings")

    finding = next((f for f in findings if f["id"] == finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    if finding.get("promoted"):
        return {"status": "already_promoted", "id": finding_id}

    existing = target.read_text(encoding="utf-8") if target.exists() else ""
    separator = f"\n\n\n# ── Promoted novel finding: {finding['test_name']} ({finding['ts']}) ──\n\n"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        existing + separator + finding["source_code"] + "\n", encoding="utf-8"
    )

    finding["promoted"] = True
    _NOVEL_FINDINGS_FILE.write_text(
        json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    return {"status": "promoted", "id": finding_id, "target": req.target_file}
