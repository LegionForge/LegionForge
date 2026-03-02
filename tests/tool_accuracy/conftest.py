"""
tests/tool_accuracy/conftest.py
────────────────────────────────
Fixtures for the tool accuracy and anti-hallucination test suites.

The `verification_server` fixture starts a lightweight HTTP server once per
session on a random port.  Every route serves content that was generated
fresh at fixture construction time (UUIDs, hex tokens) — values the LLM
cannot have memorised.  If those values appear in agent output, the tool was
actually called.
"""

import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


@pytest.fixture(scope="session")
def verification_server():
    """
    Start a one-shot verification HTTP server on a random loopback port.

    Yields a dict with:
        base_url   - http://127.0.0.1:<port>
        port       - int
        token      - UUID str served at /token
        headlines  - list[str] of 5 hex-token headlines at /news
        session_id - UUID str inside the JSON at /data.json
        json_payload - full dict at /data.json
    """
    token = str(uuid.uuid4())
    headlines = [
        f"{uuid.uuid4().hex[:6].upper()}-{uuid.uuid4().hex[:8].upper()}"
        for _ in range(5)
    ]
    session_id = str(uuid.uuid4())
    json_payload: dict = {"session_id": session_id, "token": token, "ts": time.time()}

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/token":
                self._send(200, "text/plain", token)
            elif self.path == "/news":
                html = (
                    "<html><body>"
                    + "".join(f"<h2>{h}</h2>" for h in headlines)
                    + "</body></html>"
                )
                self._send(200, "text/html", html)
            elif self.path == "/data.json":
                self._send(200, "application/json", json.dumps(json_payload))
            elif self.path == "/large":
                self._send(200, "text/plain", "X" * 15_000)
            elif self.path == "/slow":
                time.sleep(3)
                self._send(200, "text/plain", "slow-response")
            elif self.path == "/redirect":
                self.send_response(301)
                self.send_header("Location", "/token")
                self.end_headers()
            elif self.path == "/not-here":
                self._send(404, "text/plain", "Not Found")
            else:
                self._send(404, "text/plain", "Unknown path")

        def _send(self, code: int, ct: str, body: str) -> None:
            enc = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(enc)))
            self.end_headers()
            self.wfile.write(enc)

        def log_message(self, *args) -> None:  # silence access log
            pass

    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    yield {
        "base_url": f"http://127.0.0.1:{port}",
        "port": port,
        "token": token,
        "headlines": headlines,
        "session_id": session_id,
        "json_payload": json_payload,
    }

    srv.shutdown()


# ── Service availability helpers (evaluated at collection time) ───────────────


def _ollama_available() -> bool:
    try:
        import os

        import httpx

        url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
        return httpx.get(f"{url}/api/tags", timeout=2.0).status_code == 200
    except Exception:
        return False


def _postgres_available() -> bool:
    try:
        import subprocess

        r = subprocess.run(
            ["psql", "-U", "legionforge", "-d", "legionforge", "-c", "SELECT 1"],
            capture_output=True,
            timeout=3,
        )
        return r.returncode == 0
    except Exception:
        return False


requires_llm_stack = pytest.mark.skipif(
    not (_ollama_available() and _postgres_available()),
    reason="Requires Ollama (localhost:11434) + PostgreSQL (legionforge DB)",
)
