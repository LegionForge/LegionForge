"""
tests/gateway_client/config.py
────────────────────────────────
Runtime configuration loaded from environment variables.

All env vars have safe defaults so the client works with minimal setup.
Set GATEWAY_API_KEY (and optionally GATEWAY_API_KEY_2) before running.
"""

from __future__ import annotations

import os

# ── Gateway target ────────────────────────────────────────────────────────────

GATEWAY_URL: str = os.environ.get("GATEWAY_URL", "http://localhost:8080").rstrip("/")

# ── Auth credentials ──────────────────────────────────────────────────────────

# Primary API key — used for all authenticated requests.
# Must be a valid key in the gateway_users table.
# Create with:  make create-user USERNAME=testclient
GATEWAY_API_KEY: str = os.environ.get("GATEWAY_API_KEY", "")

# Second API key for cross-user isolation tests.
# If not set, cross-user tests are skipped gracefully.
GATEWAY_API_KEY_2: str = os.environ.get("GATEWAY_API_KEY_2", "")

# A key that will never exist — for 401 tests.
BAD_API_KEY: str = "INVALID-KEY-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# ── Suite selection ───────────────────────────────────────────────────────────

# Comma-separated list of suites to run.
# Values: basic, load, pentest, injection
# "all" (default) runs all four suites.
SUITE: str = os.environ.get("SUITE", "all").lower()

# ── Load suite tuning ─────────────────────────────────────────────────────────

# Concurrency level for load tests (default: 20).
LOAD_CONCURRENCY: int = int(os.environ.get("LOAD_CONCURRENCY", "20"))

# Number of iterations for repeated-request tests (default: 50).
LOAD_ITERATIONS: int = int(os.environ.get("LOAD_ITERATIONS", "50"))

# P95 response-time SLA for /health (milliseconds, default: 2000).
HEALTH_SLA_MS: int = int(os.environ.get("HEALTH_SLA_MS", "2000"))

# ── Output format ─────────────────────────────────────────────────────────────

# "terminal" — ANSI-colored pass/fail table (default)
# "json"     — machine-readable JSON to stdout
REPORT_FORMAT: str = os.environ.get("REPORT_FORMAT", "terminal").lower()

# Exit with non-zero status if any test fails (default: true).
FAIL_FAST: bool = os.environ.get("FAIL_FAST", "false").lower() == "true"


def validate() -> list[str]:
    """Return list of configuration warnings (non-fatal)."""
    warnings: list[str] = []
    if not GATEWAY_API_KEY:
        warnings.append(
            "GATEWAY_API_KEY is not set — authenticated tests will be skipped. "
            "Create a test user:  make create-user USERNAME=testclient"
        )
    if not GATEWAY_API_KEY_2:
        warnings.append(
            "GATEWAY_API_KEY_2 not set — cross-user isolation tests will be skipped."
        )
    return warnings
