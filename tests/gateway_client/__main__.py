"""
tests/gateway_client/__main__.py
──────────────────────────────────
Entry point for the LegionForge gateway test client.

Usage (Docker):
  docker run --rm \\
    -e GATEWAY_URL=http://host.docker.internal:8080 \\
    -e GATEWAY_API_KEY=<your-key> \\
    legionforge-testclient [--suite SUITE] [--json]

Usage (local venv):
  python -m tests.gateway_client [--suite SUITE] [--json]

Suites:
  basic     — functional correctness (14 tests)
  load      — load / DOS resilience (8 tests)
  pentest   — authorized security verification (12 tests)
  injection — malicious input / injection detection (35+ tests)
  agent     — live agent quality: submit real queries, assert structure, save transcripts
  all       — all suites except agent (agent is opt-in: requires gateway + Ollama)

Environment variables (see config.py for full reference):
  GATEWAY_URL          — base URL of the gateway (default: http://localhost:8080)
  GATEWAY_API_KEY      — primary Bearer token (required)
  GATEWAY_API_KEY_2    — second user's key (optional; enables cross-user tests)
  SUITE                — which suite(s) to run (default: all)
  LOAD_CONCURRENCY     — concurrent requests in load suite (default: 20)
  LOAD_ITERATIONS      — rapid-auth-failure count (default: 50)
  HEALTH_SLA_MS        — P95 health SLA in milliseconds (default: 2000)
  REPORT_FORMAT        — "text" (default) or "json"
  FAIL_FAST            — "1" to stop after first suite failure
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from tests.gateway_client import config
from tests.gateway_client import (
    suite_basic,
    suite_load,
    suite_pentest,
    suite_injection,
    suite_agent_quality,
)
from tests.gateway_client.report import (
    SuiteResult,
    dump_json,
    print_grand_summary,
    print_result,
    print_suite_header,
    print_suite_summary,
)

_ALL_SUITES = {
    "basic": suite_basic.run,
    "load": suite_load.run,
    "pentest": suite_pentest.run,
    "injection": suite_injection.run,
    # agent suite is intentionally excluded from "all" — it requires a live
    # gateway + Ollama and takes several minutes.  Run explicitly with --suite agent.
    "agent": suite_agent_quality.run,
}

# Suites run by "all" — excludes agent (opt-in only)
_DEFAULT_SUITES = ["basic", "load", "pentest", "injection"]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="LegionForge gateway integration test client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--suite",
        default=config.SUITE,
        choices=[*_ALL_SUITES.keys(), "all"],
        help="Which test suite to run (default: %(default)s)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=(config.REPORT_FORMAT == "json"),
        help="Emit JSON report instead of ANSI terminal output",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        default=config.FAIL_FAST,
        help="Stop after first suite failure",
    )
    parser.add_argument(
        "--url",
        default=None,
        help=f"Override GATEWAY_URL (current: {config.GATEWAY_URL})",
    )
    return parser.parse_args()


async def _run_suite(name: str, runner) -> SuiteResult:
    return await runner()


async def main() -> int:
    args = _parse_args()

    if args.url:
        # Allow --url CLI override (useful for quick local overrides)
        import os

        os.environ["GATEWAY_URL"] = args.url

    if not config.GATEWAY_API_KEY:
        print(
            "ERROR: GATEWAY_API_KEY environment variable is not set.\n"
            "Set it to a valid gateway Bearer token and re-run.\n"
            "Example:\n"
            "  export GATEWAY_API_KEY=lf_your_key_here\n"
            "  python -m tests.gateway_client",
            file=sys.stderr,
        )
        return 2

    suites_to_run = _DEFAULT_SUITES if args.suite == "all" else [args.suite]

    all_results: list[SuiteResult] = []
    exit_code = 0

    for suite_name in suites_to_run:
        runner = _ALL_SUITES[suite_name]

        if not args.json:
            print_suite_header(suite_name)

        result = await _run_suite(suite_name, runner)
        all_results.append(result)

        if not args.json:
            for r in result.results:
                print_result(r)
            print_suite_summary(result)

        if not result.ok:
            exit_code = 1
            if args.fail_fast:
                break

    if args.json:
        print(dump_json(all_results))
    else:
        if len(all_results) > 1:
            print_grand_summary(all_results)

    return exit_code


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
