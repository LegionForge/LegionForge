#!/usr/bin/env python
"""
scripts/run_observer.py
───────────────────────
Run the Observer agent from the command line.

The Observer scans the audit_log for repeated AI tool-call patterns and
nominates candidates for crystallization. It is read-only and never generates code.

Usage:
    python scripts/run_observer.py
    make run-observer
    make run-observer OBSERVER_HOURS=72 OBSERVER_MIN_OCC=3
"""

import asyncio
import os
import sys

# Ensure project root is on the path when run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

OBSERVER_HOURS = int(os.environ.get("OBSERVER_HOURS", "168"))  # default: 1 week
OBSERVER_MIN_OCC = int(os.environ.get("OBSERVER_MIN_OCC", "3"))


async def main() -> None:
    print()
    print(
        f"  Scanning audit_log — last {OBSERVER_HOURS}h, min_occurrences={OBSERVER_MIN_OCC}"
    )
    print()

    from src.database import init_db
    from src.agents.observer import run_observer, register_observer_tools

    await init_db()
    await register_observer_tools()
    result = await run_observer(hours=OBSERVER_HOURS, min_occurrences=OBSERVER_MIN_OCC)

    print("─── Observer Result ──────────────────────────────────────────")
    print(result.get("result") or "(no result)")
    print()
    nominated = result.get("candidates_nominated", [])
    print(
        f"Steps: {result.get('steps', '?')}  |  "
        f"Errors: {result.get('errors', '?')}  |  "
        f"Tokens: {result.get('tokens', '?')}  |  "
        f"Candidates nominated: {len(nominated)}"
    )
    if nominated:
        print("Nominated candidate IDs:")
        for cid in nominated:
            print(f"  {cid}")
        print()
        print("Next step:  make run-crystallizer CANDIDATE_ID=<id>")
    print()


if __name__ == "__main__":
    asyncio.run(main())
