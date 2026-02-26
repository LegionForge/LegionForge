#!/usr/bin/env python
"""
scripts/run_crystallizer.py
────────────────────────────
Run the Crystallizer agent for a specific candidate ID.

The Crystallizer generates a deterministic Python function + test suite from
a nominated crystallization candidate, then submits the package for Pre-HITL
analysis. The analyzer runs automatically after submission.

Usage:
    CANDIDATE_ID=cand_abc123def456 python scripts/run_crystallizer.py
    make run-crystallizer CANDIDATE_ID=cand_abc123def456

The CANDIDATE_ID is printed by the Observer after it nominates a candidate.
You can also find pending candidates at: GET /crystallization/candidates
(after make health-server).
"""

import asyncio
import os
import sys

# Ensure project root is on the path when run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CANDIDATE_ID = os.environ.get("CANDIDATE_ID", "")


async def main() -> None:
    if not CANDIDATE_ID:
        print("❌ CANDIDATE_ID env var is required.")
        print("   Usage: make run-crystallizer CANDIDATE_ID=cand_abc123def456")
        print(
            "   Find candidate IDs with: make run-observer (or make pending-packages)"
        )
        sys.exit(1)

    print()
    print(f"  Crystallizing candidate: {CANDIDATE_ID}")
    print()

    from src.database import init_db
    from src.agents.crystallizer import run_crystallizer, register_crystallizer_tools

    await init_db()
    await register_crystallizer_tools()
    result = await run_crystallizer(candidate_id=CANDIDATE_ID)

    print("─── Crystallizer Result ──────────────────────────────────────")
    print(result.get("result") or "(no result)")
    print()
    packages = result.get("packages_created", [])
    print(
        f"Steps: {result.get('steps', '?')}  |  "
        f"Errors: {result.get('errors', '?')}  |  "
        f"Tokens: {result.get('tokens', '?')}  |  "
        f"Packages submitted: {len(packages)}"
    )
    if packages:
        print("Package IDs:")
        for pid in packages:
            print(f"  {pid}")
        print()
        print("Next steps:")
        print("  • Check analysis:  make pending-packages")
        print("  • Approve:         make approve-package PACKAGE_ID=<id>")
        print("  • Reject:          make reject-package PACKAGE_ID=<id>")
    print()


if __name__ == "__main__":
    asyncio.run(main())
