#!/usr/bin/env python
"""
scripts/run_researcher.py
─────────────────────────
Run the Researcher agent with a task from the command line.

Usage:
    python scripts/run_researcher.py "What is LangGraph?"
    make run-researcher
    make run-researcher TASK="Explain pgvector in two sentences"
"""

import asyncio
import sys
import os

# Ensure project root is on the path when run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


async def main() -> None:
    task = (
        " ".join(sys.argv[1:])
        if len(sys.argv) > 1
        else (
            "What is LangGraph and how does it relate to LangChain? Give a brief summary."
        )
    )

    print()
    print(f"  Task : {task}")
    print()

    from src.database import init_db
    from src.agents.researcher import run_researcher, register_researcher_tools

    await init_db()
    # Populate the in-memory tool registry for this process
    await register_researcher_tools()
    result = await run_researcher(task=task, tracing_enabled=False)

    print("─── Result ───────────────────────────────────────────────────")
    print(result.get("result") or "(no result)")
    print()
    sources = result.get("sources", [])
    print(
        f"Steps: {result.get('steps', '?')}  |  "
        f"Errors: {result.get('errors', '?')}  |  "
        f"Tokens: {result.get('tokens', '?')}  |  "
        f"Sources: {len(sources)}"
    )
    if sources:
        print("Sources:")
        for s in sources[:5]:
            print(f"  {s}")
    print()


if __name__ == "__main__":
    asyncio.run(main())
