"""
src/agents/fan_out.py
─────────────────────
Phase 9 parallel sub-agent fan-out engine.

Dispatches a batch of SubTask objects to sub-agents concurrently via
asyncio.gather(), with per-branch JWT token derivation and structured
result collection.

Security model:
  - Each branch receives a derived token (child ⊆ parent) via derive_task_token.
  - Semaphore caps concurrent branches (default: 5) to protect local Ollama.
  - Branch errors are isolated — one failure does not cancel siblings.
  - Results preserve input order regardless of completion order.

Usage:
    from src.agents.fan_out import SubTask, fan_out, aggregate_results

    tasks = [
        SubTask(task_id="branch_0", task="Summarize LangGraph docs",
                granted_tools=["web_fetch"], granted_data_classes=["public"]),
        SubTask(task_id="branch_1", task="Find LangChain changelog",
                granted_tools=["web_fetch"], granted_data_classes=["public"]),
    ]
    results = await fan_out(
        tasks, parent_jwt=master_token, run_id=run_id,
        agent_runner=my_async_runner,
    )
    summary = aggregate_results(results)
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Awaitable, Callable

logger = logging.getLogger(__name__)

# Hard cap: never run more than this many branches simultaneously,
# regardless of caller setting.  Protects local Ollama from resource storms.
_ABSOLUTE_MAX_CONCURRENCY = 10


# ── Data types ─────────────────────────────────────────────────────────────────


@dataclass
class SubTask:
    """Describes a single branch to dispatch in a fan-out."""

    task_id: str  # Unique within this fan-out (e.g. "branch_0")
    task: str  # Natural-language task for the sub-agent
    granted_tools: list[str]  # Tools the derived token will allow
    granted_data_classes: list[str]  # Data classes the derived token will allow


@dataclass
class SubTaskResult:
    """Result from a single fan-out branch."""

    task_id: str
    task: str
    result: str
    success: bool
    error: str | None = None
    duration_ms: float = 0.0


# ── Core fan-out ───────────────────────────────────────────────────────────────


async def fan_out(
    tasks: list[SubTask],
    parent_jwt: str | None,
    run_id: str,
    agent_runner: Callable[[str, str | None, str], Awaitable[dict]],
    max_concurrency: int = 5,
) -> list[SubTaskResult]:
    """
    Dispatch tasks to sub-agents in parallel via asyncio.gather().

    Args:
        tasks:           Batch of SubTask descriptors.
        parent_jwt:      Orchestrator's master JWT.  Each branch receives a
                         derived (narrower) child token.  None → unconstrained.
        run_id:          Parent run ID.  Branch IDs are "<run_id>:<task_id>".
        agent_runner:    Async callable: (task, token, branch_run_id) → dict.
                         Must return a dict with at least a 'result' key.
        max_concurrency: Max simultaneous branches (clamped to
                         _ABSOLUTE_MAX_CONCURRENCY).

    Returns:
        List of SubTaskResult in the same order as *tasks*.
        Branch errors are captured as SubTaskResult(success=False) — they
        do NOT raise; callers decide how to handle partial results.
    """
    if not tasks:
        return []

    cap = min(max(1, max_concurrency), _ABSOLUTE_MAX_CONCURRENCY)
    semaphore = asyncio.Semaphore(cap)

    logger.info(
        "[fan_out] Dispatching %d branches | concurrency=%d | run=%s",
        len(tasks),
        cap,
        run_id[:8],
    )

    async def _run_branch(sub_task: SubTask) -> SubTaskResult:
        async with semaphore:
            branch_run_id = f"{run_id}:{sub_task.task_id}"
            t0 = time.monotonic()
            try:
                derived_token = _derive_branch_token(
                    parent_jwt,
                    sub_task.granted_tools,
                    sub_task.granted_data_classes,
                )
                raw = await agent_runner(sub_task.task, derived_token, branch_run_id)
                result_text = (
                    raw.get("result", "") if isinstance(raw, dict) else str(raw)
                )
                return SubTaskResult(
                    task_id=sub_task.task_id,
                    task=sub_task.task,
                    result=result_text,
                    success=True,
                    duration_ms=(time.monotonic() - t0) * 1000,
                )
            except Exception as exc:
                logger.error("[fan_out] Branch %s failed: %s", sub_task.task_id, exc)
                return SubTaskResult(
                    task_id=sub_task.task_id,
                    task=sub_task.task,
                    result="",
                    success=False,
                    error=str(exc),
                    duration_ms=(time.monotonic() - t0) * 1000,
                )

    results = await asyncio.gather(*[_run_branch(t) for t in tasks])

    successes = sum(1 for r in results if r.success)
    logger.info(
        "[fan_out] Complete: %d/%d succeeded | run=%s",
        successes,
        len(tasks),
        run_id[:8],
    )
    return list(results)


# ── Result aggregation ─────────────────────────────────────────────────────────


def aggregate_results(results: list[SubTaskResult]) -> str:
    """
    Collapse SubTaskResult list into a human-readable summary for the
    orchestrator's message history.

    Format:
        Fan-out complete: N branches (M succeeded, K failed)

        [✓ branch_0] Task description...
          → Result snippet...

        [✗ branch_1] Task description...
          ERROR: <error message>
    """
    n = len(results)
    n_ok = sum(1 for r in results if r.success)
    n_fail = n - n_ok

    header = f"Fan-out complete: {n} branches"
    if n_fail:
        header += f" ({n_ok} succeeded, {n_fail} failed)"
    else:
        header += f" ({n_ok} succeeded)"

    lines: list[str] = [header]
    for r in results:
        mark = "✓" if r.success else "✗"
        label = f"[{mark} {r.task_id}] {r.task[:60]}"
        if r.success:
            snippet = r.result[:400].replace("\n", " ")
            lines.append(f"\n{label}\n  → {snippet}")
        else:
            lines.append(f"\n{label}\n  ERROR: {r.error}")

    return "\n".join(lines)


# ── Internal helpers ───────────────────────────────────────────────────────────


def _derive_branch_token(
    parent_jwt: str | None,
    granted_tools: list[str],
    granted_data_classes: list[str],
) -> str | None:
    """
    Derive a narrowed JWT for one branch from the parent token.
    Returns None if parent_jwt is None (unconstrained mode).
    Non-fatal on failure — logs a warning and returns None.
    """
    if parent_jwt is None:
        return None
    try:
        from src.security import derive_task_token

        return derive_task_token(
            parent_jwt=parent_jwt,
            granted_tools=granted_tools,
            granted_data_classes=granted_data_classes,
        )
    except Exception as exc:
        # nosemgrep: python-logger-credential-disclosure -- logs the exception only; "Token" is the operation name, not a value.
        logger.warning(
            "[fan_out] Token derivation failed for branch: %s",
            exc,
        )
        return None
