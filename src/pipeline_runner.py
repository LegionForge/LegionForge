"""
src/pipeline_runner.py
────────────────────────
Sequential task pipeline executor for Phase 27.

Runs pipeline steps one at a time, templating each step's ``task_text``
with the initial input and results from completed steps, then polls the
task queue until each step finishes.

Template syntax
───────────────
    {{input}}           — the initial input string provided at run time
    {{step_0.result}}   — the result text of step 0 (0-indexed)
    {{step_1.result}}   — step 1 result, etc.

Any unresolved template variable (e.g. {{step_5.result}} when only 3 steps
have run) is left as-is and logged as a warning.

Usage (called from the pipelines gateway route as a background task):
    asyncio.create_task(
        execute_pipeline(pipeline_id, run_id, user_id, pipeline_def, initial_input)
    )
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Maximum time to wait for a single task step to complete (seconds)
_STEP_TIMEOUT = 600.0  # 10 minutes
_POLL_INTERVAL = 2.0  # seconds between status polls

# Template variable pattern: {{input}} or {{step_N.result}}
_TEMPLATE_RE = re.compile(r"\{\{(input|step_(\d+)\.result)\}\}")


def render_template(
    text: str,
    initial_input: str,
    step_results: list[dict[str, Any]],
) -> str:
    """
    Replace template variables in ``text`` with resolved values.

    Variables:
        {{input}}         → initial_input
        {{step_N.result}} → step_results[N]["result"] (or left as-is if missing)

    Args:
        text:          Template string from the pipeline step definition.
        initial_input: The initial input provided when the run started.
        step_results:  List of step result dicts from completed steps.

    Returns:
        Rendered string with all resolvable variables substituted.
    """

    def replace(m: re.Match) -> str:  # type: ignore[type-arg]
        var = m.group(1)
        if var == "input":
            return initial_input
        # {{step_N.result}}
        idx = int(m.group(2))
        if idx < len(step_results):
            return step_results[idx].get("result", "") or ""
        logger.warning("Pipeline template: step_%d not yet available", idx)
        return m.group(0)  # leave unresolved

    return _TEMPLATE_RE.sub(replace, text)


async def _wait_for_task(task_id: str, timeout: float = _STEP_TIMEOUT) -> dict:
    """
    Poll the task status until it reaches a terminal state.

    Returns the task row dict (status, result, error).
    Raises ``TimeoutError`` if the step does not complete within ``timeout`` seconds.
    Raises ``RuntimeError`` if the task reaches 'failed' or 'cancelled' state.
    """
    from src.database import get_task

    elapsed = 0.0
    while elapsed < timeout:
        task = await get_task(task_id)
        if task is None:
            raise RuntimeError(f"Task {task_id} not found while polling")
        if task["status"] == "complete":
            return task
        if task["status"] in ("failed", "cancelled"):
            raise RuntimeError(
                f"Task {task_id} reached status {task['status']!r}: "
                f"{task.get('error', 'no error detail')}"
            )
        await asyncio.sleep(_POLL_INTERVAL)
        elapsed += _POLL_INTERVAL

    raise TimeoutError(f"Task {task_id} did not complete within {timeout:.0f}s")


async def execute_pipeline(
    pipeline_id: int,
    run_id: int,
    user_id: str,
    steps: list[dict],
    initial_input: str,
) -> None:
    """
    Execute a pipeline run sequentially, updating the run record after each step.

    This function is meant to be launched as an ``asyncio.create_task()``.
    All errors are caught and recorded — they never propagate to the caller.

    Args:
        pipeline_id:   Pipeline definition ID (for logging).
        run_id:        Pipeline run ID (written back to DB).
        user_id:       Owner of the run (used to create tasks).
        steps:         List of step dicts from the pipeline definition.
        initial_input: Initial input string provided at run time.
    """
    from src.database import (
        create_task,
        update_pipeline_run_step,
        finalize_pipeline_run,
    )

    from src.gateway.events import (
        build_pipeline_complete_event,
        build_pipeline_failed_event,
        build_pipeline_start_event,
        build_pipeline_step_complete_event,
        build_pipeline_step_start_event,
        publish_pipeline_event,
    )

    step_results: list[dict] = []

    try:
        await publish_pipeline_event(
            run_id, build_pipeline_start_event(run_id, pipeline_id, len(steps))
        )

        for i, step in enumerate(steps):
            task_text = render_template(
                step.get("task_text", ""), initial_input, step_results
            )
            agent_type = step.get("agent_type", "orchestrator")
            step_name = step.get("name", f"Step {i}")

            logger.info(
                "[pipeline] Run %d step %d/%d (%s) starting",
                run_id,
                i + 1,
                len(steps),
                step_name,
            )

            # Submit the step as a normal gateway task
            try:
                task_row = await create_task(
                    user_id=user_id,
                    input_text=task_text,
                    agent_type=agent_type,
                    config={"pipeline_run_id": run_id, "pipeline_step": i},
                )
            except Exception as exc:
                raise RuntimeError(
                    f"Step {i} ({step_name!r}): failed to create task: {exc}"
                ) from exc

            task_id = task_row["task_id"]

            await publish_pipeline_event(
                run_id,
                build_pipeline_step_start_event(run_id, i, step_name, task_id),
            )

            # Wait for the task to complete
            try:
                completed = await _wait_for_task(task_id)
            except Exception as exc:
                raise RuntimeError(
                    f"Step {i} ({step_name!r}) task {task_id}: {exc}"
                ) from exc

            result_text = completed.get("result", "")
            step_results.append(
                {
                    "step": i,
                    "name": step_name,
                    "task_id": task_id,
                    "status": "complete",
                    "result": result_text,
                }
            )

            # Persist incremental progress
            await update_pipeline_run_step(run_id, i + 1, step_results)
            await publish_pipeline_event(
                run_id,
                build_pipeline_step_complete_event(
                    run_id, i, step_name, task_id, result_text
                ),
            )
            logger.info(
                "[pipeline] Run %d step %d/%d (%s) done",
                run_id,
                i + 1,
                len(steps),
                step_name,
            )

        await finalize_pipeline_run(run_id, "complete", step_results)
        await publish_pipeline_event(
            run_id, build_pipeline_complete_event(run_id, len(steps))
        )
        logger.info("[pipeline] Run %d completed (%d steps)", run_id, len(steps))

    except Exception as exc:
        logger.error("[pipeline] Run %d failed: %s", run_id, exc)
        step_results.append(
            {"step": len(step_results), "status": "failed", "error": str(exc)}
        )
        await finalize_pipeline_run(run_id, "failed", step_results)
        await publish_pipeline_event(
            run_id, build_pipeline_failed_event(run_id, str(exc))
        )
