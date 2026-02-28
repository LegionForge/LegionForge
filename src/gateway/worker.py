"""
src/gateway/worker.py
──────────────────────
Background task worker — polls the tasks table for queued tasks and runs
the appropriate agent, streaming events to SSE subscribers via publish_event().

At Phase 8 scale (household, 1–2 users) a single embedded asyncio.Task is
sufficient.  Phase 10 adds per-user token attribution and a stream-token
purge heartbeat (every 10 min) via purge_expired_stream_tokens().

Usage (started by app.py lifespan):
    asyncio.create_task(task_worker())
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

from src.database import (
    claim_next_queued_task,
    mark_task_running,
    mark_task_complete,
    mark_task_failed,
    record_api_usage,
    purge_expired_stream_tokens,
)
from src.gateway.events import (
    build_sse_event,
    build_task_complete_event,
    build_task_error_event,
    build_task_start_event,
    publish_event,
)

logger = logging.getLogger(__name__)


# ── Agent runner bridge ───────────────────────────────────────────────────────


async def _stream_agent(task: dict) -> tuple[str, int, dict]:
    """
    Run the appropriate agent using graph.astream_events() and publish SSE
    events to subscribers as they arrive.

    Returns (result_text, step_count, token_counts).

    The agent functions currently use ainvoke().  This wrapper switches to
    astream_events() by accessing the compiled graph directly.
    """
    agent_type = task["agent_type"]
    task_id = task["task_id"]
    input_text = task["input"]
    task_config = task.get("config") or {}

    run_id = str(uuid.uuid4())
    await mark_task_running(task_id, run_id)

    # Emit task_start
    await publish_event(task_id, build_task_start_event(task_id, agent_type))

    # ── Import agent graph ─────────────────────────────────────────────────
    if agent_type == "researcher":
        from src.agents.researcher import build_researcher_graph, ResearcherState

        graph = build_researcher_graph()
        initial_state = ResearcherState(task=input_text)
    elif agent_type == "orchestrator":
        from src.agents.orchestrator import build_orchestrator_graph, OrchestratorState

        graph = build_orchestrator_graph()
        initial_state = OrchestratorState(task=input_text)
    else:
        from src.base_graph import build_graph, AgentState

        graph = build_graph()
        initial_state = AgentState(task=input_text)

    config = {
        "configurable": {
            "thread_id": run_id,
            "tracing_enabled": task_config.get("tracing_enabled", True),
        }
    }
    if task_config.get("max_steps"):
        config["recursion_limit"] = task_config["max_steps"]

    # ── Stream events ──────────────────────────────────────────────────────
    collected_events: list[dict] = []
    result_text = ""
    step_count = 0
    token_counts: dict = {"input": 0, "output": 0}

    try:
        async for lg_event in graph.astream_events(
            initial_state, config=config, version="v2"
        ):
            sse_event = build_sse_event(lg_event)
            if sse_event:
                collected_events.append(sse_event)
                await publish_event(task_id, sse_event)

            # Track step count (each on_chain_end at the root level = one node)
            if lg_event.get("event") == "on_chain_end" and lg_event.get("name") in (
                "agent_node",
                "tool_node",
                "researcher_node",
            ):
                step_count += 1

            # Extract token usage if available
            if lg_event.get("event") == "on_chat_model_end":
                usage = (
                    lg_event.get("data", {}).get("output", {}).get("usage_metadata", {})
                )
                token_counts["input"] += usage.get("input_tokens", 0)
                token_counts["output"] += usage.get("output_tokens", 0)

        # Extract final result from terminal state
        final_state = lg_event.get("data", {}).get("output", {}) if lg_event else {}  # type: ignore[possibly-undefined]
        result_text = (
            final_state.get("final_answer")
            or final_state.get("result")
            or final_state.get("messages", [{}])[-1].get("content", "")
            or "[No result]"
        )
        if not isinstance(result_text, str):
            result_text = str(result_text)

    except Exception as exc:
        raise

    return result_text, step_count, token_counts


# ── Task runner ───────────────────────────────────────────────────────────────


_PURGE_INTERVAL_SECONDS = 600  # purge expired stream tokens every 10 minutes
_last_purge: float = 0.0


async def run_task(task: dict) -> None:
    """Run a single claimed task end-to-end, updating DB and publishing events."""
    task_id = task["task_id"]
    user_id = task.get("user_id")
    agent_type = task.get("agent_type", "base_agent")
    logger.info(
        f"[worker] Starting task_id={task_id} agent={agent_type} " f"user={user_id}"
    )

    try:
        result_text, steps, tokens = await _stream_agent(task)
        await mark_task_complete(
            task_id,
            result=result_text,
            steps=steps,
            tokens=tokens,
        )

        # Record actual token usage with user attribution so per-user budget
        # queries (get_user_actual_usage_today) can count it.
        # These rows are the ones with user_id set — internal LLM factory calls
        # produce rows with user_id=NULL, so there is no double-count.
        if tokens.get("input") or tokens.get("output"):
            try:
                from src.gateway.routes.tasks import _AGENT_TYPE_TO_PROVIDER

                provider = _AGENT_TYPE_TO_PROVIDER.get(agent_type, "ollama")
                await record_api_usage(
                    provider=provider,
                    model="unknown",
                    input_tokens=tokens.get("input", 0),
                    output_tokens=tokens.get("output", 0),
                    run_id=task_id,
                    agent_name=agent_type,
                    success=True,
                    user_id=user_id,
                )
            except Exception as usage_err:
                logger.warning(f"[worker] Failed to record user usage: {usage_err}")

        await publish_event(task_id, build_task_complete_event(task_id))
        logger.info(f"[worker] Completed task_id={task_id} steps={steps}")

    except Exception as exc:
        error_msg = str(exc)
        logger.error(
            f"[worker] Task failed task_id={task_id}: {error_msg}", exc_info=True
        )
        await mark_task_failed(task_id, error=error_msg)
        await publish_event(task_id, build_task_error_event(task_id, error_msg))


# ── Worker loop ───────────────────────────────────────────────────────────────


async def task_worker() -> None:
    """
    Main worker loop.  Polls the tasks table every second for queued tasks
    and runs them one at a time.

    A single worker is appropriate at household scale.  The FOR UPDATE SKIP
    LOCKED in claim_next_queued_task() is safe for future multi-worker
    scenarios without code changes here.

    Phase 10 addition: purges expired stream tokens every 10 minutes as an
    opportunistic heartbeat (not a hot path).
    """
    global _last_purge
    logger.info("[worker] Task worker started")
    while True:
        try:
            task = await claim_next_queued_task()
            if task:
                await run_task(task)
            else:
                await asyncio.sleep(1)

            # Opportunistic purge of expired stream tokens (every 10 min)
            now = asyncio.get_event_loop().time()
            if now - _last_purge >= _PURGE_INTERVAL_SECONDS:
                try:
                    await purge_expired_stream_tokens()
                    _last_purge = now
                except Exception as purge_err:
                    logger.debug(f"[worker] Stream token purge failed: {purge_err}")

        except asyncio.CancelledError:
            logger.info("[worker] Task worker shutting down")
            break
        except Exception as exc:
            logger.error(
                f"[worker] Unhandled error in worker loop: {exc}", exc_info=True
            )
            await asyncio.sleep(2)  # brief backoff before retry
