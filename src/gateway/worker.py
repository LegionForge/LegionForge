"""
src/gateway/worker.py
──────────────────────
Background task worker — polls the tasks table for queued tasks and runs
the appropriate agent, streaming events to SSE subscribers via publish_event().

At Phase 8 scale (household, 1–2 users) a single embedded asyncio.Task is
sufficient.  Phase 10 adds per-user token attribution and a stream-token
purge heartbeat (every 10 min) via purge_expired_stream_tokens().

Phase 35 adds configurable concurrency: up to WORKER_CONCURRENCY tasks run
simultaneously (default 3, override via WORKER_CONCURRENCY env var).  The
FOR UPDATE SKIP LOCKED claim query is already safe for concurrent use.

Phase 46 adds a watchdog heartbeat (every 5 min) that reaps tasks stuck in
'running' for longer than TASK_WATCHDOG_TIMEOUT seconds (default 1800 / 30 min).

Usage (started by app.py lifespan):
    asyncio.create_task(task_worker())
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone

# ── Concurrency control ────────────────────────────────────────────────────────

WORKER_CONCURRENCY: int = max(1, int(os.environ.get("WORKER_CONCURRENCY", "3")))

# Watchdog: tasks stuck in 'running' for longer than this are reaped (Phase 46)
TASK_WATCHDOG_TIMEOUT: int = max(
    60, int(os.environ.get("TASK_WATCHDOG_TIMEOUT", "1800"))
)
_WATCHDOG_INTERVAL_SECONDS = 300  # run watchdog every 5 minutes
_last_watchdog: float = 0.0

# Tracks how many tasks are currently executing (incremented before run,
# decremented in a finally block — always consistent).
_active_tasks: int = 0

from src.database import (
    claim_next_queued_task,
    fail_dependent_tasks,
    mark_task_running,
    mark_task_complete,
    mark_task_failed,
    reap_stuck_tasks,
    record_api_usage,
    purge_expired_stream_tokens,
    get_user_webhooks_for_event,
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

    # ── Import agent graph (uncompiled) ───────────────────────────────────
    from src.safeguards import SafeguardedState

    if agent_type == "researcher":
        from src.agents.researcher import build_researcher_graph

        uncompiled = build_researcher_graph()
        agent_id = "researcher"
    elif agent_type == "orchestrator":
        from src.agents.orchestrator import build_orchestrator_graph

        uncompiled = build_orchestrator_graph()
        agent_id = "orchestrator"
    else:
        from src.base_graph import build_graph

        uncompiled = build_graph()
        agent_id = "base_agent"

    # Seed all safeguard fields (step_count, action_history, token_count, …)
    # using the same run_id that was recorded in the tasks table for this run.
    # Mirror run_researcher(): seed messages with the task as the initial
    # HumanMessage so the agent_node has a non-empty message list to invoke.
    from langchain_core.messages import HumanMessage

    initial_state = {
        **SafeguardedState.initial(agent_id=agent_id),
        "task": input_text,
        "run_id": run_id,
        "messages": [HumanMessage(content=input_text)],
    }

    config = {
        "configurable": {
            "thread_id": run_id,
            "tracing_enabled": task_config.get("tracing_enabled", True),
        }
    }
    if task_config.get("max_steps"):
        config["recursion_limit"] = task_config["max_steps"]

    # ── Compile with checkpointer + stream events ──────────────────────────
    collected_events: list[dict] = []
    result_text = ""
    step_count = 0
    token_counts: dict = {"input": 0, "output": 0}
    lg_event: dict = {}

    from src.database import get_checkpointer

    try:
        async with get_checkpointer() as checkpointer:
            graph = uncompiled.compile(checkpointer=checkpointer)
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

                # Extract token usage if available.
                # data["output"] is an AIMessage (Pydantic) not a plain dict.
                if lg_event.get("event") == "on_chat_model_end":
                    output = lg_event.get("data", {}).get("output")
                    usage: dict = {}
                    if hasattr(output, "usage_metadata") and output.usage_metadata:
                        usage = dict(output.usage_metadata)
                    elif isinstance(output, dict):
                        usage = output.get("usage_metadata") or {}
                    token_counts["input"] += usage.get("input_tokens") or 0
                    token_counts["output"] += usage.get("output_tokens") or 0

        # Extract final result from terminal state
        final_state = lg_event.get("data", {}).get("output", {}) if lg_event else {}
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


async def _fire_user_webhooks(
    user_id: str | None,
    event: str,
    payload: dict,
) -> None:
    """
    Fire all active user webhooks subscribed to ``event`` (Phase 48).

    Runs as a fire-and-forget asyncio.create_task() — errors are logged,
    never raised.  Uses the same send_callback() helper as the per-task
    callback_url (Phase 26).
    """
    if not user_id:
        return
    try:
        webhooks = await get_user_webhooks_for_event(user_id, event)
        if not webhooks:
            return
        from src.webhook_sender import send_callback

        for wh in webhooks:
            asyncio.create_task(
                send_callback(payload.get("task_id", ""), wh["url"], payload)
            )
    except Exception as err:
        logger.warning("[worker] _fire_user_webhooks error: %s", err)


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

        # Build completion payload (shared by per-task + registry webhooks)
        _complete_payload = {
            "task_id": task_id,
            "status": "complete",
            "result": result_text,
            "error": None,
            "agent_type": agent_type,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }

        # Phase 26: fire completion webhook if caller supplied a callback_url
        callback_url = task.get("callback_url")
        if callback_url:
            from src.webhook_sender import send_callback

            asyncio.create_task(send_callback(task_id, callback_url, _complete_payload))

        # Phase 48: fire all user-registered webhooks subscribed to task_complete
        asyncio.create_task(
            _fire_user_webhooks(user_id, "task_complete", _complete_payload)
        )

    except Exception as exc:
        error_msg = str(exc)
        logger.error(
            f"[worker] Task failed task_id={task_id}: {error_msg}", exc_info=True
        )
        await mark_task_failed(task_id, error=error_msg)
        await publish_event(task_id, build_task_error_event(task_id, error_msg))

        # Phase 34: auto-fail any queued tasks that depended on this one
        try:
            n = await fail_dependent_tasks(task_id)
            if n:
                logger.info(
                    "[worker] Auto-failed %d dependent task(s) of %s", n, task_id
                )
        except Exception as dep_err:
            logger.warning("[worker] fail_dependent_tasks error: %s", dep_err)

        # Build failure payload (shared by per-task + registry webhooks)
        _failed_payload = {
            "task_id": task_id,
            "status": "failed",
            "result": None,
            "error": error_msg,
            "agent_type": agent_type,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }

        # Phase 26: fire failure webhook
        callback_url = task.get("callback_url")
        if callback_url:
            from src.webhook_sender import send_callback

            asyncio.create_task(send_callback(task_id, callback_url, _failed_payload))

        # Phase 48: fire all user-registered webhooks subscribed to task_failed
        asyncio.create_task(
            _fire_user_webhooks(user_id, "task_failed", _failed_payload)
        )


# ── Worker loop ───────────────────────────────────────────────────────────────


async def _run_task_tracked(task: dict) -> None:
    """Wrap run_task() with active-task counter bookkeeping."""
    global _active_tasks
    _active_tasks += 1
    try:
        await run_task(task)
    finally:
        _active_tasks -= 1


async def task_worker() -> None:
    """
    Main worker loop.  Polls the tasks table for queued tasks and launches
    up to WORKER_CONCURRENCY tasks concurrently.

    Phase 35: concurrent execution via asyncio.create_task() + _active_tasks
    counter.  The FOR UPDATE SKIP LOCKED claim query is safe for concurrent
    use — each create_task() call claims a distinct row.

    Phase 10 addition: purges expired stream tokens every 10 minutes as an
    opportunistic heartbeat (not a hot path).

    Phase 46 addition: watchdog heartbeat every 5 minutes reaps tasks stuck
    in 'running' for longer than TASK_WATCHDOG_TIMEOUT seconds.
    """
    global _last_purge, _last_watchdog
    logger.info("[worker] Task worker started (concurrency=%d)", WORKER_CONCURRENCY)
    while True:
        try:
            if _active_tasks < WORKER_CONCURRENCY:
                task = await claim_next_queued_task()
                if task:
                    asyncio.create_task(_run_task_tracked(task))
                    # Don't sleep — immediately check for more queued tasks
                    # so we can fill all concurrency slots quickly.
                else:
                    await asyncio.sleep(1)
            else:
                # All slots busy — yield briefly before rechecking.
                await asyncio.sleep(0.2)

            # Opportunistic purge of expired stream tokens (every 10 min)
            now = asyncio.get_event_loop().time()
            if now - _last_purge >= _PURGE_INTERVAL_SECONDS:
                try:
                    await purge_expired_stream_tokens()
                    _last_purge = now
                except Exception as purge_err:
                    logger.debug(f"[worker] Stream token purge failed: {purge_err}")

            # Watchdog: reap tasks stuck in 'running' (every 5 min, Phase 46)
            if now - _last_watchdog >= _WATCHDOG_INTERVAL_SECONDS:
                try:
                    reaped = await reap_stuck_tasks(TASK_WATCHDOG_TIMEOUT)
                    if reaped:
                        logger.warning(
                            "[worker] Watchdog reaped %d stuck task(s) "
                            "(timeout=%ds)",
                            reaped,
                            TASK_WATCHDOG_TIMEOUT,
                        )
                    _last_watchdog = now
                except Exception as watchdog_err:
                    logger.warning(f"[worker] Watchdog error: {watchdog_err}")

        except asyncio.CancelledError:
            logger.info("[worker] Task worker shutting down")
            break
        except Exception as exc:
            logger.error(
                f"[worker] Unhandled error in worker loop: {exc}", exc_info=True
            )
            await asyncio.sleep(2)  # brief backoff before retry
