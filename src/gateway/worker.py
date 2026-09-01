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

Issue #272 adds:
  - WORKER_NODE_ID: stable identity for this process (env var or generated UUID).
    Stamped on every claimed task row so startup reap only targets this node's
    orphans — safe in future multi-node deployments (see issue #273).
  - Startup reap: on first loop iteration, reap_stale_running_tasks() fails all
    'running' tasks previously owned by this worker_id before accepting new work.
  - _in_flight registry: maps task_id → asyncio.Task so the watchdog can cancel
    in-process coroutines when it reaps a task from the DB.
  - LLM request timeout (llm_factory.py): prevents ainvoke() from holding Ollama
    connections open indefinitely after a reap.

Usage (started by app.py lifespan):
    asyncio.create_task(task_worker())
"""

from __future__ import annotations

import asyncio
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

# ── Worker identity (#272 / #273) ─────────────────────────────────────────────
# Stable identity for this process — stamped on every claimed task row.
# Allows startup reap to target only this node's orphaned tasks without
# disturbing tasks owned by other live worker nodes (multi-node safe).
# Override via WORKER_NODE_ID env var for deterministic IDs in tests/config.
WORKER_NODE_ID: str = os.environ.get("WORKER_NODE_ID") or str(uuid.uuid4())

# In-flight asyncio.Task registry: task_id → asyncio.Task.
# Populated by task_worker when a task is created; cleared in _run_task_tracked
# finally block.  Used by the watchdog to cancel coroutines whose DB row has
# been reaped — prevents Ollama from holding connections open indefinitely.
_in_flight: dict[str, "asyncio.Task[None]"] = {}

# Tracks how many tasks are currently executing (incremented before run,
# decremented in a finally block — always consistent).
_active_tasks: int = 0

# Imports below are intentionally placed after the module-level worker state
# blocks above for organisational grouping (concurrency / identity / in-flight
# registry stay together). E402 is suppressed per-import since the order is
# intentional; the rationale lives here so it isn't repeated each time.
from langgraph.errors import GraphInterrupt  # noqa: E402

from src.database import (  # noqa: E402
    claim_next_queued_task,
    fail_dependent_tasks,
    mark_task_running,
    mark_task_complete,
    mark_task_failed,
    mark_task_paused,
    reap_stuck_tasks,
    reap_stale_running_tasks,
    record_api_usage,
    purge_expired_stream_tokens,
    get_user_webhooks_for_event,
)
from src.security.core import sanitize_log_value  # noqa: E402
from src.gateway.events import (  # noqa: E402
    build_hitl_required_event,
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
    user_id = task.get("user_id")

    run_id = str(uuid.uuid4())
    await mark_task_running(task_id, run_id)

    # Emit task_start
    await publish_event(task_id, build_task_start_event(task_id, agent_type))

    # Phase 58: set model preference for this async task context so
    # get_primary_llm() returns the correct model for this task.
    from src.llm_factory import set_task_model_preference

    set_task_model_preference(task.get("model_preference"))

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
        from src.base_graph import build_base_graph

        uncompiled = build_base_graph()
        agent_id = "base_agent"

    # Gap 3: set per-task memory context so memory_write/memory_recall tools
    # resolve to the correct agent+user namespace via contextvars.
    from src.tools.memory_tools import set_agent_memory_context

    set_agent_memory_context(agent_id, user_id)

    # Charts: set task context so code_execute can store chart payloads keyed
    # by task_id.  The caller (run_task) reads them via pop_charts() after
    # _stream_agent() returns, regardless of success or failure.
    from src.tools.code_tools import set_chart_task_id

    set_chart_task_id(task_id)

    # Seed all safeguard fields (step_count, action_history, token_count, …)
    # using the same run_id that was recorded in the tasks table for this run.
    # Include the agent-specific SystemMessage so it is persisted in the
    # LangGraph checkpoint from step 1 onward — critical for multi-step runs
    # where the LLM needs the instruction context during synthesis (step 2+).
    from langchain_core.messages import HumanMessage, SystemMessage

    # Phase I: extract image payload from task config (stored there by gateway)
    _image_b64 = task_config.get("image_b64")
    _image_mime = task_config.get("image_mime")

    def _build_human_content(text: str) -> list | str:
        """Return vision content list if image present, else plain string."""
        if _image_b64:
            from config.settings import settings

            _model_name = (settings.llm.primary_model or "").lower()
            _is_local = any(kw in _model_name for kw in ("qwen", "llama", "ollama"))
            if _is_local:
                logger.warning(
                    "[worker] Vision input ignored — local model %r does not support "
                    "image inputs. Falling back to text-only.",
                    _model_name,
                )
                return text
            return [
                {
                    "type": "image_url",
                    "image_url": {"url": f"data:{_image_mime};base64,{_image_b64}"},
                },
                {"type": "text", "text": text},
            ]
        return text

    if agent_type == "researcher":
        from src.agents.researcher import _RESEARCHER_SYSTEM_CONTENT

        initial_messages = [
            SystemMessage(content=_RESEARCHER_SYSTEM_CONTENT),
            HumanMessage(content=_build_human_content(input_text)),
        ]
        agent_extra: dict = {}
    elif agent_type == "orchestrator":
        from src.agents.orchestrator import _ORCHESTRATOR_SYSTEM_CONTENT

        initial_messages = [
            SystemMessage(content=_ORCHESTRATOR_SYSTEM_CONTENT),
            HumanMessage(content=_build_human_content(input_text)),
        ]
        agent_extra = {
            "sub_agent_results": [],
            "sequence_so_far": [],
            "task_token": None,  # nosec B105
            "verify_rounds": 0,
        }
    else:
        initial_messages = [HumanMessage(content=_build_human_content(input_text))]
        agent_extra = {}

    initial_state = {
        **SafeguardedState.initial(agent_id=agent_id),
        **agent_extra,
        "task": input_text,
        "run_id": run_id,
        "user_id": user_id,  # Memory bootstrap: persona context injection
        "messages": initial_messages,
    }

    # Phase 54: use session thread_id for persistent context across turns.
    # EXCEPTION — orchestrator: it is stateless by design (delegates to fresh researcher
    # instances every turn). Inheriting session checkpoints causes accumulated failure
    # history from retried queries to pollute the synthesis context, leading to confused
    # "I understand my previous attempts failed" output. The orchestrator always gets a
    # fresh thread (run_id) so its LangGraph state is clean per task.
    session_id = task.get("session_id")
    if session_id and agent_type != "orchestrator":
        from src.database import get_session as _db_get_session

        _sess = await _db_get_session(session_id, task["user_id"])
        lg_thread_id = _sess["thread_id"] if _sess else run_id
    else:
        lg_thread_id = run_id

    from config.settings import settings as _settings

    config = {
        "configurable": {
            "thread_id": lg_thread_id,
            "tracing_enabled": task_config.get("tracing_enabled", True),
        },
        # Default to the profile's recursion limit so the graph doesn't hit
        # LangGraph's built-in default of 25 on orchestrator fan-out tasks.
        "recursion_limit": task_config.get("max_steps")
        or _settings.safeguards.default_recursion_limit,
    }

    # ── Compile with checkpointer + stream events ──────────────────────────
    collected_events: list[dict] = []
    result_text = ""
    step_count = 0
    token_counts: dict = {"input": 0, "output": 0}
    lg_event: dict = {}

    from src.database import get_checkpointer

    try:
        async with get_checkpointer() as checkpointer:
            # interrupt_before=["hitl_gate"] is only wired in base_graph.
            # Researcher and orchestrator graphs don't have this node — pass
            # an empty list so their compilation is unchanged.
            _interrupt_nodes = ["hitl_gate"] if agent_type == "base_agent" else []
            graph = uncompiled.compile(
                checkpointer=checkpointer,
                interrupt_before=_interrupt_nodes or None,
            )
            async for lg_event in graph.astream_events(
                initial_state, config=config, version="v2"
            ):
                sse_event = build_sse_event(lg_event)
                if sse_event:
                    collected_events.append(sse_event)
                    await publish_event(task_id, sse_event)

                # Forward tool_blocked custom events dispatched by SecureToolNode.
                # These arrive as on_custom_event with name="tool_blocked".
                if (
                    lg_event.get("event") == "on_custom_event"
                    and lg_event.get("name") == "tool_blocked"
                ):
                    from src.gateway.events import build_tool_blocked_event

                    _d = lg_event.get("data") or {}
                    _tb_event = build_tool_blocked_event(
                        _d.get("tool", "unknown"),
                        _d.get("reason", "security_check_failed"),
                    )
                    collected_events.append(_tb_event)
                    await publish_event(task_id, _tb_event)

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
        _last_msg = final_state.get("messages", [None])[-1]
        _last_content = (
            _last_msg.content
            if hasattr(_last_msg, "content")
            else (_last_msg.get("content", "") if isinstance(_last_msg, dict) else "")
        )
        result_text = (
            final_state.get("final_answer")
            or final_state.get("result")
            or _last_content
            or "[No result]"
        )
        if not isinstance(result_text, str):
            result_text = str(result_text)

    except Exception:
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
    session_id = task.get("session_id")
    logger.info(
        "[worker] Starting task_id=%s agent=%s user=%s",
        task_id,
        sanitize_log_value(agent_type),
        user_id,
    )

    from src.tools.code_tools import pop_charts

    charts: list[dict] = []
    try:
        result_text, steps, tokens = await _stream_agent(task)
        # Collect any charts produced by code_execute during this task.
        # Must happen before mark_task_complete so charts reach the event.
        charts = pop_charts(task_id)
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

        # Phase 69: include result + tokens inline so browsers render without
        # a second REST round-trip.  Charts (if any) are passed through the
        # same event; they are ephemeral and not stored in the DB.
        await publish_event(
            task_id,
            build_task_complete_event(
                task_id,
                result=result_text,
                tokens=tokens,
                charts=charts or None,
            ),
        )
        logger.info(f"[worker] Completed task_id={task_id} steps={steps}")

        # Phase 54: increment session turn counter
        if session_id:
            try:
                from src.database import increment_session_turn as _inc_turn

                await _inc_turn(session_id)
            except Exception as sess_err:
                logger.warning(f"[worker] session turn increment failed: {sess_err}")

        # Gap 2: episodic memory — fire-and-forget daily summary for cross-session
        # continuity.  The coroutine gates on settings.agent_memory.enabled +
        # episodic_memory itself, so no flag check needed here.
        if user_id:
            from src.memory import summarize_and_store_episodic

            asyncio.create_task(
                summarize_and_store_episodic(
                    task=task.get("input", ""),
                    result=result_text,
                    user_id=user_id,
                    run_id=task_id,
                )
            )

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

    except GraphInterrupt:
        # LangGraph raised GraphInterrupt before executing hitl_gate_node —
        # the graph is paused at the checkpoint awaiting operator approval.
        # Mark the task 'paused' (not 'failed') and emit a terminal SSE event
        # so the client stops streaming and the HITL badge becomes visible.
        pop_charts(task_id)
        logger.info("[worker] Task paused for HITL approval task_id=%s", task_id)
        await mark_task_paused(task_id)
        # hitl_request_id is in the agent state (persisted to checkpoint by
        # check_hitl_required).  Pass None here; the UI polls /hitl/pending.
        await publish_event(task_id, build_hitl_required_event(task_id))

    except Exception as exc:
        error_msg = str(exc)
        logger.error(
            "[worker] Task failed task_id=%s: %s",
            task_id,
            sanitize_log_value(error_msg),
            exc_info=True,
        )
        # Flush any partial chart store entries so they don't leak across tasks.
        pop_charts(task_id)
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
    """Wrap run_task() with active-task counter and in-flight registry bookkeeping."""
    global _active_tasks
    _active_tasks += 1
    task_id = task["task_id"]
    try:
        await run_task(task)
    finally:
        _active_tasks -= 1
        _in_flight.pop(task_id, None)


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
    logger.info(
        "[worker] Task worker started (concurrency=%d, worker_id=%s)",
        WORKER_CONCURRENCY,
        WORKER_NODE_ID,
    )

    # Startup reap (#272): fail any 'running' tasks from our previous process
    # before accepting new work.  All such rows are guaranteed orphans — this
    # process hasn't started any tasks yet.  Multi-node safe: filtered by
    # worker_id so other live nodes' tasks are never touched.
    try:
        orphans = await reap_stale_running_tasks(WORKER_NODE_ID)
        if orphans:
            logger.warning(
                "[worker] Startup reap: failed %d orphaned task(s) from previous run: %s",
                len(orphans),
                orphans,
            )
    except Exception as startup_reap_err:
        logger.error("[worker] Startup reap failed: %s", startup_reap_err)

    while True:
        try:
            if _active_tasks < WORKER_CONCURRENCY:
                task = await claim_next_queued_task(WORKER_NODE_ID)
                if task:
                    t = asyncio.create_task(_run_task_tracked(task))
                    _in_flight[task["task_id"]] = t
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
                    reaped_ids = await reap_stuck_tasks(TASK_WATCHDOG_TIMEOUT)
                    if reaped_ids:
                        logger.warning(
                            "[worker] Watchdog reaped %d stuck task(s) "
                            "(timeout=%ds)",
                            len(reaped_ids),
                            TASK_WATCHDOG_TIMEOUT,
                        )
                        # Cancel any in-flight asyncio coroutines for reaped tasks
                        # so Ollama connections are released promptly (#272).
                        for tid in reaped_ids:
                            t = _in_flight.pop(tid, None)
                            if t and not t.done():
                                t.cancel()
                                logger.info(
                                    "[worker] Cancelled in-flight coroutine for reaped task %s",
                                    tid,
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
