"""
src/scheduler.py
────────────────
Async cron-style task scheduler for Phase 23.

The Scheduler daemon runs as a background asyncio.Task inside the gateway
lifespan.  Every ``poll_interval`` seconds it queries the ``scheduled_tasks``
table for jobs whose ``next_run_at <= now()``, fires each as a normal gateway
task (via ``create_task()``), and advances ``next_run_at`` to the next
scheduled occurrence.

Supported schedule expressions
───────────────────────────────
Standard 5-field cron (via croniter):
    "0 * * * *"       — every hour at :00
    "*/15 * * * *"    — every 15 minutes
    "0 9 * * 1-5"     — weekdays at 09:00

Built-in shortcuts (expanded to standard cron):
    @hourly  @daily  @midnight  @weekly  @monthly  @yearly  @annually

Interval shortcuts (relative to each fire time):
    @every 5m   @every 30m  @every 2h   @every 1d

Usage:
    from src.scheduler import get_scheduler

    scheduler = get_scheduler()
    await scheduler.start()   # call in gateway lifespan
    ...
    await scheduler.stop()    # call in gateway shutdown

    # Validate a cron expression before storing:
    from src.scheduler import validate_cron_expr, compute_next_run
    validate_cron_expr("*/10 * * * *")  # raises ValueError if invalid
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

UTC = timezone.utc

# ── Cron expression helpers ────────────────────────────────────────────────────

_SHORTCUTS: dict[str, str] = {
    "@hourly": "0 * * * *",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@weekly": "0 0 * * 0",
    "@monthly": "0 0 1 * *",
    "@yearly": "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
}

# @every <n><unit>  where unit is m(inutes), h(ours), d(ays)
_EVERY_RE = re.compile(r"^@every\s+(\d+)(m|h|d)$", re.IGNORECASE)


def _expand_shortcut(expr: str) -> str:
    """Expand @shortcut and @every variants; leave standard cron unchanged."""
    low = expr.strip().lower()
    if low in _SHORTCUTS:
        return _SHORTCUTS[low]
    return expr.strip()


def _every_delta(expr: str) -> timedelta | None:
    """Return timedelta for @every expressions, or None if not an @every expr."""
    m = _EVERY_RE.match(expr.strip())
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2).lower()
    if unit == "m":
        return timedelta(minutes=n)
    if unit == "h":
        return timedelta(hours=n)
    return timedelta(days=n)


def compute_next_run(cron_expr: str, after: datetime) -> datetime:
    """
    Return the next run datetime after ``after`` for the given ``cron_expr``.

    For @every intervals the next run is ``after + interval``.
    For all other expressions (including @shortcuts), croniter is used.
    """
    after = after.astimezone(UTC)

    delta = _every_delta(cron_expr)
    if delta is not None:
        return after + delta

    expanded = _expand_shortcut(cron_expr)
    try:
        from croniter import croniter  # type: ignore[import]

        return croniter(expanded, after).get_next(datetime)
    except Exception as exc:
        raise ValueError(f"Invalid cron expression {cron_expr!r}: {exc}") from exc


def validate_cron_expr(cron_expr: str) -> None:
    """
    Validate ``cron_expr``; raise ``ValueError`` with a descriptive message if invalid.

    Accepts standard 5-field cron, @shortcuts, and @every <n>(m|h|d).
    """
    if _every_delta(cron_expr) is not None:
        return  # always valid if the regex matched

    expanded = _expand_shortcut(cron_expr)
    try:
        from croniter import croniter  # type: ignore[import]

        if not croniter.is_valid(expanded):
            raise ValueError(f"Invalid cron expression: {cron_expr!r}")
    except ImportError as exc:
        raise RuntimeError("croniter is required for cron expressions") from exc


# ── Scheduler daemon ───────────────────────────────────────────────────────────


class Scheduler:
    """
    Async background scheduler that fires due ``scheduled_tasks`` as gateway tasks.

    Start from the gateway lifespan:
        scheduler = get_scheduler()
        await scheduler.start()

    Stop during shutdown:
        await scheduler.stop()
    """

    _MAINTENANCE_INTERVAL_SECONDS: int = 86400  # 24 hours

    def __init__(self, poll_interval: int = 30) -> None:
        self.poll_interval = poll_interval
        self._task: Optional[asyncio.Task] = None  # type: ignore[type-arg]
        self._last_maintenance: float = 0.0

    async def start(self) -> None:
        """Launch the background polling loop."""
        self._task = asyncio.create_task(self._run(), name="legionforge-scheduler")
        logger.info("[scheduler] Started (poll every %ds)", self.poll_interval)

    async def stop(self) -> None:
        """Cancel the polling loop and wait for it to exit."""
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("[scheduler] Stopped")

    async def _run(self) -> None:
        while True:
            try:
                await self._tick()
                await self._maybe_run_maintenance()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("[scheduler] Tick error: %s", exc)
            await asyncio.sleep(self.poll_interval)

    async def _maybe_run_maintenance(self) -> None:
        """Run nightly DB maintenance if 24 hours have elapsed since the last run."""
        now = asyncio.get_event_loop().time()
        if now - self._last_maintenance < self._MAINTENANCE_INTERVAL_SECONDS:
            return
        self._last_maintenance = now

        try:
            from config.settings import settings

            m = settings.db_maintenance
            if not m.enabled:
                return

            from src.database import run_db_maintenance

            results = await run_db_maintenance(
                tasks_days=m.tasks_days,
                api_usage_days=m.api_usage_days,
                health_metrics_days=m.health_metrics_days,
                threat_events_days=m.threat_events_days,
                audit_log_days=m.audit_log_days,
                task_events_days=m.task_events_days,
            )
            logger.info("[scheduler] Nightly DB maintenance complete: %s", results)
        except Exception as exc:
            logger.error("[scheduler] DB maintenance error: %s", exc)

    async def _tick(self) -> None:
        """Query and fire all due scheduled tasks."""
        from src.database import (
            get_due_scheduled_tasks,
        )

        due = await get_due_scheduled_tasks()
        if not due:
            return

        logger.info("[scheduler] %d job(s) due", len(due))
        for sched in due:
            await self._fire(sched)

    async def _fire(self, sched: dict) -> None:
        """Spawn a gateway task for one scheduled job and advance its next_run_at."""
        from src.database import create_task, record_scheduled_run

        sched_id: int = sched["id"]
        try:
            task = await create_task(
                user_id=sched["user_id"],
                input_text=sched["task_text"],
                agent_type=sched["agent_type"],
                config={"scheduled": True, "schedule_id": sched_id},
            )
            task_id: str = task["task_id"]
        except Exception as exc:
            logger.error(
                "[scheduler] Failed to create task for schedule %d: %s", sched_id, exc
            )
            return

        now = datetime.now(UTC)
        try:
            next_run = compute_next_run(sched["cron_expr"], now)
        except Exception as exc:
            logger.error(
                "[scheduler] Cannot compute next_run for schedule %d (%r): %s",
                sched_id,
                sched["cron_expr"],
                exc,
            )
            next_run = now + timedelta(hours=1)  # safe fallback: retry in 1h

        try:
            await record_scheduled_run(sched_id, task_id, next_run)
        except Exception as exc:
            logger.error(
                "[scheduler] Failed to record run for schedule %d: %s", sched_id, exc
            )
            return

        logger.info(
            "[scheduler] Fired schedule %d (%s) → task %s; next=%s",
            sched_id,
            sched["name"],
            task_id,
            next_run.isoformat(),
        )


# ── Module-level singleton ─────────────────────────────────────────────────────

_scheduler: Optional[Scheduler] = None


def get_scheduler(poll_interval: int = 30) -> Scheduler:
    """Return the module-level Scheduler singleton."""
    global _scheduler
    if _scheduler is None:
        _scheduler = Scheduler(poll_interval=poll_interval)
    return _scheduler


def reset_scheduler() -> None:
    """Reset the module-level singleton (test helper)."""
    global _scheduler
    _scheduler = None
