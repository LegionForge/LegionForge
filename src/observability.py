"""
src/observability.py
────────────────────
Local structured logging with rotation, per-run token tracking,
and LangSmith metric upload. Provides a unified interface for
all observability concerns.

Usage:
    from src.observability import setup_logging, log_agent_event, get_metrics

    setup_logging()   # Call once at startup
    log_agent_event("tool_call", "researcher", {"tool": "web_search", "query": "..."})
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config.settings import settings

# ── Logging setup ─────────────────────────────────────────────────────────────


def setup_logging(log_level: str | None = None) -> None:
    """
    Configure structured JSON logging with daily rotation.
    Logs to both the external drive and stdout.
    Call once at application startup.
    """
    level_str = log_level or os.environ.get("LOG_LEVEL", "INFO")
    level = getattr(logging, level_str.upper(), logging.INFO)

    log_dir = Path(settings.paths.runtime.logs)
    log_dir.mkdir(parents=True, exist_ok=True)

    log_file = log_dir / "agents.log"

    # JSON formatter for structured logs
    class JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            log_data = {
                "ts": datetime.now(tz=timezone.utc).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
            if record.exc_info:
                log_data["exception"] = self.formatException(record.exc_info)
            if hasattr(record, "extra"):
                log_data.update(record.extra)
            return json.dumps(log_data)

    # Rotating file handler — daily rotation, 30 days retention
    file_handler = logging.handlers.TimedRotatingFileHandler(
        filename=log_file,
        when="midnight",
        backupCount=settings.observability.local_logging.retention_days,
        encoding="utf-8",
    )
    file_handler.setFormatter(JsonFormatter())
    file_handler.setLevel(level)

    # Console handler — plain text for readability
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    console_handler.setLevel(level)

    # Root logger
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(file_handler)
    root.addHandler(console_handler)

    # Quieten noisy libraries
    for noisy in ["httpx", "httpcore", "asyncio", "urllib3"]:
        logging.getLogger(noisy).setLevel(logging.WARNING)

    logging.getLogger(__name__).info(
        f"Logging initialized. Level={level_str}, File={log_file}"
    )


# ── Structured event logging ──────────────────────────────────────────────────

_event_logger = logging.getLogger("agent.events")


def log_agent_event(
    event_type: str,
    agent_name: str,
    data: dict[str, Any] | None = None,
    run_id: str | None = None,
) -> None:
    """
    Log a structured agent event. These are queryable in your log files.

    Event types: tool_call, tool_result, llm_call, llm_response,
                 state_update, safeguard_triggered, error, run_start, run_end

    Usage:
        log_agent_event("tool_call", "researcher", {
            "tool": "web_search",
            "query": "LangGraph best practices",
            "step": 3,
        })
    """
    record = logging.LogRecord(
        name="agent.events",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg=f"[{agent_name}] {event_type}",
        args=(),
        exc_info=None,
    )
    record.extra = {
        "event_type": event_type,
        "agent_name": agent_name,
        "run_id": run_id,
        **(data or {}),
    }
    _event_logger.handle(record)


# ── In-memory metrics ─────────────────────────────────────────────────────────


class MetricsCollector:
    """
    Lightweight in-memory metrics collector.
    Tracks counters, histograms, and gauges per run and globally.
    """

    def __init__(self):
        self._counters: dict[str, int] = defaultdict(int)
        self._histograms: dict[str, list[float]] = defaultdict(list)
        self._gauges: dict[str, float] = {}
        self._run_tokens: dict[str, int] = defaultdict(int)
        self._start_time = time.monotonic()

    def increment(self, key: str, value: int = 1) -> None:
        self._counters[key] += value

    def record(self, key: str, value: float) -> None:
        self._histograms[key].append(value)

    def gauge(self, key: str, value: float) -> None:
        self._gauges[key] = value

    def record_tokens(self, run_id: str, tokens: int) -> None:
        self._run_tokens[run_id] += tokens
        self._counters["total_tokens"] += tokens

    def get_summary(self) -> dict:
        uptime_seconds = time.monotonic() - self._start_time

        summary: dict[str, Any] = {
            "uptime_seconds": round(uptime_seconds, 1),
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
        }

        # Add histogram stats
        hist_stats = {}
        for key, values in self._histograms.items():
            if values:
                sorted_vals = sorted(values)
                n = len(sorted_vals)
                hist_stats[key] = {
                    "count": n,
                    "min": round(sorted_vals[0], 3),
                    "max": round(sorted_vals[-1], 3),
                    "mean": round(sum(sorted_vals) / n, 3),
                    "p50": round(sorted_vals[n // 2], 3),
                    "p95": round(sorted_vals[int(n * 0.95)], 3),
                }
        if hist_stats:
            summary["histograms"] = hist_stats

        # Token stats per run
        if self._run_tokens:
            summary["run_tokens"] = dict(
                sorted(
                    self._run_tokens.items(),
                    key=lambda x: x[1],
                    reverse=True,
                )[
                    :10
                ]  # Top 10 runs by token usage
            )

        return summary

    def reset(self) -> None:
        self._counters.clear()
        self._histograms.clear()
        self._gauges.clear()
        self._run_tokens.clear()
        self._start_time = time.monotonic()


# Module-level metrics singleton
_metrics = MetricsCollector()


def get_metrics() -> MetricsCollector:
    """Get the global metrics collector."""
    return _metrics


def get_metrics_summary() -> dict:
    """Get a snapshot of all current metrics."""
    return _metrics.get_summary()


# ── LangSmith metric upload helpers ──────────────────────────────────────────


async def upload_run_metrics_to_langsmith(
    run_id: str,
    metrics: dict[str, Any],
) -> bool:
    """
    Upload custom metrics to a LangSmith run as feedback.
    Returns True if upload succeeded.

    This makes local token counts and latencies visible in the LangSmith UI
    alongside the trace.
    """
    if not settings.observability.langsmith.enabled:
        return False

    try:
        from langsmith import Client
        from src.security import get_api_key_optional

        api_key = get_api_key_optional("langsmith")
        if not api_key:
            return False

        client = Client(api_key=api_key)

        for metric_key, value in metrics.items():
            if isinstance(value, (int, float)):
                client.create_feedback(
                    run_id=run_id,
                    key=metric_key,
                    score=float(value),
                    source_info={"source": "local_metrics"},
                )

        return True

    except Exception as e:
        logging.getLogger(__name__).warning(
            f"Failed to upload metrics to LangSmith: {e}"
        )
        return False


# ── Timing context manager ────────────────────────────────────────────────────


class timed:
    """
    Context manager for timing code blocks and recording to metrics.

    Usage:
        with timed("llm_latency_ms", metrics=get_metrics()):
            response = await llm.ainvoke(prompt)
    """

    def __init__(self, metric_key: str, metrics: MetricsCollector | None = None):
        self._key = metric_key
        self._metrics = metrics or _metrics
        self._start = 0.0

    def __enter__(self):
        self._start = time.monotonic()
        return self

    def __exit__(self, *args):
        elapsed_ms = (time.monotonic() - self._start) * 1000
        self._metrics.record(self._key, elapsed_ms)
        return False
