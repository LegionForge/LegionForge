"""
src/gateway/metrics.py
───────────────────────
Lightweight Prometheus-format metrics for the LegionForge gateway.

No external dependency — counters and gauges are stored in a thread-safe
dict and serialised to Prometheus text format on demand.

Prometheus text format reference:
  https://prometheus.io/docs/instrumenting/exposition_formats/

Usage
─────
Increment a counter::

    from src.gateway.metrics import inc_counter
    inc_counter("legionforge_http_requests_total", {"method": "POST", "status": "200"})

Set a gauge::

    from src.gateway.metrics import set_gauge
    set_gauge("legionforge_redis_connected", 1.0)

Render for the /metrics endpoint::

    from src.gateway.metrics import prometheus_text
    return PlainTextResponse(prometheus_text(), media_type="text/plain; version=0.0.4")
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Optional

# ── Internal store ─────────────────────────────────────────────────────────────

_lock = threading.Lock()

# Keyed by (metric_name, sorted_label_tuple) → float value
_counters: dict[tuple, float] = defaultdict(float)
_gauges: dict[str, float] = {}

# Process start time for uptime gauge
_start_time: float = time.monotonic()

# Human-readable descriptions
_HELP: dict[str, str] = {
    "legionforge_http_requests_total": "Total HTTP requests handled by the gateway",
    "legionforge_tasks_submitted_total": "Total tasks submitted to the queue",
    "legionforge_budget_rejections_total": "Total task submissions rejected by budget check",
    "legionforge_redis_connected": "1 if Redis is currently connected, 0 otherwise",
    "legionforge_uptime_seconds": "Gateway process uptime in seconds",
}


# ── Public API ─────────────────────────────────────────────────────────────────


def inc_counter(
    name: str,
    labels: Optional[dict[str, str]] = None,
    value: float = 1.0,
) -> None:
    """Increment a counter metric."""
    key = (name, tuple(sorted((labels or {}).items())))
    with _lock:
        _counters[key] += value


def set_gauge(name: str, value: float) -> None:
    """Set a gauge metric to an exact value."""
    with _lock:
        _gauges[name] = value


def get_counter(
    name: str,
    labels: Optional[dict[str, str]] = None,
) -> float:
    """Return current counter value (0.0 if not yet set)."""
    key = (name, tuple(sorted((labels or {}).items())))
    with _lock:
        return _counters.get(key, 0.0)


def reset() -> None:
    """Reset all counters and gauges (primarily for testing)."""
    with _lock:
        _counters.clear()
        _gauges.clear()


def prometheus_text() -> str:
    """
    Serialise all metrics to Prometheus text format (version 0.0.4).

    The uptime gauge is computed fresh on each call.

    Returns:
        UTF-8 string in Prometheus text exposition format.
    """
    lines: list[str] = []

    with _lock:
        counters_snapshot = dict(_counters)
        gauges_snapshot = dict(_gauges)

    # Uptime gauge (always present)
    gauges_snapshot["legionforge_uptime_seconds"] = round(
        time.monotonic() - _start_time, 1
    )

    # Group counter entries by metric name
    counter_groups: dict[str, list[tuple[tuple, float]]] = defaultdict(list)
    for (name, label_items), value in counters_snapshot.items():
        counter_groups[name].append((label_items, value))

    for name in sorted(counter_groups):
        help_text = _HELP.get(name, name)
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} counter")
        for label_items, value in counter_groups[name]:
            if label_items:
                label_str = ",".join(f'{k}="{v}"' for k, v in label_items)
                lines.append(f"{name}{{{label_str}}} {value:.0f}")
            else:
                lines.append(f"{name} {value:.0f}")

    for name in sorted(gauges_snapshot):
        help_text = _HELP.get(name, name)
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} gauge")
        value = gauges_snapshot[name]
        lines.append(f"{name} {value}")

    return "\n".join(lines) + "\n" if lines else "# no metrics yet\n"
