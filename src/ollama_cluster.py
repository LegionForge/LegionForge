"""
src/ollama_cluster.py
─────────────────────
Multi-machine Ollama cluster manager.

Manages a pool of Ollama nodes across multiple physical machines with
health polling, routing strategies, and automatic failover.

Routing strategies:
    round_robin   — cycle through healthy nodes in order (default)
    primary_first — always prefer the first configured healthy node
    least_busy    — route to the node with the lowest recent latency

Configuration:
    Add an ``ollama_cluster:`` section to your hardware profile YAML.
    If ``nodes`` is empty (the default), the framework uses the single
    ``local_services.ollama.base_url`` value — no change to existing behaviour.

Usage:
    from src.ollama_cluster import get_cluster_manager

    manager = get_cluster_manager()
    url = manager.get_healthy_url()               # best healthy node
    url = manager.get_healthy_url("mac-studio")   # prefer a specific node

    # Live health check (async):
    statuses = await manager.check_all()
    for s in statuses:
        print(s.label, s.healthy, s.latency_ms, s.models)

    # Add/remove nodes at runtime (reflected immediately):
    manager.add_node("http://192.168.1.105:11434", label="workstation")
    manager.remove_node("old-server")

Security:
    Node URLs are admin-gated; only add nodes reachable from within your
    trusted network.  The cluster manager never forwards user data to
    nodes — it only probes the Ollama /api/tags health endpoint.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass
class NodeHealth:
    """Current health state of a single Ollama node."""

    label: str
    url: str
    healthy: bool
    latency_ms: float = 0.0
    models: list[str] = field(default_factory=list)
    last_checked: float = 0.0  # monotonic timestamp
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "url": self.url,
            "healthy": self.healthy,
            "latency_ms": self.latency_ms,
            "models": self.models,
            "last_checked_ago_s": (
                round(time.monotonic() - self.last_checked, 1)
                if self.last_checked
                else None
            ),
            "error": self.error,
        }


# ── Cluster manager ───────────────────────────────────────────────────────────


class OllamaClusterManager:
    """
    Manages a pool of Ollama nodes with health polling and routing.

    Thread-safe: the health cache is read/written under ``_lock``.
    Background daemon thread polls health every ``health_check_interval`` s.
    """

    def __init__(
        self,
        nodes: list,
        routing: str,
        health_check_interval: int,
        fallback_url: str,
    ) -> None:
        """
        Args:
            nodes: list of OllamaNodeConfig from settings (or compatible duck-typed objects).
            routing: "round_robin" | "primary_first" | "least_busy"
            health_check_interval: seconds between background health polls.
            fallback_url: URL returned when cluster is empty or all nodes unhealthy.
        """
        self._nodes: list = list(nodes)
        self._routing = routing
        self._health_check_interval = health_check_interval
        self._fallback_url = fallback_url

        self._health: dict[str, NodeHealth] = {}
        self._lock = threading.Lock()
        self._rr_index = 0
        self._started = False

        # Seed health cache with "not yet checked" state
        for node in self._nodes:
            if getattr(node, "enabled", True):
                self._health[node.label] = NodeHealth(
                    label=node.label,
                    url=node.url,
                    healthy=False,
                    last_checked=0.0,
                    error="not yet checked",
                )

    # ── Background polling ────────────────────────────────────────────────────

    def start_background_polling(self) -> None:
        """Start the background health polling daemon thread (idempotent)."""
        if self._started or not self._nodes:
            return
        self._started = True
        t = threading.Thread(
            target=self._poll_loop,
            daemon=True,
            name="ollama-cluster-health",
        )
        t.start()
        logger.info(
            "Ollama cluster: started health polling for %d node(s)", len(self._nodes)
        )

    def _poll_loop(self) -> None:
        """Background thread: poll all nodes every ``_health_check_interval`` seconds."""
        while True:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    statuses = loop.run_until_complete(self.check_all())
                    with self._lock:
                        for s in statuses:
                            self._health[s.label] = s
                finally:
                    loop.close()
            except Exception as e:
                logger.debug("Cluster health poll error: %s", e)
            time.sleep(self._health_check_interval)

    # ── URL selection ─────────────────────────────────────────────────────────

    def get_healthy_url(self, prefer_label: Optional[str] = None) -> str:
        """
        Return the base URL of a healthy Ollama node.

        Starts background polling on first call if not already running.
        Returns ``_fallback_url`` when no nodes are configured or all are down.

        Args:
            prefer_label: if set, returns this node's URL when it is healthy,
                          regardless of routing strategy.
        """
        if not self._nodes:
            return self._fallback_url

        # Lazily start polling on first call
        if not self._started:
            self.start_background_polling()

        with self._lock:
            healthy = [h for h in self._health.values() if h.healthy]

        if not healthy:
            logger.debug("Ollama cluster: all nodes unhealthy, using fallback URL")
            return self._fallback_url

        # Honour label preference
        if prefer_label:
            match = next((h for h in healthy if h.label == prefer_label), None)
            if match:
                return match.url

        if self._routing == "primary_first":
            for node in self._nodes:
                if not getattr(node, "enabled", True):
                    continue
                h = next((x for x in healthy if x.label == node.label), None)
                if h:
                    return h.url

        elif self._routing == "least_busy":
            best = min(
                healthy,
                key=lambda h: h.latency_ms if h.latency_ms > 0 else 99999.0,
            )
            return best.url

        else:  # round_robin (default)
            urls = [h.url for h in healthy]
            with self._lock:
                idx = self._rr_index % len(urls)
                self._rr_index += 1
            return urls[idx]

        return self._fallback_url

    # ── Health checks ─────────────────────────────────────────────────────────

    async def check_node(
        self, url: str, label: str, timeout: float = 10.0
    ) -> NodeHealth:
        """Perform a live health check on a single Ollama node."""
        import httpx

        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(f"{url.rstrip('/')}/api/tags")
                latency_ms = (time.monotonic() - t0) * 1000
                if resp.status_code == 200:
                    data = resp.json()
                    models = [m["name"] for m in data.get("models", [])]
                    return NodeHealth(
                        label=label,
                        url=url,
                        healthy=True,
                        latency_ms=round(latency_ms, 1),
                        models=models,
                        last_checked=time.monotonic(),
                    )
                return NodeHealth(
                    label=label,
                    url=url,
                    healthy=False,
                    latency_ms=round(latency_ms, 1),
                    last_checked=time.monotonic(),
                    error=f"HTTP {resp.status_code}",
                )
        except Exception as e:
            latency_ms = (time.monotonic() - t0) * 1000
            return NodeHealth(
                label=label,
                url=url,
                healthy=False,
                latency_ms=round(latency_ms, 1),
                last_checked=time.monotonic(),
                error=str(e)[:200],
            )

    async def check_all(self) -> list[NodeHealth]:
        """Perform live health checks on all enabled nodes concurrently."""
        enabled = [n for n in self._nodes if getattr(n, "enabled", True)]
        if not enabled:
            return []
        tasks = [
            self.check_node(n.url, n.label, getattr(n, "timeout", 10.0))
            for n in enabled
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out: list[NodeHealth] = []
        for node, r in zip(enabled, results):
            if isinstance(r, Exception):
                out.append(
                    NodeHealth(
                        label=node.label,
                        url=node.url,
                        healthy=False,
                        last_checked=time.monotonic(),
                        error=str(r)[:200],
                    )
                )
            else:
                out.append(r)  # type: ignore[arg-type]
        return out

    # ── Snapshot ─────────────────────────────────────────────────────────────

    def get_all_status(self) -> list[NodeHealth]:
        """Return the current cached health snapshot for all nodes."""
        with self._lock:
            return list(self._health.values())

    # ── Runtime node management ───────────────────────────────────────────────

    def add_node(
        self,
        url: str,
        label: str,
        weight: int = 1,
        timeout: float = 10.0,
        enabled: bool = True,
    ) -> None:
        """
        Dynamically add a node to the running cluster.

        The node appears in health checks immediately; background polling will
        probe it on the next cycle.

        Raises:
            ValueError: if a node with ``label`` already exists.
        """
        existing = {n.label for n in self._nodes}
        if label in existing:
            raise ValueError(f"Node with label '{label}' already exists")

        # Build a minimal duck-typed node object
        class _Node:
            pass

        node = _Node()
        node.url = url  # type: ignore[attr-defined]
        node.label = label  # type: ignore[attr-defined]
        node.weight = weight  # type: ignore[attr-defined]
        node.enabled = enabled  # type: ignore[attr-defined]
        node.timeout = timeout  # type: ignore[attr-defined]

        with self._lock:
            self._nodes.append(node)
            self._health[label] = NodeHealth(
                label=label,
                url=url,
                healthy=False,
                last_checked=0.0,
                error="not yet checked",
            )

        # Ensure background polling is running now that we have a node
        if not self._started:
            self.start_background_polling()

        logger.info("Cluster: added node '%s' at %s", label, url)

    def remove_node(self, label: str) -> bool:
        """
        Remove a node from the cluster by label.

        Returns:
            True if the node was found and removed, False otherwise.
        """
        with self._lock:
            before = len(self._nodes)
            self._nodes = [n for n in self._nodes if n.label != label]
            self._health.pop(label, None)
            removed = len(self._nodes) < before

        if removed:
            logger.info("Cluster: removed node '%s'", label)
        return removed

    def update_health(self, status: NodeHealth) -> None:
        """Update the cached health entry for a node (called after a manual check)."""
        with self._lock:
            self._health[status.label] = status


# ── Module-level singleton ────────────────────────────────────────────────────

_manager: Optional[OllamaClusterManager] = None
_manager_lock = threading.Lock()


def get_cluster_manager() -> OllamaClusterManager:
    """
    Return the module-level singleton OllamaClusterManager.

    Lazily initialised from ``settings.local_services.ollama_cluster`` on first
    call.  Safe to call from multiple threads — protected by ``_manager_lock``.
    """
    global _manager
    if _manager is not None:
        return _manager

    with _manager_lock:
        if _manager is not None:
            return _manager

        from config.settings import settings

        cluster_cfg = settings.local_services.ollama_cluster
        fallback_url = settings.local_services.ollama.resolved_url()

        _manager = OllamaClusterManager(
            nodes=cluster_cfg.nodes,
            routing=cluster_cfg.routing,
            health_check_interval=cluster_cfg.health_check_interval,
            fallback_url=fallback_url,
        )
        if cluster_cfg.nodes:
            _manager.start_background_polling()
        return _manager


def reset_cluster_manager() -> None:
    """
    Reset the singleton (for testing only).
    After this call, the next ``get_cluster_manager()`` re-reads settings.
    """
    global _manager
    with _manager_lock:
        _manager = None
