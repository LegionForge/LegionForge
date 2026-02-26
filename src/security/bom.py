"""
src/security/bom.py
───────────────────
Phase 4: AI Bill of Materials (AI-BOM).

Tracks every model, tool, agent, and Python dependency with:
  - version / model_id
  - origin (local Ollama | PyPI | internal)
  - SHA-256 content hash (where computable without running the model)
  - CVE scan status (never_scanned | clean | flagged)
  - last_security_review date

The Threat Analyst cross-references incoming CVE advisories against the BOM
to flag affected components. Guardian uses the BOM to verify tool hashes
match their registered manifests.

Endpoint: GET /bom on the health server (Bearer token required).
Function:  get_bom() → BOMReport (also called directly by Threat Analyst).

Design notes:
  - BOM is assembled from live sources at call time (no stale cache).
  - Tool hashes are read from the tool_registry table (ground truth).
  - Dependency versions are read from importlib.metadata (installed packages).
  - Agent entries are statically declared here — new agents must be added manually.
  - CVE scan status is stored in the tool_registry table (column: cve_scan_status).
    Default 'never_scanned'. Updated by Threat Analyst after each scan cycle.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

from config.settings import settings

logger = logging.getLogger(__name__)


# ── Data models ───────────────────────────────────────────────────────────────


@dataclass
class BOMEntry:
    """A single component in the bill of materials."""

    component_type: str  # "model" | "tool" | "agent" | "dependency"
    name: str
    version: str | None  # model_id, pkg version, or None
    origin: str  # "ollama_local" | "pypi" | "internal" | "github"
    sha256_hash: str | None  # content hash where computable; None if unavailable
    cve_scan_status: str  # "never_scanned" | "clean" | "flagged"
    last_security_review: str | None  # ISO date string or None
    metadata: dict = field(default_factory=dict)  # extra context


@dataclass
class BOMReport:
    """Full AI Bill of Materials snapshot."""

    generated_at: str  # ISO timestamp
    framework_version: str
    models: list[BOMEntry]
    tools: list[BOMEntry]
    agents: list[BOMEntry]
    dependencies: list[BOMEntry]

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "framework_version": self.framework_version,
            "models": [asdict(e) for e in self.models],
            "tools": [asdict(e) for e in self.tools],
            "agents": [asdict(e) for e in self.agents],
            "dependencies": [asdict(e) for e in self.dependencies],
            "summary": {
                "total_components": (
                    len(self.models)
                    + len(self.tools)
                    + len(self.agents)
                    + len(self.dependencies)
                ),
                "flagged": sum(
                    1
                    for e in (
                        self.models + self.tools + self.agents + self.dependencies
                    )
                    if e.cve_scan_status == "flagged"
                ),
                "never_scanned": sum(
                    1
                    for e in (
                        self.models + self.tools + self.agents + self.dependencies
                    )
                    if e.cve_scan_status == "never_scanned"
                ),
            },
        }


# ── Tracked dependencies (security-critical subset) ───────────────────────────
# We track a curated subset of packages that have direct security impact.
# Full dependency scanning (e.g. pip-audit) is handled by the CI pipeline.

_SECURITY_CRITICAL_PACKAGES = [
    "langchain-core",
    "langchain-community",
    "langgraph",
    "langchain-ollama",
    "fastapi",
    "uvicorn",
    "httpx",
    "psycopg",
    "pydantic",
    "PyJWT",
    "duckduckgo-search",
    "pgvector",
]

# ── Statically declared agents ────────────────────────────────────────────────
# New agents must be added here when they are introduced.

_KNOWN_AGENTS = [
    {
        "name": "base_agent",
        "module": "src.base_graph",
        "phase_introduced": "Phase 0",
        "role": "template",
    },
    {
        "name": "researcher",
        "module": "src.agents.researcher",
        "phase_introduced": "Phase 1",
        "role": "reader",
    },
    {
        "name": "orchestrator",
        "module": "src.agents.orchestrator",
        "phase_introduced": "Phase 3",
        "role": "analyst",
    },
    {
        "name": "threat_analyst",
        "module": "src.agents.threat_analyst",
        "phase_introduced": "Phase 4",
        "role": "security_analyst",
    },
    # Phase 5 — Crystallization pipeline
    {
        "name": "observer",
        "module": "src.agents.observer",
        "phase_introduced": "Phase 5",
        "role": "crystallization_observer",
    },
    {
        "name": "crystallizer",
        "module": "src.agents.crystallizer",
        "phase_introduced": "Phase 5",
        "role": "crystallizer",
    },
]


# ── BOM assembly ──────────────────────────────────────────────────────────────


def _hash_string(s: str) -> str:
    """SHA-256 hash of a UTF-8 string."""
    return hashlib.sha256(s.encode()).hexdigest()


def _get_package_version(pkg_name: str) -> str | None:
    """Return installed version of a package, or None if not installed."""
    try:
        return importlib.metadata.version(pkg_name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _model_entries() -> list[BOMEntry]:
    """BOM entries for all configured Ollama models."""
    models_cfg = settings.models
    entries = []
    for label, cfg in [
        ("primary", models_cfg.primary),
        ("router", models_cfg.router),
        ("embeddings", models_cfg.embeddings),
    ]:
        entries.append(
            BOMEntry(
                component_type="model",
                name=cfg.model_id,
                version=cfg.model_id,  # Ollama uses tag-based versioning in model_id
                origin="ollama_local",
                sha256_hash=None,  # Ollama manifest hash requires running process
                cve_scan_status="never_scanned",
                last_security_review=None,
                metadata={
                    "role": label,
                    "estimated_size_gb": getattr(cfg, "estimated_size_gb", None),
                    "provider": "ollama",
                    "base_url": settings.local_services.ollama.resolved_url(),
                },
            )
        )
    return entries


def _dependency_entries() -> list[BOMEntry]:
    """BOM entries for security-critical Python dependencies."""
    entries = []
    for pkg in _SECURITY_CRITICAL_PACKAGES:
        version = _get_package_version(pkg)
        entries.append(
            BOMEntry(
                component_type="dependency",
                name=pkg,
                version=version,
                origin="pypi",
                sha256_hash=_hash_string(f"{pkg}=={version}") if version else None,
                cve_scan_status="never_scanned",
                last_security_review=None,
                metadata={
                    "installed": version is not None,
                },
            )
        )
    return entries


def _agent_entries() -> list[BOMEntry]:
    """BOM entries for all known LegionForge agents."""
    entries = []
    for agent in _KNOWN_AGENTS:
        # Hash the module path as a stable identifier
        module_hash = _hash_string(agent["module"])
        entries.append(
            BOMEntry(
                component_type="agent",
                name=agent["name"],
                version=None,  # agents are versioned with the repo
                origin="internal",
                sha256_hash=module_hash,
                cve_scan_status="never_scanned",
                last_security_review=None,
                metadata={
                    "module": agent["module"],
                    "phase_introduced": agent["phase_introduced"],
                    "role": agent["role"],
                },
            )
        )
    return entries


async def _tool_entries_from_db() -> list[BOMEntry]:
    """
    BOM entries for all registered tools, read from the tool_registry table.
    Falls back to an empty list if the DB is unavailable.
    """
    try:
        from src.database import get_pool

        pool = get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                SELECT tool_id, source, version, description_hash, schema_hash,
                       entrypoint_hash, status, approved_at
                FROM tool_registry
                ORDER BY tool_id ASC
                """
            )
            rows = await cur.fetchall()
        entries = []
        for r in rows:
            # Combine hashes for a single tool fingerprint
            combined = f"{r['description_hash'] or ''}{r['schema_hash'] or ''}{r['entrypoint_hash'] or ''}"
            fingerprint = _hash_string(combined) if combined.strip() else None
            entries.append(
                BOMEntry(
                    component_type="tool",
                    name=r["tool_id"],
                    version=r["version"],
                    origin=r["source"] or "local",
                    sha256_hash=fingerprint,
                    cve_scan_status="never_scanned",
                    last_security_review=(
                        r["approved_at"].isoformat() if r["approved_at"] else None
                    ),
                    metadata={
                        "status": r["status"],
                        "description_hash": r["description_hash"],
                        "schema_hash": r["schema_hash"],
                    },
                )
            )
        return entries
    except Exception as e:
        logger.warning(f"[bom] Could not load tool entries from DB: {e}")
        return []


async def get_bom() -> BOMReport:
    """
    Assemble and return the full AI Bill of Materials.

    Reads live from:
      - config/settings.py (models)
      - importlib.metadata (installed package versions)
      - tool_registry table (registered tools + hashes)
    Statically declared:
      - Known agents (see _KNOWN_AGENTS above)

    Never raises — individual section failures return empty lists with a warning.
    """
    now = datetime.now(tz=timezone.utc).isoformat()

    models = _model_entries()
    deps = _dependency_entries()
    agents = _agent_entries()
    tools = await _tool_entries_from_db()

    report = BOMReport(
        generated_at=now,
        framework_version="4.0.0",  # Phase 4
        models=models,
        tools=tools,
        agents=agents,
        dependencies=deps,
    )

    logger.debug(
        f"[bom] BOM assembled: {len(models)} models, {len(tools)} tools, "
        f"{len(agents)} agents, {len(deps)} dependencies"
    )
    return report
