# LegionForge

**A local-first, security-native AI agent framework built on LangGraph.**

> Security is enforced in the execution path — not layered on afterward.

---

## What Is This?

LegionForge is an open-source framework for building hardened AI agent systems on local hardware. It runs local LLMs (via Ollama) or cloud APIs (OpenAI, Anthropic), with a full security stack baked into every layer of the execution pipeline.

**The one-line pitch:** The hardened, self-hosted alternative to cloud agent platforms — and a security layer that other agent frameworks can plug into.

---

## Core Design Principles

| Principle | Implementation |
|---|---|
| **Fail-safe tiering** | `halt → sandbox/retry → degrade` — never silent failure |
| **Human gates on all mutations** | No component autonomously changes security rules, promotes tools, or escalates privileges |
| **Replace AI with determinism** | Repeated deterministic tasks are crystallized into signed, containerized tools with zero LLM overhead |
| **Validate at trust boundaries** | Guardian enforces checks at every inbound/outbound boundary — agents are processing nodes, not trust boundaries |
| **Privilege tied to tasks** | Short-lived task tokens scoped to exactly what the current task requires |

---

## Security Architecture

### Guardian Sidecar
A standalone FastAPI process (`:9766`) that runs a **deterministic-only** 6-check pipeline — no LLM calls in the hot path. Fast, auditable, unpoisonable.

```
Check 0: Tool revocation (REVOKED status — immediate halt)
Check 1: Tool registry + hash validation
Check 2: Capability boundary enforcement (negative capability list)
Check 3: Destructive pattern detection
Check 4: Agent sequence contract validation
Check 5: Hash integrity (Ed25519 signed tools)
```

### Crystallization Pipeline
When agents solve the same deterministic problem repeatedly, the Observer nominates it for crystallization. The Crystallizer generates a deterministic function + test suite. A Pre-HITL Analyzer (AST guards + behavioral diff) runs before human approval. Once signed, the tool has zero LLM runtime cost.

```
Observer → Crystallizer → Pre-HITL Analyzer → Human gate → Ed25519-signed tool
```

### Threat Coverage

| Threat | Defense |
|---|---|
| **Tool Poisoning** | Hash validation at registration + cryptographic signing |
| **Rug-Pull** | Hash mismatch detection + signed tool versions |
| **Prompt Injection** (direct + indirect) | Input/output sanitizer + RAG provenance scoring |
| **Capability Amplification** | Negative capability list enforced by Guardian |
| **Resource Bomb / Economic DOS** | Pre-execution token cost estimator + rate limiter |
| **Credential Theft** | Keychain storage + PII redaction from all outbound calls |
| **RAG / Memory Poisoning** | Document provenance + embedding trust scoring |
| **Multi-Agent Cascade** | Orchestrator-only routing + signed inter-agent messages |
| **Supply Chain** | AI-BOM + signed tool library |
| **TOCTOU** | `approved_snapshot` verified post-execution in `SecureToolNode` |

---

## Phase Roadmap

| Phase | What Was Built | Status |
|---|---|---|
| **0** | PostgreSQL + pgvector, async LLM factory, health server, 23 smoke tests | ✅ Complete |
| **1** | Researcher agent, tool registry + hash validation, capability boundaries, threat event logging | ✅ Complete |
| **2** | Docker containerization, Guardian security sidecar, immutable audit log (SHA-256 hash chain), RAG provenance | ✅ Complete |
| **3** | JWT task tokens + ACLs, sub-agent orchestrator, sandbox retry tier | ✅ Complete |
| **4** | Threat Analyst agent, adaptive Guardian rules, AI Bill of Materials | ✅ Complete |
| **5** | Crystallization Pipeline — Observer + Crystallizer agents, pre-HITL analyzer, Ed25519-signed tools | ✅ Complete |
| **5.5** | Security hardening: DB RBAC, AST bypass guards (subscript/MRO/globals), tool revocation, TOCTOU mitigation, Ollama model integrity | ✅ Complete |
| **6** | PentestAgent — air-gapped red-team bot, 8 attack classes × 3 variants, stop-at-proof | ✅ Complete |
| **7** | Guardian feedback loop, SECURITY.md, v1.0 readiness | ✅ Complete |
| **8** | Gateway service (:8080), task queue, SSE streaming, web UI, A2A + MCP, Discord connector | ✅ Complete |
| **9** | langchain 1.x migration, tool library (5 tools), parallel fan-out, Phase 9.5 hardening sprint | ✅ Complete |
| **10** | Multi-user auth — DB-backed stream tokens, per-user daily budgets, `/usage/me`, user CLI | ✅ Complete |
| **11** | SecureToolNode security fix, integration tests (35), `AuthBackend` protocol, `Dockerfile.gateway`, `docs/SCALING.md` | ✅ Complete |

**430/430 smoke tests passing.** 35 integration tests passing. No running services required for smoke tests. Runs in ~2 seconds.

---

## Requirements

| Component | Version | Notes |
|---|---|---|
| Python | 3.11+ | via pyenv recommended |
| PostgreSQL | 16 or 17 | with pgvector extension |
| Ollama | latest | for local LLM inference |
| Docker | 24+ | for Guardian sidecar + analyzer container |
| macOS | 14+ (Apple Silicon) | primary target; Linux support planned |

---

## Quick Start

```bash
# 1. Clone and set up the virtual environment
git clone https://github.com/jp-cruz/LegionForge.git
cd LegionForge
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Set your hardware profile
export AGENT_HARDWARE_PROFILE=mac_m4_mini_16gb  # or mac_m5_mini_32gb

# 3. Initialize the database
make db-init

# 4. Run smoke tests (no services required)
make test-smoke
# Expected: 200 passed in ~2s

# 5. Start the health server
make health-server
# Verify: curl http://localhost:8765/health
```

---

## Key Files

| File | Purpose |
|---|---|
| `src/base_graph.py` | LangGraph agent template — copy to create new agents |
| `src/security/guardian.py` | Guardian sidecar — deterministic 6-check security pipeline |
| `src/security/core.py` | Keychain loader, PII redaction, injection detection, I/O sanitizer |
| `src/database.py` | Async PostgreSQL pool, LangGraph checkpointer, pgvector, threat event logging |
| `src/safeguards.py` | Three-layer loop protection (step counter, action history, token budget) |
| `src/tools/crystallization_analyzer.py` | Pre-HITL AST + behavioral diff analyzer |
| `src/tools/signing.py` | Ed25519 keypair management + tool manifest signing |
| `src/tools/model_integrity.py` | SHA256 GGUF streaming verification |
| `config/settings.py` | Pydantic settings singleton (loaded from hardware YAML profile) |
| `Makefile` | All development, test, and operational commands |

---

## Makefile Reference

```bash
make check           # Verify environment before starting
make start           # Full startup (drive → Ollama → PostgreSQL → model warmup)
make test-smoke      # 430 smoke tests, ~2s, no services required
make test-integration  # 35 integration tests (requires PostgreSQL)
make lint            # Black formatter check
make health-server   # Start health/status API at localhost:8765
make setup-db-roles  # Provision legionforge_app restricted PostgreSQL role (idempotent)
make verify-models   # Compute SHA256 of installed GGUF models for pinning
make build-analyzer  # Build legionforge-analyzer:latest Docker image (deny-default)
make revoke-tool     # POST /tools/{TOOL_ID}/revoke  (requires TOOL_ID=<id>)
make guardian-start  # Build + start Guardian sidecar via Docker Compose
make audit-log-verify # Verify SHA-256 hash chain integrity on audit_log
make build-pentest   # Build legionforge-pentest:latest air-gapped container
make pentest         # Run red-team attack suite in verify mode (stop-at-proof)
make pentest-resilience  # Run in resilience mode — explicit opt-in, prompts confirmation
make pentest-report  # Print most recent pentest report (or RUN_ID=<uuid>)
```

---

## Known Gaps (Accepted Residual Risk)

- **Embedding-level anomaly detection** — RAG poisoning at the semantic vector level is an open research problem. Provenance scoring and trust flagging exist; embedding-level detection is deferred.
- **pip-audit / dependency hash pinning** — Supply chain hygiene for transitive Python dependencies. Accepted residual risk.
- **GGUF hash pinning** — `make verify-models` prints hashes for pinning; `gguf_sha256: ""` in the hardware profile means model integrity is skipped until the operator pins the values.

---

## License

AGPL-3.0 with Section 7(b) attribution requirement.

Copyright 2026 John Paul "Jp" Cruz. Commercial licensing available — contact via GitHub Issues.

---

## Status

**Private development repository:** [LegionForge/LegionForge](https://github.com/LegionForge/LegionForge)

The codebase is currently in hardening and will be published here at v1.0. Watch this repository or visit [legionforge.org](https://legionforge.org) for updates.
