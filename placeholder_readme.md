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
A standalone FastAPI process (`:9766`) that runs a **deterministic-only** 7-check pipeline — no LLM calls in the hot path. Fast, auditable, unpoisonable.

```
Check 0: Tool revocation  (REVOKED status — immediate halt)
Check 1: Tool registry + SHA-256 hash validation
Check 2: Capability boundary enforcement (negative capability list)
Check 3: Destructive pattern detection in tool args
Check 4: Agent sequence contract validation
Check 5: Ed25519 signature verification
Check 6: Adaptive threat rules (hot-reloaded every 10s — no restart needed)
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
| **0** | PostgreSQL + pgvector, async LLM factory, health server | ✅ Complete |
| **1** | Researcher agent, tool registry + hash validation, capability boundaries, threat event logging | ✅ Complete |
| **2** | Docker containerization, Guardian security sidecar, immutable audit log (SHA-256 hash chain), RAG provenance | ✅ Complete |
| **3** | JWT task tokens + ACLs, sub-agent orchestrator, sandbox retry tier | ✅ Complete |
| **4** | Threat Analyst agent, adaptive Guardian rules, AI Bill of Materials | ✅ Complete |
| **5** | Crystallization Pipeline — Observer + Crystallizer agents, pre-HITL analyzer, Ed25519-signed tools | ✅ Complete |
| **5.5** | Security hardening: DB RBAC, AST bypass guards, tool revocation, TOCTOU mitigation, model integrity | ✅ Complete |
| **6** | PentestAgent — air-gapped red-team bot, 8 attack classes × 3 variants, stop-at-proof | ✅ Complete |
| **7** | Guardian feedback loop, SECURITY.md, v1.0 readiness hardening | ✅ Complete |
| **8** | Gateway service (:8080), task queue, SSE streaming, web UI, A2A + MCP, Discord connector | ✅ Complete |
| **9** | langchain 1.x migration, tool library (5 tools), parallel fan-out, Phase 9.5 hardening sprint | ✅ Complete |
| **10** | Multi-user auth — DB-backed stream tokens, per-user daily budgets, `/usage/me`, user CLI | ✅ Complete |
| **11** | SecureToolNode security fix, 38 integration tests, `AuthBackend` protocol, `Dockerfile.gateway`, `docs/SCALING.md` | ✅ Complete |
| **12** | Multi-provider auth registry — `OIDCBackend`, `GitHubOAuthBackend`, `LDAPBackend`, `KerberosBackend` | ✅ Complete |
| **13** | Kerberos GSSAPI real implementation, Redis-backed stream tokens, multi-instance docker-compose + Nginx | ✅ Complete |
| **14** | Redis global budget counters, Prometheus `/metrics` endpoint, `X-Request-ID` middleware | ✅ Complete |
| **15** | Polished web UI — localStorage key+history, cancel, tool call blocks, live timer, copy, keyboard shortcut | ✅ Complete |
| **16** | Channel connectors — Telegram (polling), Slack (Socket Mode), generic Webhook (HMAC + async callback) | ✅ Complete |
| **60–381** | 381-tool operator dashboard UI library — every gateway API endpoint surfaced as a JS function | ✅ Complete |
| **Web + Browser tools** | `web_fetch_js` Playwright headless browser for JS-rendered sites; two-layer SSRF guard | ✅ Complete |
| **Guardian G1–G4** | `legionforge_guardian` standalone package (PyPI published, public repo live, auto-sync CI); backward-compat shim in `src/security/guardian.py` | ✅ Complete |

**2133/2133 smoke tests passing.** 38/38 integration tests. 5/5 Kerberos live-KDC tests. 40/40 UI tests. 106/106 TestLab suite tests. 79/79 tool accuracy tests. Smoke suite runs in ~21 seconds (no external services required).

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
git clone https://github.com/LegionForge/LegionForge.git
cd LegionForge
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Set your hardware profile
export AGENT_HARDWARE_PROFILE=mac_m4_mini_16gb

# 3. Store your PostgreSQL admin password
echo "localhost:5432:*:$(whoami):yourpassword" >> ~/.pgpass && chmod 0600 ~/.pgpass
# New install with default Homebrew trust auth? Use:
# export POSTGRES_TRUST_AUTH=true

# 4. Initialize the database and generate security secrets
make db-init
make setup-task-token-secret
make setup-signing-key

# 5. Run smoke tests (no services required)
make test-smoke
# Expected: 2125 passed in ~21s

# 6. Start services (three terminals)
make health-server   # Operator API :8765
make gateway-start   # User API + Web UI :8080
make guardian-start  # Security sidecar :9766 (requires Docker)

# 7. Create a user and open the web UI
make create-user USERNAME=myname
open http://localhost:8080/ui
```

---

## Key Files

| File | Purpose |
|---|---|
| `src/base_graph.py` | LangGraph agent template — copy to create new agents |
| `src/security/guardian.py` | Guardian sidecar — deterministic 7-check security pipeline |
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
make test-smoke      # 2133 smoke tests, ~21s, no services required
make test-integration  # 38 integration tests (requires PostgreSQL)
make test-ui         # 40 UI tests (Playwright)
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
make discord-start   # Start Discord bot connector
make telegram-start  # Start Telegram bot connector
make slack-start     # Start Slack Socket Mode connector
make webhook-start   # Start generic inbound/outbound webhook connector (:8081)
```

---

## Known Gaps (Accepted Residual Risk)

- **Embedding-level anomaly detection** — RAG poisoning at the semantic vector level is an open research problem. Provenance scoring and trust flagging exist; embedding-level detection is deferred.
- **pip-audit / dependency hash pinning** — Supply chain hygiene for transitive Python dependencies. Managed via Dependabot; transitive hash pinning is accepted residual risk.

---

## License

AGPL-3.0 with Section 7(b) attribution requirement.

Copyright 2026 John Paul "Jp" Cruz. Commercial licensing available — contact via GitHub Issues.

---

## Status

**v0.7.1-alpha** — Phases 0–381 complete + web browser tools + Guardian G1–G4 (PyPI published). 2133/2133 smoke tests. 38/38 integration tests. 5/5 Kerberos live-KDC tests. 40/40 UI tests. 106/106 TestLab. 79/79 tool accuracy tests. All pre-v1.0 security blockers resolved.

Contributions, issues, and commercial licensing inquiries are welcome via [GitHub Issues](https://github.com/LegionForge/LegionForge/issues).
