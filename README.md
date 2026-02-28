# LegionForge

**Version:** 1.0.0 · **Updated:** 2026-02-28 · **Status:** Phases 0–11 complete — full security stack + multi-user gateway + integration tests + containerized gateway

---

A **local-first, security-native AI agent framework** built on LangGraph, designed for Apple Silicon Macs.
Agents run local LLMs via Ollama or fall back to cloud APIs. Security is built into the foundation — not bolted on later.

> **New to this project? Start with [`TLDR.md`](./TLDR.md)** — a plain-language summary of what we're building and why.

> **Design priorities:** Security · Reliability · Observability · Modularity
> **Non-negotiables:** Human gates on mutations · Loop safeguards · Keychain-only credential storage · Deterministic security hot paths

---

## Project Status

| Phase | Status | What It Is |
|---|---|---|
| 0 — Infrastructure | ✅ Complete | PostgreSQL, pgvector, LLM factory, health server, smoke tests |
| 1 — First Agent + Security Foundations | ✅ Complete | Researcher agent, tool hash validation, threat logging |
| 2 — Containerization + Guardian | ✅ Complete | Docker stack, Guardian sidecar, immutable audit log, sequence contracts |
| 3 — ACLs + Sub-Agents | ✅ Complete | JWT task tokens, role definitions, orchestrator + sub-agent architecture |
| 4 — Adaptive Threat Intelligence | ✅ Complete | Threat Analyst agent, adaptive Guardian rules, AI Bill of Materials |
| 5 — Crystallization Pipeline | ✅ Complete | Observer + Crystallizer agents, Pre-HITL analysis, Ed25519-signed tools |
| 5.5 — Security Hardening | ✅ Complete | DB RBAC, AST subscript+MRO guards, tool revocation, TOCTOU, model integrity |
| 6 — PentestAgent | ✅ Complete | Air-gapped red-team bot, 24 attack functions, 0 bypasses on clean deploy |
| 7 — Guardian Feedback Loop | ✅ Complete | Pentest→Guardian bridge, SECURITY.md, pre-release hardening |
| 8 — Gateway + Streaming + Discord | ✅ Complete | Gateway (:8080), SSE streaming, web UI, A2A + MCP, Discord connector |
| 9 — Tool Library + Fan-Out | ✅ Complete | langchain 1.x, 5 production tools, parallel fan-out, 9.5 hardening sprint |
| 10 — Multi-User Auth | ✅ Complete | DB-backed stream tokens, per-user budgets, `/usage/me`, user management CLI |
| 11 — Security Fix + Integration Tests | ✅ Complete | SecureToolNode fix, 35 integration tests, `AuthBackend` protocol, `Dockerfile.gateway`, `docs/SCALING.md` |
| 12 — Multi-Provider Auth Registry | ✅ Complete | `OIDCBackend`, `GitHubOAuthBackend`, `LDAPBackend`, `KerberosBackend` scaffold; multi-scheme `require_user`; `load_backend_from_settings()` |
| 13 — Redis State Layer + Kerberos + Multi-Instance | ✅ Complete | Real GSSAPI `KerberosBackend`; optional Redis stream tokens (`state.py`); `docker-compose.multi-instance.yml` + Nginx config |
| 14 — Redis Budgets + Prometheus + Request IDs | ✅ Complete | Redis INCRBY budget counters; `GET /metrics` Prometheus text; `X-Request-ID` middleware; Redis health in `/status` |
| 15 — Polished Web UI | ✅ Complete | localStorage key+history, cancel button, tool call blocks, live timer, token count, copy, Cmd+Enter, SSE retry |
| 16 — Channel Connectors | ✅ Complete | Telegram (polling), Slack (Socket Mode), Webhook (HMAC+async callback); shared `src/connectors/base.py` |

**484/484 smoke tests passing. 35 integration tests passing. Full security stack + multi-user gateway + multi-provider auth + Telegram/Slack/Webhook connectors operational.**

**→ Full roadmap:** [`PHASE_PLAN.md`](./PHASE_PLAN.md)

---

## Installation

### Prerequisites

| Requirement | Notes |
|---|---|
| macOS Apple Silicon | M4/M5 native. M1/M2/M3 work — update the hardware profile. |
| [Homebrew](https://brew.sh) | Package manager for PostgreSQL, Ollama, Python |
| Python 3.11 | Use `pyenv` (recommended) or `brew install python@3.11` |
| [Ollama](https://ollama.ai) | Local LLM runtime. Install via Homebrew or the macOS app. |
| [Docker Desktop](https://www.docker.com/products/docker-desktop/) | Required for the Guardian security sidecar. |
| [LangSmith](https://smith.langchain.com) account | Free tier works. Used for agent run tracing. Optional but recommended. |

---

### Step 1 — Clone and Create the Virtual Environment

```bash
git clone https://github.com/LegionForge/LegionForge.git
cd LegionForge

python3.11 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

---

### Step 2 — Configure Your Hardware Profile

The active profile is `config/hardware_profiles/mac_m4_mini_16gb.yaml`. If your external drive has a different mount path, update it:

```yaml
# config/hardware_profiles/mac_m4_mini_16gb.yaml
storage:
  external:
    mount_path: "/Volumes/YOUR_DRIVE_NAME"   # ← update this
```

> **Note:** The `Makefile` auto-detects its base directory via `git rev-parse --show-toplevel`. Run all `make` targets from the project root (where `.git` lives) and this resolves automatically.

To use a different hardware profile (e.g., for an M5 Mac Mini):
```bash
export AGENT_HARDWARE_PROFILE=mac_m5_mini_32gb
```

---

### Step 3 — Install PostgreSQL and Create the Database

```bash
brew install postgresql@17
brew services start postgresql@17

# Create the database (replace 'your_username' with your macOS username)
createdb -U your_username legionforge
```

Store the PostgreSQL password in macOS Keychain (not in any file):

```bash
security add-generic-password -s postgres -a api_key -w 'YOUR_PG_PASSWORD' -U
```

Then add this line to your `~/.zshrc` so it loads automatically:

```bash
export POSTGRES_PASSWORD=$(security find-generic-password -s postgres -a api_key -w 2>/dev/null)
```

Apply it now:
```bash
source ~/.zshrc
```

> **Why Keychain?** No secrets ever live in `.env` files, config files, or environment variables that could be committed. All credentials are read from macOS Keychain at runtime.

---

### Step 4 — Store API Keys in Keychain

Add each key you have. All are optional except the PostgreSQL password (required).

```bash
# LangSmith — agent run tracing (free tier works)
security add-generic-password -s langsmith -a api_key -w 'lsv2_YOUR_KEY' -U

# OpenAI — cloud fallback (optional)
security add-generic-password -s openai -a api_key -w 'sk-YOUR_KEY' -U

# Anthropic — cloud fallback (optional)
security add-generic-password -s anthropic -a api_key -w 'sk-ant-YOUR_KEY' -U
```

Verify a key loaded correctly:
```bash
security find-generic-password -s langsmith -a api_key -w
```

---

### Step 5 — Pull Local Models

```bash
# Start Ollama first
brew services start ollama

# Pull the three required models (~7GB total)
ollama pull llama3.1:8b          # Primary reasoning model (~4.9GB)
ollama pull qwen2.5:3b           # Router / fast structured analysis (~1.9GB)
ollama pull nomic-embed-text     # Embeddings for RAG (~274MB)
```

Verify models loaded:
```bash
ollama list
```

---

### Step 6 — Initialize the Database

This creates all tables: `api_usage`, `health_metrics`, `documents` (pgvector/HNSW), `threat_events`, `tool_registry`, `audit_log`, `agent_profiles`, `threat_rules`, and the LangGraph checkpoint tables.

```bash
make db-init
```

---

### Step 7 — One-Time Setup (run once, then done)

```bash
# Generate and store the JWT signing secret for task tokens
make setup-task-token-secret

# Register tool manifests for each agent
make register-researcher-tools
make register-orchestrator-tools
make register-threat-analyst-tools

# Register expected tool-call sequences for Guardian sequence checking
make register-agent-sequences
```

---

### Step 8 — Start Guardian (Docker)

Guardian is a security sidecar that runs as a Docker container and validates every tool call before it executes. It has zero LLM dependency — pure deterministic checks.

```bash
# Launch Docker Desktop first (GUI or CLI), then:
make docker-build
make guardian-start

# Verify Guardian is healthy
curl http://localhost:9766/health
```

> **Note:** If you skip Guardian, agents still run safely — `guardian_enabled: false` in your settings will use the Phase 1 stub instead of failing. Set it in `config/hardware_profiles/mac_m4_mini_16gb.yaml`:
> ```yaml
> security:
>   guardian_enabled: false
> ```

---

### Step 9 — Verify Everything

```bash
# Run all 422 smoke tests (no external services required — runs in ~2s)
make test-smoke

# Run the full system check (drive, venv, Keychain, Ollama, Guardian)
make check
```

Expected output from `make test-smoke`:
```
484 passed in ~3.0s
```

---

### Step 10 — Start the Framework

```bash
# Start all services: Ollama, PostgreSQL, model warmup, Guardian
make start

# In a separate terminal — start the health/metrics server
make health-server
```

Verify the health server:
```bash
# Quick liveness check (no auth required)
make health
# → {"status": "ok", "version": "4.0.0", ...}

# Full status (Bearer token required — generated automatically on first run)
make status
```

---

### Quick Reference: Common Commands

```bash
source venv/bin/activate   # Always activate venv first

make start                 # Full startup (Ollama + PostgreSQL + Guardian + warmup)
make stop                  # Graceful shutdown
make health-server         # Start health/metrics server (separate terminal)

make test-smoke            # 484 smoke tests, ~3.0s, no services required
make lint                  # Black formatter check
make format                # Auto-format

make check                 # System preflight (drive, venv, models, Guardian)
make health                # Quick liveness: GET /health
make status                # Full status: GET /status (Bearer auth)
make bom                   # AI Bill of Materials: GET /bom
make pending-rules         # Show threat rules awaiting human approval

make db-init               # (Re-)initialize database tables
make db-start              # Start PostgreSQL
make guardian-start        # Start Guardian Docker container
make guardian-logs         # Tail Guardian logs

make run-threat-analyst    # Run Threat Analyst agent (7-day threat window)
make security-audit        # Smoke tests + bandit static analysis
make audit-log-verify      # Verify audit log hash chain integrity

# Phase 5 — Crystallization pipeline
make setup-signing-key     # Generate Ed25519 keypair + store in Keychain (one-time)
make run-observer          # Scan audit_log for crystallization candidates
make run-crystallizer CANDIDATE_ID=<id>  # Generate deterministic function for a candidate
make pending-packages      # List packages awaiting human review
make approve-package PACKAGE_ID=<id>    # Sign + register crystallized tool
make reject-package PACKAGE_ID=<id>     # Reject a package with reason

# Phase 5.5 — Security hardening (run once after db-init)
make setup-db-roles        # Provision legionforge_app restricted PostgreSQL role + grants
make verify-models         # Compute SHA256 of GGUF files; pin in hardware profile
make build-analyzer        # Build legionforge-analyzer:latest deny-default Docker image
make revoke-tool TOOL_ID=<id>  # Immediately revoke a tool via health API (<10s propagation)
```

---

### Troubleshooting

**`make check` shows PostgreSQL password NOT loaded**
→ Run `source ~/.zshrc` and verify `echo $POSTGRES_PASSWORD` prints a value. If empty, re-add via `security add-generic-password`.

**`make db-init` fails with connection error**
→ Ensure PostgreSQL is running: `brew services start postgresql@17`. Verify database exists: `psql -U $(whoami) -l | grep legionforge`.

**`make guardian-start` fails**
→ Docker Desktop must be running. Check: `docker ps`. If Docker isn't on PATH, launch Docker Desktop from Applications first.

**Ollama models not found**
→ Run `ollama list` to confirm. If empty, re-run `ollama pull llama3.1:8b`. Ensure Ollama is running: `brew services start ollama`.

**`make test-smoke` shows fewer than 453 tests**
→ Ensure you're on `main` and the venv is activated. Run `git log --oneline -3` to verify you're at Phase 16 (commit referencing 484 smoke tests).

---

## Hardware Support

| Profile | Chip | RAM | Status |
|---|---|---|---|
| `mac_m4_mini_16gb` | M4 | 16GB | ✅ Active |
| `mac_m5_mini_32gb` | M5 | 32GB | 📋 Template (update on purchase) |

All hardware-specific values (memory limits, model sizes, concurrency limits, safeguard thresholds, paths) are read from a YAML profile. **Nothing is hardcoded.** Switch hardware by setting one environment variable:

```bash
export AGENT_HARDWARE_PROFILE=mac_m5_mini_32gb
```

---

## Project Structure

```
LegionForge/
├── TLDR.md                        # Start here — plain-language project summary
├── PROJECT_STATUS.md              # Current build state, infra details, todos
├── PHASE_PLAN.md                  # Full phased roadmap with exit criteria
├── RESEARCH.md                    # Threat taxonomy, design theory, open questions
├── CONTRIBUTING.md                # Branch strategy, commit conventions, test requirements
│
├── config/
│   ├── settings.py                # Pydantic config singleton
│   ├── roles.yaml                 # Four ACL roles: reader, analyst, operator, admin
│   └── hardware_profiles/
│       ├── mac_m4_mini_16gb.yaml  # Active profile
│       └── mac_m5_mini_32gb.yaml  # Template for future hardware
│
├── src/
│   ├── base_graph.py              # LangGraph agent template — copy for every new agent
│   ├── database.py                # Async PostgreSQL pool, pgvector, LangGraph checkpointer
│   ├── safeguards.py              # Three-layer loop protection + token budgets
│   ├── rate_limiter.py            # Per-provider rate limiting + cost alerts
│   ├── llm_factory.py             # Unified Ollama/OpenAI/Anthropic factory
│   ├── observability.py           # Structured logging + LangSmith upload
│   ├── health.py                  # FastAPI health/metrics server (localhost:8765)
│   │
│   ├── security/
│   │   ├── core.py                # Keychain loader, PII redaction, injection detection
│   │   ├── acl.py                 # JWT task token issuance + validation
│   │   ├── guardian.py            # Guardian FastAPI sidecar (localhost:9766)
│   │   ├── bom.py                 # AI Bill of Materials assembly
│   │   └── __init__.py            # Full backward-compat re-exports
│   │
│   ├── tools/
│   │   ├── crystallization_analyzer.py  # Pre-HITL AST + security + behavioral analysis
│   │   ├── signing.py             # Ed25519 tool manifest signing + verification
│   │   └── model_integrity.py     # SHA256 GGUF verification (Phase 5.5)
│   │
│   └── agents/
│       ├── researcher.py          # Researcher agent (web fetch, document store)
│       ├── orchestrator.py        # Orchestrator with master→derived token hierarchy
│       ├── observer.py            # Observer agent (nominates crystallization candidates)
│       ├── crystallizer.py        # Crystallizer agent (generates deterministic functions)
│       └── threat_analyst.py      # Threat Analyst (reads threat_events, proposes rules)
│
├── guardian/
│   ├── Dockerfile                 # Non-root, python:3.11-slim, minimal surface
│   └── requirements.txt           # fastapi, uvicorn, psycopg — NO LLM clients
│
├── tests/
│   ├── test_smoke.py              # 422 tests, no services required, ~1.5s
│   └── conftest.py
│
├── scripts/
│   ├── check_mount.sh             # Verify external drive mounted before agent start
│   ├── setup_postgres.sh          # One-time PostgreSQL setup helper
│   ├── db_setup_roles.sql         # Standalone SQL for legionforge_app role setup (Phase 5.5)
│   ├── run_observer.py            # Run Observer agent
│   └── run_crystallizer.py        # Run Crystallizer agent
│
├── config/
│   └── sandbox_profiles/
│       └── analyzer.sb            # macOS sandbox-exec profile for analyzer subprocess
│
├── Dockerfile.analyzer            # Deny-default analyzer sandbox (Phase 5.5)
├── docker-compose.yml             # Guardian on 127.0.0.1:9766; analyzer build-only service
└── Dockerfile.agent-base          # Full framework env, non-root agent user
```

---

## Security Architecture

Security is layered. Each phase adds a new layer — nothing from a prior phase is replaced.

| Layer | Component | Phase | Notes |
|---|---|---|---|
| Credential storage | macOS Keychain | 0 | No `.env` files with secrets, ever |
| PII redaction | `security/core.py` | 0 | Email, phone, SSN, card numbers — all outbound paths |
| Prompt injection detection | `security/core.py` | 0 | 20 regex patterns, hot path |
| Loop protection | `safeguards.py` | 0 | Three independent layers (recursion limit, step counter, action hash) |
| Rate limiting + cost alerts | `rate_limiter.py` | 0 | Hard daily caps, 80%/100% alert thresholds |
| Tool hash validation | `security/core.py` | 1 | Blocks tool poisoning / manifest rug-pull |
| Threat event logging | `database.py` | 1 | Structured log feeding Threat Analyst |
| Guardian security sidecar | `security/guardian.py` | 2 | 6-check pipeline before every tool call. Fail-safe: offline = halt |
| Immutable audit log | `database.py` | 2 | SHA-256 hash-chain, append-only |
| RAG document provenance | `security/core.py` | 2 | Trust scoring per ingested document |
| Sequence contracts | `database.py` + Guardian | 2 | Expected tool-call sequences per agent |
| Task-scoped ACL tokens | `security/acl.py` | 3 | Ephemeral per-run JWT, child ⊆ parent scope enforced |
| Sub-agent privilege hierarchy | `agents/orchestrator.py` | 3 | Master token → derived token, privilege never widens |
| Adaptive threat rules | Guardian check 6 | 4 | APPROVED rules from `threat_rules` table, hot-reloaded every 60s |
| AI Bill of Materials | `security/bom.py` | 4 | Model, agent, tool, dependency inventory with CVE scan status |
| Threat Analyst agent | `agents/threat_analyst.py` | 4 | Proposes rules from `threat_events` — cannot self-approve |
| Crystallized tool signing | `tools/signing.py` | 5 | Ed25519; tampering breaks signature |
| DB RBAC — restricted app user | `database.py` | 5.5 | `legionforge_app`: no DDL, no DELETE on audit tables |
| AST subscript + MRO guards | `tools/crystallization_analyzer.py` | 5.5 | Blocks `sys.modules['subprocess']`, MRO traversal, `globals()['eval']` |
| Tool revocation | Guardian + `health.py` | 5.5 | REVOKED status, Guardian TTL 10s, `/tools/{id}/revoke` |
| TOCTOU prevention | `base_graph.py` | 5.5 | `approved_snapshot` pre-loop; unexpected call_id → threat event + halt |
| Ollama model integrity | `tools/model_integrity.py` | 5.5 | SHA256 streaming GGUF verification on startup |
| Automated red-teaming | `agents/pentest_agent.py` | 6 | Air-gapped; manual trigger only |
| Per-user token budgets | `rate_limiter.py` + `database.py` | 10 | DB-backed daily caps per user; enforced at task submission |
| DB-backed stream tokens | `gateway/auth.py` + `database.py` | 10 | Persistent 30-min TTL tokens; survive gateway restart |

**→ Full threat research and design theory:** [`RESEARCH.md`](./RESEARCH.md)

---

## Guardian Security Sidecar

Guardian runs as a standalone Docker container (port 9766). It performs six deterministic checks before any tool call executes. No LLM is involved — pure logic.

```
Check 0: REVOKED status — tool revoked? → halt immediately (Phase 5.5)
Check 1: JWT task token validation (role + scope)
Check 2: Capability boundary (is this tool in the agent's allowed list?)
Check 3: Destructive pattern detection (rm -rf, DROP TABLE, etc.)
Check 4: Sequence contract (is this tool call in the expected sequence?)
Check 5: Tool hash integrity (does the tool manifest match the registry?)
Check 6: Adaptive rules (hot-reloaded from approved threat_rules table every 10s)
```

Guardian response tiers:
- `allowed` — proceed
- `sandbox` — retry in isolation (logged, no side effects)
- `halt` — force-end run immediately

**Guardian unavailable = fail-safe halt.** It never fails open.

---

## Loop Safeguards (Three Independent Layers)

1. **LangGraph recursion limit** — framework-level hard stop
2. **Step counter in state** — per-run explicit counter
3. **Action history tracker** — MD5 hash of tool call signatures, window=5, threshold=3

All limits are read from the active hardware profile. Nothing hardcoded.

---

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for branch strategy, commit conventions, and test requirements.

Short version: branch from `main`, never commit directly to `main`, write a smoke test alongside every new component. `make test-smoke` must pass before any PR merge.

---

## License

GNU Affero General Public License v3.0 (AGPL-3.0) with Section 7(b) attribution clause.

Copyright © 2026 John Paul "Jp" Cruz. See [`LICENSE`](./LICENSE) for full terms.
