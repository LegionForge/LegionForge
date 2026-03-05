# LegionForge

**A local-first, security-native AI agent framework built on LangGraph.**

> Security is enforced in the execution path — not layered on afterward.

[![Smoke Tests](https://github.com/jp-cruz/LegionForge/actions/workflows/smoke.yml/badge.svg)](https://github.com/jp-cruz/LegionForge/actions/workflows/smoke.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://opensource.org/licenses/AGPL-3.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-brightgreen.svg)](https://www.python.org/)

---

## What Is LegionForge?

LegionForge is an open-source framework for running hardened AI agent systems on your own hardware. It runs local LLMs via [Ollama](https://ollama.com) or cloud APIs (OpenAI, Anthropic), with a full security stack baked into every layer of the execution pipeline — not bolted on afterward.

**The one-line pitch:** The hardened, self-hosted alternative to cloud agent platforms — and a security layer that other agent frameworks can plug into.

**Why it exists:** In January 2026, OpenClaw hit 60,000 GitHub stars in 72 hours and 300,000+ users in weeks. Kaspersky found 512 vulnerabilities (8 critical). Cisco found active data exfiltration in third-party skills. LegionForge is built in the opposite order: security first, product on top.

---

## Key Numbers

| Metric | Value |
|---|---|
| Smoke tests (no services required) | **1946 / 1946 passing** (~16s) |
| Integration tests (PostgreSQL) | **38 / 38 passing** |
| Kerberos live-KDC tests | **5 / 5 passing** |
| UI tests (Playwright) | **40 / 40 passing** |
| Guardian security checks per tool call | **7** (deterministic, 0 LLM calls) |
| Threat classes covered | **11** |
| Prompt injection detection patterns | **29** (2-tier: halt + log) |
| Auth backends | **5** (API key, OIDC, GitHub, LDAP, Kerberos) |
| Channel connectors | **4** (Discord, Telegram, Slack, Webhook) |

---

## Core Design Principles

| Principle | Implementation |
|---|---|
| **Fail-safe tiering** | `halt → sandbox/retry → degrade` — never silent failure |
| **Human gates on all mutations** | No component autonomously changes security rules, promotes tools, or escalates privileges |
| **Replace AI with determinism** | Repeated deterministic tasks crystallize into signed, containerized tools with zero LLM overhead |
| **Validate at trust boundaries** | Guardian enforces checks at every inbound/outbound boundary — agents are processing nodes, not trust boundaries |
| **Privilege tied to tasks** | Short-lived JWT task tokens scoped to exactly what the current task requires |

---

## User Interfaces

Submit tasks from wherever you already are:

| Interface | How |
|---|---|
| **Web UI** | `http://localhost:8080/ui` — live SSE streaming, tool call blocks, session history |
| **Discord** | `!<task>` in any channel the bot can see |
| **Telegram** | `/<task>` to your bot |
| **Slack** | `!<task>` via Socket Mode (no public URL needed) |
| **Webhook** | `POST :8081/inbound` — HMAC-SHA256 verified, works with n8n / Zapier / any HTTP client |
| **REST API** | `POST /tasks` + `GET /tasks/{id}/stream` — full SSE streaming |

---

## Security Architecture

### Guardian Sidecar

A standalone FastAPI process (`:9766`) running a **deterministic-only** 7-check pipeline on every tool call. No LLM calls in the hot path. Unpoisonable. Fails safe to `halt` on any error.

```
Check 0  Tool revocation      — REVOKED tools blocked before any other check (cache TTL: 10s)
Check 1  Registry + Hash      — tool must be APPROVED; SHA-256 hash must match registration
Check 2  Capability boundary  — negative capability list enforced per agent profile
Check 3  Destructive patterns — regex detection of destructive command patterns in tool args
Check 4  Sequence contract    — agent tool sequences validated; deviations → sandbox retry
Check 5  Ed25519 signature    — crystallized tools must carry a valid signing-keypair signature
Check 6  Adaptive rules       — human-approved threat rules hot-reload every 10s; no restart
```

### Crystallization Pipeline

When agents solve the same deterministic problem repeatedly, LegionForge crystallizes the solution into a signed, containerized tool — zero LLM inference cost for routine work.

```
Observer ──▶ Crystallizer ──▶ Pre-HITL Analyzer ──▶ Human Gate ──▶ Ed25519-Signed Tool
```

The Pre-HITL Analyzer runs AST guards (subscript bypass, MRO traversal, `globals()`/`locals()` hijack) and behavioral diffs before any human reviews a proposal.

### Multi-Provider Authentication

The gateway supports five auth backends — swap without touching agent code:

| Backend | Scheme | Use case |
|---|---|---|
| `ApiKeyBackend` | Bearer | Default — bcrypt API keys in PostgreSQL |
| `OIDCBackend` | Bearer | Google, Okta, Auth0, Azure AD, Keycloak, Cognito |
| `GitHubOAuthBackend` | Bearer | GitHub OAuth app tokens |
| `LDAPBackend` | Basic | OpenLDAP, Active Directory |
| `KerberosBackend` | Negotiate | Kerberos/GSSAPI (requires KDC + keytab) |

Set `gateway.auth_provider` in your hardware profile YAML.

### Threat Coverage

| Threat | Defense |
|---|---|
| **Tool Poisoning** | SHA-256 hash validation at registration + Ed25519 cryptographic signing |
| **Rug-Pull** | Hash mismatch detection + signed tool versioning |
| **Prompt Injection** (direct + indirect) | 29-pattern sanitizer (Tier 1 halt / Tier 2 log) + NFKC normalization + zero-width char stripping + RAG provenance scoring |
| **Capability Amplification** | Negative capability list enforced by Guardian Check 2 |
| **Resource Bomb / Economic DOS** | Pre-execution token cost estimator + per-user daily budgets + per-provider rate limits |
| **Credential Theft** | macOS Keychain / `~/.pgpass` storage + PII redaction from all outbound API calls |
| **RAG / Memory Poisoning** | Document provenance scoring + embedding trust threshold flagging |
| **Multi-Agent Cascade** | Orchestrator-only routing + signed inter-agent messages |
| **Supply Chain** | AI-BOM + signed tool library + SHA-256 GGUF model integrity verification |
| **TOCTOU** | `approved_snapshot` stored pre-execution; post-execution result verified against snapshot |
| **AST Bypass** | Subscript, MRO traversal, `globals()`/`locals()` hijack detection in crystallization analyzer |

---

## Phase Roadmap

All phases complete.

| Phase | What Was Built |
|---|---|
| **0** | PostgreSQL + pgvector, async LLM factory (Ollama/OpenAI/Anthropic), health server |
| **1** | Researcher agent, tool registry + SHA-256 hash validation, capability boundaries, threat event logging |
| **2** | Docker containerization, Guardian security sidecar, immutable audit log (SHA-256 hash chain), RAG provenance |
| **3** | JWT task tokens + ACLs, sub-agent orchestrator, sandbox retry tier |
| **4** | Threat Analyst agent, adaptive Guardian rules, AI Bill of Materials |
| **5** | Crystallization Pipeline — Observer + Crystallizer agents, pre-HITL AST analyzer, Ed25519-signed tools |
| **5.5** | DB RBAC (`legionforge_app` restricted role), AST bypass guards, tool revocation, TOCTOU mitigation, Ollama model integrity |
| **6** | PentestAgent — air-gapped red-team bot, 8 attack classes × 3 variants, stop-at-proof mode |
| **7** | Guardian feedback loop (pentest → threat rules → Guardian), SECURITY.md, v1.0 hardening |
| **8** | FastAPI gateway (:8080), PostgreSQL task queue, SSE streaming, web UI, A2A + MCP endpoints, Discord connector |
| **9** | langchain 1.x migration, 5-tool library, parallel agent fan-out, Phase 9.5 hardening sprint |
| **10** | Multi-user auth — DB-backed stream tokens, per-user daily token budgets, `/usage/me`, user management CLI |
| **11** | `SecureToolNode` fix, 38 integration tests, `AuthBackend` protocol, `Dockerfile.gateway`, `docs/SCALING.md` |
| **12** | `OIDCBackend`, `GitHubOAuthBackend`, `LDAPBackend`, `KerberosBackend`; multi-scheme `require_user` |
| **13** | Real GSSAPI Kerberos backend, Redis-backed stream tokens, multi-instance docker-compose + Nginx |
| **14** | Redis global budget counters, Prometheus `/metrics` endpoint, `X-Request-ID` trace middleware |
| **15** | Polished web UI — localStorage key + task history, cancel, tool call blocks, live timer, copy, keyboard shortcuts |
| **16** | Telegram (polling), Slack (Socket Mode), generic Webhook (HMAC-SHA256 + async callback) connectors |
| **60–381** | 381-tool operator dashboard — every gateway API endpoint surfaced as a UI function with smoke tests |
| **Security sprint** | Extended exfiltration detection, NFKC normalization, DESTRUCTIVE_PATTERN DB logging, PostgreSQL scram-sha-256 |

---

## Requirements

| Component | Version | Notes |
|---|---|---|
| Python | 3.11+ | via pyenv recommended |
| PostgreSQL | 16 or 17 | with pgvector extension |
| Ollama | latest | for local LLM inference |
| Docker | 24+ | for Guardian sidecar + analyzer container |
| macOS | 14+ (Apple Silicon) | primary target; Linux support planned |

**Recommended hardware:** Mac Mini M4 16GB for single-user; Mac Mini M4 Pro 24GB for household (2–4 concurrent users).

---

## Quick Start

```bash
# 1. Clone and set up
git clone https://github.com/jp-cruz/LegionForge.git
cd LegionForge
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Set hardware profile
export AGENT_HARDWARE_PROFILE=mac_m4_mini_16gb
echo 'export AGENT_HARDWARE_PROFILE=mac_m4_mini_16gb' >> ~/.zshrc

# 3. Store PostgreSQL admin password
echo "localhost:5432:*:$(whoami):yourpassword" >> ~/.pgpass && chmod 0600 ~/.pgpass
# First install with default Homebrew trust auth? Use: export POSTGRES_TRUST_AUTH=true

# 4. Pull Ollama models
ollama pull llama3.1:8b        # ~4.7 GB — primary agent model
ollama pull qwen2.5:3b         # ~2.0 GB — fast router model
ollama pull nomic-embed-text   # ~0.3 GB — RAG embeddings

# 5. Initialize the database and generate secrets
make db-init
make setup-task-token-secret
make setup-signing-key

# 6. Run smoke tests (no services required)
make test-smoke
# Expected: 1946 passed in ~16s

# 7. Start services (three terminals)
make health-server   # Operator API at :8765
make gateway-start   # User API + Web UI at :8080
make guardian-start  # Security sidecar at :9766 (requires Docker)

# 8. Create a user and open the web UI
make create-user USERNAME=myname
open http://localhost:8080/ui
```

**→ Full setup guide:** [`docs/quick-start.md`](./docs/quick-start.md)

---

## Documentation

| Document | What It Covers |
|---|---|
| [`docs/quick-start.md`](./docs/quick-start.md) | Step-by-step setup, connecting channels, first task, troubleshooting |
| [`docs/architecture.md`](./docs/architecture.md) | All components, ports, ASCII diagram, connection rationale |
| [`docs/SCALING.md`](./docs/SCALING.md) | Horizontal scaling, Redis, Kerberos KDC, multi-instance Docker |
| [`SECURITY.md`](./SECURITY.md) | Threat model, HITL policy, injection detection architecture |
| [`TLDR.md`](./TLDR.md) | Project orientation — what was built and why |
| [`CHANGELOG.md`](./CHANGELOG.md) | Full version history |
| [`docs/VISION.md`](./docs/VISION.md) | Product vision, architecture rationale, design decisions |

---

## Key Files

| File | Purpose |
|---|---|
| `src/base_graph.py` | LangGraph agent template — copy to create new agents |
| `src/security/guardian.py` | Guardian sidecar — deterministic 7-check security pipeline |
| `src/security/core.py` | Keychain loader, PII redaction (8 patterns), injection detection (29 patterns), I/O sanitizer |
| `src/database.py` | Async PostgreSQL pool, LangGraph checkpointer, pgvector, audit log hash chain |
| `src/safeguards.py` | Three-layer loop protection (step counter, action history, token budget) |
| `src/gateway/app.py` | FastAPI gateway (:8080) — task queue, SSE streaming, web UI, A2A, MCP |
| `src/gateway/backends/` | Auth backend package — ApiKey, OIDC, GitHub, LDAP, Kerberos |
| `src/connectors/` | Channel connectors — Discord, Telegram, Slack, Webhook |
| `src/tools/signing.py` | Ed25519 keypair management + tool manifest signing |
| `src/tools/crystallization_analyzer.py` | Pre-HITL AST + behavioral diff analyzer |
| `config/settings.py` | Pydantic settings singleton (loaded from hardware YAML profile) |
| `Makefile` | All development, test, and operational commands |

---

## Makefile Reference

```bash
# Environment
make check             # Verify environment before starting
make start             # Full startup (Ollama + PostgreSQL + model warmup)
make stop              # Graceful shutdown

# Testing
make test-smoke        # 1946 smoke tests, ~16s, no services required
make test-integration  # 38 integration tests (requires PostgreSQL)
make test-kerberos     # 5 Kerberos live-KDC tests (requires KDC)
make test-ui           # 40 UI tests (Playwright)
make test-fast         # All tests except slow ones

# Code quality
make lint              # Black formatter check
make format            # Auto-format
make security-audit    # Smoke + bandit + URI secret scan

# Services
make health-server     # Operator health API at :8765
make gateway-start     # User-facing gateway at :8080
make guardian-start    # Guardian sidecar at :9766 (requires Docker)
make discord-start     # Discord bot connector
make telegram-start    # Telegram bot connector
make slack-start       # Slack Socket Mode connector
make webhook-start     # Generic webhook connector at :8081

# Users & auth
make create-user USERNAME=<name>
make create-user USERNAME=<name> DAILY_LIMIT=<tokens>

# Security
make pentest           # Air-gapped red-team suite (stop-at-proof)
make pentest-report    # View most recent pentest findings
make audit-log-verify  # Verify SHA-256 hash chain integrity
make revoke-tool TOOL_ID=<id>   # Emergency tool revocation
```

---

## Known Gaps (Accepted Residual Risk)

- **Embedding-level anomaly detection** — RAG poisoning at the semantic vector level is an open research problem. Provenance scoring and trust flagging exist; embedding-level detection is deferred.
- **pip-audit / dependency hash pinning** — Managed via Dependabot. `pip-audit` reports no known CVEs; transitive hash pinning is accepted residual risk.
- **langchain 1.x migration** — Planned for a future phase; current stack runs langchain 0.3.x. A LOW-severity SSRF CVE in `langchain-core` is accepted risk (LegionForge never calls the affected method with image content).

---

## License

AGPL-3.0 with Section 7(b) attribution requirement.

Copyright 2026 John Paul "Jp" Cruz. Commercial licensing available — contact via [GitHub Issues](https://github.com/jp-cruz/LegionForge/issues).

---

## Status

**v0.7.0-alpha** — Phases 0–381 complete. 1946/1946 smoke tests passing. 38/38 integration tests. All pre-v1.0 security blockers resolved. Active development toward v1.0.0 public release.

Contributions, issues, and commercial licensing inquiries welcome via [GitHub Issues](https://github.com/jp-cruz/LegionForge/issues).
