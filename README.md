# LegionForge

**A local-first, security-native AI agent framework built on LangGraph.**

> Security is enforced in the execution path — not layered on afterward.

---

## What Is This?

LegionForge is an open-source framework for building hardened AI agent systems on local hardware. It runs local LLMs (via Ollama) or cloud APIs (OpenAI, Anthropic), with a full security stack baked into every layer of the execution pipeline.

**The one-line pitch:** The hardened, self-hosted alternative to cloud agent platforms — and a security layer that other agent frameworks can plug into.

---

## What Can It Do?

Submit any task — research, summarization, code execution, data analysis — via the web UI, a REST API, or a messaging app. Watch it execute in real time as the agent reasons, calls tools, and streams results token by token.

**User interfaces:**
- **Web UI** at `http://localhost:8080/ui` — browser-based, no client install needed
- **Discord** — `!<task>` in any channel the bot can see
- **Telegram** — `/<task>` to your bot
- **Slack** — `!<task>` (Socket Mode, no public URL needed)
- **Webhook** — `POST :8081/inbound` from n8n, Zapier, or any HTTP client

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
Check 0: Tool revocation  (immediate halt if REVOKED)
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

### Multi-Provider Authentication
The gateway supports five auth backends — swap without touching agent code:

| Backend | Scheme | Use case |
|---|---|---|
| `ApiKeyBackend` | Bearer | Default — bcrypt API keys in PostgreSQL |
| `OIDCBackend` | Bearer | Google, Okta, Auth0, Azure AD, Keycloak, Cognito |
| `GitHubOAuthBackend` | Bearer | GitHub OAuth app tokens |
| `LDAPBackend` | Basic | OpenLDAP, Active Directory |
| `KerberosBackend` | Negotiate | Kerberos/GSSAPI (requires KDC + keytab) |

Set `gateway.auth_provider` in `config/hardware_profiles/mac_m4_mini_16gb.yaml`.

### Threat Coverage

| Threat | Defense |
|---|---|
| **Tool Poisoning** | Hash validation at registration + cryptographic signing |
| **Rug-Pull** | Hash mismatch detection + signed tool versions |
| **Prompt Injection** (direct + indirect) | Input/output sanitizer (29 patterns, 2-tier) + RAG provenance scoring |
| **Capability Amplification** | Negative capability list enforced by Guardian |
| **Resource Bomb / Economic DOS** | Pre-execution token cost estimator + per-user daily budgets |
| **Credential Theft** | macOS Keychain storage + PII redaction from all outbound calls |
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
| **12** | Multi-provider auth registry — `OIDCBackend`, `GitHubOAuthBackend`, `LDAPBackend`, `KerberosBackend`; multi-scheme `require_user` | ✅ Complete |
| **13** | Kerberos GSSAPI real implementation, Redis-backed stream tokens, multi-instance docker-compose + Nginx | ✅ Complete |
| **14** | Redis global budget counters, Prometheus `/metrics` endpoint, `X-Request-ID` middleware | ✅ Complete |
| **15** | Polished web UI — localStorage key+history, cancel, tool call blocks, live timer, copy, keyboard shortcut | ✅ Complete |
| **16** | Channel connectors — Telegram (polling), Slack (Socket Mode), generic Webhook (HMAC + async callback) | ✅ Complete |
| **v1.0.1** | schema fix (user_id TEXT), live Kerberos KDC, all integration tests real, MODEL_INTEGRITY_STRICT env var | ✅ Complete |
| **Phase 60–381** | 381-tool UI library (Phases 60–381, PRs #117–#201) — full operator dashboard built as JS functions over the gateway REST API | ✅ Complete |
| **Security hardening** | Extended exfiltration detection + NFKC normalization; DESTRUCTIVE_PATTERN async DB logging; PostgreSQL scram-sha-256 migration (PRs #208–#214) | ✅ Complete |
| **Web + Browser tools** | `web_fetch_js` Playwright headless browser (PR #218); two-layer SSRF guard; private-IP PII regex fix; 50 tool-accuracy tests | ✅ Complete |
| **Lazy-load Dashboard** | 296 operator tool cards in `<template>` — injected on first click; eliminates startup parse cost (PR #217) | ✅ Complete |
| **Guardian G1–G3** | `packages/legionforge_guardian` standalone package; backward-compat shim in `src/security/guardian.py`; `python -m legionforge_guardian` entry point (PR #219) | ✅ Complete |
| **Guardian G4** | Public repo [LegionForge/LegionForge-Guardian](https://github.com/LegionForge/LegionForge-Guardian) live; `pip install legionforge-guardian` on PyPI; auto-sync Action; Docker smoke verified (PRs #221–#232) | ✅ Complete |
| **Agent Memory — all 5 gaps** | Persona bootstrap (Gap 1, DB-backed SOUL.md), user prefs (Gap 5), `memory_write`/`memory_recall` tools (Gap 3), daily episodic summaries (Gap 2), pre-compaction flush (Gap 4) | ✅ Complete |
| **Dual License** | AGPLv3 open source + commercial license; `COMMERCIAL_LICENSE.md` + `CLA.md` added (PR #229) | ✅ Complete |

**2125/2125 smoke tests passing.** 38/38 integration tests. 5/5 Kerberos live-KDC tests. 40/40 UI tests. 104/104 TestLab tests. 79/79 tool accuracy tests. Smoke suite runs in ~21 seconds (no external services required).

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

## Open Security Issues

> These are accepted risks for local development, tracked here as pre-1.0 release blockers.
> See [`SECURITY.md — Known Security Gaps`](./SECURITY.md#known-security-gaps--pre-10-blockers) for full details and remediation steps.

| Issue | Severity | Status |
|---|---|---|
| ~~**PostgreSQL `trust` auth**~~ — any local process can connect to the DB without a password | Medium (local dev) / High (shared/remote) | ✅ **Closed — PR #212.** Now uses `peer` (Unix socket) + `scram-sha-256` (TCP). Passwords in `~/.pgpass`. |

---

## Quick Start

**→ Full setup guide:** [`docs/quick-start.md`](./docs/quick-start.md)

```bash
# 1. Clone and set up the virtual environment
git clone https://github.com/LegionForge/LegionForge.git
cd LegionForge
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Set your hardware profile
export AGENT_HARDWARE_PROFILE=mac_m4_mini_16gb

# 3. Store your PostgreSQL admin password in ~/.pgpass
#    (or set POSTGRES_TRUST_AUTH=true for a default Homebrew trust-auth install)
echo "localhost:5432:*:$(whoami):yourpassword" >> ~/.pgpass && chmod 0600 ~/.pgpass

# 4. Initialize the database and generate secrets
make db-init
make setup-task-token-secret
make setup-signing-key

# 5. Run smoke tests (no services required)
make test-smoke
# Expected: 2125 passed in ~21s

# 6. Start services (three separate terminals)
make health-server   # Operator API at :8765
make gateway-start   # User API at :8080
make guardian-start  # Security sidecar at :9766 (requires Docker)

# 7. Create a user and open the web UI
make create-user USERNAME=myname
open http://localhost:8080/ui
```

---

## Documentation

| Document | What It Covers |
|---|---|
| [`docs/quick-start.md`](./docs/quick-start.md) | Step-by-step setup, connecting channels, first task |
| [`docs/architecture.md`](./docs/architecture.md) | All components, ports, ASCII diagram, connection rationale |
| [`docs/SCALING.md`](./docs/SCALING.md) | Horizontal scaling, Redis, Kerberos KDC, multi-instance Docker |
| [`TLDR.md`](./TLDR.md) | Project orientation — what was built and why |
| [`SECURITY.md`](./SECURITY.md) | Threat model, HITL policy, injection detection |
| [`VERIFICATION.md`](./VERIFICATION.md) | Verification steps for each phase |
| [`docs/VISION.md`](./docs/VISION.md) | Product vision, architecture rationale, design decisions |

---

## Key Files

| File | Purpose |
|---|---|
| `src/base_graph.py` | LangGraph agent template — copy to create new agents |
| `packages/guardian/src/legionforge_guardian/app.py` | Guardian sidecar — canonical source; deterministic 7-check security pipeline |
| `src/security/guardian.py` | Backward-compat shim — re-exports all names from `legionforge_guardian.app` |
| `src/security/core.py` | Keychain loader, PII redaction (8 patterns), injection detection, I/O sanitizer |
| `src/database.py` | Async PostgreSQL pool, LangGraph checkpointer, pgvector, audit log hash chain |
| `src/safeguards.py` | Three-layer loop protection (step counter, action history, token budget) |
| `src/gateway/app.py` | FastAPI gateway (:8080) — task queue, SSE, web UI, A2A, MCP |
| `src/gateway/backends/` | Auth backend package — ApiKey, OIDC, GitHub, LDAP, Kerberos |
| `src/connectors/` | Channel connectors — Discord, Telegram, Slack, Webhook |
| `src/tools/signing.py` | Ed25519 keypair management + tool manifest signing |
| `src/tools/crystallization_analyzer.py` | Pre-HITL AST + behavioral diff analyzer |
| `config/settings.py` | Pydantic settings singleton (loaded from hardware YAML profile) |
| `Makefile` | All development, test, and operational commands |

---

## Makefile Reference

```bash
make check           # Verify environment before starting
make start           # Full startup (drive → Ollama → PostgreSQL → model warmup)
make test-smoke      # 2125 smoke tests, ~21s, no services required
make test-integration  # 38 integration tests (requires PostgreSQL)
make test-kerberos   # 5 Kerberos live-KDC tests (requires KDC)
make test-ui         # 40 UI tests (Playwright)
make lint            # Black formatter check
make health-server   # Start operator health API at :8765
make gateway-start   # Start user-facing gateway at :8080
make guardian-start  # Build + start Guardian sidecar via Docker at :9766
make create-user USERNAME=<name>     # Create gateway user (prints API key)
make discord-start   # Start Discord bot connector
make telegram-start  # Start Telegram bot connector
make slack-start     # Start Slack Socket Mode connector
make webhook-start   # Start generic inbound/outbound webhook connector (:8081)
make security-audit  # Smoke tests + bandit + secret scan
make pentest         # Run red-team attack suite in verify mode (stop-at-proof)
make pentest-report  # Print most recent pentest report
make audit-log-verify # Verify SHA-256 hash chain integrity on audit_log
make revoke-tool TOOL_ID=<id>  # Emergency tool revocation
```

---

## Known Gaps (Accepted Residual Risk)

- **Embedding-level anomaly detection** — RAG poisoning at the semantic vector level is an open research problem. Provenance scoring and trust flagging exist; embedding-level detection is deferred.
- **pip-audit / dependency hash pinning** — `pip-audit` reports no known CVEs as of v1.0.1; transitive hash pinning is accepted residual risk.

---

## Acknowledgements

LegionForge exists in a space shaped by several projects and thinkers worth calling out directly.

**[OpenClaw](https://github.com/openClaw)** — the closest spiritual peer. OpenClaw's six-component architecture (Gateway, Agent, Tools, Workspace, Sessions, Nodes) and its workspace-as-files memory model (AGENTS.md, SOUL.md, USER.md, MEMORY.md, daily logs) are genuinely well-designed. LegionForge takes a different bet — PostgreSQL-backed state over flat files, deterministic security enforcement over convention — but OpenClaw showed what a serious self-hosted agent system looks like and set a high bar.

**[Moltbot](https://github.com/moltbot)** — another self-hosted agent framework that demonstrated real multi-agent coordination before most projects were thinking about it. The multi-agent isolation patterns here were informed in part by seeing what Moltbot got right (and where it left security as an exercise for the operator).

**[LangGraph](https://github.com/langchain-ai/langgraph)** — the graph execution engine underneath everything. The checkpoint-based state persistence and the recursion-limit loop protection are LangGraph primitives that LegionForge builds on heavily.

**[LangChain](https://github.com/langchain-ai/langchain)** and the broader open-source LLM tooling ecosystem — without the ecosystem of open weights models, open inference runtimes (Ollama), and open tooling, a project like this on consumer hardware wouldn't be possible.

**[LATM — Learning to Use Tools by Making Them](https://arxiv.org/abs/2305.17126)** (Cai et al., ICLR 2024) and **[Voyager](https://arxiv.org/abs/2305.16291)** (Wang et al., NVIDIA 2023) — the closest published academic work to LegionForge-Anneal's crystallization pipeline. Both explore converting LLM-generated actions into reusable tools. LegionForge's contribution is the production-hardening layer: sandboxed execution, adversarial testing, Ed25519 signing, and HITL gate.

**[Anchor Engine](https://github.com/RSBalchII/anchor-engine-node)** by Robert S. Balch II — a deterministic semantic memory system using graph traversal (the STAR algorithm) instead of vector embeddings. Anchor Engine's core insight — that agent memory should be *deterministic and explainable*, not statistically fuzzy — directly informed LegionForge's temporal decay weighting in memory recall. The STAR gravity formula (`similarity × e^(-λ·age)`) is adapted from Anchor's whitepaper for the `similarity_search` temporal decay path in `src/database.py`.

**[The AI-Human Engineering Stack](https://github.com/hjasanchez/agentic-engineering)** by Hayen Mill and Henrique Jr. Sanchez (March 2026) — a framework for thinking about the five cognitive layers of AI engineering (Prompt, Context, Intent, Judgment, Coherence) plus Evaluation and Harness as cross-cutting meta-functions. The Manus Insight from this paper — that KV-cache hit rate is the single most important production agent metric, and that context should be ordered stable-first — directly motivated the message assembly reordering in `src/base_graph.py`.

The security-first design of LegionForge is a direct response to watching these ecosystems grow fast and ship security as an afterthought. That's not a criticism — it's the reality of how open-source evolves. This project is an attempt to show what the stack looks like when security is the first constraint, not the last.

---

## License

**Dual License:**

- **Open Source** — [AGPLv3](LICENSE) with Section 7(b) attribution requirement. Free for open-source use.
- **Commercial** — proprietary license for organizations that cannot comply with AGPLv3. See [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md).

The `legionforge-guardian` sidecar package is licensed separately under MIT.

Contributors must agree to the [Contributor License Agreement](CLA.md) (agreement implied by submitting a PR).

Copyright 2026 John Paul "Jp" Cruz.

---

## Status

**v0.7.1-alpha** — Phases 0–381 + all 5 agent memory gaps + Guardian G4 (published to PyPI) complete. 2125/2125 smoke tests. 38/38 integration tests. 5/5 Kerberos live-KDC tests. 40/40 UI tests. All pre-v1.0 security blockers resolved. Dual-licensed AGPLv3 + commercial.

Contributions, issues, and commercial licensing inquiries are welcome via [GitHub Issues](https://github.com/LegionForge/LegionForge/issues).
