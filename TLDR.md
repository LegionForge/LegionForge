# TLDR.md
# LegionForge — What Is This and What Are We Building?

**Version:** 0.7.0-alpha
**Last updated:** 2026-03-02

---

## What Is This?

A **local-first, open-source, security-native AI agent framework** built on LangGraph, running on a Mac Mini M4. Agents can use local LLMs (Ollama) or cloud APIs. Security is built into the foundation — not bolted on later.

**The one-line pitch:** The hardened, self-hosted alternative to OpenClaw — and a security layer that other agent frameworks can plug into.

---

## Current Status

✅ **Phases 0–381 complete. v0.7.0-alpha — active development toward v1.0.0.**

The full security stack is operational, plus a comprehensive task management API, multi-turn conversation sessions, configurable search providers, and much more.

**1946/1946 smoke tests passing** (~16s, no external services required).
**38/38 integration tests** (PostgreSQL required — `make test-integration`).
**40/40 UI tests** (`make test-ui`).
**29/29 tool accuracy tests** (`make test-tool-accuracy`).
**104/104 TestLab tests** · **5/5 Kerberos live-KDC tests**.

### Core Security Stack (Phases 0–16)
✅ Guardian sidecar (7 deterministic checks, hot-reload every 10s), immutable SHA-256 audit log (halt-on-tamper), crystallization pipeline (Observer→Crystallizer→Pre-HITL→Ed25519 signature), air-gapped PentestAgent (24 attack functions, 0 bypasses on clean deploy), pentest→Guardian feedback loop, multi-user gateway (:8080), five production tools, `AuthBackend` protocol with 5 backends (ApiKey, OIDC, GitHub, LDAP, Kerberos), Redis-backed stream tokens, Prometheus /metrics, web UI, Discord/Telegram/Slack/Webhook connectors, multi-instance docker-compose + Nginx.

### Task Platform (Phases 17–51)
✅ Admin API + observability endpoints, scheduled tasks (cron), document ingestion (PDF/HTML/text), persistent agent memory (pgvector), multi-machine Ollama cluster, task pipelines, priority queue, batch submission, result cache, SSE pipeline streaming, tags, notes, retry, dependencies, worker concurrency, cost estimation, agent registry, task export (JSON/CSV), timeline events, task labels, API key rotation, rate limit headers, bulk operations, analytics, full-text search (tsvector), task watchdog, keyset pagination, webhook registry, file attachments, task templates, read-only sharing.

### Conversation & Personalization (Phases 52–56)
✅ User preferences (JSONB per-user defaults), per-day token usage history, conversation sessions (LangGraph thread persistence — multi-turn memory), anti-hallucination hardening (system prompt, HTML stripping, DDG error wording), configurable search providers (DDG/Tavily/Brave/Exa/Perplexity/SearXNG with primary+fallback routing).

---

## The Big Picture — Phases 0–56 Complete

### Security Foundation (Phases 0–16)

| Phase | What Gets Built | Status |
|---|---|---|
| **0** | Infrastructure, database, LLM factory, health server | ✅ Done |
| **1** | Researcher agent + tool registry + capability boundaries + threat event logging | ✅ Done |
| **2** | Docker containerization + Guardian security sidecar + immutable audit log + RAG provenance | ✅ Done |
| **3** | Task tokens + ACLs + sub-agent orchestrator | ✅ Done |
| **4** | Threat Analyst agent + adaptive Guardian rules + AI-BOM | ✅ Done |
| **5** | Crystallization Pipeline — Observer + Crystallizer agents, pre-HITL analyzer, signed tools | ✅ Done |
| **5.5** | Security hardening: DB RBAC, AST bypass guards, tool revocation, TOCTOU, model integrity | ✅ Done |
| **6** | PentestAgent — air-gapped red-team bot, 24 attack functions, 0 bypasses | ✅ Done |
| **7** | Guardian feedback loop — pentest→Guardian bridge, SECURITY.md, pre-release hardening | ✅ Done |
| **8** | Gateway service (:8080), task queue, SSE streaming, web UI, A2A + MCP, Guardian gap fixes | ✅ Done |
| **9** | langchain 1.x migration, tool library (5 tools), parallel fan-out, Phase 9.5 hardening sprint | ✅ Done |
| **10** | Multi-user auth — DB-backed stream tokens, per-user daily budgets, `/usage/me`, user CLI | ✅ Done |
| **11** | SecureToolNode fix, integration tests, `AuthBackend` protocol, `Dockerfile.gateway`, `SCALING.md` | ✅ Done |
| **12** | Multi-provider auth registry: OIDC, GitHub OAuth, LDAP/AD, Kerberos scaffold; multi-scheme `require_user` | ✅ Done |
| **13** | Kerberos GSSAPI real implementation, Redis-backed stream tokens, multi-instance docker-compose | ✅ Done |
| **14** | Redis global budget counters, Prometheus `/metrics` endpoint, `X-Request-ID` middleware | ✅ Done |
| **15** | Polished web UI — localStorage key+history, cancel, tool blocks, timer, copy, keyboard shortcut | ✅ Done |
| **16** | Channel connectors — Telegram, Slack (Socket Mode), Webhook (HMAC, async callback) | ✅ Done |

### Task Platform & Observability (Phases 17–51)

| Phase | What Gets Built | Status |
|---|---|---|
| **17–19** | TestLab admin platform + 104-test attack suite + Dockerized Ollama | ✅ Done |
| **20** | Multi-machine Ollama cluster (round-robin, primary-first, least-busy routing) | ✅ Done |
| **21** | Persistent agent memory (pgvector recall + store) | ✅ Done |
| **22** | Document ingestion pipeline (PDF/HTML/text, chunking, provenance) | ✅ Done |
| **23** | Scheduled tasks (cron + @shortcuts + @every intervals) | ✅ Done |
| **24** | Admin API (user CRUD, quota management, admin promotion) | ✅ Done |
| **25** | Audit log & observability API (paged audit, threat summary, tool management) | ✅ Done |
| **26** | Task result webhooks (HMAC-SHA256 callbacks on completion) | ✅ Done |
| **27** | Task pipelines (multi-step task chains with 8 endpoints) | ✅ Done |
| **28** | Task priority queue + batch submission | ✅ Done |
| **29** | Task result cache (content-hash deduplication, TTL) | ✅ Done |
| **30** | Pipeline SSE progress streaming | ✅ Done |
| **31** | Task tags + full-text search (`q=` filter) | ✅ Done |
| **32** | Task notes (attach text notes to tasks) | ✅ Done |
| **33** | Task retry API | ✅ Done |
| **34** | Task dependencies (`depends_on`, failure propagation) | ✅ Done |
| **35** | Worker concurrency (3 parallel tasks via `asyncio.create_task`) | ✅ Done |
| **36** | Task cost estimation (`dry_run` mode) | ✅ Done |
| **37** | Agent capabilities registry (`GET /agents`, `GET /agents/{type}`) | ✅ Done |
| **38** | Task export API (JSON + CSV download) | ✅ Done |
| **39** | Task timeline (per-task event log) | ✅ Done |
| **40** | Task labels (bookmarked/starred/important/archived) | ✅ Done |
| **41** | API key rotation (self-service `POST /auth/rotate-key`) | ✅ Done |
| **42** | Rate limit response headers (`X-RateLimit-*`) | ✅ Done |
| **43** | Task bulk operations (cancel/delete/tag multiple tasks) | ✅ Done |
| **44** | Task stats & analytics (aggregate metrics by agent type, date range) | ✅ Done |
| **45** | Task full-text search (PostgreSQL tsvector index on input + result) | ✅ Done |
| **46** | Task watchdog (reap stuck `running` tasks after timeout) | ✅ Done |
| **47** | Keyset cursor pagination for task list | ✅ Done |
| **48** | Webhook registry (persistent per-user webhook subscriptions) | ✅ Done |
| **49** | Task attachments (text blobs attached to tasks) | ✅ Done |
| **50** | Task templates (reusable task configurations) | ✅ Done |
| **51** | Task sharing (read-only share tokens, `GET /share/{token}`) | ✅ Done |

### Conversation & Intelligence (Phases 52–56)

| Phase | What Gets Built | Status |
|---|---|---|
| **52** | User preferences (JSONB per-user task defaults) | ✅ Done |
| **53** | Usage history (per-day token breakdown) | ✅ Done |
| **54** | Conversation sessions (LangGraph thread persistence for multi-turn memory) | ✅ Done |
| **55** | Anti-hallucination hardening (system prompt, HTML stripping, DDG error safety) | ✅ Done |
| **56** | Configurable search providers (DDG/Tavily/Brave/Exa/Perplexity/SearXNG; primary+fallback) | ✅ Done |

**→ Full details:** [`PHASE_PLAN.md`](./PHASE_PLAN.md)

---

## The Threats We Are Solving

These are the real attack classes against LLM agent frameworks in 2026, and where we address them:

| Threat | Severity | Our Defense | Phase |
|---|---|---|---|
| **Tool Poisoning** — malicious instructions in tool metadata | 🔴 Critical | Hash validation at registration + cryptographic signing | 1, 5 |
| **Rug-Pull** — tool changes behavior after trust is established | 🔴 Critical | Hash mismatch detection + signed tool versions | 1, 5 |
| **Prompt Injection** (direct + indirect) | 🔴 Critical | Sanitizer in security.py + RAG provenance scoring | 0, 2 |
| **Capability Amplification** — validated agent creates unapproved tools | 🔴 Critical | Negative capability list enforced by Guardian | 1, 2 |
| **Resource Bomb / Economic DOS** | 🟠 High | Pre-execution token cost estimator + rate limiter | 1 |
| **Credential Theft** | 🟠 High | Keychain storage + PII/key pattern redaction from all outbound calls | 0, 1 |
| **RAG / Memory Poisoning** | 🟠 High | Document provenance + embedding trust scoring | 2 |
| **Multi-Agent Cascade** | 🟠 High | Orchestrator-only routing + signed inter-agent messages | 3 |
| **Supply Chain** | 🟡 Medium | AI-BOM + signed tool library + CVE cross-reference | 4, 5 |
| **MITM / Interchange** | 🟡 Medium | TLS + Guardian validation of inter-agent messages | 2, 3 |
| **Compositional Emergence** — safe components combine maliciously | 🟡 Medium | Capability minimization + approved combination patterns | 2 |

**→ Full threat research:** [`RESEARCH.md`](./RESEARCH.md)

---

## Key Design Decisions (and Why)

**Guardian is deterministic-only in the hot path.** No LLM calls during security checks. Fast, auditable, predictable. LLM analysis only happens offline for threat review.
→ *Why:* An LLM-based security check can itself be prompt-injected. Deterministic pattern matching cannot.

**Fail-safe is tiered, not binary.** High-confidence threat = halt and quarantine. Ambiguous = sandbox and retry. Soft failure = degrade and continue.
→ *Why:* Blanket "stop on any anomaly" breaks legitimate agents. Blanket "retry everything" fails to stop real attacks. The tier is declared per-tool at config time.
→ *Details:* [`RESEARCH.md §2`](./RESEARCH.md)

**Privilege is tied to tasks, not agents.** Agents receive short-lived task tokens scoped to exactly what the current task requires. Sub-agents get narrower derived tokens.
→ *Why:* An agent with broad persistent permissions is a confused deputy. Any injected instruction gets those permissions too. Task-scoped tokens limit blast radius.
→ *Details:* [`RESEARCH.md §4`](./RESEARCH.md)

**Human gates on all mutations.** No component autonomously changes security rules, promotes tools, or escalates privileges.
→ *Why:* The Threat Analyst, Guardian, and PentestAgent can all be manipulated. The human approver is the terminal defense. Protect the approver with clear diffs and rate limits on proposals.
→ *Details:* [`RESEARCH.md §3.2`](./RESEARCH.md)

**Validate at trust boundaries, not processing nodes.** Guardian enforces checks at every inbound/outbound trust boundary. Agents are processing nodes — not trust boundaries.
→ *Why:* Validating everywhere is expensive and inconsistent. Validating at boundaries is surgical and auditable.

**Replace AI with determinism wherever possible.** When agents solve the same deterministic problem repeatedly, they flag it for crystallization into a signed, containerized tool. Zero LLM overhead for routine work.
→ *Why:* LLMs are expensive, non-deterministic, and an attack surface for routine tasks. Signed deterministic tools are none of those things.
→ *Details:* [`PHASE_PLAN.md — Phase 5`](./PHASE_PLAN.md)

---

## What We Are (and Are Not) Building

**We are building** a secure, self-hosted, multi-user agent platform — the thing OpenClaw proved people want, built with the security foundations OpenClaw proved are necessary. The platform exposes a gateway API, a streaming web UI, and messaging-channel connectors (Discord, Signal, etc.) so users can submit tasks to agents and watch them execute in real time.

**We are also building** the security infrastructure layer (Guardian, audit log, crystallization) as a separable product that other agent frameworks can plug into.

**We are not** automating human judgment. Security rule changes, tool promotions, privilege escalations, and crystallization approvals always require explicit human approval.

**We are not** fine-tuning models. Pre-trained Ollama models only. Fine-tuning introduces backdoor risks that require a separate security process.

**We are not** targeting supercomputer workloads. Full Phase 7 deployment peaks at ~12–14GB RAM on an M4 Mini 16GB. Phase 8 adds the gateway and UI services; a 24GB M4 Pro Mini is recommended for comfortable multi-user operation.

---

## Known Gaps (as of v0.7.0-alpha)

~~**PostgreSQL trust auth**~~ — **Closed (PR #212).** Local connections now use `peer` auth (Unix socket) and `scram-sha-256` (TCP). Passwords stored in `~/.pgpass`. New-developer installs: `export POSTGRES_TRUST_AUTH=true` before `make db-init` (PR #213).

**Embedding-level RAG poisoning** is an open research problem. Provenance scoring and trust flagging exist; embedding-level anomaly detection is deferred.

**OAuth / LDAP not wired by default.** `OIDCBackend`, `GitHubOAuthBackend`, `LDAPBackend`, and `KerberosBackend` are all implemented (Phase 12–13). Activate by setting `gateway.auth_provider` in the hardware profile YAML — default remains `api_key`.

**Conversation sessions not yet integrated in web UI.** Phase 54 added the backend API. The web UI still submits tasks as standalone runs (no thread persistence). Planned for Phase 57.

---

## The Red-Team Summary

If someone wanted to attack this framework right now, here is the attack plan in order of likely success:

1. **Target the Researcher agent** with indirect injection in a web page the agent retrieves
2. **Poison the RAG store** via the Researcher agent storing a maliciously crafted document
3. **Read the health endpoint** (`/metrics`, `/usage`) to learn API usage patterns, then time a resource bomb when the daily budget is nearly exhausted
4. **Wait for PentestAgent** to be deployed — if not air-gapped and signed, it becomes the attacker's tool library
5. **Social engineer the human approval gate** by generating a plausible-sounding Threat Analyst report recommending a rule that creates a whitelist exception

**The lesson:** Your human approval gates are your strongest defense and your primary target once technical defenses are in place. Make them easy to use correctly and hard to manipulate.

**→ Full red-team analysis:** [`RESEARCH.md §3`](./RESEARCH.md)

---

## Open Technical Debt

**Finding 4 — DESTRUCTIVE_PATTERN not logged to DB:** Guardian Check 3 (destructive pattern detection) halts tool execution but the threat event is not written to `threat_events`. Low priority; logged to stderr only. Tracked for a future hardening sprint.

**Kerberos live KDC** is fully operational: MIT Kerberos 1.22.2 KDC running locally, `gssapi` built against MIT Kerberos (not Heimdal), SPNEGO round-trip verified end-to-end, `make test-kerberos` passes **5/5**. Full setup guide in `docs/SCALING.md`.

**→ Target architecture:** [`docs/VISION.md`](./docs/VISION.md)
**→ Current build state:** [`PROJECT_STATUS.md`](./PROJECT_STATUS.md)

---

## File Map

| File | What It Is |
|---|---|
| **TLDR.md** (this file) | Start here. Orientation and summary. |
| [`PROJECT_STATUS.md`](./PROJECT_STATUS.md) | Current build state, infrastructure details, known issues |
| [`PHASE_PLAN.md`](./PHASE_PLAN.md) | Full phased roadmap with components, dependencies, and exit criteria |
| [`RESEARCH.md`](./RESEARCH.md) | Threat taxonomy, design theory, open questions, competitive context |
| [`SECURITY.md`](./SECURITY.md) | Threat model, HITL halt/log policy, injection detection architecture |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | Branch strategy, commit conventions, smoke test requirements |
| [`VERIFICATION.md`](./VERIFICATION.md) | Step-by-step setup and verification guide |
| [`docs/VISION.md`](./docs/VISION.md) | Product vision, target architecture, hardware reality, Phase 8+ roadmap |
| [`docs/PHASE_8_GATEWAY_SPEC.md`](./docs/PHASE_8_GATEWAY_SPEC.md) | Phase 8 gateway API contract, schema, and implementation plan |
| [`docs/A2A_CONFORMANCE.md`](./docs/A2A_CONFORMANCE.md) | A2A protocol conformance checklist and gap analysis |
| [`docs/architecture.md`](./docs/architecture.md) | Implementation-level technical reference (modules, patterns, data flow) |
