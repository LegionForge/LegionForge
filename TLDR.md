# TLDR.md
# LegionForge — What Is This and What Are We Building?

**Version:** 1.0.0
**Last updated:** 2026-02-27

---

## What Is This?

A **local-first, open-source, security-native AI agent framework** built on LangGraph, running on a Mac Mini M4. Agents can use local LLMs (Ollama) or cloud APIs. Security is built into the foundation — not bolted on later.

**The one-line pitch:** The hardened, self-hosted alternative to OpenClaw — and a security layer that other agent frameworks can plug into.

---

## Current Status

✅ **Phases 0–7 are complete. v1.0.0 is shipped.**

The full security stack is operational: Guardian sidecar (7 checks), immutable audit log with halt-on-tamper, crystallization pipeline (Observer → Crystallizer → Pre-HITL Analyzer → human gate → Ed25519-signed tool), air-gapped PentestAgent (24 attack functions, 0 bypasses on clean deploy), and the pentest→Guardian feedback loop (approved findings hot-reload into enforcement within 10 seconds).

**323/323 smoke tests passing** (~1s, no external services required).

✅ **Phase 8 complete:** Gateway service (:8080), task queue, SSE streaming, web UI, A2A + MCP endpoints, Guardian arg-forwarding gaps closed.

---

## The Big Picture — Phases 0–8 Complete

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
| **9** | Tool library expansion, langchain 1.x migration, parallel agent fan-out | ⬜ Next |

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

## Known Gaps (as of Phase 8)

**Agents run serially, not in parallel.** The orchestrator spawns one sub-agent at a time. Parallel fan-out requires `asyncio.gather()` or LangGraph `Send()` — Phase 9.

**Tool library is narrow.** Only web search, web fetch, and document summarize exist. Phase 9 adds file I/O, structured data query, HTTP API calls, and sandboxed code execution.

**langchain-core SSRF (Dependabot #4, LOW — accepted risk).** Fix requires migrating the full langchain stack from 0.3.x → 1.x. We never call the vulnerable method (`ChatOpenAI.get_num_tokens_from_messages` with image URLs). Planned for Phase 9.

**Embedding-level RAG poisoning** is an open research problem. Provenance scoring and trust flagging exist; embedding-level anomaly detection is deferred.

**GGUF hash pinning** — `gguf_sha256: ""` in the hardware profile means model integrity is skipped until the operator pins the values after running `make verify-models`.

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

## Immediate Next Steps

### Phase 9 — Tool Expansion, langchain 1.x Migration, Parallel Fan-Out

**Priority order:**

1. **langchain 0.3.x → 1.x migration** — closes Dependabot #4 (LOW SSRF), unlocks new LangGraph features. All langchain-* pins must upgrade together.

2. **Tool library expansion** — file I/O, structured data query, HTTP API calls, sandboxed code execution. Each new tool requires: Ed25519 registration + Guardian capability entry + smoke tests.

3. **Parallel agent fan-out** — orchestrator currently spawns sub-agents serially. Add `asyncio.gather()` / LangGraph `Send()` for parallel task execution.

**→ Full Phase 8 spec (complete):** [`docs/PHASE_8_GATEWAY_SPEC.md`](./docs/PHASE_8_GATEWAY_SPEC.md)
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
