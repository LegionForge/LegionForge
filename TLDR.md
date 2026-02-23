# TLDR.md
# LegionForge — What Is This and What Are We Building?

**Version:** 1.1.0
**Last updated:** 2026-02-22 22:00 CST

---

## What Is This?

A **local-first, open-source, security-native AI agent framework** built on LangGraph, running on a Mac Mini M4. Agents can use local LLMs (Ollama) or cloud APIs. Security is built into the foundation — not bolted on later.

**The one-line pitch:** The hardened, self-hosted alternative to OpenClaw — and a security layer that other agent frameworks can plug into.

---

## Current Status

✅ **Infrastructure is done.** All plumbing is running: PostgreSQL 17, pgvector, async LangGraph checkpointing, rate limiting, observability, health server, 23/23 smoke tests passing.

🔄 **Now building:** The first real agent (Researcher) + Phase 1 security foundations.

---

## The Big Picture — Six Phases

| Phase | What Gets Built | Why It Matters |
|---|---|---|
| **0** ✅ | Infrastructure, database, LLM factory, health server | Foundation — done |
| **1** 🔄 | Researcher agent + tool registry + capability boundaries + threat event logging | First agent + closes biggest security gaps |
| **2** | Docker containerization + Guardian security sidecar + immutable audit log + RAG provenance | Platform-independent; any framework can use Guardian |
| **3** | Task tokens + ACLs + sub-agent orchestrator | Safe multi-agent with tightly scoped privileges |
| **4** | Threat Analyst agent + adaptive Guardian rules + AI-BOM | Framework learns from its own threat history |
| **5** | Crystallization Pipeline — Observer + Crystallizer agents, pre-HITL analyzer, signed deterministic tools | Systematically replace AI with determinism; zero LLM overhead for routine tasks |
| **6** | PentestAgent (air-gapped red-team bot) | Continuous security regression testing against your own agents |

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

## What We Are NOT Building (and Why)

- **We are not building another OpenClaw.** OpenClaw is a personal assistant interface. We are building the security infrastructure layer that frameworks like OpenClaw need but don't ship with.
- **We are not building a supercomputer workload.** Full Phase 6 deployment peaks at ~8–9GB RAM on the M4. Stays within the 16GB envelope with model swapping.
- **We are not automating human judgment.** Security rule changes, tool promotions, privilege escalations, and crystallization approvals always require explicit human approval.
- **We are not fine-tuning models yet.** Using pre-trained Ollama models only. Fine-tuning introduces backdoor risks that require a separate security process.

---

## What We Are Missing (Known Gaps)

- **AI-BOM (Bill of Materials)** — cross-reference all components against CVE feeds. Planned Phase 4.
- **Immutable audit log** — current logs are mutable files. Hash-chain append-only log planned Phase 2.
- **LangSmith privacy audit (R-02)** — confirm PII redaction runs before upstream trace upload. Phase 1 critical blocker.
- **Output sanitization on tool responses** — input sanitization exists; outbound tool response sanitization is a Phase 1 critical blocker.
- **Embedding-level anomaly detection** — RAG poisoning at the vector level. Phase 2 open question.
- **pip-audit / dependency hash pinning** — supply chain hygiene for our own dependencies. Research item R-06.

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

Start here, in this order. Items marked 🔴 are critical blockers — the Researcher agent cannot ship without them.

1. 🔴 Add `tool_registry` table + `register_tool()` + `verify_tool_before_invocation()` to `security.py`
2. 🔴 Add output sanitization on all external tool responses to `security.py`
3. 🔴 Apply PII redaction to all outbound API calls, not just LangSmith (closes R-02)
4. 🔴 Add capability boundary enforcement to `base_graph.py` (negative capability list)
5. Add `threat_events` table to `database.py`
6. Add pre-execution token cost estimation to `rate_limiter.py`
7. Add model integrity hash check to `startup.sh`
8. Add no-op security stubs to `base_graph.py` (`guardian_check`, `validate_acl_token`, `score_embedding_trust`)
9. Build `src/agents/researcher.py`
10. Write `tests/test_researcher.py` (integration test)
11. Write smoke tests alongside every new component (see `CONTRIBUTING.md`)

**→ Full task list:** [`PROJECT_STATUS.md — Immediate Next Steps`](./PROJECT_STATUS.md)
**→ Full phase plan:** [`PHASE_PLAN.md — Phase 1`](./PHASE_PLAN.md)

---

## File Map

| File | What It Is |
|---|---|
| **TLDR.md** (this file) | Start here. Orientation and summary. |
| [`PROJECT_STATUS.md`](./PROJECT_STATUS.md) | Current build state, infrastructure details, known issues, immediate todos |
| [`PHASE_PLAN.md`](./PHASE_PLAN.md) | Full phased roadmap with components, dependencies, and exit criteria |
| [`RESEARCH.md`](./RESEARCH.md) | Threat taxonomy, design theory, open questions, competitive context |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | Branch strategy, commit conventions, smoke test requirements |
| [`VERIFICATION.md`](./VERIFICATION.md) | Step-by-step setup and verification guide |
