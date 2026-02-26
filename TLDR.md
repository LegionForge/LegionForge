# TLDR.md
# LegionForge — What Is This and What Are We Building?

**Version:** 1.2.0
**Last updated:** 2026-02-26

---

## What Is This?

A **local-first, open-source, security-native AI agent framework** built on LangGraph, running on a Mac Mini M4. Agents can use local LLMs (Ollama) or cloud APIs. Security is built into the foundation — not bolted on later.

**The one-line pitch:** The hardened, self-hosted alternative to OpenClaw — and a security layer that other agent frameworks can plug into.

---

## Current Status

✅ **Phases 0–5.5 are complete.** The full crystallization pipeline is operational (Observer → Crystallizer → Pre-HITL Analyzer → Human gate → Ed25519-signed tool), and a ten-vector security hardening sprint has closed the major attack surface identified during adversarial threat-model review.

**200/200 smoke tests passing.** Database RBAC, AST bypass guards, tool revocation, TOCTOU prevention, and Ollama model integrity are all in production.

⬜ **Next:** Phase 6 — PentestAgent (air-gapped red-team bot, continuous security regression).

---

## The Big Picture — Six Phases (+ Security Hardening Sprint)

| Phase | What Gets Built | Status |
|---|---|---|
| **0** | Infrastructure, database, LLM factory, health server | ✅ Done |
| **1** | Researcher agent + tool registry + capability boundaries + threat event logging | ✅ Done |
| **2** | Docker containerization + Guardian security sidecar + immutable audit log + RAG provenance | ✅ Done |
| **3** | Task tokens + ACLs + sub-agent orchestrator | ✅ Done |
| **4** | Threat Analyst agent + adaptive Guardian rules + AI-BOM | ✅ Done |
| **5** | Crystallization Pipeline — Observer + Crystallizer agents, pre-HITL analyzer, signed tools | ✅ Done |
| **5.5** | Security hardening: DB RBAC, AST bypass guards, tool revocation, TOCTOU, model integrity | ✅ Done |
| **6** | PentestAgent — air-gapped red-team bot, continuous security regression | ⬜ Next |

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

- **Automated red-teaming** — Phase 6 PentestAgent will run a full attack suite against deployed agents (prompt injection, RAG poisoning, privilege escalation, resource bombs, crystallized tool behavioral attacks). Manual trigger only.
- **Embedding-level anomaly detection** — RAG poisoning at the semantic vector level remains an open research problem. Provenance scoring and trust flagging exist; embedding-level anomaly detection is deferred.
- **pip-audit / dependency hash pinning** — supply chain hygiene for our own Python dependencies. Supply chain attacks via transitive deps remain an accepted residual risk.
- **GGUF hash pinning** — `make verify-models` prints hashes for pinning; `gguf_sha256: ""` in the hardware profile means model integrity is skipped until the operator pins the values.
- **Structured escalation requests** — the Phase 3 design doc describes structured output for escalation (`{"status": "needs_escalation", ...}`). The token-level blocking exists; the UI for structured approval flows is deferred.

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

### One-time production hardening (Phase 5.5 post-merge)

Run these once against a running PostgreSQL instance — they're idempotent:

```bash
make setup-db-roles    # provision legionforge_app restricted PostgreSQL user
make verify-models     # print SHA256 of GGUF files, then pin in mac_m4_mini_16gb.yaml
make build-analyzer    # build deny-default Docker analyzer image
```

### Phase 6 — PentestAgent

The next development phase builds an air-gapped red-team bot that runs a structured attack suite against deployed agents. Results feed the Threat Analyst; undetected attacks become proposed Guardian rules.

Key design constraints:
- **Isolation:** air-gapped container, no production data access, synthetic environment only
- **Trigger:** manual only — never autonomous
- **Attack surface:** direct prompt injection, indirect injection via poisoned RAG documents, tool metadata poisoning, resource bombs, ACL privilege escalation, crystallized tool behavioral equivalence attacks
- **Output:** structured pentest report at `/security/pentest/latest`; proposed Guardian rules for human review

**→ Full Phase 6 spec:** [`PHASE_PLAN.md — Phase 6`](./PHASE_PLAN.md)
**→ Current build state:** [`PROJECT_STATUS.md`](./PROJECT_STATUS.md)

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
