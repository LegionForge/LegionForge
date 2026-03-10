# RESEARCH.md
# LegionForge — Threat Research, Design Theory & Open Questions

**Version:** 2.0.0
**Last updated:** 2026-02-22

> **Related docs:**
> - [`TLDR.md`](./TLDR.md) — Quick summary
> - [`PROJECT_STATUS.md`](./PROJECT_STATUS.md) — Current build state
> - [`PHASE_PLAN.md`](./PHASE_PLAN.md) — Implementation roadmap

---

## §1 — Attack Taxonomy: What We Are Defending Against

This section catalogs the threat classes relevant to LLM agent frameworks as of early 2026, mapped to our framework components and mitigations.

---

### 1.1 Tool Poisoning

**What it is:** Malicious instructions embedded in a tool's *metadata* (name, description, input schema) rather than its output. The LLM reads tool descriptions during registration and treats them as trusted instructions. An attacker who can modify a tool's description can hijack the agent's behavior before any user input is processed.

**Why it's severe:** Research benchmarks (MCPTox, 2025) found attack success rates above 60% on most major models, including 72.8% on o1-mini. More capable models are *more* susceptible because they follow instructions more precisely. Existing safety alignment is largely ineffective against this vector.

**Variants:**
- *Tool Metadata Poisoning* — modifying tool description/schema at rest
- *Rug-Pull* — tool behaves legitimately initially, then changes description after trust is established (some variants poll a C2 server for activation)
- *Rug-Pull at Depth* — tool behavior changes without description changing (dependency update, external API behavior change, model weight change). Hash check on description passes; behavior is different.
- *Shadow Attack* — a malicious tool mimics and intercepts calls to a legitimate one
- *Tool Preference Manipulation* — a tool description claims to be "the best option" or "required for security," manipulating LLM tool selection
- *Parasitic Toolchain* — chained tools propagate malicious instructions through an interlinked tool network

**Our mitigation:**
- Phase 1: Tool registry with explicit human approval gate before any tool executes
- Phase 1: Hash tool description + schema + entrypoint + declared side effects at registration; verify before every invocation
- Phase 1: Behavioral contract enforcement — tools declare side effects, Guardian enforces them
- Phase 1: Model integrity hash at startup — unexpected model file change halts startup
- Phase 2: Guardian validates hash on every `/check` call
- Phase 5: Cryptographic signing of all tools in the tool library; signature verification at load time
- Phase 6: PentestAgent runs rug-pull simulations against all registered tools

**Open questions:**
- R-01: Should description changes for in-library tools trigger automatic demotion to PENDING vs. hard block?
- R-11: How do we detect rug-pull at depth — behavioral change without description change — in LLM-based tools where inference is non-deterministic?

---

### 1.2 Prompt Injection

**What it is:** Malicious instructions embedded in content the agent processes — web pages, emails, documents, API responses — that the LLM interprets as legitimate commands rather than data.

**Direct injection:** Attacker controls the user input directly (e.g., jailbreaks, goal hijacking).

**Indirect injection:** Attacker plants instructions in third-party content that the agent will later retrieve. The user never sees the malicious content. Attack success rates for indirect injection in research settings: 27–85% depending on model and delivery method.

**Memory injection (SpAIware):** Malicious instructions are injected into the agent's long-term memory (RAG store, conversation history) and persist across sessions. A document might read as legitimate to humans but be positioned at embedding level to intercept security-sensitive queries.

**Our mitigation:**
- Phase 0: `security.py` prompt injection pattern detection (existing)
- Phase 1: All web content passes through `security.py` sanitizer before entering LLM context
- Phase 1: Output sanitization on all external tool responses (new — not just inputs)
- Phase 2: RAG document provenance scoring; low-trust content flagged in context
- Phase 2: Embedding-level trust scoring for stored documents
- **Not fully solved:** "No model achieves both strong task performance and robust defense" against sophisticated injection. Design assumes some attacks succeed; mitigation focuses on blast radius limitation.

---

### 1.3 Credential Stuffing / Key Theft

**What it is:** Agents need credentials to call external APIs. Attackers target: `.env` files, environment variables in process memory, log files that capture context windows, and the agent's context window itself (which may be logged to external services).

**The context window leak:** Agents frequently log their entire context — including loaded environment variables — to LangSmith, debug endpoints, or external servers. A credential in the context window is a credential at risk.

**Our mitigation:**
- Phase 0: macOS Keychain storage (no `.env` files with credentials)
- Phase 0: PII redaction in `security.py` (covers email, phone, SSN, card)
- Phase 1: Extend PII redaction to all outbound API calls (not just LangSmith traces)
- Phase 1: Audit LangSmith trace content — verify sanitization runs before upload (R-02)
- Phase 2: Guardian scrubs tool call arguments and outputs for credential patterns before logging
- Phase 3: Task tokens are short-lived and scoped; no long-lived agent credentials

---

### 1.4 Resource Exhaustion / Economic DOS

**What it is:** Crafted prompts designed to maximize token consumption, trigger deep tool-call chains, or exploit the agent's loop-following behavior to rack up costs.

**Our mitigation:**
- Phase 0: `rate_limiter.py` with daily token/cost alerts and hard cutoffs
- Phase 0: `safeguards.py` loop protection fires after N steps (fires *after* tokens consumed)
- Phase 1: Pre-execution token cost estimation before any API call; reject resource bombs before they start
- Phase 2: Guardian detects anomalous call rates within a single run
- Phase 2: Docker resource limits on agent containers

---

### 1.5 MITM / Security Interchange Attacks

**What it is:** Interception of communication between agents, between an agent and a tool, or between an agent and an external API. In multi-agent systems, a compromised intermediate agent can modify messages in transit, creating cascading failures.

**Our mitigation:**
- Phase 3: Inter-agent communication routes through the orchestrator only
- Phase 3: All inter-agent messages validated by Guardian before delivery
- Phase 4: Threat Analyst monitors for unusual inter-agent communication patterns
- Phase 5: Cryptographic signing of tool outputs; inter-agent message signing

---

### 1.6 Supply Chain / Dependency Poisoning

**What it is:** Malicious code or instructions introduced through third-party dependencies — pip packages, MCP server plugins, Docker base images, or the tool library itself.

**Our mitigation:**
- Phase 1: Tool registry with explicit approval gate — no unapproved tool executes
- Phase 5: Cryptographic signing of all tools; any tampering breaks signature
- Phase 5: AI-BOM tracks all dependencies with versions and CVE status
- Phase 4: Threat Analyst cross-references CVE feeds against the BOM
- Phase 6: PentestAgent tests tool library entries for supply chain attack patterns

---

### 1.7 RAG / Memory Poisoning

**What it is:** Corrupting the agent's knowledge base (pgvector store) with adversarially crafted documents. Documents may appear legitimate to humans but are positioned at the embedding level to intercept specific query types.

**Why this is underrated:** A poisoned document in the vector store is a *persistent* problem — it affects every future retrieval that returns it, across all runs, indefinitely. It is the one attack class that survives agent restart.

**Our mitigation:**
- Phase 2: Document provenance table — source, trust score, content hash at ingestion time
- Phase 2: `score_document_trust()` — sources classified by trust tier
- Phase 2: Low-trust documents flagged in LLM context with explicit warning
- Phase 2: Embedding distribution anomaly detection at ingestion (one-time cost per document)

---

### 1.8 Adversarial ML / Model Backdoors

**What it is:** Malicious instructions embedded during model fine-tuning. "BadAgent" research shows 20% data poisoning achieves >90% attack success rate. Relevant only if we fine-tune.

**Our mitigation:** Use only models from verified sources. AI-BOM tracks model origins. Model integrity hashed at startup. Do not fine-tune without a full security review process.

---

### 1.9 Capability Amplification / Emergent Tool Creation *(new)*

**What it is:** An internal agent, operating entirely within its approved scope, dynamically creates or modifies tools at runtime. The agent is legitimate. The tool creation capability is legitimate. The result is an unapproved tool that inherits the agent's trust level.

**Why it's dangerous:** This is the Ken Thompson "Trusting Trust" problem applied to agents. A validated agent that can write and execute code is a compiler. What it produces is not validated, but it runs with the agent's trust level. No hash check catches it — the tool didn't exist at registration time.

**The attack path:** Agent is given a task → agent determines it needs a new capability → agent writes a Python function → agent invokes it → unapproved code executes with agent's permissions.

**Our mitigation:**
- Phase 1: Negative capability list in Guardian — no agent may register tools, write executable files, or invoke unregistered callables, regardless of task token scope. This list cannot be overridden by any token.
- Phase 2: Guardian enforces the capability boundary on every `/check` call
- Phase 3: Orchestrator-only agent spawning pattern — sub-agents cannot spawn peers

**Residual risk:** A sufficiently clever agent might synthesize capability through a chain of individually-permitted actions. Capability minimization raises the bar but does not fully eliminate this.

---

### 1.10 Modification of Previously Validated Components *(new)*

**What it is:** A component passes validation at registration time and is marked APPROVED. Later, something changes without triggering a hash mismatch: a transitive dependency updates, a configuration file is modified, an external API the tool calls changes its behavior, or an Ollama model is silently updated.

**The key distinction from tool poisoning:** The tool's *description* hasn't changed (hash check passes), but the tool's *behavior* has changed. This is the rug-pull at depth — the attack surface is the gap between what you hashed and what actually determines runtime behavior.

**Our mitigation:**
- Phase 1: Extended tool manifest — hash description, schema, entrypoint code, and declared side effects
- Phase 1: Model integrity hash at startup — `ollama pull` changes the model file; verify before any agent runs
- Phase 1: TLS certificate pinning on external API endpoints approved at registration — unexpected cert change = investigate before updating
- Phase 2: Behavioral contract enforcement — if a tool does something outside its declared side effects, `BEHAVIORAL_CONTRACT_VIOLATION` is logged and the action is halted
- Phase 5: Dependency hash pinning in tool manifests — transitive dependency changes break the manifest hash

**Open question:** R-11 — how do we detect behavioral drift in LLM-based tools where non-determinism means identical inputs can produce different outputs?

---

### 1.11 Compositional Emergence *(new)*

**What it is:** Each approved component is individually benign. Their combination produces behavior that none of them exhibit alone. No single component triggers a detector. The malicious behavior is a property of the composition.

**Why it's hard:** Formally verifying that a composition of N components doesn't produce emergent behavior requires exploring an astronomically large state space. This is NP-hard in the general case. It is not a solved problem in computer security.

**Real-world analog:** No single syscall is dangerous. A specific sequence of syscalls exfiltrates data. This is why systems like seccomp-bpf filter syscall *sequences*, not individual calls.

**Our mitigation:**
- Phase 1: Capability minimization — agents that can't create tools can't create novel compositions that weren't anticipated
- Phase 2: Approved combination patterns — expected tool sequences declared per agent at registration; novel combinations flagged for human review before production execution
- Phase 2: Sequence anomaly detection in `audit_log` — Guardian watches for suspicious action sequences
- Phase 2: Sandbox-first execution for any tool combination that has never been run before
- Phase 4: Threat Analyst analyzes action sequences in `audit_log` for anomalous patterns

**Accepted residual risk:** Novel emergent behavior from approved component combinations is not fully preventable. Named and accepted. Compensating controls: capability minimization, combination monitoring, sandbox-first for novel combos, immutable audit trail for forensic reconstruction.

---

## §2 — Fail-Safe Taxonomy

The framework uses a three-tier fail-safe model. The appropriate tier is declared per-tool and per-agent at configuration time, not determined at runtime.

### Tier 1 — Halt and Quarantine

**When:** High-confidence threat (Guardian confidence ≥ 0.85). Known attack patterns. Tool hash mismatch. Credential exfiltration attempt. Capability boundary violation. Unregistered tool invocation attempt.

**What happens:**
1. Execution stops immediately at the current LangGraph node
2. Agent state is written to PostgreSQL with status `QUARANTINED`
3. The run_id is added to a blocklist
4. Ephemeral credentials and task tokens for this run are revoked
5. Event written to `threat_events` and `audit_log`
6. Alert fires to health dashboard

### Tier 2 — Sandbox and Retry

**When:** Ambiguous anomaly (Guardian confidence 0.40–0.84). Statistically unusual behavior. Novel tool combination not previously seen.

**What happens:**
1. Execution pauses at the suspicious node
2. The suspicious action is re-executed in an isolated sandbox container
3. Sandbox behavior is compared to expected behavior
4. Divergent behavior escalates to Tier 1 — divergence itself is a strong signal of malicious intent
5. Event logged regardless of outcome

### Tier 3 — Degrade and Continue

**When:** Soft failure — tool unavailable, model timeout, non-security constraint violation.

**What happens:** Fail back to a defined alternative path; partial result returned with confidence annotation; event logged.

---

## §3 — The Security Framework as Attack Surface

### 3.1 Guardian as Attack Target

Guardian sees every prompt, every tool argument, every credential reference in the check path. A compromised Guardian is a perfect wiretap.

**Mitigations:** Zero external dependencies; no eval/exec in threat event processing; loopback only; read-only access pattern for Guardian's own decision data; constant-time check responses to prevent timing attacks.

### 3.2 Threat Analyst as Attack Target

Threat Analyst reads external intelligence feeds. A poisoned feed could manipulate it into proposing rules that lower defenses.

**Mitigations:** All external content passes through RAG provenance scoring; proposed rules require human approval before application; Threat Analyst cannot apply its own rules; human reviewer sees full proposed rule in plain language.

### 3.3 PentestAgent as Attack Target

PentestAgent stores working attack payloads. If compromised, it becomes the attacker's most powerful tool.

**Mitigations:** Air-gapped container with no production network access; manual invocation only; attack payload library stored encrypted and signed; containers spun up fresh and destroyed after each run.

### 3.4 The Human Approval Gate as Attack Target

Once technical defenses are hardened, the human approval gate becomes the primary attack target.

**Attack vectors:** Crafting a plausible Threat Analyst report recommending a weakening rule; fatigue attacks (large volume of benign proposals before slipping in a malicious one); timing attacks.

**Mitigations:** Rules presented in plain language with explicit "what this allows / what this blocks" summaries; approval UI flags new ALLOW conditions more prominently than new BLOCK conditions; rate limit on rule proposals per day (R-08); explicit confirmation required for any rule creating a new ALLOW exception.

---

## §4 — Trust Surface Map

### What We Validate and Where

Validate at trust boundaries. Do not validate at processing nodes.

**Trust boundaries** — where Guardian enforces controls:

| Boundary | Direction | Threat | Control | Phase |
|---|---|---|---|---|
| External tool response | inbound | Injection, poisoned content | Output sanitization + injection detection | **1** |
| Outbound API call | outbound | PII/credential exfiltration | Redaction on all outbound calls | **1** |
| Tool invocation | internal | Tool poisoning, capability violation | Registry + hash verify + capability boundary | **1** |
| RAG ingestion | inbound | Memory/embedding poisoning | Document provenance + trust scoring at ingestion | 2 |
| Agent → agent message | internal | Prompt infection, cascade | Inter-agent validation + scope check | 3 |
| Orchestrator → sub-agent | internal | Privilege escalation | Derived task tokens, narrower scope | 3 |
| External feed → Threat Analyst | inbound | Intelligence poisoning | Provenance scoring on all Threat Analyst inputs | 4 |
| Tool library → agent | inbound | Supply chain, rug-pull at depth | Cryptographic signing + signature verify | 5 |

**Processing nodes** — secured via safeguards, not validation:
- Internal agent logic
- LLM inference
- Safeguard checks
- Internal state transitions within a single agent

### What We Do NOT Validate (and Why)

- **Internal agent code at runtime** — verify via git instead; hashing your own running code is redundant and fragile
- **LLM inference correctness** — not a security control; this is an accuracy problem, not a trust boundary problem
- **Individual tool calls in isolation** — we validate the tool identity and capability scope, not the semantic correctness of each call

---

## §5 — ACL and Privilege Design Theory

### 5.1 The Confused Deputy Problem

An agent with broad permissions is a confused deputy. When an attacker injects instructions into the agent's context, the agent acts on those instructions using its own legitimate credentials. The network layer cannot distinguish a legitimate database query from an attacker-coerced exfiltration.

### 5.2 Task Tokens vs. Agent Identity

Privilege should be tied to the task, not the agent. A `TaskToken` represents a specific authorization scoped to a run, expiring, non-extendable by the agent itself.

### 5.3 Sub-Agent Privilege Inheritance

Sub-agents receive derived tokens scoped at or below the parent's scope. Enforced cryptographically — the orchestrator signs the derived token; Guardian validates the derivation chain.

### 5.4 The Negative Capability List

Distinct from the scope system. Where task tokens define what an agent *is allowed to do*, the negative capability list defines what *no agent can ever do regardless of any token*. It is not a permission — it is a hard architectural constraint enforced by Guardian.

Current negative capability list:
```
register_tool          — only humans register tools
write_executable       — no writing .py, .sh, .so, .dylib files
invoke_unregistered    — only registry-approved tools run
modify_registry        — registry is append-only via human gate
escalate_scope         — no self-promotion of task token
spawn_agent_direct     — only orchestrator spawns agents
modify_own_state       — agents cannot edit their own task tokens
```

This list is the primary defense against capability amplification (§1.9).

---

## §6 — Content Provenance and the Chain of Trust Problem

### 6.1 Why Transport Security Is Insufficient for Agentic Systems

TLS secures each hop independently. It says nothing about whether the content at any hop is truthful, or whether an intermediate agent was compromised by a previous hop's output before passing instructions forward. Each TLS session is a fresh trust assertion with no memory of the chain.

In a multi-agent pipeline, "trust me bro" is the implicit protocol at every inter-agent message boundary. The content has no provenance. By the time a result reaches the end of the chain, it could have been modified at any intermediate step with no cryptographic evidence of that modification.

### 6.2 What Content Signing Actually Proves (and Doesn't)

**Content signing proves:**
- Integrity — the content was not modified after signing
- Origin authentication — the content came from the holder of this private key
- Temporal binding — it was signed approximately when the timestamp claims

**Content signing does not prove:**
- Correctness — the content is actually right
- Safety — the content won't cause harm
- Good faith — the signer wasn't compromised before signing

This is the fundamental limitation: the threat surface in agentic AI is *semantic*, not *syntactic*. A perfectly integrity-protected message can instruct an agent to exfiltrate a database, and no cryptographic primitive will catch it because the bits are fine — it's what they mean that's dangerous.

### 6.3 The CA Hierarchy Analogy

The agentic trust chain problem is structurally isomorphic to the web PKI problem. The conceptual mapping:

| Web PKI | Agent Framework |
|---|---|
| Root CA | Framework operator (human) |
| Intermediate CA | Orchestrator agent |
| Leaf certificate | Tool or sub-agent |
| Certificate | Task token + public key binding |
| OCSP / CRL | Guardian revocation check |
| Certificate Transparency log | `audit_log` table (append-only hash chain) |
| Certificate pinning | Tool registry hash binding |
| Chain of trust | Agent delegation chain |

The Phase 3 task token system already *is* a CA hierarchy — orchestrator holds the master token, sub-agents get derived tokens. Adding Ed25519 key pairs to task tokens and signing inter-agent messages converts it into a cryptographically verifiable provenance chain.

### 6.4 What Content Signing Adds to the Security Model

With a cryptographic provenance chain on inter-agent messages, every message carries proof that:
1. Every entity in the chain was issued a credential by a verifiable parent
2. No credential in the chain has been revoked
3. Every entity operated within its declared scope
4. The content was not modified at any hop (content hash chain)
5. The chain is temporally consistent (no replays, no expired credentials)
6. Guardian attested to each hop

**What it still doesn't add:** Proof that a legitimate tool wasn't compromised before signing, or that the content is semantically safe. Those require Guardian content analysis and the Threat Analyst, not cryptography.

### 6.5 Why MCP Doesn't Have This

MCP signs the transport, not the content. This means a compromised MCP server can return poisoned tool results that look legitimate at the transport layer — the content arrives over a valid TLS connection from the right server, but the server itself was compromised after that cert was issued.

Content-level signing would close this gap. It's absent from MCP because: the ecosystem is too young for a PKI standard, key distribution at scale is hard, and TLS felt sufficient for two-party interactions. Multi-agent chains break the two-party assumption. This is an open gap in the MCP specification.

---

## §7 — Tool Crystallization Theory

### 7.1 The Core Insight

LLMs excel at novel reasoning. They are expensive for repetitive, deterministic work. When agents solve the same well-structured problem repeatedly, crystallize it into a signed deterministic tool. Zero LLM overhead for routine work.

### 7.2 When Crystallization is Appropriate

Candidate: solved 5+ times consistently, no ambiguity, same algorithm would always be correct, no external knowledge required beyond inputs.

Not a candidate: variable structure inputs, judgment or context required, natural language interpretation, novel problem each time.

### 7.3 Security Implications of the Tool Library

The tool library is a supply chain. Cryptographic signing addresses tampering, but creates a key management requirement. Key rotation procedure: re-sign all tools with new key, keep old key valid for 30-day grace period, then revoke.

---

## §8 — Open Research Questions

Questions we do not yet have firm answers to, ordered by phase and priority.

| # | Question | Phase | Priority | Status |
|---|---|---|---|---|
| R-01 | Should description changes for in-library tools trigger automatic demotion to PENDING vs. hard block? | 5 | High | Open |
| R-02 | Does LangSmith receive sanitized or raw traces? Audit required before Phase 1 ships. | **1** | **Critical** | Open — close with Phase 1 PII audit |
| R-03 | Optimal pre-execution token estimation formula accounting for unknown tool chain depth | **1** | High | Open |
| R-04 | Embedding-level anomaly detection: per-retrieval vs. per-ingestion cost tradeoff on M4 hardware | 2 | Medium | Open |
| R-05 | Should inter-agent messages be signed with Ed25519 keys derived from task tokens? (Replaces JWT-only approach) | 3 | Medium | Open — see §6.3 for architecture |
| R-06 | What does a pip-audit / requirements hash-pinning CI policy look like for this project? | 2 | Medium | Open |
| R-07 | Fine-tuning security policy: if we ever fine-tune Ollama models, what is the training data provenance requirement? | future | Low | Open |
| R-08 | What is the right rate limit on Threat Analyst rule proposals per day to prevent fatigue attacks on the human approver? | 4 | Medium | Open |
| R-09 | Can semantic sanitization (LLM-based, offline) be run on a schedule over all stored RAG documents to detect retroactive poisoning? | 4 | Low | Open |
| R-10 | Resource requirements benchmark: full Phase 6 deployment peak memory under concurrent agent load on M4/16GB | 5 | High | Open |
| R-11 | How do we detect rug-pull at depth — behavioral change without description change — in LLM-based tools where inference is non-deterministic? | 2 | High | Open — no clean solution known |
| R-12 | Approved tool combination patterns: how do we build a baseline of normal agent action sequences without an impractical burn-in period? | 2 | Medium | Open |
| R-13 | Is the MCP specification the right place to propose content-level signing? What would a draft look like and who are the right stakeholders? | future | Low | Open — worth watching MCP spec development |
| R-14 | For the negative capability list: can a sufficiently clever agent synthesize a forbidden capability through a chain of individually-permitted actions? What chains should we enumerate? | 2 | High | Open — partial enumeration needed before Phase 2 |
| R-15 | Compositional emergence detection: at what N (number of approved components) does the interaction state space become too large to monitor meaningfully? What's the right monitoring strategy at scale? | 4 | Medium | Open — theoretical; revisit at Phase 4 |
| R-16 | TLS certificate pinning for external tool API endpoints: how do we handle legitimate cert rotation without creating operational friction that leads to security bypass? | 2 | Medium | Open |

---

## §9 — Residual Risks — Named and Accepted

These risks are real, partially or fully unsolvable with current tooling, and are accepted explicitly with compensating controls documented. Named and accepted risk is better than ignored risk.

| Risk | Class | Why It's Hard | Compensating Controls |
|---|---|---|---|
| Compromised tool that signs its own malicious output | Semantic | Content signing proves provenance, not safety | Output sanitization + Guardian content analysis + behavioral contract enforcement |
| Novel semantic injection evading pattern matching | Semantic | Guardian hot path is deterministic; unknown-novel attacks can't be enumerated | Sandbox-retry (Tier 2) + Threat Analyst (Phase 4) + PentestAgent (Phase 6) |
| Compositional emergence from approved components | Compositional | NP-hard to verify in general case | Capability minimization + combination monitoring + sandbox-first for novel combinations + immutable audit trail |
| Behavioral drift from model weight changes | Behavioral | Hash checks description, not inference behavior | Model integrity hash at startup; re-approval required after any `ollama pull` |
| Embedding-level RAG poisoning (semantic, not content-based) | Semantic | Open research problem; evades text-based filters | Provenance scoring + trust flagging in context; embedding anomaly detection at ingestion (Phase 2) |
| Human approval gate social engineering | Human | Terminal defense is human; humans can be manipulated | Plain-language rule presentation + diff view + ALLOW-condition prominence + proposal rate limits |
| Root key compromise | Infrastructure | Entire credential chain depends on root key | Root key offline when not in use; all issuance logged to audit_log; emergency `FRAMEWORK_COMPROMISED` halt |

---

## §10 — Competitive Context

### Why This Framework Is Differentiated

**vs. Zenity, Cisco AI Defense, Microsoft Defender for Agents:** All enterprise-tier, closed-source, cloud-dependent, subscription-priced. No local-first or self-hosted option.

**vs. OpenClaw hardening guides:** Surface-level deployment hardening. No framework-level security primitives, no adaptive threat intelligence, no tool signing, no ACL token system.

**vs. LangGraph / CrewAI / Microsoft Agent Framework:** Orchestration frameworks with bolt-on security. Our security model is built into the framework template from day one.

**The specific gap we fill:** An open-source, self-hosted, containerized, LangGraph-based agent framework with framework-native security primitives — Guardian, tool registry, capability boundary enforcement, task tokens, Threat Analyst, PentestAgent — designed to be additive and platform-independent. Usable as a security layer by other frameworks via Guardian's HTTP API.

### Ecosystem Context (as of Feb 2026)

- OpenClaw (formerly Clawdbot/Moltbot) — 100K+ GitHub stars, going to open-source foundation; CVE-2026-25253 (CVSS 8.8) public
- Cisco AI Defense — enterprise MCP traffic inspection, February 2026 update
- Microsoft Dynamic Threat Detection Agent — public preview, Azure-native, adaptive behavioral signals
- MCPTox benchmark (AAAI 2026) — first systematic tool poisoning evaluation; 72.8% ASR on o1-mini
- OWASP Top 10 for Agentic AI — published 2025, now the reference standard for agent security assessment
- MCP specification — transport-level security only; content signing gap is unaddressed and unproposed as of Feb 2026

---

## §11 — References

1. MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers — arXiv 2508.14925 (2025)
2. When MCP Servers Attack: Taxonomy, Feasibility, and Mitigation — arXiv 2509.24272 (2025)
3. Prompt Injection Attacks in LLMs and AI Agent Systems: MDPI Information 17(1) 54 (2026)
4. OWASP Top 10 for LLM Applications and Agentic AI (2025)
5. MCP-SafetyBench: A Benchmark for Safety Evaluation — OpenReview (2025)
6. LLM Agent-Based Attacks — emergentmind.com synthesis (2025)
7. Security for Production AI Agents — Iain Harper's Blog (January 2026)
8. Cisco AI Defense Expansion announcement — Cisco Live EMEA, February 2026
9. Securing OpenClaw (Moltbot/Clawdbot): Docker hardening — Composio blog (2026)
10. How to Sandbox AI Agents in 2026 — Northflank Blog
11. From Clawdbot to Moltbot to OpenClaw: Digital Backdoor — Vectra AI (2026)
12. Container Escape Vulnerabilities: AI Agent Security — Blaxel Blog (2026)
13. AI Security Trends 2026 — Prompt Security (2025)
14. Reflections on Trusting Trust — Ken Thompson, ACM Communications, 1984 (foundational — capability amplification analog)
15. Formal Verification of Multi-Agent Systems — survey, various (NP-hardness of compositional verification)

### Design Theory & Memory Architecture

16. **The AI-Human Engineering Stack** — Hayen Mill & Henrique Jr. Sanchez (March 2026).
    GitHub: https://github.com/hjasanchez/agentic-engineering
    A five-layer cognitive framework for AI engineering (Prompt → Context → Intent → Judgment → Coherence) plus Evaluation and Harness meta-functions. Directly informed: KV-cache stability ordering in `src/base_graph.py` (the Manus Insight — stable context first, dynamic context last). The paper's layer analysis also provided a diagnostic map for LegionForge's architectural strengths (Layer 4: Judgment) and gaps (Layer 5: Coherence).

17. **Anchor Engine — STAR: Semantic Temporal Associative Retrieval** — Robert S. Balch II (2025–2026).
    GitHub: https://github.com/RSBalchII/anchor-engine-node
    DOI: 10.5281/zenodo.18841399
    A deterministic semantic memory system using graph traversal (bipartite Atoms ↔ Tags) instead of vector embeddings, with a physics-based gravity scoring formula. Directly informed: temporal decay in `src/database.py` `similarity_search()` — the STAR gravity formula `W = similarity × e^(-λ·Δt)` with a 30-day half-life is adapted from Anchor's published whitepaper (`docs/whitepaper.md`). The core insight — that agent memory retrieval should be deterministic and explainable, not statistically fuzzy — aligns with LegionForge's broader principle of replacing probabilism with determinism wherever possible.

18. **LATM — Learning to Use Tools by Making Them** — Cai et al., ICLR 2024.
    arXiv: https://arxiv.org/abs/2305.17126
    Foundational academic work on converting LLM-generated actions into reusable tools. Closest published antecedent to LegionForge-Anneal's crystallization pipeline.

19. **Voyager: An Open-Ended Embodied Agent with Large Language Models** — Wang et al., NVIDIA 2023.
    arXiv: https://arxiv.org/abs/2305.16291
    Demonstrated lifelong tool accumulation in agents. LegionForge-Anneal's differentiator from both Voyager and LATM is the production-hardening layer: sandboxed execution, adversarial testing, Ed25519 signing, HITL gate.
