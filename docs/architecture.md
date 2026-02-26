# LegionForge Architecture

Phase 5.5 — Crystallization Pipeline + Security Hardening
Last updated: 2026-02-26

---

## 1. System Component Map

Shows every running process/service and how they connect.

```
┌─────────────────────────────────────────────────────────────────┐
│                        Mac M4 Mini 16 GB                        │
│                                                                 │
│  ┌──────────────────┐    ┌──────────────────┐                  │
│  │   Ollama :11434  │    │  PostgreSQL :5432 │                  │
│  │                  │    │                   │                  │
│  │  llama3.1:8b     │    │  DB: legionforge  │                  │
│  │  qwen2.5:3b      │    │                   │                  │
│  │  nomic-embed     │    │  Tables:          │                  │
│  │  (models on ext  │    │  · api_usage      │                  │
│  │   drive)         │    │  · tool_registry  │                  │
│  └────────┬─────────┘    │  · threat_events  │                  │
│           │              │  · health_metrics │                  │
│           │              │  · documents      │                  │
│           │              │    (pgvector)     │                  │
│  ┌────────▼─────────────►│                   │                  │
│  │  Health Server   │    │  checkpoints      │                  │
│  │  :8765           │    │  (LangGraph)      │                  │
│  │  /health         │    └────────┬──────────┘                  │
│  └──────────────────┘             │                             │
│                                   │                             │
│  ┌────────────────────────────────▼──────────────────────────┐  │
│  │                     Agent Process                          │  │
│  │                                                            │  │
│  │   src/base_graph.py  ──►  src/agents/researcher.py        │  │
│  │   src/security.py        src/safeguards.py                │  │
│  │   src/rate_limiter.py    src/llm_factory.py               │  │
│  │   src/observability.py   src/database.py                  │  │
│  │   config/settings.py                                      │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                 │
│  External:  DuckDuckGo (web_search) ──► Phase 2: SearxNG       │
│             Public HTTPS URLs      (web_fetch, SSRF-validated)  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Module Dependency Graph

Arrow means "imports from". Security primitives are at the bottom (no project imports).

```
                   researcher.py
                       │  │
          ┌────────────┘  └────────────┐
          ▼                            ▼
     base_graph.py ─────────────► safeguards.py
          │    │                       │
          │    └──────────┐            │
          │               ▼            │
          ▼          rate_limiter.py   │
     llm_factory.py                   │
          │                           │
          │    ┌──────────────────────┘
          │    │
          ▼    ▼
       security.py      observability.py      database.py
          │                   │                   │
          └───────────────────┴───────────────────┘
                              │
                              ▼
                       config/settings.py
                       (Pydantic singleton,
                        no project deps)
```

**Key rule:** `security.py` has zero project-level imports — it is the root of the
dependency tree. This prevents circular imports and keeps the security primitives
independently testable.

---

## 3. Agent Execution Flow (LangGraph State Machine)

This is the graph that runs for every agent invocation.

```
                         ┌──────────┐
                         │  START   │
                         └────┬─────┘
                              │ initial state
                              ▼
                    ┌─────────────────┐
              ┌────►│   agent_node    │◄────────────────────────┐
              │     │                 │                         │
              │     │ 1. increment    │                         │
              │     │    step_count   │                         │
              │     │ 2. sanitize     │                         │
              │     │    messages     │                         │
              │     │    (outbound)   │                         │
              │     │ 3. preflight    │                         │
              │     │    budget check │                         │
              │     │ 4. llm.ainvoke  │                         │
              │     │ 5. track tokens │                         │
              │     └────────┬────────┘                         │
              │              │                                   │
              │              ▼                                   │
              │   ┌──────────────────────┐                      │
              │   │  route_after_agent() │                      │
              │   │                      │                      │
              │   │  check_safeguards()  │                      │
              │   │  · force_end?        │──── "end" ──────────►│
              │   │  · loop_detected?    │                      │
              │   │  · step >= max?      │            ┌─────────┴────────┐
              │   │  · errors >= max?    │            │  finalizer_node  │
              │   │                      │            │                  │
              │   │  tool_calls in msg?  │            │ · extract result │
              │   └──────────┬───────────┘            │ · log run_end    │
              │              │                        └─────────┬────────┘
              │     ┌────────┴────────┐                         │
              │     │                 │                         ▼
              │  "tools"          "finalize"               ┌─────────┐
              │     │                 │                     │   END   │
              │     ▼                 └────────────────────►└─────────┘
              │  ┌──────────────────────────┐
              │  │    SecureToolNode        │
              │  │    (6-step pipeline)     │
              │  │    see diagram 4         │
              └──┤                          │
                 │  returns updated state   │
                 └──────────────────────────┘

Legend:
  ──► edge (always)
  ─── conditional edge (labeled with route value)
  All nodes are async. State is immutable between steps (reducer pattern).
```

---

## 4. SecureToolNode Pipeline

Every tool call passes through these 6 steps in order.
A failure at any step halts the tool call and returns `force_end: True`.

```
  Tool call request (from LLM tool_calls in last message)
                         │
                         ▼
         ┌───────────────────────────────┐
         │  Step 1: Registry + Hash      │
         │  verify_tool_before_          │
         │  invocation(tool_id)          │
         │                               │
         │  · Is tool_id in DB?          │
         │  · Status = APPROVED?         │
         │  · description_hash match?    │
         │  · schema_hash match?         │
         └───────────────┬───────────────┘
                         │ pass
                         ▼
         ┌───────────────────────────────┐
         │  Step 2: Guardian Check       │
         │  Guardian.check(tool_id,      │
         │    "invoke", state)           │
         │                               │
         │  · Is action in              │
         │    FORBIDDEN_CAPABILITIES?   │
         │  · (Phase 2: full sidecar)   │
         └───────────────┬───────────────┘
                         │ pass
                         ▼
         ┌───────────────────────────────┐
         │  Step 3: Loop Detection       │
         │  detect_action_loop(state,    │
         │    tool_id, tool_input)       │
         │                               │
         │  · SHA256 of tool_id+args     │
         │  · Same sig 3x in last 5?     │
         │  · Sets loop_detected: True   │
         └───────────────┬───────────────┘
                         │ pass
                         ▼
         ┌───────────────────────────────┐
         │  Step 4: Arg Sanitization     │
         │  (per-argument loop)          │
         │                               │
         │  4a. sanitize_tool_input()    │
         │      · PII redaction          │
         │      · Injection scan         │
         │                               │
         │  4b. validate_fetch_url()     │
         │      (url/uri/endpoint args)  │
         │      · Block private IPs      │
         │      · Block localhost        │
         │      · Block metadata IPs     │
         │      · Block non-HTTP schemes │
         │      · Per-hop redirect check │
         │                               │
         │  4c. detect_destructive_      │
         │      pattern()                │
         │      · HALT tier → force_end  │
         │      · LOG tier → warning+go  │
         └───────────────┬───────────────┘
                         │ pass (all args clean)
                         ▼
         ┌───────────────────────────────┐
         │  Step 5: Execute Tool         │
         │  inner ToolNode.ainvoke()     │
         │                               │
         │  Actual tool function runs:   │
         │  · web_search (DDGS)          │
         │  · web_fetch  (httpx)         │
         │  · document_summarize (LLM)   │
         └───────────────┬───────────────┘
                         │
                         ▼
         ┌───────────────────────────────┐
         │  Step 6: Output Sanitization  │
         │  sanitize_output() on every   │
         │  tool result message          │
         │                               │
         │  · PII redaction              │
         │  · Injection scan             │
         │  · TOOL_RESULT_INJECTION      │
         │    threat event if detected   │
         │  · Optional halt              │
         │    (halt_on_tool_result_      │
         │     injection config flag)    │
         └───────────────┬───────────────┘
                         │
                         ▼
         ┌───────────────────────────────┐
         │  Step 7: TOCTOU Verification  │
         │  (Phase 5.5)                  │
         │                               │
         │  · Verify every              │
         │    ToolMessage.tool_call_id   │
         │    was in approved_snapshot   │
         │  · Unexpected call_id →       │
         │    TOCTOU_DETECTED event      │
         │    + force_end=True           │
         └───────────────┬───────────────┘
                         │
                         ▼
              Updated state returned
              (messages include tool results)
```

---

## 5. Data Flow: Inbound vs Outbound Sanitization

"Outbound" = data leaving the agent process. "Inbound" = data entering agent context.

```
  USER INPUT
      │
      │  sanitize_text()
      │  · PII redaction
      │  · Injection scan
      ▼
  ┌─────────────────────────────────────────────────┐
  │                  agent_node                     │
  │                                                 │
  │  OUTBOUND ──────────────────────────────────►  │
  │  sanitize_messages()  ──►  llm.ainvoke()        │
  │  (PII redaction on                              │
  │   history before LLM)                           │
  │                                                 │
  │  OUTBOUND ──────────────────────────────────►  │
  │  sanitize_tool_input()  ──►  external API       │
  │  (strip PII from queries    (DuckDuckGo,        │
  │   before sending out)        web pages)         │
  │                                                 │
  │  INBOUND ◄──────────────────────────────────   │
  │  external data  ──►  sanitize_output()          │
  │  (web pages,         · PII redaction            │
  │   search results)    · Injection scan           │
  │                      · Log anomalies            │
  │                                                 │
  │  OUTBOUND ──────────────────────────────────►  │
  │  sanitize_for_trace()  ──►  LangSmith           │
  │  (additional scrub                              │
  │   before trace logging)                         │
  └─────────────────────────────────────────────────┘

  DATA STORES (all writes sanitized before insert):
  · threat_events  ← security violations (structured types)
  · api_usage      ← token counts per provider/run
  · health_metrics ← latency, error rates
  · checkpoints    ← LangGraph state snapshots (for resumption)
  · documents      ← RAG vectors (Phase 2+)
```

---

## 6. Threat Detection Tiers

What happens when a pattern fires depends on the tier.

```
  Tool argument text
         │
         ▼
  detect_destructive_pattern(text)
         │
         ├──► Scan 9 pattern categories
         │
         ▼
  ┌──────────────────────────────────────────────────────────┐
  │  Matched categories split into two tiers                 │
  └──────────────────────────────────────────────────────────┘
         │                        │
         ▼                        ▼
  ┌─────────────────┐    ┌────────────────────┐
  │   HALT TIER     │    │    LOG TIER         │
  │                 │    │                     │
  │ CMD_INJECTION   │    │ CREDENTIAL_PROBE    │
  │ SELF_PROBE      │    │ RECONNAISSANCE      │
  │ DATA_STAGING    │    │ INTERNAL_PROBE      │
  │ PRIVILEGE_      │    │ BULK_DESTRUCTIVE    │
  │ ESCALATION      │    │ SYSTEM_PATH_PROBE   │
  │                 │    │                     │
  │ Unambiguously   │    │ Ambiguous — may be  │
  │ adversarial.    │    │ legitimate research  │
  │ No valid task   │    │ (API key rotation,  │
  │ triggers these. │    │  Docker tutorials,  │
  │                 │    │  admin queries).    │
  └────────┬────────┘    └──────────┬──────────┘
           │                        │
           ▼                        ▼
  ┌─────────────────┐    ┌────────────────────┐
  │  logger.warning │    │  logger.warning    │
  │  force_end=True │    │  run continues     │
  │                 │    │                    │
  │  Phase 2:       │    │  Phase 4:          │
  │  interrupt_     │    │  DB persist to     │
  │  before pause   │    │  threat_events     │
  │  + operator     │    │  for Threat        │
  │  approval UI    │    │  Analyst review    │
  └─────────────────┘    └────────────────────┘
```

---

## 7. Tool Registry Lifecycle

How a tool gets from "code" to "allowed to run inside an agent".

```
  Developer writes tool function
               │
               ▼
  ToolManifest defined (tool_id, description,
    input_schema, declared_side_effects, source)
               │
               │  register_tool(manifest, approved_by="operator")
               ▼
  ┌─────────────────────────────────────────────┐
  │  _compute_tool_hash(manifest)               │
  │                                             │
  │  description_hash  = SHA256(description)    │
  │  schema_hash       = SHA256(sorted JSON)    │
  │  entrypoint_hash   = SHA256(source code)    │
  │  (disk I/O — only at registration time)     │
  └────────────────────┬────────────────────────┘
                       │
          ┌────────────┴──────────────┐
          ▼                           ▼
  _TOOL_REGISTRY[id]         INSERT INTO tool_registry
  (in-memory dict)           status = 'APPROVED'
  (fast, per-call lookup)    (persistent, survives restart)

                       │ at runtime
                       ▼
  verify_tool_before_invocation(tool_id)
  │
  ├──► Is tool_id in _TOOL_REGISTRY?   NO  → SecurityError (CAPABILITY_VIOLATION)
  │
  ├──► _compute_fast_hash(manifest)
  │    · description_hash + schema_hash only
  │    · No disk I/O (hot path safe)
  │
  └──► Hashes match?   NO  → SecurityError (TOOL_HASH_MISMATCH)
                       YES → return True (tool approved)
```

---

## 8. Phase Roadmap (Security Layers)

What's built vs what's coming.

```
  Phase 0 ✅  Infrastructure skeleton
  ─────────────────────────────────────────────────────────────
  PostgreSQL  │  LLM factory (Ollama/OpenAI/Anthropic)
  pgvector    │  Health server (:8765)
  Safeguards  │  23 smoke tests
  (step, loop, token budget)

  Phase 1 ✅  Security foundations
  ─────────────────────────────────────────────────────────────
  Tool registry + hash integrity   │  SecureToolNode
  Output sanitization (inbound)    │  Outbound PII redaction
  SSRF prevention                  │  Destructive pattern detection
  Capability boundary              │  Researcher agent
  46 smoke tests                   │

  Phase 2 ✅  Containerization + Guardian
  ─────────────────────────────────────────────────────────────
  Guardian sidecar (:9766)         │  Immutable audit log (hash chain)
  Docker Compose stack             │  RAG document provenance
  Sequence contracts               │  Health server bearer auth
  58 smoke tests                   │

  Phase 3 ✅  ACLs + Task Tokens + Sub-Agents
  ─────────────────────────────────────────────────────────────
  JWT task tokens                  │  Sub-agent orchestrator
  Role definitions (roles.yaml)    │  Privilege escalation blocking
  95 smoke tests                   │

  Phase 4 ✅  Adaptive Threat Intelligence
  ─────────────────────────────────────────────────────────────
  Threat Analyst agent             │  Adaptive Guardian rules (hot-reload)
  AI Bill of Materials             │  /rules human approval endpoints
  143 smoke tests                  │

  Phase 5 ✅  Crystallization Pipeline
  ─────────────────────────────────────────────────────────────
  Observer agent (nominates)       │  Crystallizer agent (generates)
  Pre-HITL Analyzer (AST+diff)     │  Ed25519 signing + packaging
  HITL review endpoints            │  CredentialStore (Keychain/env/file)
  sandbox-exec analyzer profile    │  168 smoke tests

  Phase 5.5 ✅  Security Hardening Sprint (10 vectors)
  ─────────────────────────────────────────────────────────────
  DB RBAC: legionforge_app user    │  Tool revocation (REVOKED + TTL 10s)
  AST subscript + MRO guards       │  TOOL_RESULT_INJECTION threat event
  TOCTOU approved_snapshot         │  Docker deny-default analyzer sandbox
  Ollama SHA256 model integrity    │  /tools/{id}/revoke endpoint
  200 smoke tests                  │

  Phase 6 ⬜  PentestAgent (NEXT)
  ─────────────────────────────────────────────────────────────
  Air-gapped attack suite          │  Pentest → Guardian feedback loop
  Synthetic environment only       │  Structured pentest report
  Manual trigger only              │  ~220 smoke tests target
```

---

## Notes on Design Decisions

**Why SecureToolNode wraps everything instead of putting controls in each tool?**
Belt-and-suspenders. SecureToolNode is the authoritative enforcement point — it runs
regardless of which agent calls which tool. Individual tools have last-line-of-defense
checks in case they're ever called outside a graph.

**Why is security.py import-free (no project deps)?**
It's the root of the dependency tree. Any circular import involving security.py would
break the entire import chain. Keeping it dependency-free means it can be imported
first, tested in isolation, and never deadlocks the module loader.

**Why phase the Guardian to a sidecar?**
Phase 1 Guardian stub checks FORBIDDEN_CAPABILITIES in-process. A real Guardian
needs to: (a) survive agent crashes, (b) enforce cross-agent policies, (c) be
audited independently. Moving it to a sidecar process (Phase 2) achieves all three
without coupling it to agent code.

**Why log-and-continue for ambiguous patterns instead of always halting?**
Halting on CREDENTIAL_PROBE or RECONNAISSANCE would block legitimate research queries
("how do API keys get rotated?", "enumerate Python package dependencies"). The LOG
tier records these for operator review without disrupting the workflow. Only patterns
with zero legitimate interpretations (CMD_INJECTION, SELF_PROBE, etc.) halt immediately.
