# LegionForge Architecture

**Version:** 1.0.0 — Phase 14 complete
**Last updated:** 2026-02-28

---

## 1. System Component Map

Every running process/service and how they connect.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           Mac M4 Mini 16 GB                              │
│                                                                          │
│  ┌──────────────────┐    ┌──────────────────────────────────────────┐    │
│  │   Ollama :11434  │    │          PostgreSQL :5432                 │    │
│  │                  │    │                                          │    │
│  │  llama3.1:8b     │    │  DB: legionforge  (17 tables)            │    │
│  │  qwen2.5:3b      │    │  Users: legionforge (admin, DDL only)    │    │
│  │  nomic-embed     │    │         legionforge_app (app runtime)    │    │
│  │  (models on      │    │                                          │    │
│  │   ext drive)     │    │  LangGraph: checkpoints / blobs / writes │    │
│  └────────┬─────────┘    │  Security: threat_events / audit_log /  │    │
│           │              │           tool_registry / threat_rules   │    │
│           │              │  RAG:     documents (pgvector, 768-dim)  │    │
│           │              │  Ops:     api_usage / health_metrics     │    │
│           │              │  Crystal: candidates / packages / anal.  │    │
│           │              │  Pentest: runs / findings / prop. rules  │    │
│           │              └─────────────────┬────────────────────────┘    │
│           │                                │                             │
│  ┌────────▼──────────────────────────────► │                             │
│  │  Operator Health Server  :8765         ◄┘                             │
│  │  src/health.py                                                        │
│  │  · /health  /status  /metrics  /usage  /bom                          │
│  │  · /rules  (Guardian rule approval)                                   │
│  │  · /crystallization  (HITL review queue)                              │
│  │  · /tools/{id}/revoke  · /pentest/*                                   │
│  │  Bearer auth on all except /health                                    │
│  └───────────────────────────────────────────────────────────────────────┘
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  Docker: Guardian Sidecar  :9766                                 │    │
│  │  src/security/guardian.py                                        │    │
│  │                                                                  │    │
│  │  7-check deterministic pipeline — no LLM in hot path            │    │
│  │  Hot-reloads threat_rules from DB every 10s                     │    │
│  │  All SecureToolNode calls route through here                    │    │
│  │  Bearer auth required (GUARDIAN_REQUIRE_AUTH=true default)      │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  Agent Runtime (Python process — not yet containerized)          │    │
│  │                                                                  │    │
│  │  Available agents:                                               │    │
│  │  · run_agent()         — base_graph.py template                  │    │
│  │  · run_researcher()    — web fetch, RAG, Ed25519 tools           │    │
│  │  · run_orchestrator()  — task routing, derived JWT tokens        │    │
│  │  · run_observer()      — nominates crystallization candidates    │    │
│  │  · run_crystallizer()  — generates deterministic tools           │    │
│  │  · run_threat_analyst()— proposes Guardian rules                 │    │
│  │  · run_pentest()       — air-gapped attack suite (Docker)        │    │
│  │                                                                  │    │
│  │  Entry: python src/health.py or direct run_* call               │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  Docker: Dockerfile.analyzer — deny-default (--network none, read-only)  │
│  Docker: Dockerfile.pentest  — air-gapped  (--network none, read-only)   │
│                                                                          │
│  External:  DuckDuckGo (web_search)  ·  Public HTTPS URLs (web_fetch)   │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Module Dependency Graph

Arrow means "imports from". Security primitives are at the root (no project imports).

```
agents/
  researcher.py  orchestrator.py  observer.py  crystallizer.py
  threat_analyst.py  pentest_agent.py
       │                │                │
       └────────────────┴────────────────┘
                        │
                        ▼
                  base_graph.py ──────────────────► safeguards.py
                        │    │                           │
                        │    └────────────────┐          │
                        │                    ▼          │
                        │              rate_limiter.py  │
                        ▼                              │
                 llm_factory.py                        │
                        │            ┌─────────────────┘
                        │            │
                        ▼            ▼
               security/            database.py      observability.py
                 core.py                │                   │
                 guardian.py            │                   │
                 acl.py                 │                   │
                 bom.py                 │                   │
                        │              │                   │
                        └──────────────┴───────────────────┘
                                       │
                                       ▼
                              config/settings.py
                              credentials.py
                              (Pydantic singleton, no project deps)

tools/
  signing.py  crystallization_analyzer.py  model_integrity.py  pentest_tools.py
       └──────── imported by agents as needed ────────────────────────────────┘
```

**Key rules:**
- `security/core.py` has zero project-level imports — root of the security dependency tree. Independently testable, no circular import risk.
- `config/settings.py` is the configuration singleton — imported by almost everything, depends on nothing.
- New agents MUST import `base_graph.py` patterns, not re-implement them.

---

## 3. Agent Execution Flow (LangGraph State Machine)

Every agent runs this graph. Agent-specific logic lives in the `agent_node` function.

```
                       ┌──────────┐
                       │  START   │
                       └────┬─────┘
                            │ initial state
                            │ (SafeguardedState.initial(agent_id=...))
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
            │  │    (7-step pipeline)     │
            │  │    see §4                │
            └──┤                          │
               │  returns updated state   │
               └──────────────────────────┘

Legend:
  ──► edge (always)
  ─── conditional edge (labeled with route value)
  All nodes are async. State is immutable between steps (reducer pattern).
  force_end is a cooperative flag — routes to finalizer_node, not an exception.
```

**agent_id consistency invariant:** `SafeguardedState.initial(agent_id="X")` MUST use the same string as `issue_task_token(agent_id="X")` in the same `run_*` function. If they diverge, threat events and audit log entries are attributed to different identities. See `SECURITY.md §agent_id Consistency Invariant`.

---

## 4. SecureToolNode Pipeline (7 Steps)

Every tool call passes through all 7 steps in order.
A HALT at any step sets `force_end=True` and returns without executing the tool.

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
       │  POST guardian/:9766/check    │
       │                               │
       │  7-check pipeline:            │
       │  0. Revocation check          │
       │  1. Registry + hash           │
       │  2. Capability boundary       │
       │  3. Destructive patterns      │
       │  4. Sequence contract         │
       │  5. Ed25519 signature         │
       │  6. Adaptive threat rules     │
       │     (hot-reloaded every 10s)  │
       └───────────────┬───────────────┘
                       │ pass
                       ▼
       ┌───────────────────────────────┐
       │  Step 3: Loop Detection       │
       │  detect_action_loop(state,    │
       │    tool_id, tool_input)       │
       │                               │
       │  · SHA256 of tool_id+args     │
       │  · Same signature 3× in       │
       │    last 5 calls?              │
       │  · Sets loop_detected: True   │
       └───────────────┬───────────────┘
                       │ pass
                       ▼
       ┌───────────────────────────────┐
       │  Step 4: Arg Sanitization     │
       │  (per-argument loop)          │
       │                               │
       │  4a. Injection scan           │
       │      (Tier 1 patterns → HALT) │
       │      (Tier 2 patterns → LOG)  │
       │      see §5                   │
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
       │  · Injection scan (Tier 1/2)  │
       │  · TOOL_RESULT_INJECTION      │
       │    threat event if detected   │
       │  · Tier 1 → halt if config    │
       │    halt_on_tool_result_inject │
       │  · Tier 2 → log and continue  │
       └───────────────┬───────────────┘
                       │
                       ▼
       ┌───────────────────────────────┐
       │  Step 7: TOCTOU Verification  │
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

## 5. Injection Detection — Pattern Tiering

Two-tier model for all injection detection. The tier determines the response, not just the detection.

```
  Text to scan (tool arg or tool output)
                │
                ▼
       detect_injection(text)  [29 patterns]
                │
                ▼
  ┌─────────────────────────────────────────────────────────┐
  │  Match found — which tier?                              │
  └─────────────────────────────────────────────────────────┘
                │                              │
                ▼                              ▼
  ┌─────────────────────┐          ┌─────────────────────────┐
  │   TIER 1 — HALT     │          │   TIER 2 — LOG ONLY      │
  │                     │          │                         │
  │ 13 patterns:        │          │ Remaining 16 patterns:  │
  │ "ignore all prev."  │          │ "act as"                │
  │ "disregard all"     │          │ "pretend you are"       │
  │ "forget prev instr" │          │ "for research purposes" │
  │ "override all prev" │          │ "hypothetically"        │
  │ "jailbreak"         │          │ "from now on"           │
  │ "dan mode"          │          │ "developer mode"        │
  │ "dan N.N"           │          │ "simulate being"        │
  │ "enable/unlock mode"│          │ "decode from base64"    │
  │ "reveal your prompt"│          │ etc.                    │
  │ "what are your      │          │                         │
  │  instructions"      │          │ Real injection signals  │
  │ <system> XML tags   │          │ that also appear in     │
  │ [INST] / [/INST]    │          │ legitimate research     │
  │ <|im_start|> tokens │          │ queries.                │
  │                     │          │                         │
  │ No legitimate use   │          │ Trade-off accepted.     │
  │ in tool args.       │          │ Phase 8: replace with   │
  │                     │          │ context-aware classifier│
  └──────────┬──────────┘          └───────────┬─────────────┘
             │                                 │
             ▼                                 ▼
  ┌─────────────────────┐          ┌─────────────────────────┐
  │  force_end=True     │          │  log_threat_event()     │
  │  TOOL_ARG_INJECTION │          │  action_taken="LOGGED"  │
  │  action="BLOCKED"   │          │  confidence=0.5         │
  │  confidence=0.9     │          │  run continues          │
  └─────────────────────┘          └─────────────────────────┘

has_halt_worthy_injection(matched_patterns) → bool
  Implemented in: src/security/core.py
  Exported from:  src/security/__init__.py
  Used in:        src/base_graph.py SecureToolNode steps 4a and 6
```

**User-input vs tool-arg detection:**
- User input (`run_*` functions): gated by `prompt_injection_guard` setting. Set `false` in dev/test.
- Tool args (`SecureToolNode` step 4a): always-on, cannot be disabled via config.
- Tool output (`SecureToolNode` step 6): always-on, cannot be disabled.

---

## 6. Guardian — 7-Check Pipeline

The Guardian sidecar is called on every tool invocation via `SecureToolNode` step 2.
It runs deterministically — no LLM calls in the hot path.

```
  POST guardian:9766/check
  {
    "tool_id": "...",
    "action":  "invoke",   ← always "invoke" in Phase 7; Phase 8 adds action types
    "agent_id": "...",
    "capabilities": [...],
    "task_token": "..."
  }
                │
                ▼
  ┌─────────────────────────────────────────────────────────┐
  │  Check 0: Tool Revocation                               │
  │  Is tool status REVOKED in 10s TTL cache?               │
  │  YES → REVOKED_TOOL_INVOCATION (HALT)                   │
  └─────────────────────────────────────────────────────────┘
                │ pass
                ▼
  ┌─────────────────────────────────────────────────────────┐
  │  Check 1: Tool Registry + Hash                          │
  │  Is tool in registry? Description + schema hash match?  │
  │  NO → UNREGISTERED_TOOL / TOOL_HASH_MISMATCH (HALT)     │
  └─────────────────────────────────────────────────────────┘
                │ pass
                ▼
  ┌─────────────────────────────────────────────────────────┐
  │  Check 2: Capability Boundary                           │
  │  Does the action fall in FORBIDDEN_CAPABILITIES?        │
  │  YES → CAPABILITY_VIOLATION (HALT)                      │
  │  Note: action hardcoded to "invoke" in Phase 7          │
  └─────────────────────────────────────────────────────────┘
                │ pass
                ▼
  ┌─────────────────────────────────────────────────────────┐
  │  Check 3: Destructive Pattern Detection                 │
  │  Scan args for CMD_INJECTION, SELF_PROBE, etc.          │
  │  Gap: args={} in Phase 7 — check fires on metadata only │
  │  Phase 8 closes: forward actual tool args               │
  └─────────────────────────────────────────────────────────┘
                │ pass
                ▼
  ┌─────────────────────────────────────────────────────────┐
  │  Check 4: Sequence Contract                             │
  │  Is this tool call in the agent's declared sequence?    │
  │  Out-of-sequence → SEQUENCE_VIOLATION (LOG or HALT)     │
  └─────────────────────────────────────────────────────────┘
                │ pass
                ▼
  ┌─────────────────────────────────────────────────────────┐
  │  Check 5: Ed25519 Signature                             │
  │  Is the tool manifest signed with the approved key?     │
  │  Invalid sig → SIGNATURE_MISMATCH (HALT)                │
  └─────────────────────────────────────────────────────────┘
                │ pass
                ▼
  ┌─────────────────────────────────────────────────────────┐
  │  Check 6: Adaptive Threat Rules                         │
  │  Match against APPROVED rules in threat_rules table     │
  │  (hot-reloaded every 10s — no Guardian restart needed)  │
  │  Match → action per rule config (LOG or HALT)           │
  └─────────────────────────────────────────────────────────┘
                │ pass all
                ▼
          {"allowed": true}
```

---

## 7. Crystallization Pipeline

Converts high-frequency agent patterns into signed, deterministic tools.

```
  Many agent runs produce same pattern
              │
              ▼
  ┌──────────────────────┐
  │  Observer agent      │
  │  run_observer()      │
  │                      │
  │  Reads audit_log,    │
  │  identifies repeated │
  │  tool call patterns  │
  │  → INSERT INTO       │
  │    crystallization_  │
  │    candidates        │
  │    (status=NOMINATED)│
  └──────────┬───────────┘
             │
             ▼
  ┌──────────────────────┐
  │  Crystallizer agent  │
  │  run_crystallizer()  │
  │                      │
  │  Generates Python    │
  │  function + test     │
  │  suite from pattern  │
  │  → INSERT INTO       │
  │    crystallization_  │
  │    packages          │
  │    (PENDING_ANALYSIS)│
  └──────────┬───────────┘
             │
             ▼
  ┌──────────────────────┐
  │  Pre-HITL Analyzer   │
  │  Docker (deny-default│
  │  --network none)     │
  │                      │
  │  AST guards:         │
  │  · subscript bypass  │
  │  · MRO traversal     │
  │  · globals()/locals()│
  │  Behavioral diff vs  │
  │  original agent code │
  │  → packages table    │
  │    READY_FOR_REVIEW  │
  │    or REJECTED       │
  └──────────┬───────────┘
             │
             ▼
  ┌──────────────────────┐
  │  Human Approval Gate │
  │  /crystallization/   │
  │  candidates/{id}/    │
  │  approve             │
  │                      │
  │  Operator reviews    │
  │  diff + analysis     │
  │  MUST explicitly     │
  │  approve or reject   │
  └──────────┬───────────┘
             │ approved
             ▼
  ┌──────────────────────┐
  │  Ed25519 Signing     │
  │  sign_tool_manifest()│
  │                      │
  │  Private key from    │
  │  Keychain            │
  │  Manifest + sig      │
  │  → tool_registry     │
  │    (status=APPROVED) │
  └──────────────────────┘
  Tool is now available
  to agents via registry
```

---

## 8. Data Flow: Sanitization Layers

"Outbound" = data leaving the agent process. "Inbound" = data entering agent context.

```
  USER INPUT (run_* function)
      │
      │  sanitize_text(check_injection=settings.security.prompt_injection_guard)
      │  · PII redaction
      │  · Injection scan (if guard enabled)
      ▼
  ┌─────────────────────────────────────────────────┐
  │                  agent_node                     │
  │                                                 │
  │  OUTBOUND ─────────────────────────────────►   │
  │  sanitize_messages()  ──►  llm.ainvoke()        │
  │  (PII redaction on history before LLM call)     │
  │                                                 │
  │  OUTBOUND ─────────────────────────────────►   │
  │  sanitize_tool_input()  ──►  external API       │
  │  (strip PII from queries before sending)        │
  │                                                 │
  │  INBOUND ◄─────────────────────────────────    │
  │  tool result  ──►  sanitize_output()            │
  │  (web pages,       · PII redaction              │
  │   search results)  · Injection Tier 1/2 scan   │
  │                    · Log or halt on detection   │
  │                                                 │
  │  OUTBOUND ─────────────────────────────────►   │
  │  sanitize_for_trace()  ──►  LangSmith           │
  │  (additional scrub before trace logging)        │
  └─────────────────────────────────────────────────┘

  DATA STORES (all writes sanitized before insert):
  · threat_events   ← security violations (structured types, see §9)
  · api_usage       ← token counts per provider/run
  · health_metrics  ← latency, error rates
  · checkpoints     ← LangGraph state snapshots (for resumption)
  · documents       ← RAG vectors (768-dim, HNSW index)
  · audit_log       ← append-only SHA-256 hash chain
```

---

## 9. Threat Event Types

All security violations are logged to `threat_events` as structured records.

| Type | Trigger | Action |
|---|---|---|
| `INJECTION_DETECTED` | User input injection pattern matched | LOGGED (Tier 2) |
| `TOOL_ARG_INJECTION` | Tool arg injection — Tier 1 pattern | BLOCKED + force_end |
| `TOOL_ARG_INJECTION` | Tool arg injection — Tier 2 pattern | LOGGED only |
| `TOOL_RESULT_INJECTION` | Tool output injection — Tier 1 | BLOCKED (if config) |
| `TOOL_RESULT_INJECTION` | Tool output injection — Tier 2 | LOGGED only |
| `TOOL_HASH_MISMATCH` | Tool description/schema changed since registration | BLOCKED |
| `CAPABILITY_VIOLATION` | Tool not registered or outside agent scope | BLOCKED |
| `REVOKED_TOOL_INVOCATION` | Tool in REVOKED status | BLOCKED |
| `SEQUENCE_VIOLATION` | Tool call out of declared agent sequence | LOG or BLOCKED |
| `SIGNATURE_MISMATCH` | Ed25519 signature invalid | BLOCKED |
| `PRIVILEGE_ESCALATION` | Child token attempts to exceed parent capabilities | BLOCKED |
| `TOCTOU_DETECTED` | Post-exec tool_call_id not in approved_snapshot | BLOCKED + force_end |
| `LOOP_DETECTED` | Same tool+args signature ≥ 3× in last 5 calls | BLOCKED + force_end |
| `PREFLIGHT_BUDGET_EXCEEDED` | Token cost estimate exceeds daily budget | BLOCKED |
| `MODEL_INTEGRITY_MISMATCH` | GGUF SHA256 doesn't match pinned value | BLOCKED |
| `AUDIT_LOG_TAMPER` | SHA-256 hash chain broken at startup | BLOCKED → RuntimeError halt |
| `PII_REDACTED` | PII found and redacted from input/output | LOGGED |

---

## 10. Tool Registry Lifecycle

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
  │    · No disk I/O (hot-path safe)
  │
  └──► Hashes match?   NO  → SecurityError (TOOL_HASH_MISMATCH)
                       YES → return True (tool approved for invocation)

  Tool revocation path:
  POST /tools/{id}/revoke (operator only)
  → tool_registry.status = 'REVOKED'
  → Guardian TTL cache invalidated within 10s
  → subsequent check 0 → REVOKED_TOOL_INVOCATION (HALT)
```

---

## 11. Phase Roadmap (Security Layers)

```
  Phase 0 ✅  Infrastructure skeleton
  ─────────────────────────────────────────────────────────────────
  PostgreSQL + pgvector  │  LLM factory (Ollama/OpenAI/Anthropic)
  Safeguards             │  Health server (:8765)
  (step, loop, token)    │  23 smoke tests

  Phase 1 ✅  Security foundations
  ─────────────────────────────────────────────────────────────────
  Tool registry + hash   │  SecureToolNode (6-step pipeline)
  Output sanitization    │  Outbound PII redaction
  SSRF prevention        │  Destructive pattern detection
  Researcher agent       │  46 smoke tests

  Phase 2 ✅  Containerization + Guardian
  ─────────────────────────────────────────────────────────────────
  Guardian sidecar :9766 │  Immutable audit log (hash chain)
  Docker Compose         │  RAG document provenance
  Sequence contracts     │  Health server bearer auth
                         │  58 smoke tests

  Phase 3 ✅  ACLs + Task Tokens + Sub-Agents
  ─────────────────────────────────────────────────────────────────
  JWT task tokens        │  Sub-agent orchestrator
  Role definitions       │  Privilege escalation blocking
                         │  95 smoke tests

  Phase 4 ✅  Adaptive Threat Intelligence
  ─────────────────────────────────────────────────────────────────
  Threat Analyst agent   │  Adaptive Guardian rules (hot-reload)
  AI Bill of Materials   │  /rules human approval endpoints
                         │  143 smoke tests

  Phase 5 ✅  Crystallization Pipeline
  ─────────────────────────────────────────────────────────────────
  Observer agent         │  Crystallizer agent
  Pre-HITL Analyzer      │  Ed25519 signing + packaging
  HITL review endpoints  │  CredentialStore
                         │  168 smoke tests

  Phase 5.5 ✅  Security Hardening Sprint
  ─────────────────────────────────────────────────────────────────
  DB RBAC (app user)     │  Tool revocation (10s TTL)
  AST subscript guards   │  TOOL_RESULT_INJECTION threat event
  TOCTOU snapshot        │  Docker deny-default analyzer sandbox
  GGUF model integrity   │  200 smoke tests

  Phase 6 ✅  PentestAgent (Air-Gapped Red Team)
  ─────────────────────────────────────────────────────────────────
  24 attack functions    │  Pentest → Guardian feedback loop
  8 attack classes       │  Structured pentest report
  Air-gapped Docker      │  Synthetic environment
  0 bypasses on clean    │  228 smoke tests

  Phase 7 ✅  Guardian Feedback Loop + Pre-Release Hardening
  ─────────────────────────────────────────────────────────────────
  Pentest→rule pipeline  │  SECURITY.md + responsible disclosure
  Pattern tiering (29)   │  audit log tamper → RuntimeError halt
  agent_id in state      │  GUARDIAN_REQUIRE_AUTH default → true
  document_summarize     │  <external_content> injection boundary
  boundary fix           │  Guardian Gap 1+2 closed
  Guardian args fixed    │  312 smoke tests

  Phase 8 ✅  Gateway + Streaming + Task Queue + Web UI + Discord Connector
  ─────────────────────────────────────────────────────────────────
  Gateway service :8080  │  SSE streaming (astream_events)
  Task queue (tasks tbl) │  Minimal web UI (GET /ui)
  A2A + MCP endpoints    │  Per-user Bearer auth + stream tokens
  Guardian Gap 1+2 fixed │  Discord connector (src/connectors/)
  323 smoke tests        │
  → Spec: docs/PHASE_8_GATEWAY_SPEC.md

  Phase 9 ✅  Tool Library + langchain 1.x + Parallel Fan-Out + 9.5 Hardening
  ─────────────────────────────────────────────────────────────────
  langchain 1.x migration│  Closes Dependabot #4 (LOW SSRF)
  http_get + http_post   │  SSRF guard, I/O sanitize, 50 KB cap
  file_read + file_write │  Path allowlist, traversal guard, ext block
  code_execute sandbox   │  --network none --read-only --pids-limit 20
  fan_out.py engine      │  asyncio.gather(), Semaphore cap, JWT/branch
  fan_out_researchers    │  Parallel tool in orchestrator
  Rate-limiter race fix  │  check_and_reserve() atomic under lock
  /status TTL cache      │  30 s cache; hits skip DB/Ollama/subprocess
  3 new PII patterns     │  [DB_DSN] [PRIVATE_IP] [HOME_PATH]
  397 smoke tests        │

  Phase 10 ✅  Multi-User, Auth, and Scale
  ─────────────────────────────────────────────────────────────────
  DB-backed stream tokens│  Per-user daily token budgets
  User management CLI    │  /usage/me endpoint
  stream_tokens table    │  Worker user attribution
  api_usage.user_id      │  422 smoke tests

  Phase 11 ✅  SecureToolNode Fix, Integration Tests, Modular Auth, Gateway Container
  ─────────────────────────────────────────────────────────────────
  SecureToolNode fix     │  Synthesize ToolMessage on copy failure (critical security)
  AuthBackend protocol   │  Pluggable OAuth/LDAP/JWT via set_auth_backend()
  Integration tests      │  35 tests (PostgreSQL), 3 Ollama-scaffolded
  Dockerfile.gateway     │  Containerized gateway, non-root uid 1001
  docs/SCALING.md        │  Horizontal scaling guide + OAuth pattern
  /usage/me on gateway   │  Moved to gateway app (port 8080) with require_user
  dict_row fixes         │  row["col"] throughout get_user_*_today functions
  430 smoke tests        │  +8 from Phase 11

  Phase 12 ✅  Multi-Provider Auth Backend Registry
  ─────────────────────────────────────────────────────────────────
  src/gateway/backends/ │  8-file package: base, api_key, oidc, github, ldap, kerberos, registry, __init__
  OIDCBackend           │  JWKS/discovery; covers Google, Okta, Auth0, Keycloak, Azure AD, Cognito
  GitHubOAuthBackend    │  /user API flow; opaque token support
  LDAPBackend           │  bind+search+rebind; OpenLDAP + Active Directory
  KerberosBackend       │  Real GSSAPI flow (Phase 13); graceful None when gssapi absent
  require_user          │  Multi-scheme: Bearer / Basic / Negotiate
  load_backend_from_settings │  Factory; maps auth_provider string → backend instance
  OIDCConfig/LDAPConfig │  Pydantic sub-models in GatewayConfig; oidc/ldap sections in YAML
  PyJWT[crypto]         │  RS256/ES256 JWKS decode; ldap3 added for LDAP
  443 smoke tests        │  +13 from Phase 12

  Phase 13 ✅  Kerberos Real Implementation + Redis State Layer + Multi-Instance
  ─────────────────────────────────────────────────────────────────
  KerberosBackend       │  Real GSSAPI accept-security-context flow; graceful None fallback when gssapi absent
  KerberosConfig        │  keytab_path, service_name, realm, daily_token_limit in GatewayConfig
  src/gateway/state.py  │  Optional Redis-backed stream token store; DB fallback; init_redis/close_redis lifecycle
  GatewayConfig.redis_url │  Empty = DB mode; "redis://..." = Redis mode (REDIS_URL env var also accepted)
  auth.py               │  Stream token ops delegate to state.py (transparent to callers)
  app.py lifespan       │  init_redis() / close_redis() called at startup/shutdown
  docker-compose.multi-instance.yml │  2-replica gateway + Redis + Nginx load balancer
  config/nginx/         │  nginx.multi-instance.conf; round-robin, SSE buffering off
  redis[asyncio]        │  redis 5.x (asyncio built-in); fakeredis for smoke tests
  453 smoke tests        │  +10 from Phase 13

  Phase 14 ✅  Redis Budget Counters + Prometheus Metrics + Request Trace IDs
  ─────────────────────────────────────────────────────────────────
  state.py additions    │  redis_budget_check_and_reserve(), redis_budget_release(), redis_budget_get()
  rate_limiter.py       │  per_user_budget_check() delegates to Redis INCRBY when redis_mode() is True
  src/gateway/metrics.py │  Prometheus text formatter (no new deps); inc_counter(), set_gauge(), prometheus_text()
  src/gateway/middleware.py │  RequestIDMiddleware (X-Request-ID header/UUID4 gen); MetricsMiddleware (request counters)
  app.py GET /metrics   │  Prometheus text endpoint; also sets legionforge_redis_connected gauge
  health.py _check_redis() │  Independent Redis PING in /status; redis component added when configured
  tests/test_kerberos_integration.py │  Integration skeleton (5 tests); skip unless KERBEROS_TEST_KDC=1
  463 smoke tests        │  +10 from Phase 14
```

---

## 12. Design Decision Record

**Why SecureToolNode wraps everything instead of per-tool controls?**
Belt-and-suspenders. `SecureToolNode` is the authoritative enforcement point — it runs
regardless of which agent calls which tool. Individual tools have last-line-of-defense
checks only. This means adding a new tool never creates a security gap.

**Why is `security/core.py` import-free?**
It's the root of the dependency tree. Any circular import involving `core.py` would
break the entire import chain. Keeping it dependency-free makes it independently
testable and ensures it can always be imported first.

**Why phase Guardian to a sidecar?**
A real Guardian needs to: (a) survive agent crashes, (b) enforce cross-agent policies,
(c) be audited independently. A sidecar process achieves all three without coupling
Guardian logic to agent code. Guardian also hot-reloads threat rules without restart.

**Why log-and-continue for Tier 2 injection patterns?**
Halting on "hypothetically speaking" or "for educational purposes" would block
legitimate research queries. Tier 2 records the event for Threat Analyst review
without disrupting the workflow. Only Tier 1 patterns — with zero legitimate
interpretations — halt immediately.

**Why `run_id` ordering matters?**
`SafeguardedState.initial()` generates the `run_id` UUID. `sanitize_text()` may detect
injection and log to `threat_events`. If `sanitize_text()` is called first, the log
entry has no `run_id` — forensically useless. Ordering rule: `initial()` always before
`sanitize_text()`. See `SECURITY.md §run_id Ordering Rule`.

**Why halt on audit log tamper at startup — not during a run?**
If the audit log is tampered, all forensic evidence about past runs is compromised.
The correct response is to stop the system entirely and investigate — not to allow
more agent runs that would add unverifiable entries. `RuntimeError` at `init_db()`
guarantees the process exits before any agent runs.

**Why a separate Gateway service (Phase 8) instead of extending health.py?**
The operator health service (`:8765`) is a single-user, trusted-operator interface.
The gateway (`:8080`) is a multi-user, externally-exposed interface. Different
threat models, different auth requirements, different rate limiting, different
audit requirements. Coupling them in one process would mix trust levels and complicate
independent security audit of each.

*Related docs:*
- [`docs/VISION.md`](./VISION.md) — product vision and Phase 8+ architecture
- [`docs/PHASE_8_GATEWAY_SPEC.md`](./PHASE_8_GATEWAY_SPEC.md) — Phase 8 implementation plan
- [`docs/A2A_CONFORMANCE.md`](./A2A_CONFORMANCE.md) — A2A protocol conformance
- [`SECURITY.md`](../SECURITY.md) — threat model and security policy
- [`PHASE_PLAN.md`](../PHASE_PLAN.md) — full phased roadmap
