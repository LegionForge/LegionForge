# PHASE_PLAN.md
# LegionForge — Phased Roadmap

**Version:** 0.7.0-alpha
**Last updated:** 2026-03-03
**Status:** Phases 0–59 ✅ complete (846/846 smoke tests · 38/38 integration · 5/5 Kerberos · 40/40 UI)

> **See bottom of this file** for Phases 17–59 compact history added 2026-03-03.

Phases 0–16 are documented in full detail below.
Phases 17–59 are summarised in the addendum section at the end.

> **Related docs:**
> - [`TLDR.md`](./TLDR.md) — Quick summary
> - [`PROJECT_STATUS.md`](./PROJECT_STATUS.md) — Current build state and infrastructure
> - [`RESEARCH.md`](./RESEARCH.md) — Threat research and design theory

---

## Design Principles

Before the phases: these principles govern every decision.

**Modularity over monolith.** Every component is optional, replaceable, and independently testable. No phase requires you to implement all of its components before moving to the next.

**Stubs before skeletons.** Every interface that will exist later must have a no-op stub today. Agents built in Phase 1 are pre-wired for Phase 3 security — they just call stubs. This prevents retroactive refactoring.

**Deterministic before adaptive.** Security components use fast, deterministic logic first. LLM-based analysis is layered on top for offline review only, never in the hot path.

**Human gates on mutations.** No component autonomously changes security rules, promotes tools, or escalates privileges. All mutations require explicit human approval.

**Smallest attack surface.** Security components (Guardian especially) have zero external dependencies beyond the framework's own modules. No third-party imports in the critical path.

**Fail-safe is tiered, not binary.** See RESEARCH.md §2 for the three-tier model (Halt, Sandbox-Retry, Degrade).

**Replace AI with determinism wherever possible.** When an agent has solved the same well-structured problem repeatedly, that solution should be crystallized into a deterministic, zero-LLM tool. LLM inference is expensive, non-deterministic, and an attack surface. Deterministic code is none of those things. The goal is to continuously shrink the surface area that requires AI reasoning.

---

## Phase Overview

```
Phase 0    ✅  Infrastructure                    → DONE
Phase 1    ✅  First Agent + Security Foundations → DONE
Phase 2    ✅  Containerization + Guardian        → DONE
Phase 3    ✅  ACLs + Task Tokens + Sub-Agents    → DONE
Phase 4    ✅  Adaptive Security                  → DONE    (weeks 11–14)
Phase 5    ✅  Crystallization Pipeline           → DONE    (weeks 15–19)
Phase 5.5  ✅  Security Hardening Sprint          → DONE    (10-vector hardening; 200 smoke tests)
Phase 6    ✅  Red Team + Pentest Bot             → DONE    (PentestAgent; 228 smoke tests)
Phase 7    ✅  Guardian Feedback Loop + v1.0     → DONE    (pentest→Guardian bridge; SECURITY.md; 242 smoke tests)
```

Each phase is independently shippable. Phases do not block each other for core agent work — security layers are additive.

---

## Phase 0 — Infrastructure Foundation ✅ COMPLETE

**Goal:** Running framework with all plumbing in place.
**Exit criteria:** 23/23 smoke tests pass, health server green.

### Deliverables (all complete)
- `database.py` — async PostgreSQL + pgvector + LangGraph checkpointer
- `security.py` — Keychain loader, PII redaction, prompt injection detection
- `safeguards.py` — three-layer loop protection
- `rate_limiter.py` — per-provider rate limiting + cost alerts
- `llm_factory.py` — unified Ollama/OpenAI/Anthropic factory
- `observability.py` — structured JSON logging + LangSmith upload
- `health.py` — FastAPI health/metrics server
- `base_graph.py` — LangGraph agent template

---

## Phase 1 — First Agent + Security Foundations 🔄 ACTIVE

**Goal:** Build the Researcher agent. Simultaneously add the security foundations that every future agent depends on. No new services — only additions to existing modules.

**Duration:** ~3 weeks
**Dependencies:** Phase 0 complete ✅
**Exit criteria:** Researcher agent operational; tool registry enforced; threat_events logging; tool hash validation passing; capability boundary stubs in place; all tests green including integration tests.

### Component 1.1 — Tool Registry with Human Approval Gate
**File:** `src/security.py` (additions) + `database.py` (migration)
**Priority:** 🔴 Must exist before any external tool call
**New table:** `tool_registry`
**New functions:** `register_tool()`, `verify_tool_before_invocation()`, `revoke_tool()`

Every tool — internal or external — must have an explicit approval record before Guardian will allow it to execute. The registry stores: `tool_id`, `source`, `version`, `description_hash`, `schema_hash`, `entrypoint_hash` (for local tools), `declared_side_effects`, `approved_by`, `approved_at`, `approval_notes`, `status` (APPROVED / SUSPENDED / REVOKED).

Add `make verify-tool-registry` to startup sequence. If any loaded tool is not in the registry with status APPROVED, startup fails.

This is the foundational control for the entire crystallization pipeline in Phase 5. Every crystallized tool will flow through this registry.

### Component 1.2 — Tool Metadata Validation (Extended)
**File:** `src/security.py` (additions)
**New function:** `validate_tool_registration(tool_name, description, schema, entrypoint, side_effects) → ToolManifest`
**New function:** `verify_tool_integrity(tool_name, manifest) → bool`

Hash at registration: tool name + description + input schema + entrypoint file + declared side effects. Verify before every invocation. A mismatch on any field is a `TOOL_HASH_MISMATCH` threat event and a Tier 1 halt.

### Component 1.3 — Capability Boundary Enforcement
**File:** `src/base_graph.py` (stub) + future `guardian.py` (enforcement)
**Priority:** 🔴 Must exist before Researcher ships

Negative capability list — no task token can grant these, no agent may perform them:

```python
FORBIDDEN_CAPABILITIES = {
    "register_tool",       # only humans register tools
    "write_executable",    # no writing .py/.sh/.so files
    "invoke_unregistered", # only registry-approved tools run
    "modify_registry",     # registry is append-only via human gate
    "escalate_scope",      # no self-promotion of task token
    "spawn_agent_direct",  # only orchestrator spawns agents
    "modify_own_state",    # agents cannot edit their own task tokens
}
```

Implement as a Guardian stub now. Wire to real Guardian enforcement in Phase 2.

### Component 1.4 — Output Sanitization on All External Tool Responses
**File:** `src/security.py` (additions)
**Priority:** 🔴 Must exist before Researcher ships

The current sanitizer runs on inputs. Apply the same PII redaction and injection detection to everything returned by external tools before it enters agent context. One function, consistent application at every inbound trust boundary.

### Component 1.5 — PII Redaction on All Outbound API Calls
**File:** `src/security.py` + `src/observability.py`
**Priority:** 🔴 Must exist before Researcher ships

Apply redaction to every outbound call — not just LangSmith traces. Audit what LangSmith traces contain before upload (closes R-02). Add a test that injects synthetic PII into a trace payload and asserts it's redacted before upload.

### Component 1.6 — Pre-Execution Cost Estimation
**File:** `src/rate_limiter.py` (additions)
**New function:** `estimate_token_cost(prompt, tools, history) → TokenEstimate`
**New function:** `preflight_check(estimate, provider) → PreflightResult`

Estimate tokens before any API call. Reject resource bombs before tokens are consumed.

### Component 1.7 — Threat Events Table + Logging
**File:** `src/database.py` (additions)
**Migration:** Add `threat_events` table

```sql
CREATE TABLE threat_events (
    id           BIGSERIAL PRIMARY KEY,
    ts           TIMESTAMPTZ DEFAULT now(),
    agent_id     TEXT NOT NULL,
    run_id       TEXT NOT NULL,
    threat_type  TEXT NOT NULL,
    confidence   FLOAT,
    raw_input    TEXT,
    action_taken TEXT NOT NULL,
    metadata     JSONB
);
```

### Component 1.8 — Security Stubs in base_graph.py
**File:** `src/base_graph.py` (additions)

```python
async def guardian_check(state) -> GuardianResult:
    return GuardianResult(allowed=True, reason="stub")

async def validate_acl_token(state) -> ACLResult:
    return ACLResult(allowed=True, scope="full")

async def score_embedding_trust(doc) -> float:
    return 1.0

async def check_capability_boundary(action) -> bool:
    return True  # stub — Phase 2 enforces this for real
```

### Component 1.9 — Model Integrity Check at Startup
**File:** `startup.sh` + `src/security.py`

Hash Ollama model files at startup. Store hashes in the tool registry alongside tool hashes. Unexpected model hash change = `MODEL_INTEGRITY_FAILURE` threat event = startup halts.

```bash
make verify-model-integrity   # new Makefile target
```

### Component 1.10 — Researcher Agent
**File:** `src/agents/researcher.py`
**Template:** `src/base_graph.py`
**Model:** `llama3.1:8b` via Ollama
**Tools:** web search, web fetch, document summarization (all registered in tool_registry before first run)
**Tests:** `tests/test_researcher.py`

All web content passes through `security.py` sanitizer before entering LLM context. All tool responses pass through output sanitization. This agent is also the first real data source for the Phase 5 Observer agent — every tool call it makes is logged and will be analyzed for crystallization candidates.

### Phase 1 Technical Debt Cleanup
- Fix `AsyncConnectionPool` deprecation warning in `database.py`
- Update PG16 path string in `setup_postgres.sh` to PG17
- Add DB + Ollama integration tests

---

## Phase 2 — Containerization + Guardian Sidecar

**Goal:** Make the framework platform-independent. Any agent framework can use Guardian as an external security oracle. Add immutable logging and RAG provenance.

**Duration:** ~3 weeks
**Dependencies:** Phase 1 complete
**Exit criteria:** Full stack runs via `docker-compose up`. Guardian blocks known tool poisoning patterns. Capability boundary enforcement is real (not stubs). Health server requires token auth.

### Component 2.1 — Docker Compose Stack
**File:** `docker-compose.yml` (new)

```yaml
services:
  postgres:            # existing, containerized
  ollama:              # existing, containerized
  health-server:       # existing health.py, containerized
  guardian:            # new — security sidecar on :8766
  agent-base:          # base image all agents extend
  crystallized-tools:  # new — runtime for signed deterministic tool containers
```

### Component 2.2 — Guardian Service
**File:** `src/security/guardian.py` (new service)
**Exposes:** `POST /check` — synchronous security check before tool execution
**Exposes:** `POST /report` — async threat event ingestion
**Exposes:** `GET /rules` — current active rule set (read-only)

Hot path is deterministic only. No LLM calls. Pattern matching against threat_rules. Fast enough to be inline with every tool call.

Guardian now also enforces the negative capability list (Component 1.3) for real — stubs are replaced.

**Fail-safe tiers implemented:**

| Tier | Condition | Action |
|---|---|---|
| 1 — Halt | Confidence ≥ 0.85, or any capability boundary violation, or any unregistered tool invocation | Block, quarantine, alert |
| 2 — Sandbox Retry | Confidence 0.40–0.84, or novel tool combination never seen before | Re-run in sandbox, compare behavior |
| 3 — Degrade | Soft failure (tool unavailable, timeout) | Fall back, log, continue |

### Component 2.3 — Immutable Audit Log
**File:** `src/database.py` (additions)

```sql
CREATE TABLE audit_log (
    seq        BIGSERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ DEFAULT now(),
    event_type TEXT NOT NULL,
    agent_id   TEXT,
    payload    JSONB NOT NULL,
    prev_hash  TEXT NOT NULL,
    row_hash   TEXT NOT NULL
);
```

Hash chain verification runs on startup. Any gap proves tampering.

### Component 2.4 — RAG Document Provenance
**File:** `src/database.py` + `src/security.py`
**Migration:** Add `document_provenance` table

Every document entering the pgvector store gets: source URL, ingestion timestamp, trust score (0.0–1.0), content hash, embedding hash. Documents from unknown or low-trust sources default to 0.3. Retrieved documents with trust < 0.5 are flagged in LLM context.

Embedding anomaly detection at ingestion: flag documents whose embedding is unusually close to known sensitive query patterns (security config, credentials, system prompts). One-time cost per document rather than per-retrieval.

### Component 2.5 — Approved Tool Combination Patterns
**File:** `src/security/guardian.py` (additions)

Each agent declares its expected tool call sequences at registration time. Guardian monitors for combinations that have never been seen before. Novel combinations trigger Tier 2 (sandbox-first execution) before production execution. This is the primary behavioral defense against compositional emergence.

```python
# Declared at agent registration
RESEARCHER_EXPECTED_SEQUENCES = [
    ["web_search", "web_fetch", "document_summarize"],
    ["web_search", "document_summarize"],
    ["web_fetch", "document_summarize"],
]
# Any other combination → Tier 2 sandbox before production
```

### Component 2.6 — Health Server Auth
**File:** `src/health.py`

Bearer token authentication on all endpoints. Token stored in Keychain. Safe to expose on non-localhost once containerized.

---

## Phase 3 — ACLs, Task Tokens, Sub-Agent Architecture ✅ COMPLETE

**Goal:** Enable multi-agent workflows with tightly scoped privilege.

**Duration:** ~4 weeks
**Dependencies:** Phase 2 complete
**Exit criteria:** Sub-agents spawned with task-scoped tokens; privilege escalation attempts logged and blocked; Researcher can spawn a sub-agent for a bounded task.
**Smoke tests:** 88 → 95 (+7 Phase 3 orchestrator tests; 58 → 95 total across all phases)

### Component 3.1 — Task Token System ✅
**File:** `src/security/acl.py` (new)

```python
@dataclass
class TaskToken:
    token_id: str
    agent_id: str
    run_id: str
    granted_tools: list[str]
    granted_tables: list[str]
    granted_data_classes: list[str]
    expires_at: datetime
    parent_token_id: str | None
    escalation_policy: str   # "deny" | "request_human"
```

JWT-signed by a key in Keychain. Guardian validates the token signature on every `/check` call.

### Component 3.2 — Sub-Agent Orchestrator Pattern ✅
**File:** `src/agents/orchestrator.py` (new)

Orchestrator holds master token. Sub-agents receive derived tokens with narrower scope. Sub-agent results validated by Guardian before being passed back. No direct agent-to-agent communication — all traffic routes through orchestrator.

Implementation details:
- `_issue_master_token()` — analyst-role JWT at run start; `escalation_policy="deny"`
- `_derive_researcher_token()` — narrows master to researcher tools + `["public"]` data only
- `spawn_researcher` @tool — delegates via `_spawn_researcher_sub_agent()`; master JWT captured
  in module-level `_master_token_ref` dict (mutable ref persists across closures)
- `run_researcher(task_token=...)` — new param accepts pre-issued derived token from orchestrator
- `make setup-task-token-secret` — one-time Keychain setup target
- `make register-orchestrator-tools` — one-time tool registration

### Component 3.3 — Role Definitions ✅
**File:** `config/roles.yaml` (new)

```yaml
roles:
  reader:
    tools: [web_search, web_fetch, document_read]
    data_classes: [public]
  analyst:
    tools: [web_search, web_fetch, document_read, database_query]
    data_classes: [public, internal]
  crystallization_observer:
    tools: [audit_log_read, tool_call_history_read]
    data_classes: [internal]
    notes: "Read-only role for the Observer agent — Phase 5"
  security_analyst:
    tools: [threat_events_read, audit_log_read, rule_propose]
    data_classes: [security]
```

### Component 3.4 — Escalation Visibility ✅

Both `escalation_policy` values **halt the run** — the difference is how the event is classified:

| Policy | Meaning | Logged to | Visible on |
|--------|---------|-----------|-----------|
| `"deny"` | Suspicious — agent should never need this tool | `threat_events` as `TOOL_SCOPE_VIOLATION` | `/status` threat summary |
| `"alert"` | Operational under-scoping — token probably needs tuning | `audit_log` as `ESCALATION_BLOCKED` | `/status` escalation_events |

Both write to `/status` as **read-only history** — not pending approvals. The failed run is dead. The operator reviews the log, widens the role in `roles.yaml`, and issues a new token for the next run.

**Security invariant (hard constraint — never relax):**
> Escalation logging never grants capability. Approving an escalation NEVER modifies `roles.yaml`, the tool registry, or grants capability to future runs. The only legitimate way to expand an agent's baseline permissions is a human editing `roles.yaml` and committing it.

**Phase 4 upgrade path — Structured Escalation Requests:**
Rather than implicit tool-call blocking, Phase 4 adds an explicit structured output mechanism:
- Agent produces `{"status": "needs_escalation", "tool": "...", "justification": "..."}` in its output
- Orchestrator intercepts *before any tool is invoked* — agent never exceeded its boundary
- Human approves via `/escalations` endpoint → orchestrator issues a **run-scoped, single-use** derived token
- Approved tool expires with the run; never stored as a rule

---

## Phase 4 — Adaptive Threat Intelligence ✅ COMPLETE

**Goal:** The framework learns from its own threat history.

**Duration:** ~4 weeks
**Dependencies:** Phase 3 complete; meaningful data in `threat_events`
**Exit criteria:** Threat Analyst produces weekly digest; proposed rules go through human approval gate; Guardian applies approved rules without restart.
**Completed:** 2026-02-25 — 143/143 smoke tests passing

### Component 4.1 — Threat Analyst Agent ✅
**File:** `src/agents/threat_analyst.py`
**Role:** `security_analyst`
**Schedule:** Daily, via cron or LangGraph scheduled trigger (`make run-threat-analyst`)

Reads `threat_events` (read-only via task token with `deny` escalation policy). Fetches BOM for CVE cross-reference. Proposes new detection rules as PENDING JSONB in `threat_rules` table. Generates threat digest. Cannot apply its own rules. Uses `qwen2.5:3b` (router LLM — fast structured analysis, not reasoning).

### Component 4.2 — Adaptive Guardian Rules ✅

Guardian polls `threat_rules` every 60s for APPROVED rules (`_refresh_caches()`). Hot-reloads without restart. PENDING and REJECTED rules ignored. `_check_6_adaptive_rules()` enforces three rule types:
- `CAPABILITY_BLOCK` — halts if `tool_id` matches blocked tool
- `INJECTION_PATTERN` — halts if any string arg matches compiled regex pattern
- `SEQUENCE_BLOCK` — sandboxes if sequence-so-far starts with blocked sequence
Malformed rule defs skip with warning (never crash the check pipeline). Guardian version 4.0.0.

### Component 4.3 — AI Bill of Materials (AI-BOM) ✅
**File:** `src/security/bom.py` (new)

Tracks every model, tool, agent, and Python dependency with version, origin, SHA-256 hash, CVE scan status, last security review date. `GET /bom` health endpoint returns full BOM (Bearer auth required). BOM assembly is DB-fault-tolerant: returns 0 tools if DB unavailable rather than failing. 12 security-critical packages tracked. `/rules`, `/rules/{id}/approve`, `/rules/{id}/reject` endpoints added to health server for human-gate workflow.

### Database additions ✅
- `threat_rules` table with `PENDING`/`APPROVED`/`REJECTED` status and JSONB `rule_def`
- `THREAT_TYPES` extended: `RULE_PROPOSED`, `RULE_APPLIED`
- `RULE_TYPES = {"INJECTION_PATTERN", "CAPABILITY_BLOCK", "SEQUENCE_BLOCK", "RATE_LIMIT_TIGHTEN"}`
- Async helpers: `propose_threat_rule()`, `get_pending_rules()`, `get_approved_rules()`, `approve_threat_rule()`, `reject_threat_rule()`, `get_threat_events_for_analysis()`

---

## Phase 5 — Crystallization Pipeline ✅ COMPLETE

**Goal:** Systematically identify agent behaviors that don't need AI, generate deterministic replacements, analyze them rigorously before human review, sign and containerize them, and register them in the tool library. This phase converts learned AI behavior into durable, zero-LLM, auditable infrastructure.

**Duration:** ~5 weeks
**Dependencies:** Phase 4 complete (Threat Analyst validates new tool entries; Guardian enforces signing; meaningful call history exists in `audit_log` for the Observer to analyze)
**Exit criteria:** At least one crystallized tool in production; full pipeline from observation through analysis through HITL approval through signed deployment is operational and documented.

**Completed:** 2026-02-25 — 168/168 smoke tests passing at Phase 5 completion; 200/200 after Phase 5.5 hardening sprint.

Implemented components:
- `src/agents/observer.py` — LangGraph Observer agent (read-only, nominates candidates)
- `src/agents/crystallizer.py` — LangGraph Crystallizer agent (generates deterministic functions + test suites)
- `src/tools/crystallization_analyzer.py` — Deterministic Pre-HITL Analyzer (AST + security + subprocess test execution)
- `src/tools/signing.py` — Ed25519 key management + manifest signing/verification
- `src/health.py` — 5 crystallization review endpoints (list/detail/approve/reject/revise)
- `src/database.py` — 3 new tables + 11 CRUD functions + tool_registry signature columns
- `config/roles.yaml` — `crystallizer` role
- `scripts/run_observer.py`, `scripts/run_crystallizer.py`
- Makefile: `setup-signing-key`, `run-observer`, `run-crystallizer`, `pending-packages`, `approve-package`, `reject-package`

---

### The Crystallization Pipeline

```
audit_log / tool_call_history
        │
        ▼
  ┌─────────────┐
  │  OBSERVER   │  ← LangGraph agent, read-only role
  │   AGENT     │    watches call patterns, identifies candidates
  └──────┬──────┘
         │  candidate report
         ▼
  ┌─────────────┐
  │CRYSTALLIZER │  ← LangGraph agent, generates deterministic code
  │   AGENT     │    produces: function + manifest + test suite
  └──────┬──────┘
         │  candidate package
         ▼
  ┌─────────────┐
  │  PRE-HITL   │  ← deterministic analysis tooling (no LLM)
  │  ANALYZER   │    security scan, behavioral diff, complexity report
  └──────┬──────┘
         │  analysis report + candidate package
         ▼
  ┌─────────────┐
  │    HUMAN    │  ← reviews analysis report, approves or rejects
  │   REVIEW    │    the only step that can promote a tool to APPROVED
  └──────┬──────┘
         │  approved
         ▼
  ┌─────────────┐
  │  SIGNING +  │  ← Ed25519 sign, Docker image build, registry entry
  │  PACKAGING  │    Guardian enforces signature on every invocation
  └──────┬──────┘
         │  deployed
         ▼
  tool_registry (status: APPROVED, signed: true)
  docker registry (signed image, resource-limited container)
```

---

### Component 5.1 — Observer Agent

**File:** `src/agents/observer.py`
**Role:** `crystallization_observer` (read-only, defined in Phase 3 roles)
**Model:** `llama3.1:8b` or `qwen2.5:3b` (pattern recognition, not heavy reasoning)
**Schedule:** Runs on a configurable schedule (default: nightly) or triggered manually
**Input:** `audit_log` tool call history — sequences, inputs, outputs, token costs, latency
**Output:** Candidate report written to `crystallization_candidates` table (status: NOMINATED)

**What the Observer does:**

The Observer reads the agent's action history and looks for patterns that satisfy the crystallization criteria. It is not generating code — it is pattern recognition and candidate nomination only.

Crystallization criteria (all must be satisfied):
1. The same logical operation has been performed N or more times (configurable, default 5)
2. The inputs follow a consistent structure across instances
3. The outputs are consistent and deterministic given the same inputs
4. The operation involves no ambiguity, judgment, or natural language interpretation
5. The same algorithm would produce the correct result across all observed instances
6. The token cost of the AI-based approach is measurably higher than a deterministic equivalent would be

**What the Observer produces per candidate:**

```python
@dataclass
class CrystallizationCandidate:
    candidate_id: str
    operation_name: str          # human-readable name the Observer gives it
    observed_count: int          # how many times seen
    first_seen: datetime
    last_seen: datetime
    example_inputs: list[dict]   # 3-5 representative input samples
    example_outputs: list[dict]  # corresponding outputs
    input_schema: dict           # inferred JSON schema of inputs
    output_schema: dict          # inferred JSON schema of outputs
    token_cost_total: int        # total tokens spent on this operation historically
    token_cost_per_call: float   # average tokens per invocation
    estimated_savings_pct: float # estimated token reduction if crystallized
    reasoning: str               # Observer's explanation of why this qualifies
    disqualifying_factors: list  # Observer's honest list of why it might NOT qualify
    status: str                  # NOMINATED
```

**Critical constraint:** The Observer can only *nominate* candidates. It cannot generate code. It cannot modify the tool registry. Its task token grants only `audit_log_read` and `crystallization_candidates_write`.

---

### Component 5.2 — Crystallizer Agent

**File:** `src/agents/crystallizer.py`
**Role:** `crystallizer` (new role — read crystallization candidates, write candidate packages)
**Model:** `llama3.1:8b` (code generation task — needs the primary model)
**Trigger:** Runs after Observer nominates candidates. Can be triggered manually or on schedule.
**Input:** A `CrystallizationCandidate` from the `crystallization_candidates` table
**Output:** A complete candidate package written to `crystallization_packages` table (status: PENDING_ANALYSIS)

**What the Crystallizer does:**

The Crystallizer takes a nominated candidate and generates everything needed for a complete tool — the function implementation, the manifest, and critically, a test suite that will be used to verify behavioral equivalence before human review.

**Crystallizer output package:**

```python
@dataclass
class CrystallizationPackage:
    package_id: str
    candidate_id: str

    # The generated code
    function_code: str           # the deterministic Python function
    function_signature: str      # typed signature

    # The tool manifest (what will go into tool_registry if approved)
    tool_name: str
    tool_description: str
    input_schema: dict
    output_schema: dict
    declared_side_effects: list  # ["pure"] for stateless, or explicit list

    # The test suite (critical — used by Pre-HITL Analyzer)
    test_cases: list[TestCase]   # input/expected_output pairs from observed examples
    edge_cases: list[TestCase]   # edge cases the Crystallizer identified
    adversarial_cases: list[TestCase]  # inputs that might break the function

    # Crystallizer's self-assessment
    confidence_score: float      # 0.0–1.0, Crystallizer's confidence in correctness
    known_limitations: list[str] # honest list of cases this might not handle
    suggested_fallback: str      # what should happen if this tool fails at runtime

    status: str                  # PENDING_ANALYSIS
```

**Crystallizer constraints:**
- Cannot register the tool
- Cannot modify existing tools
- Cannot deploy anything
- Generated code goes into the candidates table, not into the tool registry
- Must generate a test suite — a package without tests is rejected before analysis

---

### Component 5.3 — Pre-HITL Analyzer

**File:** `src/tools/crystallization_analyzer.py` (new — deterministic tooling, not an agent)
**Type:** Deterministic analysis pipeline — no LLM involved
**Trigger:** Runs automatically when a package reaches status PENDING_ANALYSIS
**Input:** A `CrystallizationPackage`
**Output:** An `AnalysisReport` attached to the package; package status updated to READY_FOR_REVIEW or REJECTED_BY_ANALYSIS

**Why this is deterministic tooling, not an agent:**

The Pre-HITL Analyzer exists specifically to give the human reviewer an objective, LLM-free assessment of the candidate tool. If the analysis itself used an LLM, it would be subject to the same injection, hallucination, and non-determinism risks as the rest of the system. The human reviewer needs to trust the analysis. That requires deterministic tooling.

**What the Pre-HITL Analyzer does:**

```
1. STATIC ANALYSIS
   Run the generated code through:
   - AST parser to detect forbidden constructs (exec, eval, __import__,
     subprocess, os.system, open for write, socket, requests/httpx calls)
   - Complexity analysis (cyclomatic complexity, lines of code, nesting depth)
   - Dependency scan — does the function import anything not already in requirements.txt?
   - Side effect detection — does the code do anything not declared in declared_side_effects?

2. BEHAVIORAL EQUIVALENCE TESTING
   Run all test cases from the Crystallizer's test suite:
   - Execute the generated function against every example_input
   - Compare output to example_output
   - Report pass rate, any mismatches, and diff on failures
   - Flag any test cases where the function raises an exception

3. BEHAVIORAL DIFF vs. AGENT
   For each test case, also run the original AI-based tool call
   (using the same inputs against the live Researcher agent):
   - Compare deterministic output vs. AI output
   - Flag cases where they differ significantly
   - This is the ground truth check — does the crystallized version
     actually replicate what the agent was doing?

4. ADVERSARIAL INPUT TESTING
   Run the Crystallizer's adversarial cases plus a standard set of
   boundary inputs:
   - Empty inputs
   - Null values where the schema allows them
   - Maximum-length strings
   - Unicode edge cases
   - Type coercions (string where int expected, etc.)
   Report any unhandled exceptions or unexpected outputs.

5. SECURITY SCAN
   - Confirm no network calls in the function body
   - Confirm no filesystem writes
   - Confirm no credential access
   - Confirm no dynamic code execution
   - Confirm function is pure/stateless if declared_side_effects == ["pure"]

6. COMPLEXITY REPORT
   Human-readable summary:
   - "This function is X lines, cyclomatic complexity Y (low/medium/high)"
   - "It handles Z test cases correctly out of N"
   - "It differs from the AI baseline in W cases (see diffs below)"
   - "It has no forbidden constructs"
   - "It has no undeclared side effects"
   - "Estimated token savings if adopted: X tokens/day based on observed frequency"
```

**Analysis report structure:**

```python
@dataclass
class AnalysisReport:
    package_id: str
    analyzed_at: datetime

    # Static analysis
    forbidden_constructs: list[str]   # empty = clean
    undeclared_dependencies: list[str]
    undeclared_side_effects: list[str]
    cyclomatic_complexity: int
    lines_of_code: int

    # Behavioral equivalence
    test_cases_total: int
    test_cases_passed: int
    test_cases_failed: int
    failed_case_diffs: list[dict]     # input, expected, actual for each failure

    # Behavioral diff vs. agent
    ai_equivalence_rate: float        # 0.0–1.0
    ai_divergence_cases: list[dict]   # cases where deterministic != AI output

    # Adversarial testing
    adversarial_cases_total: int
    adversarial_exceptions: list[dict]
    adversarial_unexpected_outputs: list[dict]

    # Security
    security_clean: bool
    security_findings: list[str]      # empty = clean

    # Summary for human reviewer
    recommendation: str               # "APPROVE", "REJECT", "NEEDS_REVISION"
    recommendation_reasoning: str     # plain English explanation
    estimated_daily_token_savings: int
    risk_flags: list[str]            # anything the human should pay special attention to

    # Outcome
    status: str   # READY_FOR_REVIEW or REJECTED_BY_ANALYSIS
```

Packages are auto-rejected (without human review) if:
- Any forbidden constructs are found
- Any undeclared dependencies are found
- Security scan finds any violations
- Test case pass rate < 80%
- AI equivalence rate < 70%

Everything else goes to the human with the full report.

---

### Component 5.4 — Human Review Interface

**Endpoint:** `GET /crystallization/candidates` — list all packages at READY_FOR_REVIEW
**Endpoint:** `GET /crystallization/candidates/{package_id}` — full package + analysis report
**Endpoint:** `POST /crystallization/candidates/{package_id}/approve` — approve and trigger signing
**Endpoint:** `POST /crystallization/candidates/{package_id}/reject` — reject with reason
**Endpoint:** `POST /crystallization/candidates/{package_id}/revise` — send back to Crystallizer with notes

**What the human sees:**

The review interface is designed to make it easy to make the right decision and hard to make the wrong one. The human sees:

1. **The analysis report** — plain English, not raw data. "This function passes 47 of 50 test cases. The 3 failures are on edge cases involving empty string inputs. Here are the diffs."

2. **The behavioral diff** — side-by-side comparison of what the AI agent did vs. what the deterministic function does, for a representative set of inputs.

3. **The generated code** — the actual Python function. Short enough to read in 2 minutes for most candidates (if it's longer than ~50 lines, that's a complexity risk flag).

4. **The risk flags** — prominently displayed, not buried. If the analyzer found anything concerning, it appears at the top.

5. **The estimated savings** — concrete: "Adopting this tool would save approximately 1,240 tokens per day based on observed call frequency."

**Approval is explicit and logged.** Every approval writes to `audit_log` with: who approved, when, which analysis report they based the decision on, and the package_id. The approval event is part of the tamper-evident hash chain.

---

### Component 5.5 — Signing + Packaging Pipeline

**File:** `src/tools/signing.py` (new)
**Trigger:** Runs automatically after human approval
**Input:** Approved `CrystallizationPackage`
**Output:** Signed tool entry in `tool_registry` + signed Docker image in local registry

**Signing process:**

```python
async def sign_and_package(package: CrystallizationPackage, approval_event_id: str):

    # 1. Build the tool manifest
    manifest = ToolManifest(
        tool_id=f"{package.tool_name}@{semver}",
        source="crystallization_pipeline",
        version=semver,
        description_hash=sha256(package.tool_description),
        schema_hash=sha256(json.dumps(package.input_schema, sort_keys=True)),
        entrypoint_hash=sha256(package.function_code),
        declared_side_effects=package.declared_side_effects,
        approved_by=approval.approved_by,
        approved_at=approval.approved_at,
        approval_event_id=approval_event_id,  # links to audit_log entry
    )

    # 2. Sign the manifest with the framework's Ed25519 key (from Keychain)
    signing_key = load_signing_key_from_keychain()
    manifest.signature = signing_key.sign(
        json.dumps(manifest.dict(), sort_keys=True).encode()
    ).hex()

    # 3. Build Docker image
    dockerfile = generate_dockerfile(package.function_code, package.input_schema)
    image_tag = f"crystallized/{package.tool_name}:{semver}"
    docker_build(dockerfile, tag=image_tag)

    # 4. Register in tool_registry
    await db.register_tool(manifest, status="APPROVED")

    # 5. Log to audit_log
    await audit_log.write("TOOL_CRYSTALLIZED", {
        "tool_id": manifest.tool_id,
        "package_id": package.package_id,
        "approval_event_id": approval_event_id,
        "signature": manifest.signature[:16] + "...",
    })
```

**Docker container constraints for crystallized tools:**
- Non-root user
- Read-only filesystem
- No network egress
- No environment variable access (inputs via stdin/args only)
- CPU and memory limits set at container definition time
- Time limit enforced by the container runtime
- Signed image manifest (Docker Content Trust)

These constraints are enforced at the container level — even if the function code somehow tried to make a network call, the container would block it.

---

### Component 5.6 — New Database Tables for Phase 5

```sql
-- Nominated candidates from Observer agent
CREATE TABLE crystallization_candidates (
    id               BIGSERIAL PRIMARY KEY,
    candidate_id     TEXT UNIQUE NOT NULL,
    operation_name   TEXT NOT NULL,
    observed_count   INTEGER NOT NULL,
    first_seen       TIMESTAMPTZ,
    last_seen        TIMESTAMPTZ,
    example_inputs   JSONB,
    example_outputs  JSONB,
    input_schema     JSONB,
    output_schema    JSONB,
    token_cost_total INTEGER,
    estimated_savings_pct FLOAT,
    reasoning        TEXT,
    disqualifying_factors JSONB,
    status           TEXT DEFAULT 'NOMINATED',
    nominated_at     TIMESTAMPTZ DEFAULT now(),
    nominated_by     TEXT DEFAULT 'observer_agent'
);

-- Full packages from Crystallizer agent
CREATE TABLE crystallization_packages (
    id                BIGSERIAL PRIMARY KEY,
    package_id        TEXT UNIQUE NOT NULL,
    candidate_id      TEXT REFERENCES crystallization_candidates(candidate_id),
    tool_name         TEXT NOT NULL,
    tool_description  TEXT,
    function_code     TEXT NOT NULL,
    input_schema      JSONB,
    output_schema     JSONB,
    declared_side_effects JSONB,
    test_cases        JSONB,
    confidence_score  FLOAT,
    known_limitations JSONB,
    suggested_fallback TEXT,
    status            TEXT DEFAULT 'PENDING_ANALYSIS',
    created_at        TIMESTAMPTZ DEFAULT now()
);

-- Analysis reports from Pre-HITL Analyzer
CREATE TABLE crystallization_analyses (
    id                        BIGSERIAL PRIMARY KEY,
    package_id                TEXT REFERENCES crystallization_packages(package_id),
    analyzed_at               TIMESTAMPTZ DEFAULT now(),
    test_cases_passed         INTEGER,
    test_cases_failed         INTEGER,
    failed_case_diffs         JSONB,
    ai_equivalence_rate       FLOAT,
    ai_divergence_cases       JSONB,
    security_clean            BOOLEAN,
    security_findings         JSONB,
    recommendation            TEXT,
    recommendation_reasoning  TEXT,
    estimated_daily_savings   INTEGER,
    risk_flags                JSONB,
    status                    TEXT    -- READY_FOR_REVIEW or REJECTED_BY_ANALYSIS
);
```

---

## Phase 5.5 — Security Hardening Sprint ✅ COMPLETE

**Goal:** Close ten attack vectors identified during adversarial threat-model review of the Phase 5 crystallization pipeline. No new agents — security hardening only.

**Completed:** 2026-02-26 — 200/200 smoke tests passing.

### What was hardened

| # | Vector | Fix |
|---|---|---|
| 1 | `sys.modules['subprocess']` subscript bypass | `ast.Subscript` node check in crystallization_analyzer |
| 2 | `__builtins__['eval']()` subscript bypass | same check |
| 3 | MRO traversal `().__class__.__bases__[0].__subclasses__()` | `__bases__`, `__subclasses__`, `__mro__`, `__class__`, `__dict__` → `_FORBIDDEN_ATTRS` |
| 4 | `globals()['eval']()` / `locals()` lookups | `globals`, `locals`, `type` → `_FORBIDDEN_NAMES` |
| 5 | DB superuser for all runtime queries | Two-phase `init_db()` — admin pool for DDL, restricted `legionforge_app` pool for runtime (no DELETE on audit tables, no DDL) |
| 6 | No `REVOKED` status in tool_registry; 60s stale cache | `REVOKED` status + Guardian TTL 60s → 10s + `POST /tools/{id}/revoke` |
| 7 | Tool result injection: logs only, no threat event | `SecureToolNode` emits `TOOL_RESULT_INJECTION` event + optional halt |
| 8 | Analyzer uses subprocess — not deny-default container | `Dockerfile.analyzer` deny-default; Docker > sandbox-exec > bare priority |
| 9 | Guardian TOCTOU: state mutable between check + exec | `approved_snapshot` captured pre-loop; post-exec `tool_call_id` verification |
| 10 | Ollama model files: no SHA256 integrity verification | `src/tools/model_integrity.py`; `MODEL_INTEGRITY_MISMATCH` threat event; `make verify-models` |

### New files
- `src/tools/model_integrity.py` — streaming SHA256 GGUF verification
- `Dockerfile.analyzer` — deny-default analyzer sandbox
- `requirements.analyzer.txt` — minimal analyzer deps (numpy, pandas, scipy only)
- `scripts/db_setup_roles.sql` — standalone SQL for manual PostgreSQL role setup

### New Makefile targets
```bash
make setup-db-roles    # provision legionforge_app PostgreSQL role + grants (idempotent)
make verify-models     # print SHA256 of GGUF files for hash pinning
make build-analyzer    # build legionforge-analyzer:latest Docker image
make revoke-tool TOOL_ID=<id>  # immediately revoke a tool via health API
```

---

## Phase 6 — PentestAgent + Continuous Security Regression

**Goal:** Automated red-teaming of deployed agents. Guardian misses become regression tests. Security posture improves with every detected attack.

**Duration:** ~4 weeks
**Dependencies:** Phase 5 complete; signed tool library operational
**Exit criteria:** PentestAgent runs full attack suite against Researcher agent; results feed Threat Analyst; at least one Guardian rule improved based on pentest findings; at least one crystallized tool is included in the attack surface.

### Component 6.1 — PentestAgent
**File:** `src/agents/pentest_agent.py`
**Isolation:** Air-gapped container. No production data access. Synthetic environment only.
**Trigger:** Manual only. Never autonomous.

Attack capabilities (all against synthetic targets only):
- Direct prompt injection suite
- Indirect injection via synthetic poisoned documents
- Tool metadata poisoning variants
- Resource bomb patterns
- ACL privilege escalation attempts
- RAG poisoning via synthetic low-trust documents
- Rug-pull simulation
- Credential exfiltration patterns (synthetic credentials only)
- **Crystallized tool behavioral equivalence attacks** — verify that a crystallized tool can't be tricked into producing outputs that differ from the AI baseline in security-relevant ways (new, Phase 6 addition)

### Component 6.2 — Pentest → Guardian Feedback Loop

Results feed Threat Analyst as high-priority input. Undetected attacks become proposed Guardian rules. Human approves. Guardian improves.

### Component 6.3 — Pentest Report

Structured markdown report per run: security score (0–100), attacks attempted vs. detected, top undetected vectors, Guardian rule recommendations, comparison to previous run. Available at `/security/pentest/latest`.

---

## Cross-Phase: What Never Changes

| Principle | Implementation |
|---|---|
| Human gate on all mutations | No autonomous rule change, tool promotion, privilege escalation, or crystallization approval |
| Guardian has no LLM in hot path | Deterministic checks only at `/check`; LLM analysis is offline only |
| Pre-HITL analysis is deterministic | No LLM in the crystallization analysis pipeline — the human reviewer must be able to trust the analysis |
| PentestAgent is air-gapped | Never touches production data; manual trigger only |
| All external content is untrusted | Provenance scoring required before RAG ingestion |
| Audit log is append-only | Hash chain; verification on startup |
| Security failures are observable | Every block, sandbox, and degrade event writes to threat_events |
| Crystallized tools are more trusted than AI tools | But not unconditionally — Guardian still validates signatures and behavioral contracts on every invocation |

---

## Dependency Map

```
Phase 0 (Infrastructure)
    └── Phase 1 (First Agent + Security Foundations)
            ├── Phase 2 (Containerization + Guardian)
            │       └── Phase 3 (ACLs + Sub-Agents)
            │               └── Phase 4 (Adaptive Threat Intel)
            │                       └── Phase 5 (Crystallization Pipeline)
            │                               └── Phase 6 (PentestAgent)
            │
            └── [Agent development can proceed independently at any phase]
                    researcher.py          → Phase 1
                    orchestrator.py        → Phase 3
                    threat_analyst.py      → Phase 4
                    observer.py            → Phase 5
                    crystallizer.py        → Phase 5
                    crystallization_analyzer.py → Phase 5 (deterministic tooling)
                    pentest_agent.py       → Phase 6
```

---

## Resource Reality Check

**Mac Mini M4, 16GB RAM — can it run this?**

| Phase | Additional RAM | Additional Disk | Notes |
|---|---|---|---|
| 1 | ~0.5GB | ~1GB | New tables, new functions |
| 2 | ~1GB (Guardian container) | ~2GB | Docker overhead; Guardian is lightweight |
| 3 | ~0.5GB | minimal | ACL system is pure logic |
| 4 | ~2GB peak | ~5GB | Threat Analyst runs Ollama inference; scheduled, not concurrent |
| 5 | ~2GB peak | ~10GB | Observer + Crystallizer run sequentially; crystallized tool containers are ephemeral and small; analysis is CPU-bound not RAM-bound |
| 6 | ~3GB peak (air-gapped) | ~5GB | PentestAgent runs only on manual trigger |
| 7 | ~0GB | ~1MB | Pure DB + logic work; no new containers or models |

Total at full Phase 7 deployment, peak concurrent: ~8–9GB RAM. Within the 16GB envelope with Ollama model swap managed (one model loaded at a time).

---

## Phase 7 — Guardian Feedback Loop + v1.0 Readiness ✅ COMPLETE

**Goal:** Complete Phase 6.2 (Pentest→Guardian bridge). Wire approved pentest rules into
Guardian's enforcement pipeline. Document HITL halt policy. v1.0 housekeeping.

**Duration:** 1 sprint
**Dependencies:** Phase 6 complete; `threat_rules` + `_check_6_adaptive_rules()` in place (Phase 4)
**Exit criteria:** Approved pentest rules promoted to `threat_rules`; Guardian enforces within 10s;
SECURITY.md written; 242/242 smoke tests passing.

### Component 7.1 — Pentest→Guardian Bridge

**File:** `src/database.py`

`promote_pentest_rule_to_threat_rule()` converts an approved `pentest_proposed_rules` row
into a `threat_rules` row (status='APPROVED', approved_by='operator_hitl'). The type
mapping is:

| pentest type | Guardian type | Guardian check |
|---|---|---|
| `REGEX` | `INJECTION_PATTERN` | `_check_6_adaptive_rules()` — matches against arg strings |
| `CAPABILITY` | `CAPABILITY_BLOCK` | `_check_6_adaptive_rules()` — blocks named tool_id |
| `RATE_LIMIT` | `RATE_LIMIT_TIGHTEN` | stored; provider-side enforcement |

**File:** `src/health.py`

`POST /pentest/rules/{finding_id}/approve` now:
1. Sets `pentest_proposed_rules.status = 'APPROVED'`
2. Calls `promote_pentest_rule_to_threat_rule()` — bridges to `threat_rules`
3. Calls `append_audit_log()` with event_type='PENTEST_RULE_PROMOTED'
4. Returns `{..., "threat_rule_id": "...", "enforcement": "active_within_10s"}`

Guardian picks up the new row on its next 10-second cache refresh. No Guardian restart needed.

### Component 7.2 — SECURITY.md

New `SECURITY.md` at repo root covering:
- Full threat model (13 threats + defenses)
- HITL halt vs log tier policy (NIST SP 800-61r3 + MITRE ATT&CK references)
- Tier 1: HALT — injection in args, self-probe, privilege escalation, TOCTOU, Guardian unavailable
- Tier 2: LOG+ALERT — injection in input, credential probe, rate limit, sequence violation
- Tier 3: DEGRADE — non-critical failures, budget exhaustion
- Pentest baseline (0 bypasses on clean deployment)
- Responsible disclosure (90-day window, `[SECURITY]` tag, private channel)

### Component 7.3 — v1.0 Housekeeping

- `PHASE_PLAN.md`: Phase 6 + Phase 7 marked complete; Phase Overview updated
- `placeholder_readme.md`: Phase 7 row; Known Gaps deduped; smoke test count 228 → 242
- `tests/test_smoke.py`: +14 Phase 7 tests (228 → 242)

---

## Phase 8 — Gateway + Streaming + Task Queue + Web UI + Discord ✅ COMPLETE

**Completed:** 2026-02-27 — 323/323 smoke tests passing.

**What was built:** FastAPI gateway (`:8080`), embedded asyncio task worker, SSE streaming via `astream_events`, minimal Web UI, A2A + MCP endpoints, per-user Bearer token auth, Discord connector. Closed Guardian tool-args blind spot (Gap 1) and hardcoded-action bug (Gap 2).

**New files:** `src/gateway/` (app, auth, events, worker, routes/), `src/connectors/discord.py`, `src/gateway/static/index.html`, `Dockerfile.sandbox`

---

## Phase 9 — Tool Library + langchain 1.x + Parallel Fan-Out ✅ COMPLETE

**Completed:** 2026-02-28 — 397/397 smoke tests passing (377 at Phase 9 + 20 more in 9.5 hardening).

**What was built:**
- langchain 1.x migration (closes Dependabot #4 SSRF, LOW)
- Tool library: `http_get`, `http_post` (SSRF guard, 50 KB cap), `file_read`, `file_write` (path allowlist, traversal guard), `code_execute` (air-gapped Docker sandbox)
- Parallel fan-out engine: `src/agents/fan_out.py` — `asyncio.gather()` + `Semaphore` cap + per-branch JWT + error isolation
- Phase 9.5 hardening: rate-limiter TOCTOU fix (`check_and_reserve()` atomic under lock), `/status` 30s TTL cache, 3 new PII patterns (`[DB_DSN]`, `[PRIVATE_IP]`, `[HOME_PATH]`)

---

## Phase 10 — Multi-User, Auth, and Scale ✅ COMPLETE

**Completed:** 2026-02-28 — 422/422 smoke tests passing (+25 Phase 10 tests).

**Goal:** DB-backed stream tokens that survive gateway restart; per-user daily token budgets enforced at submission time; user attribution on `api_usage`; user management CLI.

**What was built:**

### Schema additions (`src/database.py`)
- `stream_tokens` table — `(token, task_id, user_id, expires_at TIMESTAMPTZ)` + TTL index
- `gateway_users.daily_token_limit INTEGER NOT NULL DEFAULT 100000`
- `tasks.estimated_tokens INTEGER NOT NULL DEFAULT 0`
- `api_usage.user_id TEXT` + index

### Stream tokens → DB (`src/gateway/auth.py`)
Replaced in-memory `_stream_tokens` dict with `create_stream_token` / `resolve_stream_token` / `delete_stream_token` backed by PostgreSQL. Worker purges expired tokens every 10 minutes.

### Per-user budget check (`src/rate_limiter.py`)
`per_user_budget_check(user_id, provider, estimated_tokens, daily_limit)` — 2 DB reads: `SUM(total_tokens)` from `api_usage WHERE user_id=... AND DATE=today` plus `SUM(estimated_tokens)` from `tasks WHERE user_id=... AND status IN ('queued','running')`. Raises `RuntimeError` → HTTP 429 if `actual + in_flight + estimated > daily_limit`.

### Task submission (`src/gateway/routes/tasks.py`)
Token estimation heuristic (`len(words) * 1.3 + 500`), `per_user_budget_check()` call before queue insert, `estimated_tokens` stored on task row.

### Worker attribution (`src/gateway/worker.py`)
`run_task()` passes `user_id` from task dict to `record_actual_usage()`. Worker heartbeat purges expired stream tokens every 10 minutes.

### `/usage/me` endpoint (`src/health.py`)
Returns `{user_id, username, daily_limit, today: {tokens_used, tokens_in_flight, tokens_remaining}, providers}` from `api_usage` for the authenticated user.

### User management CLI (`src/cli/manage_users.py`)
```bash
python -m src.cli.manage_users create-user   --username alice --daily-limit 100000
python -m src.cli.manage_users deactivate-user --username alice
python -m src.cli.manage_users set-quota     --username alice --daily-limit 500000
python -m src.cli.manage_users list-users
make create-user USERNAME=alice
```

### Config (`config/settings.py` + hardware YAML)
`GatewayConfig` model with `default_daily_token_limit: int = 100000`. `gateway:` section in `mac_m4_mini_16gb.yaml`.

**Explicitly deferred to Phase 11:** Redis, load balancer, multiple gateway processes, OAuth, integration tests.

---

## Phase 11 — SecureToolNode Fix, Integration Tests, Modular Auth, Gateway Containerization ✅ COMPLETE

**Completed:** 2026-02-28 — 430/430 smoke tests passing (+8 Phase 11 tests). 35 integration tests passing (3 Ollama-scaffolded).

**Goal:** Close the four open issues from Phase 10: critical security fix in SecureToolNode, end-to-end integration test suite, modular auth architecture for OAuth readiness, and containerized gateway.

**What was built:**

### SecureToolNode silent-failure fix (`src/base_graph.py`)
When both `model_copy()` and `copy()` fail on a tool result message, the original code had a bare `pass` — allowing unsanitized content into agent context. Fixed by synthesizing a new `ToolMessage` with sanitized content when both copy paths fail, preserving `tool_call_id` and `name` for graph coherence. This is a critical security fix: the agent *always* sees sanitized content regardless of message object type.

### Modular auth architecture (`src/gateway/auth.py`)
Extracted `AuthBackend` protocol (`@runtime_checkable`) and `ApiKeyBackend` class. Added `get_auth_backend()` / `set_auth_backend()`. OAuth, LDAP, or JWT backends can now be plugged in at startup without changing `require_user` or any route code. See `docs/SCALING.md` for the OAuth integration pattern.

### `GatewayConfig.auth_provider` (`config/settings.py` + YAML)
Added `auth_provider: str = "api_key"` to `GatewayConfig`. YAML profile has `auth_provider: api_key` under `gateway:`. Provides a config hook for the Phase 12 OAuth switch.

### Integration test suite (`tests/test_integration.py`)
35 tests, `@pytest.mark.integration`, require PostgreSQL. 3 Ollama-dependent tests are scaffolded with `pytest.skip()`. Groups:
- DB Schema (6): column existence, init_db idempotency, is_active default
- Auth (4): correct/wrong/inactive key, missing Authorization header
- Stream tokens (5): create, resolve, expired, unknown, purge
- Task submission (8): 202, injection 400, invalid agent 422, owner 200, cross-user 404, list, cancel 204, blank 422
- Budget enforcement (4): passes under limit, 429 on exceeded, zero usage, inflight count
- Usage endpoint (4): shape, daily_limit match, 401 without auth, tokens_remaining
- User CLI (4): create_user callable, deactivate_user, set_quota, list_users

Test fixtures use direct psycopg admin connections for all cleanup DELETEs (`legionforge_app` has no DELETE on `tasks`/`api_usage`/`gateway_users` by RBAC design).

### `Dockerfile.gateway`
Containerized gateway: `python:3.11-slim`, non-root `gateway` user (uid 1001), `EXPOSE 8080`. Multi-worker safe (DB-backed queue + `FOR UPDATE SKIP LOCKED`). Build: `make build-gateway`. Run: `make gateway-start-docker`.

### `docs/SCALING.md`
Horizontal scaling guide: multi-worker uvicorn, nginx/Caddy load balancer configs, `AuthBackend` OAuth integration pattern, Redis decision guide (when to add it), pre-multi-instance checklist.

### `/usage/me` on gateway (`src/gateway/app.py`)
Moved `GET /usage/me` to the gateway app (`:8080`) via `require_user` dependency. The endpoint remains on the health app as well; the gateway version is the canonical user-facing path.

### dict_row production fix (`src/database.py`)
Fixed `row[0]` / `r[0]` integer-index access in `get_user_actual_usage_today`, `get_user_inflight_tokens`, `get_user_usage_summary_today`. All three functions use `dict_row` pool — column name access is required (`row["total"]`, `r["tokens"]`, etc.).

### `list_users()` return value (`src/cli/manage_users.py`)
`list_users()` now returns the users list in addition to printing, enabling programmatic use (tests + scripting).

### Makefile additions
`test-integration`, `test-all`, `build-gateway`, `gateway-start-docker`.

**Test delta:** 422 → 430 smoke tests (+8). Integration test suite: 35 passed, 3 skipped.

---

## Phase 12 — Multi-Provider Auth Backend Registry ✅ COMPLETE

**Completed:** 2026-02-28 — 443/443 smoke tests passing (+13 Phase 12 tests).

**Goal:** Build the full auth backend registry: OIDC (covers Google, Okta, Auth0, Keycloak, Azure AD), GitHub OAuth (opaque token flow), LDAP/Active Directory, and Kerberos (scaffolded). Fix incorrect docs claiming output sanitization was deferred to Phase 12 (it was fully implemented in Phase 9). Redis explicitly deferred (household scale, no need yet).

**What was built:**

### `src/gateway/backends/` package (8 files)
New auth backend registry: `base.py` (updated `AuthBackend` protocol + `SCHEME_BEARER`/`SCHEME_BASIC`/`SCHEME_NEGOTIATE` constants), `api_key.py` (moved from `auth.py`), `oidc.py`, `github.py`, `ldap_backend.py`, `kerberos.py` (scaffold), `registry.py`, `__init__.py`.

### Updated `AuthBackend` protocol (`src/gateway/backends/base.py`)
Added `scheme: str = "bearer"` parameter to `authenticate()`. Backward compatible — existing callers passing only a credential string continue to work. Three scheme constants exported: `SCHEME_BEARER`, `SCHEME_BASIC`, `SCHEME_NEGOTIATE`.

### `OIDCBackend` (`src/gateway/backends/oidc.py`)
Validates JWT access tokens via JWKS (PyJWT, async httpx fetching). Discovery doc + JWKS cached in-process (1h + configurable TTL). Falls back to userinfo endpoint for opaque tokens. Auto-provisions `gateway_users` row on first login (`api_key_hash='[OAUTH-NO-KEY]'` sentinel). Covers: Google, Okta, Auth0, Keycloak, Azure AD, Ping, Cognito, any OIDC IdP.

### `GitHubOAuthBackend` (`src/gateway/backends/github.py`)
GitHub OAuth apps issue opaque tokens — OIDC JWKS flow doesn't apply. Validates by calling `GET https://api.github.com/user`. Auto-provisions on first login. Returns `user_id="github:<id>"`.

### `LDAPBackend` (`src/gateway/backends/ldap_backend.py`)
Service-account bind → user search → user-credential rebind. Supports OpenLDAP (`uid={username}`) and Active Directory (`sAMAccountName={username}`) via configurable search filter. Bind password from Keychain (`legionforge_ldap_bind_password`). Auto-provisions on first login. Returns `user_id="ldap:<dn>"`. Accepts `scheme="basic"` only.

### `KerberosBackend` (`src/gateway/backends/kerberos.py`)
Scaffold only. Instantiates safely; `authenticate()` raises `NotImplementedError` with actionable setup instructions (KDC, service principal, keytab, `gssapi` package). Phase 13+ implementation.

### `BackendRegistry` (`src/gateway/backends/registry.py`)
`load_backend_from_settings(settings)` factory: maps `settings.gateway.auth_provider` → backend instance. Supported: `api_key`, `oidc`, `github`, `ldap`, `kerberos`. Raises `ValueError` for unknown values.

### Multi-scheme `require_user` (`src/gateway/auth.py`)
Parses three Authorization schemes: `Bearer` (api_key / OIDC / GitHub), `Basic` (LDAP, base64-decoded), `Negotiate` (Kerberos). Delegates to the active backend's `authenticate(credential, scheme=scheme)`. Returns 401 on any failure.

### `OIDCConfig` + `LDAPConfig` (`config/settings.py`)
New Pydantic sub-models added to `GatewayConfig`. All fields default to empty (disabled). `auth_provider` field now documents all five options.

### Hardware profile additions (`config/hardware_profiles/mac_m4_mini_16gb.yaml`)
`gateway.oidc` and `gateway.ldap` sections added with commented documentation. `auth_provider: api_key` remains the default.

### Gateway lifespan wiring (`src/gateway/app.py`)
`load_backend_from_settings(settings)` called in the lifespan context manager; logs the active provider name on startup.

### requirements.txt
`PyJWT~=2.8` → `PyJWT[crypto]~=2.8` (adds `cryptography` dep for RS256/ES256 JWKS decode). Added `ldap3~=2.9`.

### Doc correction
Removed incorrect "No output sanitization deferred to Phase 12" claim from `TLDR.md` and `PROJECT_STATUS.md`. Output sanitization (`sanitize_output()`) was fully implemented in Phase 9.

### New Keychain items (documented)
`legionforge_oidc_client_secret`, `legionforge_github_client_secret`, `legionforge_ldap_bind_password`.

**Test delta:** 430 → 443 smoke tests (+13 Phase 12 tests).

---

## Phase 13 — Kerberos Full Implementation, Redis-Backed State, Multi-Datacenter ✅ COMPLETE

**Completed:** 2026-02-28 — 453/453 smoke tests passing (+10 Phase 13 tests).

**Goal:** Close the last three Phase 12 deferred items:
1. **Kerberos** — Replace `NotImplementedError` scaffold with real GSSAPI Negotiate flow
   (graceful `None` fallback when `gssapi` package not installed; no crash).
2. **Redis-backed state** — Optional Redis layer for stream tokens and rate-limiter counters,
   activated by `settings.gateway.redis_url`; transparent DB fallback when empty.
3. **Multi-datacenter** — `docker-compose.multi-instance.yml` (2 gateway replicas + Redis +
   Nginx); update `docs/SCALING.md` with concrete Redis integration steps.

### 13.1 Kerberos Real Implementation (`src/gateway/backends/kerberos.py`)

**Before (Phase 12 scaffold):** `authenticate()` always raises `NotImplementedError`.
**After (Phase 13):** Real GSSAPI accept-security-context flow with graceful fallback.

```
Flow (when gssapi installed + KDC configured):
  1. Decode base64 SPNEGO token from the Negotiate credential.
  2. Acquire server credentials from the keytab file
     (path: settings.gateway.kerberos.keytab_path, default /etc/legionforge/http.keytab).
  3. Call gssapi.SecurityContext.step(token) to verify the SPNEGO exchange.
  4. Extract client principal name (e.g. alice@EXAMPLE.COM).
  5. Strip realm → username = "alice".
  6. Upsert gateway_users row with api_key_hash='[KERBEROS-NO-KEY]' sentinel.
  7. Return {user_id: "kerberos:{principal}", username, daily_token_limit}.

Graceful fallback (when gssapi not installed):
  - Log a WARNING on first call.
  - Return None (not raise) → caller gets 401, not 500.
  - Smoke tests verify this path without a real KDC.
```

`KerberosConfig` added to `GatewayConfig`:
```yaml
gateway:
  kerberos:
    keytab_path: /etc/legionforge/http.keytab  # service keytab
    service_name: HTTP                          # GSSAPI service name
    realm: ""                                  # e.g. EXAMPLE.COM — empty = KDC default
```

### 13.2 Redis-Backed Stream Token Store (`src/gateway/state.py`)

`src/gateway/state.py` provides an optional Redis layer for the three operations that
need to be globally consistent across multiple gateway instances:

| Operation | DB path (current) | Redis path (new, opt-in) |
|---|---|---|
| `create_stream_token` | `INSERT INTO stream_tokens` | `SETEX stream_token:{tok} 1800 "{task_id}:{user_id}"` |
| `resolve_stream_token` | `SELECT … WHERE expires_at > NOW()` | `GET stream_token:{tok}` |
| `delete_stream_token` | `DELETE FROM stream_tokens` | `DEL stream_token:{tok}` |

Activation: set `gateway.redis_url: redis://localhost:6379/0` in the hardware YAML
(or `REDIS_URL` env var). When empty, the existing DB path is used unchanged — no
performance impact for single-instance deployments.

`GatewayConfig` additions:
```python
redis_url: str = ""      # empty = DB mode; "redis://..." = Redis mode
```

### 13.3 Multi-Datacenter Deployment (`docker-compose.multi-instance.yml`)

```
┌─────────┐    ┌─────────┐
│Gateway 1│    │Gateway 2│   ← Two replicas behind Nginx
└────┬────┘    └────┬────┘
     │              │
     └──────┬───────┘
            ▼
      ┌──────────┐
      │  Redis   │  ← Shared stream tokens + rate counters
      └────┬─────┘
           │
     ┌─────▼──────┐
     │ PostgreSQL │  ← Tasks, users, audit, checkpoints
     └────────────┘
```

`SCALING.md` updated with:
- Redis install + connection string
- How to set `redis_url` in the hardware profile
- Load balancer sticky-session note (not needed — stream tokens are Redis-global)
- Health check probe for Redis in lifespan

### 13.4 New/Modified Files

| File | Change |
|---|---|
| `src/gateway/backends/kerberos.py` | Real GSSAPI flow + graceful fallback |
| `src/gateway/state.py` | Redis stream token store (opt-in) |
| `src/gateway/auth.py` | Use `state.create/resolve/delete_stream_token` |
| `src/gateway/app.py` | Redis connect/close in lifespan |
| `config/settings.py` | `KerberosConfig`, `redis_url` in `GatewayConfig` |
| `config/hardware_profiles/mac_m4_mini_16gb.yaml` | `kerberos:` + `redis_url:` sections |
| `requirements.txt` | `redis[asyncio]~=5.0`, `fakeredis~=2.23` |
| `docker-compose.multi-instance.yml` | 2-replica example |
| `docs/SCALING.md` | Redis setup guide |
| `tests/test_smoke.py` | +10 tests → 453 |

### 13.5 New Keychain Items

| Service | Purpose |
|---|---|
| `legionforge_kerberos_keytab_path` | Path to the HTTP service keytab file |

### 13.6 Smoke Tests (+10 → 453)

```
test_p13_gateway_state_importable
test_p13_redis_stream_token_create_resolve_delete   (fakeredis)
test_p13_redis_stream_token_expired_returns_none    (fakeredis)
test_p13_db_stream_token_store_importable
test_p13_kerberos_backend_graceful_when_no_gssapi
test_p13_kerberos_backend_returns_none_not_raises
test_p13_kerberos_config_in_gateway_config
test_p13_gateway_config_has_redis_url
test_p13_multi_instance_compose_exists
test_p13_scaling_md_mentions_redis
```

**Test delta:** 443 → 453 smoke tests (+10 Phase 13 tests).

---

## Phase 14 — Redis Budget Counters, Request Trace IDs, Prometheus Metrics ✅ Complete

**Goal:**
1. **Rate-limiter Redis counters** — Per-user daily budget checks via Redis `INCRBY` with daily TTL key; eliminates per-instance counter drift under concurrent load across replicas.
2. **Kerberos integration test skeleton** — `tests/test_kerberos_integration.py` with `pytest.skip` unless `KERBEROS_TEST_KDC` env var is set; mirrors the Ollama test pattern.
3. **Advanced observability** — Prometheus-format `/metrics` endpoint on gateway (no new deps — inline formatter), Redis health in operator `/status`, `X-Request-ID` middleware propagated on all gateway responses.

### 14.1 Redis Budget Counters (`src/gateway/state.py`)

New functions added alongside the stream token operations:

```
redis_budget_check_and_reserve(user_id, estimated_tokens, daily_limit)
  → INCRBY lf:budget:{user_id}:{YYYY-MM-DD} estimated_tokens
  → EXPIREAT to tomorrow midnight UTC if TTL not yet set
  → if new_val > daily_limit: DECRBY + raise RuntimeError

redis_budget_release(user_id, estimated_tokens, actual_tokens)
  → net INCRBY/DECRBY to correct estimated → actual on task completion

redis_budget_get(user_id) → int
  → GET lf:budget:{user_id}:{today}; 0 if not set
```

`per_user_budget_check()` in `rate_limiter.py` delegates to Redis when `state.redis_mode()` is True, otherwise falls through to the existing 2-read DB path.

### 14.2 Gateway Metrics (`src/gateway/metrics.py` + `src/gateway/middleware.py`)

**`src/gateway/metrics.py`** — thread-safe counter/gauge store with inline Prometheus text
formatter (no `prometheus_client` dependency). Exposes:
- `legionforge_http_requests_total{method, path, status}`
- `legionforge_tasks_submitted_total`
- `legionforge_redis_connected{instance}` (gauge 0/1)
- `legionforge_uptime_seconds` (gauge)

**`src/gateway/middleware.py`** — Two Starlette middlewares:
- `RequestIDMiddleware` — reads `X-Request-ID` header; generates UUID4 if absent; echoes back on all responses
- `MetricsMiddleware` — increments request counter per method/path/status on each request

Both wired into `src/gateway/app.py`. New endpoint: `GET /metrics` returns Prometheus text.

### 14.3 Redis Health in `/status` (`src/health.py`)

Health server's `/status` endpoint gets a `redis` component:
```json
{
  "components": {
    "redis": {"status": "ok", "url": "redis://localhost:6379/0"},
    ...
  }
}
```
Omitted (not an error) when `gateway.redis_url` is empty.

### 14.4 Kerberos Integration Test Skeleton

`tests/test_kerberos_integration.py` — skipped unless `KERBEROS_TEST_KDC=1`:
- `test_kerberos_backend_init_with_keytab` — initializes `KerberosBackend` with keytab path
- `test_kerberos_backend_wrong_token_returns_none` — malformed token → None
- `test_kerberos_spnego_accept_context` — real GSSAPI accept (needs KDC)
- `test_kerberos_user_provisioned_on_first_auth` — DB row created after successful auth

### 14.5 Test Delta

```
test_p14_redis_budget_check_and_reserve_ok
test_p14_redis_budget_exceeds_limit_raises
test_p14_redis_budget_release_corrects_count
test_p14_redis_budget_key_format
test_p14_gateway_metrics_module_importable
test_p14_prometheus_text_contains_counter_type
test_p14_prometheus_text_contains_gauge_type
test_p14_gateway_middleware_importable
test_p14_request_id_middleware_generates_uuid
test_p14_kerberos_integration_skeleton_exists
```

**Test delta:** 453 → 463 smoke tests (+10 Phase 14 tests).

---

## Phase 15 — Polished Web UI ✅ Complete

**Goal:** Replace the minimal single-page demo with a fully usable web interface.
No framework. Single HTML file. All vanilla JS.

### 15.1 Features

| Feature | Detail |
|---|---|
| **Persistent API key** | Stored in `localStorage`; show/hide toggle; clear button |
| **Agent type selector** | Dropdown: `orchestrator` / `researcher` / `base_agent` |
| **Cancel button** | Appears while task is running; calls `DELETE /tasks/{id}` |
| **Tool call blocks** | `tool_start` / `tool_end` rendered as styled labelled blocks |
| **Status bar** | Live elapsed timer during run; token estimate + final status on complete |
| **Task result fetch** | `GET /tasks/{id}` called on complete to display full structured result |
| **Session history** | Last 20 tasks persisted in `localStorage`; sidebar with status badges; click to restore output |
| **Copy output** | One-click copy of the full output to clipboard |
| **Keyboard shortcut** | `Ctrl+Enter` / `Cmd+Enter` submits the task |
| **Auto-resize textarea** | Grows with content; max 300 px before scrolling |
| **Heartbeat indicator** | Connection dot pulses while SSE is live |
| **Stream reconnect** | On unexpected SSE disconnect, retries once with same stream token |

### 15.2 SSE Event Mapping

| SSE event | UI action |
|---|---|
| `task_start` | Status bar → "Running…"; start elapsed timer; show Cancel |
| `chain_start` | Append node label (dim text) |
| `token` | Append delta to output (fast inline streaming) |
| `tool_start` | Open tool block: `▶ tool_name` |
| `tool_end` | Close tool block: `✓ tool_name` |
| `task_complete` | Stop timer; fetch `GET /tasks/{id}` for token count; status → "✓ Complete"; hide Cancel; save to history |
| `task_error` | Status → "✗ Error: …"; hide Cancel |
| `task_cancelled` | Status → "⊘ Cancelled"; hide Cancel |
| `heartbeat` | Pulse the connection dot |

### 15.3 Layout

```
┌─ LegionForge ─────────────────────── ● ─┐
│                                          │
│  API Key [••••••••] [Show] [✕]          │
│  Agent   [Orchestrator ▾]               │
│                                          │
│  ┌──────────── Task ───────────────────┐ │
│  │ (auto-resize textarea)              │ │
│  └─────────────────────────────────────┘ │
│  [▶ Submit  ⌘↵]  [✕ Cancel]  [Clear]   │
│                                          │
├─ Output ─────────────────────── [Copy] ─┤
│  ● Running…  task abc-123       3.2s    │
│  ──────────────────────────────────────  │
│  [node: researcher]                      │
│  ▶ web_search ──────────────────────── ✓│
│  Based on my research…                   │
│  ✓ Complete · 1,247 tokens · 8.3s       │
│                                          │
├─ History (20) ──────────────────────── ─┤
│  ✓ abc-123  researcher  "Research AI…"  │
│  ✗ def-456  orchestrator "Write code…"  │
└──────────────────────────────────────────┘
```

### 15.4 Test Delta

```
test_p15_ui_file_exists
test_p15_ui_has_api_key_input
test_p15_ui_has_agent_type_selector
test_p15_ui_has_cancel_function
test_p15_ui_persists_api_key_in_localstorage
test_p15_ui_has_history_rendering
test_p15_ui_has_keyboard_shortcut
test_p15_ui_has_copy_function
```

**Test delta:** 463 → 471 smoke tests (+8 Phase 15 tests).

---

## Phase 16 — Channel Connectors ✅ Complete

**Goal:** Add Telegram and Slack connector bots (matching the Discord connector pattern)
and a generic inbound/outbound webhook connector so any HTTP-capable tool (GitHub webhooks,
Zapier, Make/Integromat, IFTTT, cron jobs) can submit tasks to the gateway and receive
results via callback POST.

**Test count:** 484/484 smoke tests (+13 from Phase 15 baseline of 471).

---

### Scope

| Deliverable | File | Notes |
|---|---|---|
| Shared connector helpers | `src/connectors/base.py` | `_load_secret()` + `_consume_sse()` used by all connectors |
| Telegram connector | `src/connectors/telegram.py` | `python-telegram-bot` polling; mirrors Discord pattern |
| Slack connector | `src/connectors/slack.py` | `slack-bolt` Socket Mode; no public URL required |
| Webhook connector | `src/connectors/webhook.py` | FastAPI :8081; inbound task POST → SSE → callback POST; HMAC signing |
| ConnectorsConfig settings | `config/settings.py` | `TelegramConfig`, `SlackConfig`, `WebhookConfig`, `ConnectorsConfig` |
| Hardware profile | `config/hardware_profiles/mac_m4_mini_16gb.yaml` | `connectors:` section |
| Requirements | `requirements.txt` | `python-telegram-bot~=21.0`, `slack-bolt~=1.18` |
| Makefile targets | `Makefile` | `telegram-start`, `slack-start`, `webhook-start` |
| Smoke tests | `tests/test_smoke.py` | +13 → 484 total |

---

### Design

#### Shared helpers (`src/connectors/base.py`)

All three connectors share identical secret-loading and SSE-parsing logic, extracted
from `discord.py` into a shared module:

```
_load_secret(keychain_service, env_var) → str
_consume_sse(client, stream_url, stream_token, gateway_url) → AsyncGenerator[dict]
```

#### Telegram connector (`src/connectors/telegram.py`)

```
Flow:
  Telegram message starting with PREFIX (default "/")
    → POST /tasks (gateway, as telegram-bot user)
    → subscribe SSE stream
    → edit reply message every MAX_EDIT_INTERVAL seconds
    → final edit on task_complete / task_error

Keychain:
  legionforge_telegram_token    — Bot token from BotFather
  legionforge_telegram_api_key  — Gateway Bearer API key

Env overrides:
  TELEGRAM_GATEWAY_URL, TELEGRAM_ALLOWED_CHATS, TELEGRAM_PREFIX,
  TELEGRAM_MAX_EDIT_INTERVAL, TELEGRAM_AGENT_TYPE

Message limit: 4096 chars (Telegram API limit)
```

#### Slack connector (`src/connectors/slack.py`)

```
Flow:
  Slack message/app_mention starting with PREFIX (default "!")
    → POST /tasks (gateway, as slack-bot user)
    → subscribe SSE stream
    → update Slack message every MAX_EDIT_INTERVAL seconds
    → final update on task_complete / task_error

Socket Mode: no public URL needed; connects via Slack WebSocket API.
Requires: App-level token (xapp-...) with connections:write scope.

Keychain:
  legionforge_slack_bot_token  — Bot token (xoxb-...)
  legionforge_slack_app_token  — App-level token for Socket Mode (xapp-...)
  legionforge_slack_api_key    — Gateway Bearer API key

Env overrides:
  SLACK_GATEWAY_URL, SLACK_ALLOWED_CHANNELS, SLACK_PREFIX,
  SLACK_MAX_EDIT_INTERVAL, SLACK_AGENT_TYPE
```

#### Webhook connector (`src/connectors/webhook.py`)

```
Serves FastAPI on :8081 (WEBHOOK_PORT).

POST /inbound
  Body: {task: str, callback_url: str, agent_type?: str, secret?: str}
  1. Verify HMAC-SHA256 X-Hub-Signature-256 header (when inbound_secret configured)
  2. Submit task to gateway (as webhook-bot user)
  3. Stream SSE to completion
  4. POST {task_id, status, result, elapsed_seconds} to callback_url
  Returns 202 immediately with {task_id, message: "queued"}

GET /health
  Returns {status: "ok", gateway_url: "..."}

Keychain:
  legionforge_webhook_api_key       — Gateway Bearer API key
  legionforge_webhook_inbound_secret — HMAC secret for inbound verification (optional)
```

---

### New Keychain Items

| Service | Purpose |
|---|---|
| `legionforge_telegram_token` | Telegram bot token from BotFather |
| `legionforge_telegram_api_key` | Gateway Bearer API key for telegram-bot user |
| `legionforge_slack_bot_token` | Slack bot token (xoxb-...) |
| `legionforge_slack_app_token` | Slack app-level token for Socket Mode (xapp-...) |
| `legionforge_slack_api_key` | Gateway Bearer API key for slack-bot user |
| `legionforge_webhook_api_key` | Gateway Bearer API key for webhook-bot user |
| `legionforge_webhook_inbound_secret` | HMAC-SHA256 secret for inbound webhook verification |

---

### Smoke Tests (+13 → 484)

```
test_p16_connector_base_importable
test_p16_telegram_connector_importable
test_p16_slack_connector_importable
test_p16_webhook_connector_importable
test_p16_load_secret_raises_on_missing_keychain_and_env
test_p16_consume_sse_parses_token_event
test_p16_consume_sse_parses_task_complete_event
test_p16_consume_sse_parses_task_error_event
test_p16_webhook_hmac_verify_valid_signature
test_p16_webhook_hmac_verify_rejects_bad_signature
test_p16_webhook_inbound_missing_callback_url_rejected
test_p16_settings_has_connectors_section
test_p16_hardware_profile_has_connectors_section
```

---

## v1.0.1 — Post-Release Patches (PRs #36–#42, 2026-03-01)

No new phases. Bug fixes and operational completions only.

**Final test counts: 492/492 smoke tests · 38/38 integration tests · 5/5 Kerberos live-KDC tests.**

| Fix | PR | Impact |
|---|---|---|
| pytest.ini session-scoped event loop; 3 Ollama integration tests fully implemented | #36 | 38/38 integration tests (was 35/38) |
| `MODEL_INTEGRITY_STRICT` env var override; `/status` model integrity section | #38 | +8 smoke tests → 492 total |
| `resume_run_config()` helper — loop protection survives checkpoint resume | #39 | +3 smoke tests → 492 total |
| Kerberos integration test DB API fixed (psycopg, `%s`, `get_pool()`) | #40 | Tests 4-5 no longer fail on wrong DB API |
| MIT Kerberos 1.22.2 KDC live; `gssapi` built vs MIT; `make test-kerberos` | #41 | 3/5 Kerberos tests pass live |
| `gateway_users.user_id TEXT`; `api_key_hash UNIQUE` dropped; sentinel standardised | #42 | 5/5 Kerberos tests pass (DB provisioning fixed) |

---

## Phases 17–59 — Task Platform & Conversation Intelligence (2026-03-01 → 2026-03-03)

Added as compact addendum. See git log for full details.

| Phase | PR | Feature | New Smoke Tests | Running Total |
|---|---|---|---|---|
| 17 | #43 | Researcher Agent (LangGraph web-search + web-fetch) | +24 | 516 |
| 18 | #44 | UI Tests + TestLab Admin Platform (Playwright, :8090) | +9 | 525 |
| 19 | #45 | Attack Test Suite + Dockerised Ollama (104 testlab tests) | +9 | 534 |
| 20 | #48 | Multi-Machine Ollama Cluster (health poll, routing, failover) | +11 | 545 |
| 21 | #49 | Persistent Agent Memory (pgvector recall/store) | +10 | 555 |
| 22 | #50 | Document Ingestion Pipeline (chunk, PDF, HTML strip) | +10 | 565 |
| 23 | #51 | Scheduled Tasks (cron + @every shortcuts, croniter) | +11 | 576 |
| 24 | #52 | Admin API (user CRUD, quota, promote, stats) | +10 | 586 |
| 25 | #53 | Audit Log & Observability API (threats, metrics, tools) | +8 | 594 |
| 26 | #54 | Task Result Webhooks (callback_url, HMAC-SHA256) | +6 | 600 |
| 27 | #55 | Task Pipelines (pipelines+pipeline_runs, 8 endpoints) | +8 | 608 |
| 28 | #56 | Task Priority Queue + Batch Submission | +5 | 613 |
| 29 | #57 | Task Result Cache (content_hash, use_cache, cache_ttl) | +5 | 618 |
| 30 | #58 | Pipeline SSE Progress Streaming | +4 | 622 |
| 31 | #59 | Task Tags & Search (tags TEXT[], q+tags filters) | +5 | 627 |
| 32 | #60 | Task Notes (task_notes table, POST/GET/DELETE) | +5 | 632 |
| 33 | #61 | Task Retry API (POST /tasks/{id}/retry) | +4 | 636 |
| 34 | #62 | Task Dependencies (depends_on, fail propagation) | +5 | 641 |
| 35 | #63 | Worker Concurrency (WORKER_CONCURRENCY, SKIP LOCKED) | +4 | 645 |
| 36 | #64 | Task Cost Estimation (dry_run, /estimate) | +5 | 650 |
| 37 | #65 | Agent Capabilities Registry (GET /agents) | +4 | 654 |
| 38 | #66 | Task Export API (GET /tasks/export?format=json\|csv) | +4 | 658 |
| 39 | #67 | Task Timeline (task_events, GET /tasks/{id}/timeline) | +5 | 663 |
| 40 | #68 | Task Labels (labels TEXT[], GIN index, PUT /labels) | +5 | 668 |
| 41–42 | #69–70 | Ollama cluster UI tab; pipeline SSE improvements | +8 | 676 |
| 43 | #71 | Task Bulk Operations (bulk-cancel, bulk-delete) | +5 | 681 |
| 44 | #72 | Task Stats & Analytics (GET /tasks/stats) | +5 | 686 |
| 45 | #73 | Rate Limit Dashboard (GET /admin/rate-limits) | +4 | 690 |
| 46 | #74 | Task Watchdog Heartbeat (reap stuck 'running' tasks) | +4 | 694 |
| 47 | #75 | Keyset Pagination (cursor-based, GET /tasks) | +5 | 699 |
| 48 | #76 | Webhook Registry (multi-subscribe, HMAC-SHA256 delivery) | +6 | 705 |
| 49 | #77 | Task Attachments (text blobs, GET/POST/DELETE) | +5 | 710 |
| 50 | #78 | Task Templates (reusable, GET/POST/PUT/DELETE) | +5 | 715 |
| 51 | #79 | Task Sharing (read-only share tokens) | +5 | 720 |
| 52 | #80 | User Preferences (per-user task defaults) | +5 | 725 |
| 53 | #81 | Usage History (per-day token breakdown, GET /usage/history) | +5 | 730 |
| 54 | #82 | Conversation Sessions (LangGraph thread persistence) | +6 | 736 |
| 55 | #85 | Tool Accuracy & Anti-Hallucination Test Suite (29 tests) | +29 | 765 |
| 56 | #95 | Configurable Search Providers (ddg/tavily/brave/exa/etc.) | +9 | 774 |
| — | #91–94 | Bug fixes: SSE fallback, tool hash mismatch, UI, startup | +18 | 792 |
| — | #96–97 | Gateway startup fix (trust auth, Keychain lookup) | +0 | 792 |
| 57 | #98 | Conversation Session UI Integration (picker, JS, POST) | +10 | 828 (after +36 tool accuracy) |
| — | #90 | Bug fixes: task failures, DB init, web fetch, TestLab LAN | +0 | 828 |
| 58 | #99 | Model Selection per Task (ContextVar, Fast/Balanced/Powerful) | +8 | 836 |
| 59 | #100 | Task Rating & Feedback (thumbs up/down, /annotate endpoints) | +10 | 846 |
| 60 | #101 | Documentation Update (PHASE_PLAN.md addendum Phases 17–59) | +0 | 846 |
| 61 | #102 | Prompt Templates UI (save/load/delete backed by Phase 50 API) | +10 | 856 |
| 62 | #103 | Task Search UI (search card, 400ms debounce, GET /tasks?q=) | +6 | 862 |
| 63 | #104 | Usage Summary in Web UI (today's token count in footer) | +5 | 867 |
| 64 | #105 | Markdown Rendering in Output (marked.js, renderMarkdown, appendResult) | +7 | 874 |
| 65-67 | #106 | Copy Result, Keyboard Shortcuts, Syntax Highlighting | +12 | 886 |
| 68 | #107 | Task Pinning / Starring (toggleStar, starred label, sort) | +6 | 892 |
| 69 | #108 | Streaming Token Output + pytest-timeout fix | +8 | 900 |
| 70 | #109 | File Attachment on Tasks (FileReader, attachment_text, inject) | +8 | 908 |
| 71 | #110 | Agent Self-Verification Loop (verify_node, MAX_VERIFY_ROUNDS=1) | +6 | 914 |
| — | #111 | fix: tool_accuracy tests (DDG kwargs); PHASE_PLAN 64-71 docs | +2 | 916 |
| — | #112 | perf: bounded _terminal_events OrderedDict FIFO (2000 entries) | +2 | 916 |
| 72 | #113 | Light/Dark Mode Toggle (CSS vars, 🌙/☀️, localStorage) | +6 | 922 |
| 73 | #114 | Task Export to Markdown (GET /tasks/export?format=markdown) | +5 | 927 |
| 74 | #115 | Browser Notifications (🔕/🔔, notifyTaskComplete, tag dedup) | +4 | 931 |
| 75 | #117 | Scheduled Tasks UI (Schedules card, CRUD, loadSchedules/createSchedule/deleteSchedule) | +6 | 937 |
| 76 | #118 | Task Notes UI (📝 Notes button, toggleNotesPanel/loadNotes/addNote/deleteNote) | +6 | 943 |
| 77 | #118 | Task Share Link (🔗 Share button, shareTask(), inline copy URL) | +5 | 948 |
| 78 | #119 | Task Timeline UI (⏱ Timeline button, toggleTimeline(), tl-event/dot/type/ts CSS) | +5 | 953 |
| 79 | #120 | Pipeline Runner UI (Pipelines card, loadPipelines/runPipeline/deletePipeline) | +6 | 959 |
| 80 | #121 | Task Retry Button (↩ Retry on error/cancel, retryTask(), POST /tasks/{id}/retry) | +4 | 963 |
| 81 | #121 | Cost Estimator UI (≈ Estimate button, estimateCost(), dry_run:true, token+cost display) | +4 | 967 |
| 82 | #122 | Task Stats Card (↻ refresh, GET /tasks/stats, stats-grid with total+status+tokens) | +4 | 971 |
| 83 | #122 | Agents Directory Card (GET /agents, agent-type-badge+desc, auto-load in init) | +5 | 976 |
| 84 | #123 | Document Ingestor UI (ingestor-card, ingestDocument(), POST /documents/ingest, chunk count) | +4 | 980 |
| 85 | #123 | Memory Search UI (memory-search-card, searchMemory(), POST /memory/search, similarity%) | +4 | 984 |
| 86 | #124 | Security Threats Summary (admin, threats-card, loadThreats, GET /admin/threats/summary) | +4 | 988 |
| 87 | #124 | Tool Registry Admin UI (admin, tool-registry-card, loadTools/revokeOrApproveTool) | +5 | 993 |
| 88 | #125 | Health Metrics Dashboard (admin, health-metrics-card, loadHealthMetrics, CPU/RAM/Disk grid) | +4 | 997 |
| 89 | #125 | User Management Admin UI (admin, user-mgmt-card, loadUsers/createUser, POST /admin/users) | +5 | 1002 |
| 90 | #126 | Audit Log Viewer (admin, audit-log-card, loadAuditLog, GET /admin/audit, event_type+ts) | +4 | 1006 |
| 91 | #126 | Keyboard Shortcuts Help Modal (? button, toggleHelpModal, #help-modal overlay, Escape closes) | +5 | 1011 |
| 92 | #127 | Webhook Management UI (webhooks-card, loadWebhooks/registerWebhook/deleteWebhook, POST/DELETE /webhooks) | +4 | 1015 |
| 93 | #127 | User Preferences UI (preferences-card, loadPreferences/savePreference/deletePreference, /auth/preferences) | +4 | 1019 |
| 94 | #127 | Admin Annotations Viewer (annotations-card, loadAnnotations, /admin/annotations, 👍/👎 rendering) | +4 | 1023 |
| 95 | #128 | Who Am I Identity Badge (identity-card, loadIdentity, GET /auth/me, username/role/quota) | +4 | 1027 |
| 96 | #128 | Pipeline Run History (run-history-card, loadPipelineRuns, GET /pipelines/{id}/runs) | +3 | 1030 |
| 97 | #128 | Audit Chain Integrity Verify (audit-verify-card, verifyAuditChain, GET /admin/audit/verify, ✓/✗ display) | +4 | 1034 |
| 98 | #128 | Task Attachments Viewer (attachments-card, loadAttachments, GET /tasks/{id}/attachments) | +3 | 1037 |
| 99 | #129 | API Key Rotation UI (rotate-key-card, rotateApiKey, POST /auth/rotate-key, auto-fill input) | +4 | 1041 |
| 100 | #129 | Batch Task Submission UI (batch-card, submitBatch, POST /tasks/batch, ≤20 task guard) | +4 | 1045 |
| 101 | #129 | Session Tasks Browser (session-tasks-card, loadSessionTasks, GET /sessions/{id}/tasks) | +4 | 1049 |
| 102 | #130 | Bulk Task Operations (bulk-ops-card, bulkCancel/Delete/Tag, /tasks/bulk/{cancel,delete,tag}) | +5 | 1054 |
| 104 | #130 | Task Share Links Viewer (shares-list-card, loadShares, GET /tasks/{id}/shares) | +3 | 1057 |
| 105 | #130 | Document List UI (doc-list-card, loadDocuments/deleteDocument, GET /documents) | +4 | 1061 |
| 106 | #131 | Single Task Delete Button (🗑 in rating bar, deleteTask, DELETE /tasks/{id}) | +3 | 1064 |
| 107 | #131 | Task Tags Editor (setTaskTags, PUT /tasks/{id}/tags, comma-separated input) | +2 | 1066 |
| 108 | #131 | Memory Stats & Clear (loadMemoryStats, clearMemory, GET /memory/stats, DELETE /memory) | +4 | 1070 |
| 109 | #131 | Export CSV/JSON (exportTasksCsv/Json, ↓ csv/json buttons, /tasks/export?format=) | +4 | 1074 |

| 110 | #132 | Task Detail Viewer (task-detail-card, loadTaskDetail, GET /tasks/{id}, td-field/td-label/td-value rendering) | +4 | 1078 |
| 111 | #132 | A2A / MCP Info Card (a2a-info-card, loadAgentCard, GET /.well-known/agent.json, capabilities display) | +3 | 1081 |
| 112 | #132 | Task Labels Editor (task-labels-card, loadTaskLabels/applyLabel, PUT /tasks/{id}/labels, label-pill CSS) | +4 | 1085 |
| 113 | #132 | File Attachment Upload (upload-attach-card, uploadAttachment, file.text(), POST /tasks/{id}/attachments) | +4 | 1089 |

| 114 | #133 | MCP Tools Viewer (mcp-tools-card, loadMcpTools, GET /mcp/tools, mcp-row CSS, status coloring) | +4 | 1093 |
| 115 | #133 | Agent Details Viewer (agent-detail-card, loadAgentDetail, GET /agents/{type}, type selector) | +4 | 1097 |
| 116 | #133 | Memory Manual Ingest (memory-ingest-card, ingestMemory, POST /memory/ingest, textarea input) | +3 | 1100 |
| 117 | #133 | Pipeline Create UI (pipeline-create-card, createPipeline, POST /pipelines, JSON steps textarea) | +4 | 1104 |

| 118 | #134 | Template Run UI (template-run-card, runTemplate, POST /templates/{id}/run; loadTemplates populates run-sel) | +4 | 1108 |
| 119 | #134 | Admin Threat Events (threat-events-card, loadThreatEvents, GET /admin/threats, red type + timestamp) | +3 | 1111 |
| 120 | #134 | Admin User Actions (admin-user-actions-card, adminDeactivateUser/adminSetQuota, DELETE+PUT /admin/users) | +4 | 1115 |
| 121 | #134 | Schedule Edit UI (schedule-edit-card, editSchedule, PUT /schedules/{id}, cron+name+enabled) | +4 | 1119 |

| 122 | #135 | Pipeline Run Detail (pipeline-run-detail-card, loadPipelineRunDetail, GET /pipelines/runs/{id}) | +3 | 1122 |
| 123 | #135 | A2A Task Submit (a2a-submit-card, submitA2ATask, POST /a2a/tasks, A2A message format) | +4 | 1126 |
| 124 | #135 | Admin Privilege Toggle (admin-toggle-card, toggleUserAdmin, PUT /admin/users/{u}/admin) | +3 | 1129 |
| 125 | #135 | Admin Schedules Viewer (admin-schedules-card, loadAdminSchedules, GET /admin/schedules) | +3 | 1132 |

| 126 | #136 | Pipeline Edit (pipeline-edit-card, savePipelineEdit, PUT /pipelines/{id}, loadPipelineForEdit) | +4 | 1136 |
| 127 | #136 | Pipeline Detail Viewer (pipeline-detail-card, loadPipelineDetail, GET /pipelines/{id}, step chain) | +3 | 1139 |
| 128 | #136 | Session Detail Viewer (session-detail-card, loadSessionDetail, GET /sessions/{id}, detail sel) | +4 | 1143 |
| 129 | #136 | A2A Task Status Check (a2a-status-card, checkA2ATask, GET /a2a/tasks/{id}, artifact result) | +3 | 1146 |

| 130 | #137 | Usage History Detail (usage-history-card, loadUsageHistory, /usage/history?days=N, per-day table) | +3 | 1149 |
| 131 | #137 | Task Tag Filter (task-tag-filter-card, loadTasksByTag, GET /tasks?tags[]=tag, matching list) | +3 | 1152 |
| 132 | #137 | Admin Metrics History (metrics-history-card, loadMetricsHistory, /admin/metrics/history, CPU/RAM/Disk) | +3 | 1155 |
| 133 | #137 | Shared Task Viewer (shared-task-viewer-card, viewSharedTask, GET /shared/{token}, no auth) | +3 | 1158 |

| 134 | #138 | Attachment Content Viewer (attachment-viewer-card, viewAttachment/deleteAttachment, GET/DELETE /tasks/{id}/attachments/{id}) | +5 | 1163 |
| 135 | #138 | Task Status Filter (status-filter-card, loadTasksByStatus, GET /tasks?status=X, result list) | +3 | 1166 |
| 136 | #138 | Admin User Profile (admin-user-profile-card, loadAdminUserProfile, GET /admin/users/{u}, td-field layout) | +3 | 1169 |
| 137 | #138 | Task Note Quick-Add (note-quick-add-card, addQuickNote, POST /tasks/{id}/notes, note_text payload) | +3 | 1172 |

| 138 | #139 | Admin System Stats (admin-stats-card, loadAdminStats, GET /admin/stats, td-field grid of all stats) | +3 | 1175 |
| 139 | #139 | Share Revoke (share-revoke-card, revokeShare, DELETE /tasks/{id}/shares/{token}, confirm guard) | +3 | 1178 |
| 140 | #139 | Pipeline Runs List (pipeline-runs-card, loadPipelineRuns, GET /pipelines/{id}/runs, runs-sel populated in loadPipelines) | +4 | 1182 |
| 141 | #139 | Task Annotation Viewer (task-annotation-card, loadTaskAnnotation, GET /tasks/{id}/annotation, rating + comment) | +3 | 1185 |

| 142 | #140 | Schedule Detail Viewer (schedule-detail-card, loadScheduleDetail, GET /schedules/{id}, cron/next_run fields) | +3 | 1188 |
| 143 | #140 | Template Detail Viewer (template-detail-card, loadTemplateDetail, GET /templates/{id}, template-detail-sel in loadTemplates) | +4 | 1192 |
| 144 | #140 | Task Label Filter (label-filter-card, loadTasksByLabel, GET /tasks?label=X, 4 preset labels) | +3 | 1195 |
| 145 | #140 | Task Notes Browser (notes-browser-card, browseTaskNotes, GET /tasks/{id}/notes, standalone viewer) | +3 | 1198 |

| 146 | #141 | Provider Usage Breakdown (provider-usage-card, loadProviderUsage, GET /usage/me, per-provider tokens) | +3 | 1201 |
| 147 | #141 | Task Timeline Standalone (task-timeline-card, loadTaskTimeline, GET /tasks/{id}/timeline, event-type rows) | +3 | 1204 |
| 148 | #141 | Task Attachments List (attachments-list-card, loadTaskAttachmentsList, GET /tasks/{id}/attachments) | +3 | 1207 |
| 149 | #141 | Audit Log Event Filter (audit-filter-card, loadAuditFiltered, GET /admin/audit?event_type=X) | +3 | 1210 |

| 150 | #142 | Task Quick Clone (task-clone-card, cloneTask, GET /tasks/{id} → fill textarea + agent_type) | +3 | 1213 |
| 151 | #142 | Gateway Health Card (gateway-health-card, loadGatewayHealth, GET /health, status color indicator) | +3 | 1216 |
| 152 | #142 | Recent Tasks Live Refresh (recent-tasks-card, loadRecentTasks, GET /tasks?limit=5, status-colored rows) | +3 | 1219 |
| 153 | #142 | Tag Cloud Explorer (tag-cloud-card, loadTagCloud, GET /tasks?limit=100, tag aggregation pill cloud) | +3 | 1222 |

**Current state:** 1222/1222 smoke · 38/38 integration · 5/5 Kerberos · 40/40 UI · 104/104 TestLab · 29/29 tool accuracy
