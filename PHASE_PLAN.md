# PHASE_PLAN.md
# LegionForge — Phased Roadmap

**Version:** 4.0.0
**Last updated:** 2026-02-25
**Status:** Phase 0 ✅ Complete | Phase 1 ✅ Complete | Phase 2 ✅ Complete | Phase 3 ✅ Complete | Phase 4 ✅ Complete

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
Phase 0  ✅  Infrastructure                    → DONE
Phase 1  ✅  First Agent + Security Foundations → DONE
Phase 2  ✅  Containerization + Guardian        → DONE
Phase 3  ✅  ACLs + Task Tokens + Sub-Agents    → DONE
Phase 4  ✅  Adaptive Security                  → DONE    (weeks 11–14)
Phase 5  ⬜  Crystallization Pipeline           → NEXT    (weeks 15–19)
Phase 6  ⬜  Red Team + Pentest Bot             → (weeks 20+)
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
**Completed:** 2026-02-25 — 117/117 smoke tests passing

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

## Phase 5 — Crystallization Pipeline

**Goal:** Systematically identify agent behaviors that don't need AI, generate deterministic replacements, analyze them rigorously before human review, sign and containerize them, and register them in the tool library. This phase converts learned AI behavior into durable, zero-LLM, auditable infrastructure.

**Duration:** ~5 weeks
**Dependencies:** Phase 4 complete (Threat Analyst validates new tool entries; Guardian enforces signing; meaningful call history exists in `audit_log` for the Observer to analyze)
**Exit criteria:** At least one crystallized tool in production; full pipeline from observation through analysis through HITL approval through signed deployment is operational and documented.

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

Total at full Phase 6 deployment, peak concurrent: ~8–9GB RAM. Within the 16GB envelope with Ollama model swap managed (one model loaded at a time).
