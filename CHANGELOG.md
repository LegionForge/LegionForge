# Changelog — LegionForge

All notable changes to this project are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-02-26

First stable release. All seven phases complete. 242/242 smoke tests passing.

### Added — Phase 0: Infrastructure Foundation

- Async PostgreSQL connection pool (`psycopg3`) with `pgvector` for RAG embeddings
- `AsyncPostgresSaver` LangGraph checkpointer for graph state persistence
- Pydantic settings singleton loaded from hardware YAML profiles
  (`config/hardware_profiles/mac_m4_mini_16gb.yaml`)
- Unified LLM factory supporting Ollama (local), OpenAI, and Anthropic with cloud fallback
- FastAPI health server on `:8765` with `/health` (unauthenticated) and `/status`
  (Bearer-protected)
- 23 initial smoke tests; no running services required

### Added — Phase 1: First Agent + Security Foundations

- `ResearcherAgent` — first production agent using `SecureToolNode` + three-layer loop
  protection (step counter, action-history hash dedup, token budget guard)
- Tool registry with SHA-256 hash validation at registration and invocation
- 24 prompt-injection detection patterns (regex, pre-compiled at import time)
- PII redaction on all outbound API calls and LangSmith traces
- `threat_events` table for structured security event logging
- Capability boundary enforcement (negative capability list)

### Added — Phase 2: Containerisation + Guardian Sidecar

- **Guardian** — standalone FastAPI sidecar on `:9766` running a deterministic
  six-check pipeline with no LLM calls in the hot path:
  - Check 0: Tool revocation (REVOKED status — immediate halt)
  - Check 1: Tool registry + SHA-256 hash validation
  - Check 2: Capability boundary enforcement
  - Check 3: Destructive pattern detection
  - Check 4: Agent sequence contract validation
  - Check 5: Hash integrity (Ed25519 signed tools)
- Immutable `audit_log` table with SHA-256 hash chain (tamper detection on startup)
- RAG provenance scoring (`store_document_with_provenance()`)
- `agent_profiles` table + per-agent sequence contracts
- Bearer token auth on health endpoints (token stored in macOS Keychain)
- `guardian/Dockerfile` + `docker-compose.yml` with Guardian sidecar service
- Fail-safe design: Guardian unavailable → immediate `force_end`, never fail-open

### Added — Phase 3: ACLs, Task Tokens, Sub-Agent Architecture

- JWT task tokens — short-lived, scoped to exactly the capabilities the current task
  requires. Child tokens cannot exceed parent capabilities.
- `OrchestratorAgent` — routes tasks to sub-agents using token narrowing
- `derive_task_token()` with privilege-escalation enforcement (child ⊆ parent)
- Sandbox retry tier (second tier of the halt→sandbox→degrade fail-safe model)
- `roles.yaml` — human-readable capability definitions, version-controlled

### Added — Phase 4: Adaptive Threat Intelligence

- `ThreatAnalystAgent` — reads `threat_events`, proposes Guardian rules
- `threat_rules` table (`INJECTION_PATTERN`, `CAPABILITY_BLOCK`, `SEQUENCE_BLOCK`,
  `RATE_LIMIT_TIGHTEN`), loaded into Guardian's `_check_6_adaptive_rules()` cache
  every 10 seconds
- HITL approval gate: `POST /rules/{rule_id}/approve` — no autonomous rule changes
- AI Bill of Materials (`src/security/bom.py`) — tracks models, agents, dependencies
- Guardian v4 — adaptive rules as Check 6

### Added — Phase 5: Crystallization Pipeline

- **Observer** — monitors agent runs, identifies repeated deterministic tasks
- **Crystallizer** — generates deterministic Python function + test suite from
  identified patterns; eliminates LLM inference cost for solved problems
- **Pre-HITL Analyzer** — AST-based security scan before human review:
  - Bans `eval`, `exec`, `os.system`, `subprocess`, `__import__`
  - Guards against subscript bypasses (`sys.modules['subprocess']`),
    MRO traversal (`().__class__.__bases__[0].__subclasses__()`),
    and `globals()`/`locals()` dictionary access
- Ed25519 signing (`src/tools/signing.py`) — crystallized tools are signed before
  deployment; Guardian verifies signatures at every invocation
- Full HITL approval flow: Observer → Crystallizer → Analyzer → Human gate → Signed tool

### Added — Phase 5.5: Security Hardening Sprint

- PostgreSQL RBAC: `legionforge_app` restricted role (read/write app tables only;
  cannot drop tables or access `pg_catalog`)
- `CredentialStore` — unified secret management with macOS Keychain, file backend,
  and environment variable fallback; purges secrets from `os.environ` after load
- Tool revocation: `REVOKED` status + immediate Guardian cache invalidation (10s TTL,
  reduced from 60s)
- TOCTOU mitigation: `SecureToolNode` stores `approved_snapshot` pre-execution;
  post-execution result is compared against the snapshot; mismatch → halt
- Ollama model integrity: SHA-256 streaming verification of GGUF files
- Guardian bearer auth for the Guardian `/check` endpoint itself
- 200 smoke tests at phase completion

### Added — Phase 6: PentestAgent (Air-Gapped Red-Team Bot)

- `PentestAgent` — LangGraph state machine running an exhaustive attack suite:
  - 8 attack classes × 3 variants = 24 attack functions
  - Classes: Prompt Injection, RAG Poisoning, Tool Poisoning, Resource Bomb,
    Privilege Escalation, Crystallization Bypass, Revocation Bypass, TOCTOU
  - **Stop-at-proof** (default): bypass found → log → move to next class; no
    cross-test chaining, no cascading exploitation
  - `--mode=resilience`: explicit opt-in, interactive confirmation prompt,
    continues past bypasses to measure blast radius
- `SyntheticEnvironment` — isolated `legionforge_pentest` PostgreSQL database,
  stub Ollama HTTP responder (deterministic, no real model calls), fake credentials
  (marked STUB, never real keys)
- `PentestReport` — JSON, Markdown, and dark-theme HTML renderers
- `Dockerfile.pentest` — air-gapped container (`--network none`, `--read-only`,
  `--tmpfs /tmp`, `--pids-limit 50`, `--security-opt no-new-privileges`)
- 6 health endpoints: `POST/GET /pentest/run[s]/{run_id}/findings/report`
- HITL gate for proposed rules: `POST /pentest/rules/{finding_id}/approve`
- 3 new DB tables: `pentest_runs`, `pentest_findings`, `pentest_proposed_rules`
- 6 new `THREAT_TYPES` for pentest bypass events
- Makefile targets: `make build-pentest`, `make pentest`, `make pentest-resilience`,
  `make pentest-report`

### Added — Phase 7: Guardian Feedback Loop + v1.0 Readiness

- **Pentest → Guardian bridge**: `promote_pentest_rule_to_threat_rule()` converts
  approved pentest rules into `threat_rules`; Guardian enforces within 10 seconds
  via the existing `_check_6_adaptive_rules()` cache — no Guardian restart required
  - `REGEX` → `INJECTION_PATTERN`
  - `CAPABILITY` → `CAPABILITY_BLOCK`
  - `RATE_LIMIT` → `RATE_LIMIT_TIGHTEN`
- `POST /pentest/rules/{finding_id}/approve` now returns `threat_rule_id` and
  writes an audit log entry (`PENTEST_RULE_PROMOTED`)
- `SECURITY.md` — threat model, HITL halt/log tier policy (NIST SP 800-61r3 +
  MITRE ATT&CK), responsible disclosure (90-day window), pentest baseline
- `CHANGELOG.md` — this file

### Security

- `cryptography` bumped `~=42.0` → `~=44.0` (resolves Dependabot HIGH/MEDIUM/LOW
  CVEs: SECT curve subgroup attack + OpenSSL wheel vulnerabilities)
- Three `bandit` false-positive annotations (`# nosec B608/B108`, `usedforsecurity=False`)
  eliminating all medium/high static analysis findings

### Infrastructure

- `make security-audit` — runs smoke tests + bandit + URI password scan; required
  to pass before every PR merge
- 242 smoke tests at v1.0; no running services required; runs in ~2 seconds

---

## Pre-1.0 History

Development history is preserved in full commit log.
Key milestones: 23 tests (Phase 0) → 46 → 58 → 65 → 110 → 143 → 200 → 228 → 242.

[1.0.0]: https://github.com/LegionForge/LegionForge/releases/tag/v1.0.0
