# Changelog — LegionForge

All notable changes to this project are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Fixed — 2026-03-20 (UAT Day 6)

- **`gateway-start` missing secrets injection** — `make gateway-start` only set `POSTGRES_USER`; all Keychain-sourced secrets (Postgres password, tool signer, task token, Tavily, Brave, InceptionLabs, OpenRouter, health token, app password) were never injected. From SSH, login.keychain-db is not in the session search list so both `keyring` and `security` CLI fallbacks fail silently. Fix: `gateway-start` now injects all 10 secrets via `$(KEYCHAIN)` path, matching `servers-start`.
- **`_KEY_ENV_FALLBACKS` missing provider mappings** — `get_api_key("legionforge_inceptionlabs_api_key")` generated env var `LEGIONFORGE_INCEPTIONLABS_API_KEY_API_KEY` (double suffix), never matching `INCEPTIONLABS_API_KEY` injected by `servers-start`. Added mappings for InceptionLabs, OpenRouter, Tavily, Brave.
- **`num_ctx` only applied to primary Ollama model** — models loaded by direct ID (e.g. `qwen3.5:latest`) got Ollama's 4096-token default, causing context overflow and agent looping. Fix: profile `num_ctx` (16384) is now the default for all Ollama models.
- **Ollama VRAM exhaustion on model switch** — `keep_alive=-1` means loaded models never self-evict. Switching from `qwen3.5:latest` (8.5GB) to `llama3.1:8b` (4.7GB) would hang indefinitely. Fix: `_get_ollama()` now checks `/api/ps` and evicts any loaded model that isn't the target before returning.

### Fixed — 2026-03-17 (UAT Day 4)

- **`fanoutresearchers` Guardian HALT** — `SecureToolNode` was re-extracting `tool_calls` via `getattr(last_msg)` after `model_copy`, which does not reliably propagate updates in all LangChain versions. Un-normalised name flowed into Guardian, which correctly rejected it. Fix: assign `tool_calls = normalised_tcs` directly; add defensive reverse alias lookup in `verify_tool_before_invocation` as a second layer. Closes #276.
- **`copyOutput` copies only status lines** — `appendResult()` renders via `appendHTML()` which bypasses `outputBuffer`. `copyOutput()` now prefers `.o-result` `innerText` when present, falling back to the buffer for in-progress/error states.
- **`make briefing` stale NEXT.md section** — was grepping for `## Do these in order` (Day 1 content); replaced with `head -45` so the current day's "start here" block is always shown.
- **`make briefing` hardcoded repo** — removed `-R LegionForge/LegionForge` from `gh pr list`; uses `gh` default, survives org transfer.
- **`make briefing` origin/main sync check** — fetches remote and warns with re-sync command if dev is behind. Catches missed post-merge re-syncs.
- **`make briefing` end-of-session reminder block** — timestamp format (`YYYY-MM-DD HH:MM UTC`), checkpoint.md, and post-merge re-sync now printed at every session start.

---

## [0.7.1-alpha] — 2026-03-13 (Guardian v0.2.0 + security hardening)

### Added — 2026-03-13

- **Guardian `/health` enhancement** — response now includes `status: ok|degraded`, `cache_age_seconds`, `db_reachable`, `tools_registered`, `rules_active`, `uptime_seconds`. Status is `degraded` if DB is unreachable or cache is stale > 30s.
- **Guardian `/metrics` endpoint** — Prometheus text format; counters for `guardian_checks_total{result}`, `guardian_threat_events_total{type}`, and `guardian_cache_refresh_age_seconds` gauge. No auth required (consistent with main app `/metrics`).
- **Guardian canary tool** — `guardian_canary` seeded in `tool_registry` at init. Any call to this tool halts immediately with `CANARY_TRIGGERED` threat event (confidence 1.0). Tripwire for probing attacks and hallucinating models.
- **Guardian INFRA-1** — `GUARDIAN_HOST` now defaults to `127.0.0.1` (localhost only). Docker deployments must explicitly set `GUARDIAN_HOST=0.0.0.0`. Closes INFRA-1 post-v1.0 gate.
- **Guardian `/invalidate-cache`** — admin-only endpoint that forces immediate cache refresh, bypassing the 10s TTL. Enables instant tool revocation propagation during incidents.
- **Chart extraction tests** — 10 unit tests for `_extract_charts()` in `tests/tool_integrity/test_code_execute_sandbox.py`. Covers SVG/PNG/Plotly sentinel extraction, figure group ID capture, size cap enforcement, empty block handling, and LLM summary replacement. No Docker required.
- **GitHub Actions Node.js 24** — `sync-guardian.yml` upgraded to `actions/checkout@v4.2.2` + `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true`. Resolves Node 20 deprecation warning ahead of June 2026 enforcement.

---

## [0.7.1-alpha] — 2026-03-12 (chat UI + test suites)

### Added — 2026-03-12 (post-#240 UAT session)

- **Chat mode UI** (`src/gateway/static/index.html`) — toggle button (`💬`) converts the web UI into a persistent chat interface. Activating chat mode hides admin/config cards, scrolls conversation history into a full-viewport bubble view, pins the input bar at the bottom, auto-creates a session, and persists state to `localStorage`. SSE token streaming continues to work; `appendSpan()` calls `scrollChatToBottom()` automatically. Normal dashboard mode restored on toggle-off. No backend changes required.
- **Hallucination test suite** (`tests/hallucination/`) — 12 manually-run tests (`pytest.mark.hallucination`). Covers: stable-content web fetch grounding (httpbin, PyPI, JSONPlaceholder), web search grounding (Python.org, FastAPI), runtime UUID nonce anti-fabrication (UUID must be fetched, not invented), sequential UUID distinctness, 404 non-fabrication, and source citation verification (`sources[]` must contain the exact fetched URL). Requires Ollama + PostgreSQL + internet access; excluded from `make test` and `make ci` by default.
- **Tool integrity test suites** (`tests/tool_integrity/`) — 33 tests across 5 suites:
  - **Schema conformance** (12 tests, `pytest.mark.tool_integrity`, no services) — input boundary rejection (empty content, oversized content, invalid enum scope/content_type) and return-type conformance on SSRF-blocked paths and feature-disabled paths for all 8 registered tools.
  - **Result injection** (4 tests, `tool_integrity`) — end-to-end Tier 1 injection blocking via `run_researcher()` with a live injection server; control test for clean pages; `http_post` PII redaction verification before outbound send.
  - **Guardian e2e** (5 tests, `pytest.mark.tool_integrity_guardian`) — health endpoint responsiveness, forbidden tool ID blocking (`register_tool`), destructive argument detection (`rm -rf /` in `file_write` content), legitimate tool allowance, unregistered tool denial.
  - **Docker sandbox containment** (6 tests, `pytest.mark.tool_integrity_sandbox`) — network blocked (`--network=none`), `/etc/` write blocked (`--read-only`), `/tmp` writable, timeout enforcement (300s sleep), stderr captured, clean code executes.
  - **Memory namespace isolation** (6 tests, `pytest.mark.tool_integrity_memory`) — same-agent recall, cross-agent isolation, scope isolation (agent vs user), fresh namespace emptiness, injection payload blocking, cross-user isolation.
- **Makefile targets** (7 new): `test-hallucination`, `test-tool-integrity`, `test-tool-integrity-schema`, `test-tool-integrity-injection`, `test-tool-integrity-guardian`, `test-tool-integrity-sandbox`, `test-tool-integrity-memory`.
- **`pytest.ini` marks** (6 new): `hallucination`, `live_web`, `tool_integrity`, `tool_integrity_guardian`, `tool_integrity_sandbox`, `tool_integrity_memory`.

### Fixed — 2026-03-12

- `test_memory_write_rejects_oversized_content` / `_invalid_scope` / `test_memory_recall_rejects_invalid_scope` — tests now `monkeypatch` `settings.agent_memory.enabled = True` so size/scope checks are reached before the disabled guard fires.
- `test_http_post_rejects_invalid_content_type` — Pydantic `Literal` constraint raises `ValidationError` before the function body; test correctly uses `pytest.raises((ValidationError, Exception))` instead of asserting on return value.

---

## [0.7.1-alpha] — 2026-03-10 (ongoing)

### Added — 2026-03-10 (post-#239 bug-fix session)

- **KV-cache stable context ordering** (`src/base_graph.py`) — agent message assembly now builds `[persona (most stable) → prefs → memory recall → task (most dynamic)]`. Previously assembled in reverse order, defeating KV-cache prefix reuse on every run. Inspired by the Manus Insight in *The AI-Human Engineering Stack* (Mill & Sanchez, March 2026).
- **Temporal decay on memory recall** (`src/database.py`, `src/memory.py`) — `similarity_search()` gains a `temporal_decay` path using the STAR gravity formula: `score × e^(-0.000962 × age_hours)` (30-day half-life). `MemoryStore.search()` enables temporal decay by default so recent memories rank above equally similar but older ones. Min-similarity threshold is preserved on raw cosine score. The `memory_recall` tool now surfaces age alongside score (`[0.847, 3h ago]`). Adapted from the STAR algorithm whitepaper by Robert S. Balch II ([Anchor Engine](https://github.com/RSBalchII/anchor-engine-node)).
- **Researcher tool sequences** — `BROWSER_TOOL_SEQUENCES` expanded from 4 → 14 entries. Sequences starting with `web_fetch_js` followed by `web_search`, `web_fetch`, or another `web_fetch_js` were missing, causing Guardian to sandbox the researcher on virtually every modern news site. Gateway lifespan now auto-registers sequences on startup (was manual `make register-agent-sequences` only). 2133/2133 smoke.
- **SecureToolNode tool name normalisation** (`src/base_graph.py`) — normalises underscore-stripped tool names from local models (e.g. `spawnresearcher` → `spawn_researcher`) before security registry and Guardian checks.
- **Attribution** — `README.md`, `LegionForge_readme.md`, `RESEARCH.md`, and inline source comments now credit Anchor Engine (Robert S. Balch II), *The AI-Human Engineering Stack* (Mill & Sanchez), LATM (Cai et al.), and Voyager (Wang et al.) for design influences.

### Fixed — PRs #235–#239

- **PR #235** — Orchestrator hallucination: added `SystemMessage` to `run_orchestrator()` so `llama3.1:8b` / `qwen2.5:7b` calls `spawn_researcher` instead of answering from training data. Maintenance scheduler `permission denied` on `threat_events` DELETE fixed with short-lived admin connection. 2055/2055 smoke.
- **PR #236** — Live Ollama model selector: replaced hardcoded model preset buttons with a `GET /models` live-loaded dropdown. Switched primary model to `qwen2.5:7b` and embeddings to `mxbai-embed-large:latest`. Fixed `apiFetch()` JSON parse in `loadModels()`. Excluded embedding models from the selector response.
- **PR #237** — 5-role DB privilege model + Row-Level Security + DOS protection. `legionforge_worker`, `legionforge_gateway`, `legionforge_maintenance`, `legionforge_guardian`, `legionforge_readonly` with minimum required grants. RLS on `tasks`, `gateway_users`, `api_usage`. Sliding-window HTTP rate limiter, queue depth cap, SSE stream slot limit, per-route memory rate limits. 2089/2089 smoke.
- **PR #238** — Guardian `TASK_TOKEN_SECRET` missing on container restart (force-remove stale container in `make guardian-start`). `stream_token null` guard in UI — cache-hit tasks fall back to polling instead of 401 streaming. Missing DB grants: `INSERT` on `task_events` for `legionforge_worker`; `DELETE` on `audit_log` for `legionforge_maintenance`. `finalizer_node` now handles empty/whitespace LLM responses instead of emitting `[No result]`. `SecureToolNode` halt paths append a `ToolMessage` to clear dangling `tool_calls`. Ollama status banner in web UI. 2106/2106 smoke.
- **PR #239** — Researcher agent retry+fallback for ignored tool_choice=required (mirrors orchestrator guard). Deterministic web_search injection when both LLM attempts fail. Makefile test isolation: make test/make test-fast run smoke → testlab → ui as separate pytest invocations, preventing asyncio event loop pollution. 2125/2125 smoke.

---

## [0.7.0-alpha] — 2026-03-05

Post-v1.0.0 development sprint. All pre-v1.0 security blockers resolved. 1946/1946 smoke tests.

### Added — v1.0.1 Patches (PRs #36–#42, 2026-03-01)

- **Schema fix**: `gateway_users.user_id` changed from `UUID` to `TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text` — allows OAuth natural IDs (e.g. `github:12345`, `oidc:sub-claim`); idempotent `ALTER TABLE` migration
- **`api_key_hash UNIQUE` constraint dropped** — multiple OAuth users share the `[OAUTH-NO-KEY]` sentinel; bcrypt hashes are cryptographically unique without a DB constraint
- **`MODEL_INTEGRITY_STRICT` env var** — overrides YAML at deploy time; `/status` surfaces per-model integrity results under `components.model_integrity`
- **Live Kerberos KDC** — MIT Kerberos 1.22.2 user-owned KDC on port 7088; `gssapi` built against MIT Kerberos (not macOS Heimdal); `make test-kerberos` target; `SCALING.md` KDC guide
- **Loop protection checkpoint resume** — `resume_run_config(thread_id)` passes `None` as graph input so LangGraph hydrates safeguard counters from checkpoint rather than resetting
- **All 38 integration tests real** — Ollama test stubs replaced with live tests; `asyncio_default_fixture_loop_scope=session` in `pytest.ini`
- 492/492 smoke tests at v1.0.1

### Added — Phases 8–16 (PRs #43–#116, 2026-03-01 – 2026-03-03)

- **Phase 8**: FastAPI gateway (:8080), PostgreSQL task queue (`FOR UPDATE SKIP LOCKED`), `astream_events()` SSE streaming, minimal web UI, A2A Agent Card, MCP tools endpoint, Discord connector
- **Phase 9**: langchain 1.x migration, 5-tool library, parallel agent fan-out, security hardening sprint
- **Phase 10**: DB-backed stream tokens, per-user daily token budgets, `/usage/me`, user management CLI
- **Phase 11**: `SecureToolNode` security fix, 38 integration tests, `AuthBackend` protocol, `Dockerfile.gateway`, `docs/SCALING.md`
- **Phase 12**: `OIDCBackend`, `GitHubOAuthBackend`, `LDAPBackend`, `KerberosBackend` — multi-scheme `require_user` gate
- **Phase 13**: Real GSSAPI Kerberos backend, Redis-backed stream token store, multi-instance `docker-compose.multi.yml` + Nginx
- **Phase 14**: Redis global budget counters, Prometheus `/metrics` endpoint, `X-Request-ID` trace middleware
- **Phase 15**: Polished web UI — localStorage API key + history, task cancel, tool call blocks, live elapsed timer, copy button, `?` keyboard shortcut
- **Phase 16**: Telegram polling connector, Slack Socket Mode connector, HMAC-SHA256 generic webhook connector (:8081), shared `src/connectors/base.py`
- 846/846 smoke tests at Phase 16; 40/40 UI tests; 104/104 TestLab tests

### Added — Agent Capability Phases 71–101 (PRs #110–#129, 2026-03-03)

- Agent self-verification loop, light/dark mode toggle, task export to Markdown, browser notifications, scheduled tasks UI, task notes + share link, task timeline, pipeline runner, task retry + cost estimator, task stats card, agents directory, document ingestor, memory search, security threats summary, tool registry admin, health metrics dashboard, user management admin, audit log viewer, keyboard shortcuts modal, webhook management, user preferences, admin annotations viewer, identity badge, pipeline run history, audit verify, task attachments, API key rotation, batch submit, session tasks browser
- 1049/1049 smoke tests at Phase 101

### Added — UI Tool Library, Phases 102–381 (PRs #130–#201, 2026-03-03 – 2026-03-04)

381 JavaScript UI functions over the gateway REST API — complete operator dashboard. Each function maps to one API endpoint; each gets 3 smoke tests. Groups:

- **Task management**: detail, clone, pin/unpin, priority queue, label/tag/keyword/date filters, dependency chain, siblings, bulk ops, result download, live watcher, JSON inspector, annotation viewer/stats, draft save, live counter, pagination
- **Usage & quota**: token budget bar, usage chart, cost history, my profile, top token users, admin quota
- **Pipelines & schedules**: list/create/edit/detail/steps/runs/health (pipelines), list/detail/toggle/next-run/history (schedules)
- **Security & audit**: threats monitor/summary/detail/by-type, audit log viewer/filter/verify, HITL event log
- **Memory & documents**: memory stats/recall/ingest, document list/chunks/search, ingest status
- **Admin**: admin stats/metrics/user-detail/user-tokens/schedules/annotations, gateway stats, connector status, agent run metrics, system health
- **Sessions & webhooks**: session list/detail/delete, webhook list/history/detail/test
- **Providers & models**: model list, model prefs, provider usage, Ollama status, search provider status
- 1920/1920 smoke tests at Phase 381

### Security — Hardening Sprint (PRs #208–#214, 2026-03-04 – 2026-03-05)

- **PR #208**: `audit_anchors` table + anchor-aware `verify_audit_log_chain()` + `prune_audit_log()` + `run_db_maintenance()` scheduler heartbeat + `make db-maintenance` target
- **PR #209**: Fixed `system_prompt_exfiltration` bypass (3 new detection patterns) + 5 pentest infrastructure bugs; 24/24 pentest PASS
- **PR #210**: Extended exfiltration detection — 3 new patterns (leak/dump/expose verbs, system message synonyms, "what were you told/instructed") + NFKC normalization + zero-width character stripping in `detect_injection()`
- **PR #211**: `check_hitl_required()` made `async`; DESTRUCTIVE_PATTERN events now written to `threat_events` — LOG tier (`confidence=0.6`) and HALT tier (`confidence=1.0`); `base_graph.py` updated to `await`
- **PR #212**: PostgreSQL `trust` → `scram-sha-256` — `pg_hba.conf`: `local→peer`, `host→scram-sha-256`; `_read_pgpass()`/`_write_pgpass_entry()` helpers; trust fallback removed; `_cached_app_pw` cache; **pre-v1.0 security blocker closed**
- **PR #213**: `POSTGRES_TRUST_AUTH=true` escape hatch — explicit opt-in for new-developer trust-auth installs
- **PR #214**: Documentation sync — all status docs updated to v0.7.0-alpha / Phase 381 / 1946 tests
- 1946/1946 smoke tests; 38/38 integration tests

### Added — Browser Tools + UI + Guardian Spinoff (PRs #215–#219, 2026-03-05 – 2026-03-06)

- **PR #215**: Docs sync — README, CONTRIBUTING, CHANGELOG, VISION.md updated to 1946 baseline
- **PR #216**: Public-facing docs — `LegionForge_readme.md`, `LegionForge_index.md`, `docs/quick-start.md`, `docs/architecture.md` updated for GitHub Pages
- **PR #217**: Lazy-load Operator Dashboard — 296 tool cards moved into `<template id="op-dashboard-tmpl">`; injected on first click; eliminates ~296-card DOM parse on every page load; 3 smoke tests updated
- **PR #218**: `web_fetch_js` Playwright headless browser tool — two-layer SSRF (URL validation + page route filter); resource type blocking (image/media/font/stylesheet/websocket aborted); Chromium sandbox intact; `src/agents/researcher.py` registers `web_fetch_js`; 50 tool-accuracy tests (Groups A–F); PII fix — `(?<!://)` lookbehind in private-IP regex prevents URL host redaction
- **PR #219 / G1**: Decouple `guardian.py` from all `src.*` module-level imports; inline `_GUARDIAN_DESTRUCTIVE_PATTERNS`, `_validate_task_token`, `_append_audit_log_direct`; 13 drift-guard smoke tests; 1969→1982
- **PR #219 / G1.5**: Remove last lazy `from src.database import append_audit_log` inside `/report` endpoint; fully standalone; 1982→1989
- **PR #219 / G2 scaffold**: `packages/guardian/` — `pyproject.toml` (MIT, `legionforge-guardian` entry point), `init.sql` (5 tables, all `IF NOT EXISTS`), `Dockerfile`, `docker-compose.yml`, `legionforge_guardian/sdk/client.py` (`GuardianClient` + `guardian_check()` with fail-safe halt); editable install `-e packages/guardian`; 11 SDK tests + 7 smoke tests
- **PR #219 / G2 code move**: `guardian.py` canonical source moved to `packages/guardian/src/legionforge_guardian/app.py`; `src/security/guardian.py` becomes thin backward-compat shim (`_sys.modules[__name__].__dict__.update(...)`)
- **PR #219 / G3**: Fix `init.sql` `threat_events` schema (`ts`/`run_id` to match LegionForge DB); finalize Dockerfile CMD; 6 G3 smoke tests
- 1989 → 1995 smoke tests

### Added — Agent Memory Gaps (OpenClaw parity, 2026-03-06)

Closing 4 of 5 agent memory gaps identified vs. the OpenClaw memory model:

- **Gap 5 — User preference bootstrap**: `user_context_bootstrap(user_id)` in `src/memory.py` reads the `user_preferences` table and injects a `SystemMessage` before every LLM call — the USER.md equivalent. `bootstrap_user_prefs` flag in `AgentMemoryConfig`. `AgentState.user_id` threaded from gateway worker. 10 smoke tests; 1995 → 2005.
- **Gap 3 — Agent-driven memory writes**: `src/tools/memory_tools.py` — `memory_write` (scope=agent|user, 2000-char cap, PII-sanitized, injection-guarded) + `memory_recall` (semantic search). `set_agent_memory_context(agent_id, user_id)` context var resolves namespace without state access. Wired into `RESEARCHER_TOOLS` and gateway worker. Fixed latent `NameError` in `worker._stream_agent` (`user_id` was referenced before assignment). 17 smoke tests; 2005 → 2022.
- **Gap 2 — Daily episodic memory**: `summarize_and_store_episodic()` in `src/memory.py` — router LLM (qwen2.5:3b) produces a 2-3 sentence summary after each task completion; stored under `user:<uid>/daily:<YYYY-MM-DD>`. Fire-and-forget `asyncio.create_task()` in `run_task()`. Cross-session continuity without re-explanation.
- **Gap 4 — Pre-compaction flush**: `flush_key_facts()` in `src/memory.py` — when `force_end=True` (token budget hit or loop detected), router LLM extracts 3-5 bullet-point facts from the last 10 messages before context is discarded; stored in agent namespace. Wired in `finalizer_node()` in `base_graph.py`. `episodic_memory` + `flush_on_compaction` flags in `AgentMemoryConfig`. 13 smoke tests; 2022 → 2035.
- **Gap 1 — Persona namespace bootstrap (SOUL.md equivalent)**: `MemoryStore.get_all(namespace)` — always-load retrieval for non-query-dependent content; `persona_bootstrap(agent_id, user_id)` loads `persona:agent:<id>` (operator-defined agent character) and `persona:user:<uid>` (per-user standing instructions), formats as `[Agent persona]` / `[User persona]` SystemMessage blocks. Injected as the outermost SystemMessage in `agent_node` (before preferences, before recall). `persona_bootstrap` flag in `AgentMemoryConfig`. Stored via `POST /memory/ingest` — DB-backed, per-user + per-agent scoped, multi-instance safe. 10 smoke tests; 2035 → 2045. **All 5 memory gaps closed.**

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
