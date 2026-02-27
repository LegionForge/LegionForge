# PROJECT_STATUS.md
# LegionForge

**Version:** 1.0.0
**Last updated:** 2026-02-27
**Branch:** `main`
**Hardware:** Mac Mini M4, 16GB, 1TB external drive (`/Volumes/MAC_MINI_1TB`)
**Status:** ✅ Phases 0–8 complete + Guardian gap fixes. Phase 9 — Tool expansion + langchain 1.x migration is next.

> **Related docs:**
> - [`TLDR.md`](./TLDR.md) — Quick summary and orientation
> - [`PHASE_PLAN.md`](./PHASE_PLAN.md) — Full phased roadmap with goals and dependencies
> - [`RESEARCH.md`](./RESEARCH.md) — Threat research, design theory, and open questions
> - [`docs/VISION.md`](./docs/VISION.md) — Product vision and target architecture

---

## Current State

All phases through 8 are complete. The full security stack is operational and the user-facing gateway is live.

```
make test-smoke    → 323/323 passing (~1s, no external services required)
make health-server → localhost:8765 all components green
make gateway-start → localhost:8080 gateway API + streaming UI
make discord-start → Discord bot connector (requires Keychain secrets, see VERIFICATION.md)
git log --oneline -1 → 9837d17 feat: Phase 8 — Discord connector (src/connectors/discord.py)
```

---

## What's Shipped (Phases 0–8)

### Source Files (`src/`)

| File | Purpose | Phase |
|---|---|---|
| `database.py` | Async PostgreSQL (admin + restricted app pool), LangGraph checkpointer, pgvector, 14-table schema, audit log SHA-256 hash chain | 0–5.5 |
| `security/core.py` | Keychain loader, CredentialStore, PII redaction, injection detection (29 patterns, Tier 1/2), `has_halt_worthy_injection()` | 1, hardening |
| `security/guardian.py` | Guardian FastAPI sidecar (:9766) — 7-check deterministic pipeline (no LLM in hot path); 10s rule hot-reload | 2, 4, 7 |
| `security/acl.py` | JWT task token issuance + validation; privilege escalation blocking | 3 |
| `security/bom.py` | AI Bill of Materials assembly | 4 |
| `safeguards.py` | Three-layer loop protection (step counter, action history, token budget); `SafeguardedState.initial(agent_id=...)` | 0, hardening |
| `rate_limiter.py` | Per-provider async rate limiting, daily caps, 80%/100% alert thresholds | 0 |
| `llm_factory.py` | Unified async factory for Ollama/OpenAI/Anthropic, cloud fallback | 0 |
| `observability.py` | JSON structured logging + LangSmith upload, per-run tracing toggle | 0 |
| `credentials.py` | CredentialStore (Keychain/env/file), secret purging from `os.environ` | 5.5 |
| `health.py` | FastAPI (:8765) — health, status, metrics, usage, BOM, crystallization review, tool revocation, pentest reports | 0–6 |
| `base_graph.py` | LangGraph template — TOCTOU snapshot, Guardian check, SecureToolNode (7-step pipeline with Tier 1/2 injection tiering), `run_agent()` | 1–hardening |
| `agents/researcher.py` | Researcher agent — web fetch, document store, Ed25519-registered tools, `<external_content>` injection boundary | 1 |
| `agents/orchestrator.py` | Orchestrator — master→derived JWT token hierarchy, task routing | 3 |
| `agents/threat_analyst.py` | Reads `threat_events`, proposes Guardian rules (cannot self-approve) | 4 |
| `agents/observer.py` | Monitors runs, nominates crystallization candidates | 5 |
| `agents/crystallizer.py` | Generates deterministic functions + test suites from patterns | 5 |
| `agents/pentest_agent.py` | PentestAgent state machine, 8 attack classes × 3 variants, stop-at-proof mode | 6 |
| `agents/synthetic_env.py` | Isolated pentest environment (stub DB, fake Ollama, fake credentials) | 6 |
| `agents/pentest_report.py` | PentestReport dataclasses, JSON/Markdown/HTML renderers | 6 |
| `tools/signing.py` | Ed25519 keypair management + tool manifest signing/verification | 5 |
| `tools/model_integrity.py` | SHA256 streaming GGUF verification; `MODEL_INTEGRITY_MISMATCH` threat event | 5.5 |
| `tools/crystallization_analyzer.py` | Pre-HITL AST analyzer (subscript/MRO/globals guards), Docker/sandbox/bare sandboxes | 5 |
| `tools/pentest_tools.py` | 24 attack functions (8 classes × 3 variants) | 6 |
| `gateway/app.py` | FastAPI gateway (:8080) — task queue, SSE streaming, Web UI, CORS, lifespan | 8 |
| `gateway/auth.py` | Bearer token auth, bcrypt API key hashing, stream tokens (30-min TTL) | 8 |
| `gateway/events.py` | LangGraph→SSE event mapping, in-process pub/sub queues | 8 |
| `gateway/worker.py` | Embedded asyncio task worker — polls queue, streams events to subscribers | 8 |
| `gateway/routes/tasks.py` | `POST/GET /tasks`, `GET /tasks/{id}`, `DELETE /tasks/{id}` | 8 |
| `gateway/routes/stream.py` | `GET /tasks/{id}/stream` — SSE via EventSourceResponse | 8 |
| `gateway/routes/a2a.py` | `/.well-known/agent.json`, `/a2a/tasks` — A2A protocol conformance | 8 |
| `gateway/routes/mcp.py` | `GET /mcp/tools`, `POST /mcp/tools/invoke` (501 stub, Phase 9) | 8 |
| `gateway/static/index.html` | Minimal streaming Web UI (dark theme, EventSource, token deltas) | 8 |
| `connectors/discord.py` | Discord bot — `!<task>` → gateway POST → SSE → reply edits every 2s | 8 |

### Guardian — 7 Checks

| Check | What It Enforces |
|---|---|
| 0 | Tool revocation — REVOKED status → immediate halt (10s TTL cache) |
| 1 | Tool registry + SHA-256 hash validation |
| 2 | Capability boundary enforcement (negative capability list) |
| 3 | Destructive pattern detection in tool arguments |
| 4 | Agent sequence contract validation |
| 5 | Ed25519 signed tool verification |
| 6 | Adaptive threat rules hot-reloaded from `threat_rules` table every 10s |

### Docker Images

| Image | Purpose |
|---|---|
| `guardian/Dockerfile` | FastAPI sidecar (:9766), Python 3.11-slim, zero LLM dependencies |
| `Dockerfile.analyzer` | Pre-HITL analyzer — deny-default (`--network none --read-only --pids-limit 20`) |
| `Dockerfile.pentest` | PentestAgent — air-gapped (`--network none --read-only`) |

### Tests

- `tests/test_smoke.py` — **323 tests**, no running services required, ~1s
- `tests/conftest.py` — pytest configuration and shared fixtures

---

## Infrastructure

### PostgreSQL 17

- **Version:** 17 (Homebrew)
- **Data directory:** Homebrew default
- **Database:** `legionforge`
- **Users:** `legionforge` (superuser — DDL/startup only), `legionforge_app` (restricted runtime — SELECT/INSERT/UPDATE/DELETE only)
- **Password:** stored in macOS Keychain (`service: postgres`)
- **Auto-start:** via `brew services`

**All tables (14):**

| Table | Purpose |
|---|---|
| `checkpoints` | LangGraph agent state |
| `checkpoint_blobs` | LangGraph binary state |
| `checkpoint_writes` | LangGraph pending writes |
| `checkpoint_migrations` | LangGraph schema versions |
| `documents` | Vector store for RAG (pgvector, 768-dim, HNSW index) |
| `api_usage` | Token/call tracking per provider/run |
| `health_metrics` | Persisted health check snapshots |
| `tool_registry` | Approved tool manifests with hashes, Ed25519 signatures, revocation status |
| `threat_events` | Structured security event log (INJECTION_DETECTED, TOOL_HASH_MISMATCH, TOOL_ARG_INJECTION, TOOL_RESULT_INJECTION, MODEL_INTEGRITY_MISMATCH, AUDIT_LOG_TAMPER, …) |
| `audit_log` | Append-only SHA-256 hash-chain tamper-evident event log |
| `agent_profiles` | Registered agent sequence contracts |
| `threat_rules` | Adaptive rule set — PENDING/APPROVED/REJECTED; Guardian hot-reloads every 10s |
| `crystallization_candidates` | Observer-nominated candidates |
| `crystallization_packages` | Crystallizer-generated packages + test suites |
| `crystallization_analyses` | Pre-HITL analysis reports |
| `pentest_runs` | PentestAgent run metadata |
| `pentest_findings` | Individual attack findings with severity, bypass status |
| `pentest_proposed_rules` | Guardian rules proposed from pentest findings (pending human approval) |

### pgvector

- **Version:** 0.8.1
- **Note:** requires manual dylib link after PostgreSQL upgrades. See `VERIFICATION.md`.

### Ollama Models

| Model | Size | Purpose |
|---|---|---|
| `llama3.1:8b` | 4.9GB | Primary reasoning |
| `qwen2.5:3b` | 1.9GB | Router/supervisor |
| `nomic-embed-text:latest` | 274MB | Embeddings (768-dim) |
| Models directory | `/Volumes/MAC_MINI_1TB/ollama_models/` | External drive |

### macOS Keychain Items

| Service | Purpose |
|---|---|
| `postgres` | PostgreSQL password |
| `langsmith` | LangSmith tracing API key |
| `legionforge_health` | Bearer token for `/status`, `/metrics`, `/usage` |
| `legionforge_task_token` | TASK_TOKEN_SECRET for JWT signing |
| `legionforge_signing_key` | Ed25519 private key for tool signing |
| `legionforge_discord_token` | Discord bot token (Phase 8 connector) |
| `legionforge_discord_api_key` | Gateway API key for the `discord-bot` gateway user |

---

## Daily Startup Sequence

```bash
source ~/.zshrc                          # loads POSTGRES_PASSWORD
cd /Volumes/MAC_MINI_1TB/LegionForge
source venv/bin/activate
make check                               # verify drive + config + keychain
make verify-tool-registry               # fail if any loaded tool is unregistered
make test-smoke                          # 323 tests, ~1s
make health-server                       # start status endpoint (keep terminal open)
```

In a second terminal, verify all green:
```bash
curl -s -H "Authorization: Bearer $(security find-generic-password -s legionforge_health -w)" \
     http://localhost:8765/status | python3 -m json.tool
```

---

## Project Identity

| Item | Detail |
|---|---|
| Release name | **LegionForge** |
| Private dev repo | https://github.com/LegionForge/LegionForge |
| License | AGPL-3.0 with Section 7(b) attribution clause |
| Owner | John Paul "Jp" Cruz ([@jp-cruz](https://github.com/jp-cruz)) |

---

## Known Issues / Technical Debt

### Active (unfixed)

| Item | Priority | Notes |
|---|---|---|
| Rate limiter race condition | High | Two concurrent calls can both pass the daily cap before either increments; fix with lock around check-and-reserve |
| No rate limiting on `/status` endpoint | High | Each hit spawns fresh DB + Ollama checks; add request cache + rate cap before any networked exposure |
| PII patterns incomplete | Medium | `_PII_PATTERNS` missing: IPv4, internal URLs, DB DSNs, file paths with usernames |
| Loop protection resets on checkpoint resume | Medium | Step counter and action history reset on resume; terminated loop can restart clean |
| No integration tests | Medium | Smoke tests pass without services; add DB + Ollama required integration tests |
| `INTERVAL hours` not validated | Medium | `get_usage_summary()` / `get_threat_summary()` — `hours` must be bounded 1–8760 before query |
| GGUF hash pinning | Low | `gguf_sha256: ""` in hardware profile skips model integrity; run `make verify-models` and pin the values |
| Guardian tool args gap | ✅ Fixed | `guardian_check()` now forwards real `tool_input`; checks 3, 5, 6 see actual arguments. |
| Guardian action field hardcoded | ✅ Fixed | `check_2` now also blocks forbidden `tool_id`; `action` read from state (default `"invoke"`). |

### Accepted / By Design

| Item | Decision |
|---|---|
| Embedding-level RAG poisoning | Open research problem; provenance scoring exists; anomaly detection deferred |
| False positives on Tier 2 injection patterns | Accepted trade-off — research queries may match "hypothetically speaking" etc.; Phase 8 replaces with context-aware classifier |
| Guardian runs as admin user | Guardian needs full DB access for rule updates; accepted with compensating control (air-gapped sidecar) |

---

## Security Trust Surface

| Trust Boundary | Threat | Control |
|---|---|---|
| External tool response → agent context | Indirect injection, poisoned content | Tool-result injection detection (Tier 1/2 tiering) + `<external_content>` delimiters |
| Agent context → external API call | PII/credential exfiltration | Redaction on all outbound calls |
| Tool invocation → Guardian | Tool poisoning, rug-pull, capability violation | Registry check + hash verify + 7-check pipeline |
| Web content → RAG store | Memory poisoning | Document provenance at ingestion + trust scoring |
| Agent → agent message | Prompt infection, cascade | Inter-agent message validation + scope check |
| Orchestrator → sub-agent | Privilege escalation | Derived task tokens (child capabilities ⊆ parent) |
| Tool library → agent | Supply chain, rug-pull | Ed25519 signing + signature verify |
| Startup → runtime | Audit log tampering | SHA-256 hash chain verified at startup; tamper → `RuntimeError` halt |

**Not trust boundaries (process nodes — secured by safeguards, not validation):**
Internal agent logic · LLM inference · Safeguard checks · Internal state transitions

---

## Residual Risks

| Risk | Compensating Control |
|---|---|
| Compromised tool that signs its own malicious output | Output sanitization + Guardian content analysis + behavioral contract |
| Novel semantic injection evading pattern matching | Sandbox-retry (Tier 2), Threat Analyst, PentestAgent |
| Compositional emergence from approved components | Capability minimization + combination monitoring + sandbox-first for novel combos |
| Behavioral drift from model weight changes | Model integrity hash at startup; re-approval required after any `ollama pull` |
| Embedding-level RAG poisoning | Provenance scoring + trust flagging; embedding anomaly detection deferred |

---

See [`PHASE_PLAN.md`](./PHASE_PLAN.md) for the full sequenced roadmap.
See [`docs/VISION.md`](./docs/VISION.md) for the Phase 8+ product architecture.
