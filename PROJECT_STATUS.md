# PROJECT_STATUS.md
# LegionForge

**Version:** 0.7.0-alpha
**Last updated:** 2026-03-08
**Branch:** `dev`
**Hardware:** Mac Mini M4, 16GB, 1TB external drive (`/Volumes/MAC_MINI_1TB`)
**Status:** ✅ Phases 0–381 complete. Bug-fix mode — no new phases until v1.0.

> **Related docs:**
> - [`TLDR.md`](./TLDR.md) — Quick summary and orientation
> - [`PHASE_PLAN.md`](./PHASE_PLAN.md) — Full phased roadmap with goals and dependencies
> - [`RESEARCH.md`](./RESEARCH.md) — Threat research, design theory, and open questions
> - [`docs/VISION.md`](./docs/VISION.md) — Product vision and target architecture

---

## Current State

All phases through 381 are complete. The full security stack, gateway, tool library, parallel agent fan-out, multi-user auth, integration tests, modular auth backend, containerized gateway, multi-provider auth registry, Redis-backed state layer, Prometheus metrics endpoint, request trace ID middleware, polished web UI, Telegram/Slack/Webhook channel connectors, comprehensive UI tool library (381 tools), and PostgreSQL scram-sha-256 auth are operational.

```
make test-smoke        → 2106/2106 passing (~17s, no external services required)
make test-integration  → 38/38 passed (requires PostgreSQL)
make test-kerberos     → 5/5 passed (requires live KDC + PostgreSQL)
make test-ui           → 40/40 passed (Playwright)
make health-server     → localhost:8765 all components green (Redis health when configured)
make gateway-start     → localhost:8080 gateway API + streaming UI + /metrics endpoint
make discord-start     → Discord bot connector
make telegram-start    → Telegram bot connector (requires Keychain secrets)
make slack-start       → Slack Socket Mode connector (requires Keychain secrets)
make webhook-start     → Generic webhook connector (:8081)
make build-gateway     → legionforge-gateway:latest Docker image
git log --oneline -1 → fix: gateway_users schema + Kerberos tests 5/5 passing (#42)
```

---

## What's Shipped (Phases 0–16)

### Source Files (`src/`)

| File | Purpose | Phase |
|---|---|---|
| `database.py` | Async PostgreSQL (admin + restricted app pool), LangGraph checkpointer, pgvector, 14-table schema, audit log SHA-256 hash chain | 0–5.5 |
| `security/core.py` | Keychain loader, CredentialStore, PII redaction, injection detection (29 patterns, Tier 1/2), `has_halt_worthy_injection()` | 1, hardening |
| `security/guardian.py` | Backward-compat shim — re-exports all names from `legionforge_guardian.app`; canonical source moved to `packages/guardian/` (G2) | 2, 4, 7, G2 |
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
| `agents/orchestrator.py` | Orchestrator — master→derived JWT token hierarchy, serial `spawn_researcher` + parallel `fan_out_researchers` | 3, 9 |
| `agents/fan_out.py` | Parallel fan-out engine — `asyncio.gather()`, `Semaphore` cap, per-branch JWT, error isolation, order-preserved results | 9 |
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
| `gateway/auth.py` | Bearer token auth, bcrypt API key hashing, stream tokens (30-min TTL); `AuthBackend` protocol + `ApiKeyBackend` + `get/set_auth_backend()` | 8, 11 |
| `gateway/events.py` | LangGraph→SSE event mapping, in-process pub/sub queues | 8 |
| `gateway/worker.py` | Embedded asyncio task worker — polls queue, streams events to subscribers | 8 |
| `gateway/routes/tasks.py` | `POST/GET /tasks`, `GET /tasks/{id}`, `DELETE /tasks/{id}` | 8 |
| `gateway/routes/stream.py` | `GET /tasks/{id}/stream` — SSE via EventSourceResponse | 8 |
| `gateway/routes/a2a.py` | `/.well-known/agent.json`, `/a2a/tasks` — A2A protocol conformance | 8 |
| `gateway/routes/mcp.py` | `GET /mcp/tools`, `POST /mcp/tools/invoke` (501 stub, Phase 10) | 8 |
| `tools/http_tools.py` | `http_get` + `http_post` — SSRF guard, I/O sanitize, 50 KB cap, 30 s timeout | 9 |
| `tools/file_tools.py` | `file_read` + `file_write` — path allowlist, realpath traversal guard, executable extension block | 9 |
| `tools/code_tools.py` | `code_execute` — air-gapped Docker sandbox (`--network none --read-only --pids-limit 20`) | 9 |
| `gateway/static/index.html` | Minimal streaming Web UI (dark theme, EventSource, token deltas) | 8 |
| `connectors/discord.py` | Discord bot — `!<task>` → gateway POST → SSE → reply edits every 2s | 8 |
| `cli/__init__.py` | CLI package marker | 10 |
| `cli/manage_users.py` | User management CLI — `create-user`, `deactivate-user`, `set-quota`, `list-users` | 10 |
| `gateway/backends/__init__.py` | Auth backend package exports | 12 |
| `gateway/backends/base.py` | `AuthBackend` protocol + `Credential` scheme constants | 12 |
| `gateway/backends/api_key.py` | `ApiKeyBackend` — bcrypt key verification against `gateway_users` | 12 |
| `gateway/backends/oidc.py` | `OIDCBackend` — JWKS discovery, JWT decode (PyJWT), userinfo fallback, first-login provisioning | 12 |
| `gateway/backends/github.py` | `GitHubOAuthBackend` — opaque token → `/user` API, first-login provisioning | 12 |
| `gateway/backends/ldap_backend.py` | `LDAPBackend` — bind+search+rebind for AD/OpenLDAP | 12 |
| `gateway/backends/kerberos.py` | `KerberosBackend` — GSSAPI Negotiate via `gssapi` package; graceful `None` fallback when `gssapi` absent | 13 |
| `gateway/backends/registry.py` | `load_backend_from_settings()` factory — maps `auth_provider` setting to backend instance | 12 |
| `gateway/state.py` | Redis-backed stream token store (`create/resolve/delete_stream_token`); Redis global budget counters (`redis_budget_check_and_reserve` / `redis_budget_release`) | 13, 14 |
| `gateway/metrics.py` | Prometheus-format `/metrics` endpoint — inline text formatter, no new deps; `MetricsMiddleware` | 14 |
| `gateway/middleware.py` | `RequestIDMiddleware` (reads/generates `X-Request-ID`) + `MetricsMiddleware` (per-route counters) | 14 |
| `connectors/base.py` | Shared connector helpers — `_load_secret`, `_consume_sse`, `_run_task` | 16 |
| `connectors/telegram.py` | Telegram bot — `python-telegram-bot` polling, edit-in-place responses, throttling | 16 |
| `connectors/slack.py` | Slack bot — `slack-bolt` Socket Mode (no public URL), edit-in-place responses | 16 |
| `connectors/webhook.py` | Generic webhook connector — FastAPI :8081, HMAC-SHA256 inbound verification, async callback POST | 16 |

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
| `guardian/Dockerfile` | LegionForge-integrated Guardian deploy (uses `legionforge_guardian` package) |
| `packages/guardian/Dockerfile` | Standalone Guardian deploy — no LegionForge source required |
| `Dockerfile.analyzer` | Pre-HITL analyzer — deny-default (`--network none --read-only --pids-limit 20`) |
| `Dockerfile.pentest` | PentestAgent — air-gapped (`--network none --read-only`) |
| `Dockerfile.sandbox` | code_execute sandbox — Python 3.11-slim, non-root `sandbox` user, stdlib only |
| `Dockerfile.gateway` | Gateway service (:8080) — `uvicorn`, non-root `gateway` user, multi-worker ready |
| `Dockerfile.testclient` | HTTP test client — 4 suites (basic/load/pentest/injection), non-root `testclient` user, httpx only |

### Tests

- `tests/test_smoke.py` — **2106 tests**, no running services required, ~17s
- `tests/test_integration.py` — **38 tests**, `@pytest.mark.integration`, requires PostgreSQL + Ollama (`make test-integration`)
- `tests/test_kerberos_integration.py` — **5 tests**, requires live KDC + PostgreSQL (`make test-kerberos`); tests SPNEGO round-trip + DB user provisioning
- `tests/conftest.py` — pytest configuration, shared fixtures, async integration fixtures (db, test_user, auth_headers, gateway_client)
- `pytest.ini` — `asyncio_mode=strict`, `asyncio_default_fixture_loop_scope=session`, `asyncio_default_test_loop_scope=session`; required so the session-scoped psycopg pool shares one event loop with all tests

---

## Infrastructure

### PostgreSQL 17

- **Version:** 17 (Homebrew)
- **Data directory:** Homebrew default
- **Database:** `legionforge`
- **Admin user:** `jp` (superuser — DDL/startup only); password in `~/.pgpass` + Keychain (`service: postgres`)
- **App roles (5):** `legionforge_worker` · `legionforge_gateway` · `legionforge_maintenance` · `legionforge_guardian` · `legionforge_readonly` — each with minimum required privileges; Row-Level Security enforced on key tables
- **Auto-start:** via `brew services`

**All tables (17):**

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
| `stream_tokens` | DB-backed gateway stream tokens with 30-min TTL (replaces in-memory dict) |

### pgvector

- **Version:** 0.8.1
- **Note:** requires manual dylib link after PostgreSQL upgrades. See `VERIFICATION.md`.

### Ollama Models

| Model | Size | Purpose |
|---|---|---|
| `qwen2.5:7b` | ~4.7GB | Primary reasoning |
| `qwen2.5:3b` | 1.9GB | Router/supervisor |
| `mxbai-embed-large:latest` | ~670MB | Embeddings (1024-dim) |
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
| `legionforge_oidc_client_secret` | OIDC client secret (`OIDCBackend`) |
| `legionforge_github_client_secret` | GitHub OAuth app client secret (`GitHubOAuthBackend`) |
| `legionforge_ldap_bind_password` | LDAP service-account bind password (`LDAPBackend`) |
| `legionforge_kerberos_keytab_path` | Path to HTTP keytab file; default `/etc/legionforge/http.keytab` (`KerberosBackend`) |
| `legionforge_telegram_token` | Telegram bot token from BotFather |
| `legionforge_telegram_api_key` | Gateway Bearer API key for `telegram-bot` gateway user |
| `legionforge_slack_bot_token` | Slack bot token (`xoxb-...`) |
| `legionforge_slack_app_token` | Slack app-level token for Socket Mode (`xapp-...`) |
| `legionforge_slack_api_key` | Gateway Bearer API key for `slack-bot` gateway user |
| `legionforge_webhook_api_key` | Gateway Bearer API key for `webhook-bot` gateway user |
| `legionforge_webhook_inbound_secret` | HMAC-SHA256 secret for inbound webhook verification |

---

## Daily Startup Sequence

```bash
source ~/.zshrc                          # loads POSTGRES_PASSWORD
cd /Volumes/MAC_MINI_1TB/LegionForge
source venv/bin/activate
make check                               # verify drive + config + keychain
make verify-tool-registry               # fail if any loaded tool is unregistered
make test-smoke                          # 2106 tests, ~17s
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

None. All known technical debt is resolved as of v1.0.1.

### Fixed (v1.0.1 — post-release patches, PRs #36–#42)

| Item | Fix | PR |
|---|---|---|
| 3 Ollama integration tests unconditionally skipped | `pytest.ini` session-scoped event loop (`asyncio_default_fixture_loop_scope=session`); all 3 Ollama tests fully implemented; 38/38 integration tests pass | #36 |
| Loop protection resets on checkpoint resume | `resume_run_config(thread_id)` in `safeguards.py` — passes `None` as graph input so LangGraph hydrates `step_count`/`action_history`/`token_count` from checkpoint rather than resetting | #39 |
| `model_integrity_strict` not deploy-time settable | `MODEL_INTEGRITY_STRICT=true` env var overrides YAML; `/status` surfaces per-model integrity results under `components.model_integrity` | #38 |
| Kerberos integration test DB queries used wrong API | Fixed `asyncpg` → `psycopg` cursor API (`%s` params, `conn.cursor()`, `cur.fetchone()`, `get_pool()`) | #40 |
| Kerberos live KDC not set up | MIT Kerberos 1.22.2 KDC running locally (user-owned, port 7088); `gssapi` built from source against MIT Kerberos (not macOS Heimdal); `make test-kerberos` target; full SCALING.md guide | #41 |
| `gateway_users.user_id UUID` rejects OAuth natural IDs | Changed to `TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text`; idempotent `ALTER TABLE` migration; all OAuth backends (`oidc`, `github`, `ldap`, `kerberos`) write "scheme:id" strings | #42 |
| `api_key_hash UNIQUE` blocks second OAuth user | Constraint dropped — multiple OAuth users share `[OAUTH-NO-KEY]` sentinel; bcrypt hashes are cryptographically unique without a DB constraint | #42 |
| `_KERBEROS_NO_KEY` sentinel inconsistent | Standardised to `[OAUTH-NO-KEY]` across all four OAuth backends; `ApiKeyBackend` sentinel guard handles all of them | #42 |

### Fixed (Phase 16)

| Item | Fix |
|---|---|
| No Telegram connector | `src/connectors/telegram.py` — `python-telegram-bot` polling; mirrors Discord pattern; edit-in-place with throttling; `make telegram-start` |
| No Slack connector | `src/connectors/slack.py` — `slack-bolt` Socket Mode (no public URL); update-in-place with throttling; `make slack-start` |
| No generic webhook connector | `src/connectors/webhook.py` — FastAPI :8081; `POST /inbound` accepts task+callback_url; HMAC-SHA256 verification (X-Hub-Signature-256); async background task → callback POST on complete; `make webhook-start` |
| `_load_secret` + `_consume_sse` duplicated in Discord | Extracted to `src/connectors/base.py`; all four connectors share the same helpers |
| No `ConnectorsConfig` in settings | `TelegramConfig`, `SlackConfig`, `WebhookConfig`, `ConnectorsConfig` added to `config/settings.py`; `connectors:` section in hardware profile YAML |

### Fixed (Phase 15)

| Item | Fix |
|---|---|
| Web UI was a minimal demo (no key persistence, no history, no cancel) | Full rewrite of `src/gateway/static/index.html` — localStorage API key + history (20 entries), agent type selector, cancel button (`DELETE /tasks/{id}`), tool call blocks, live elapsed timer, token count on complete, copy output, `Cmd/Ctrl+Enter` shortcut, auto-resize textarea, SSE retry on disconnect |

### Fixed (Phase 14)

| Item | Fix |
|---|---|
| Per-instance budget counter drift under concurrent load | `redis_budget_check_and_reserve()` / `redis_budget_release()` in `state.py`; `per_user_budget_check()` delegates to Redis when active — global INCRBY counter shared across all replicas |
| No Prometheus metrics on gateway | `GET /metrics` endpoint returns Prometheus text format (`src/gateway/metrics.py`; no new deps — inline formatter); `MetricsMiddleware` counts requests by method/path/status |
| No request correlation IDs | `RequestIDMiddleware` reads `X-Request-ID` header or generates UUID4; echoes on all responses; stored on `request.state.request_id` |
| Redis health not visible in `/status` | `_check_redis()` in `health.py` — independent PING check using `settings.gateway.redis_url`; `redis` component added to `/status` when configured |

### Fixed (Phase 12)

| Item | Fix |
|---|---|
| OAuth / LDAP auth not available | `src/gateway/backends/` package: `OIDCBackend` (JWKS/OIDC), `GitHubOAuthBackend` (opaque tokens), `LDAPBackend` (bind+search+rebind); set `gateway.auth_provider` in YAML |
| Wrong "output sanitization deferred" docs | Removed from `TLDR.md` and `PROJECT_STATUS.md`; `sanitize_output()` was fully implemented in Phase 9 |
| `require_user` Bearer-only | Updated to parse Bearer / Basic / Negotiate; delegates scheme to the active backend |
| `PyJWT` missing `[crypto]` extra | `PyJWT[crypto]~=2.8` — RS256/ES256 JWKS decode now works; `ldap3~=2.9` added |

### Fixed (Phase 11)

| Item | Fix |
|---|---|
| SecureToolNode silent failure on copy error | Both `model_copy()` and `copy()` failure now synthesizes a `ToolMessage` with sanitized content; dirty content can no longer leak into agent state |
| No integration tests | `tests/test_integration.py` — 38 tests (`@pytest.mark.integration`), covers auth, stream tokens, task lifecycle, budget enforcement, `/usage/me`, CLI, Ollama worker |
| `INTERVAL hours` not validated | Already parameterized + validated (`1–8760`) in `get_usage_summary()` / `get_threat_summary()` — removed from issues |
| Auth not modular | `AuthBackend` protocol + `ApiKeyBackend` + `get/set_auth_backend()` in `gateway/auth.py`; OAuth can be plugged in at startup |
| Gateway not containerized | `Dockerfile.gateway` added; `make build-gateway` + `make gateway-start-docker` |

### Fixed (Phase 10)

| Item | Fix |
|---|---|
| In-memory stream tokens lost on gateway restart | `stream_tokens` DB table; `create_stream_token` / `resolve_stream_token` / `delete_stream_token` backed by PostgreSQL |
| No per-user budget enforcement | `per_user_budget_check()` — 2 DB reads (actual_used + in_flight); raises RuntimeError → HTTP 429 at submission time |
| No user attribution on token spend | `api_usage.user_id` column; worker writes per-task attribution; `/usage/me` endpoint exposes per-user summary |
| Single-user gateway | `gateway_users.daily_token_limit` + `tasks.estimated_tokens` + `src/cli/manage_users.py` CLI |

### Fixed (Phase 9 + 9.5)

| Item | Fix |
|---|---|
| Rate limiter TOCTOU race | `DailyCounter.check_and_reserve()` atomically checks + reserves under lock; `guard()` always releases in `finally` |
| `/status` resource storm | 30 s TTL cache (`_status_cache_lock`); hits skip DB/Ollama/subprocess entirely |
| PII patterns incomplete | Added `[DB_DSN]`, `[PRIVATE_IP]` (RFC 1918 + loopback), `[HOME_PATH]` (`/Users/` + `/home/`) |
| Guardian tool args gap | `guardian_check()` now forwards real `tool_input`; checks 3, 5, 6 see actual arguments |
| Guardian action field hardcoded | `check_2` also blocks forbidden `tool_id`; `action` read from state (default `"invoke"`) |

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
