# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

A local-first, security-native AI agent framework for Apple Silicon Macs, built on LangGraph. Agents run local LLMs (Ollama) or cloud APIs. Security is baked in at every layer — not bolted on.

Read `TLDR.md` for orientation, `PHASE_PLAN.md` for the roadmap, `CONTRIBUTING.md` for branch/commit conventions.

## Common Commands

All development commands run through the Makefile. Always activate the venv first: `source venv/bin/activate`.

```bash
# Development
make check          # Verify drive, venv, models, config before starting
make start          # Full startup (drive check → Ollama → PostgreSQL → model warmup)
make stop           # Graceful shutdown

# Testing
make test-smoke     # 2247 smoke tests, ~21s, no external services required
make test-critical  # smoke + security_attacks + UI page-load, ~35s — fast iteration gate
make test           # Full suite: smoke → testlab → ui (separate sessions, ~70s)
make test-integration  # 41 integration tests (requires PostgreSQL — make db-start first)
make test-fast      # smoke + testlab(not slow) + ui

# CI gate — run this before every commit, not just test-smoke
make ci             # make test + security-audit (bandit + URI scan) — required before merge

# Code quality
make lint           # Black formatter check (src/, tests/, config/)
make format         # Auto-format with Black
make security-audit # smoke tests + bandit + URI scan

# Database
make db-init        # Initialize PostgreSQL + LangGraph + app tables (one-time)
make db-start       # Start PostgreSQL service

# Health & gateway
make health         # Quick liveness check (localhost:8765/health)
make status         # Full system status
make health-server  # Start health API server (localhost:8765)
make gateway-start  # Start gateway API (localhost:8080)
make discord-start  # Start Discord connector bot

# Run a single test
pytest tests/test_smoke.py::test_injection_detection_positive -v
```

## Architecture

### Core Design Principles
- Fail-safe tiering: halt → sandbox/retry → degrade (never silently succeed)
- Human gates on all mutations
- Replace AI with determinism wherever possible
- Validate at trust boundaries, not at processing nodes
- Privilege tied to tasks, not persistent to agents

### Key Modules

**`config/settings.py`** — Pydantic singleton loaded from a hardware YAML profile. Import as `from config.settings import settings`. All memory limits, model names, safeguard thresholds, and paths come from here. Active profile: `config/hardware_profiles/mac_m4_mini_16gb.yaml`. Switch profiles via `export AGENT_HARDWARE_PROFILE=<name>`.

**`src/base_graph.py`** — The LangGraph template. Copy this when creating new agents. It wires in three-layer loop protection, token budgeting, per-run tracing toggle, TOCTOU snapshot, and Guardian pre-invocation check automatically.

**`src/security/core.py`** — API key management via macOS Keychain (no `.env` secrets), prompt injection detection (29 patterns, Tier 1/2 tiering), and PII redaction. All inputs must pass through `sanitize_input()` before use; all outputs through `sanitize_output()` before logging to LangSmith.

**`src/security/guardian.py`** — Guardian FastAPI sidecar (:9766). 7-check deterministic pipeline (no LLM in hot path): tool revocation, hash validation, capability boundary, destructive pattern detection, sequence contracts, Ed25519 verification, adaptive threat rules. Rules hot-reload every 10s from `threat_rules` table.

**`src/safeguards.py`** — Three independent loop-protection layers:
1. Step counter (LangGraph recursion limit — hard stop)
2. Action history loop detection (MD5 hash of tool call signatures, window=5, threshold=3)
3. Token budget guard (alert at 80%, force-end at 100%)

**`src/database.py`** — Async PostgreSQL pool (admin + restricted app roles), LangGraph `AsyncPostgresSaver` for checkpoint-based graph resumption, pgvector for RAG, 16 tables. Key tables: `api_usage`, `health_metrics`, `documents` (768-dim HNSW), `threat_events`, `audit_log` (SHA-256 hash chain), `tasks`, `gateway_users`.

**`src/llm_factory.py`** — Unified factory for Ollama (local) + OpenAI + Anthropic. Reads all config from the hardware profile. Supports cloud fallback when local models are insufficient.

**`src/rate_limiter.py`** — Per-provider rate limits with pre-execution token cost estimation. Hard daily caps with 80%/100% alert thresholds. Prevents resource bombs before LLM calls are made.

**`src/gateway/app.py`** — FastAPI gateway (:8080). Task submission queue, SSE streaming, minimal web UI, A2A + MCP endpoints, Bearer token auth.

**`src/connectors/discord.py`** — Discord bot connector. Bridges `!<task>` messages → gateway → SSE stream → reply edits.

### Threat Event Logging
Security violations are logged to the `threat_events` table with structured types: `INJECTION_DETECTED`, `TOOL_HASH_MISMATCH`, `PREFLIGHT_BUDGET_EXCEEDED`, `PII_REDACTED`, `LOOP_DETECTED`, `STEP_LIMIT_REACHED`, `TOKEN_BUDGET_EXCEEDED`, `TOOL_ARG_INJECTION`, `TOOL_RESULT_INJECTION`, `MODEL_INTEGRITY_MISMATCH`. This feeds the Phase 4 Threat Analyst agent.

### Infrastructure Dependencies
- **PostgreSQL 17** (Homebrew) — database: `legionforge`; password in macOS Keychain (`service: postgres`)
- **Ollama** — local LLM runtime; primary `llama3.1:8b`, router `qwen2.5:3b`, embeddings `nomic-embed-text`; models at `/Volumes/MAC_MINI_1TB/ollama_models/`
- **Docker Desktop** — required for Guardian sidecar (`make guardian-start`)

## Phase Status

- **Phases 0–16** ✅ Complete: Full security stack, multi-user gateway, integration tests, modular auth, containerized gateway, multi-provider auth registry, Redis-backed state layer, real Kerberos GSSAPI backend, multi-instance docker-compose, Redis global budget counters, Prometheus /metrics endpoint, request trace ID middleware, polished web UI, Telegram/Slack/Webhook channel connectors. 492/492 smoke tests, 38/38 integration tests, 5/5 Kerberos live-KDC tests.
- **Phases 60–381 + G1–G4 + H + I + J + HITL** ✅ Complete: 381-tool operator dashboard, web_fetch_js headless browser, Guardian G4 (published to PyPI as `legionforge-guardian`, public repo live at LegionForge/LegionForge-Guardian, auto-sync Action), agent memory all 5 gaps, dual license (AGPLv3 + commercial), session continuity UI, multi-modal image input, HITL approval gate, WhatsApp connector. 2247/2247 smoke tests, 79/79 tool accuracy tests, 114/114 crystallization tests.

## Branch & Commit Conventions

- `main` ← `dev` ← `feature/xxx` / `fix/xxx` / `refactor/xxx`
- Smoke test count must never decrease; current baseline: 2247 (v0.7.1-alpha, post-WhatsApp + HITL)
- **Gate before every commit: `make ci`** (smoke → testlab → ui + bandit + URI scan). `make test-smoke` alone is not sufficient — cross-suite event loop issues only appear in the full run.
- One concern per commit/PR. Do not bundle UI changes, agent logic changes, and test changes in a single commit. If a fix touches more than two files, ask whether it should be split.
- Commit messages follow conventional commits (`feat:`, `fix:`, `chore:`, `security:`, `docs:`)
- Co-author line: `Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>`

## Working with Claude

Before making any code change, Claude must:
1. **State a test plan** — which existing tests cover the behavior, which new tests will be added, and how the fix will be verified end-to-end (not just unit-level).
2. **Run `make ci` before committing** — all three test suites (smoke, testlab, ui) plus security-audit must pass. Smoke-only is insufficient.
3. **Prefer narrowly scoped fixes** — fix the specific code path that is broken, not every related path. If a fix touches agent prompts or LLM calls, also verify with a live gateway task (not just mocks).
4. **Flag cross-suite risk** — any change to asyncio code, event loop handling, pytest fixtures, or the conftest files must note the cross-suite isolation risk and be verified with `make test`.

Common failure patterns to check for every agent/LLM change:
- What does this code path do if the LLM returns no `tool_calls`? (use `mock_llm_no_tool_calls` fixture)
- Does the fix apply through the gateway worker `initial_state` path, not just direct invocation?
- Does adding async fixtures to a test file break isolation when run with `pytest tests/`?

## Checkpoint File (`checkpoint.md`)

Update `checkpoint.md` in the project root after every major operation. Major operations include:
- Any PR merged to main
- Any phase completed
- Any commit that changes test counts, phase status, or core architecture

Fields to update each time:
```
VERSION: <semver>
UPDATE: <increment by 1>
BRANCH: <current branch>
COMMIT: <current HEAD hash>
TIMESTAMP: <ISO 8601 UTC>
LAST_OP: <one-line description of what just happened>
SMOKE_TESTS: <passing>/<total>
INTEGRATION_TESTS: <passing>/<total> (+ <N> skipped — reason)
```

The checkpoint file is a fast-reference state record. Keep it current — stale checkpoints are useless.
