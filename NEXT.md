# NEXT — Session Handoff
*Updated by Claude at end of each session. Read this first. Takes 30 seconds.*

---

## Last updated
2026-03-17 03:45 UTC — UAT Day 4 (partial). PRs #274 #278 merged. Fix #276 committed (PR #279 open). Copy output bug fixed. `make briefing` overhauled.

## State
- **Branch:** `dev` — 4 commits ahead of main (PR #279 open)
- **Smoke tests:** 2251/2251
- **Open PRs:** #279 (fanoutresearchers alias fix — closes #276)
- **Ship target:** v0.8.0 — Sunday 2026-03-22
- **Mode:** UAT + pre-v0.8.0 bug fixes

## UAT Day 5 — start here (2026-03-18)

### 🔴 Priority 1: Merge PR #279 + restart servers
PR is green. Merge, re-sync dev, then restart gateway (`make servers-start`) so the fanoutresearchers fix is live.

### 🔴 Priority 2: Retest #276 — fanoutresearchers
After servers restart, resubmit the HackerNews headlines task. Should complete without HALT.

### 🔴 Priority 3: Fix #266 — HITL UI (pre-v0.8.0 blocker)
Header badge + admin queue panel + approve/reject modal.

### Priority 4: Fix #268 — persist tool call events
Agent events not written to task_events table. Fix steps counter for sub-agent calls.

### Priority 5: `make sanity` / runtime health target
Raised during UAT Day 4: smoke tests don't catch runtime failures (service down, invalid API key, DB unreachable). Design and add a `make sanity` target — 30s real checks: gateway /health, DB ping, valid API key round-trip, Ollama model loaded. This would have caught today's invalid credentials issue immediately.

### Priority 6: Fix postgres Keychain item missing
`security find-generic-password -s postgres -a api_key` returns not found. Password only lives in `~/.pgpass`. CLI tools (`make rotate-key`, `make create-user`) fail unless `POSTGRES_USER` + `POSTGRES_PASSWORD` are manually exported. Need to store the admin password in Keychain so CLI tools work without manual env setup.

### Priority 7: Continue UAT T4 block (researcher + RAG)
- T4.1: researcher agent end-to-end (single web search task)
- T4.2: document ingestion + RAG retrieval
- T4.3: memory clear

---

## UAT Day 4 — completed (2026-03-17, partial session)

### ✅ Merged
- PR #274 (worker startup reap — closes #272)
- PR #278 (get_user_connection %s — psycopg3 placeholder)
- dev re-synced with origin/main

### ✅ Fixed and committed
- **#276 fanoutresearchers Guardian HALT** — PR #279 open, not yet merged
- **copyOutput copies only status lines** — committed to dev (8ac416f)
- **`make briefing` overhaul** — hardcoded repo, stale NEXT.md grep, sync check, end-of-session reminders

### 🔴 Still open
- **#276** — PR #279 open; servers need restart after merge to pick up fix
- **Invalid credentials / Keychain gap** — `postgres` Keychain item missing; `make rotate-key` requires manual env export (see Priority 6 above)

---

## UAT Day 3 issues opened (2026-03-17)
| Issue | Title | Priority |
|-------|-------|----------|
| #273 | Multi-node worker architecture — PostgreSQL LISTEN/NOTIFY + worker_nodes | post-v1.0 |
| #275 | Bump actions/checkout to Node.js 24 compatible version | post-v0.8.0 (deadline Jun 2026) |
| **#276** | **fanoutresearchers alias normalization bypassed — Guardian HALT on fan-out tasks** | **pre-v0.8.0 blocker — PR #279 open** |
| #277 | Show logged-in username in UI header | pre-v0.8.0 |

## UAT Day 2 issues opened (2026-03-16)
| Issue | Title | Priority |
|-------|-------|----------|
| #263 ✅ | HITL scope clarification — FORCE-END vs HITL-REVIEW tiers | merged |
| #265 | False negative: leetspeak bypasses gateway injection filter | post-v0.8.0 |
| #266 | HITL UI — badge + queue panel + approve/reject modal | pre-v0.8.0 blocker |
| #268 | Persist tool call events to task_events + fix steps counter | pre-v0.8.0 |
| #269 | UI call tree (i) badge — tool calls, steps, sources per task | pre-v0.8.0 |
| #270 | Multi-model behavioral matrix — tool-block hallucination | research/post |
| #271 | Researcher agent should return source citations | post-v0.8.0 |
| #272 ✅ | Worker startup stale task reap + LLM call timeout + asyncio cancellation | merged |

---

## On deck (post-UAT, pre-v0.8.0)
- Telegram connector: bot token + gateway user not yet configured
- Cloud API keys: Anthropic + OpenAI in Keychain (waiting on keys)
- Demo/README: screenshot or GIF for public README

## Post-v0.8.0 backlog (do not act on before ship)
- Agent/skill marketplace architecture
- bcrypt async in auth handlers
- Missing index on `api_usage.user_id`
- LangGraph graph compilation caching
- Property-based/fuzzing tests for security core (Hypothesis)
- HITL automated test (LangGraph halt → approve → resume)
- 6 proposed GitHub Actions workflows
- Mobile/responsive UI pass
- 381-panel admin search/filter
- Automated benchmark harness (model × context × provider sweep)

## At v0.8.0 — Public Release Prep
See bottom of previous NEXT.md for full history rewrite + org transfer steps.

## How to use this file
- **Start of session:** `make briefing` → tell Claude: `read NEXT.md and tell me where we are`
- **End of session:** tell Claude: `update NEXT.md`
