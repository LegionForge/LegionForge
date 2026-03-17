# NEXT — Session Handoff
*Updated by Claude at end of each session. Read this first. Takes 30 seconds.*

---

## Last updated
2026-03-17 22:30 UTC — UAT Day 4. Guardian DB connectivity fixed. Alias normalization confirmed working. New pre-v0.8.0 blocker found: orchestrator synthesis bug (system prompt contradicts step-2). T4.1 still blocked.

## State
- **Branch:** `dev` — 7 commits ahead of main + 1 uncommitted change (Makefile)
- **Smoke tests:** 2251/2251
- **Open PRs:** none (PR #279 merged)
- **Uncommitted:** `Makefile` — `guardian-start` POSTGRES_USER fix (needs commit + PR)
- **Ship target:** v0.8.0 — Sunday 2026-03-22
- **Mode:** UAT + pre-v0.8.0 bug fixes

## UAT Day 5 — start here (2026-03-18)

### 🔴 Priority 1: Commit Makefile guardian-start fix + open synthesis issue
Two things before any testing:
1. Commit the Makefile change (`export POSTGRES_USER=legionforge_guardian` in `guardian-start`)
2. Open a GitHub issue for the orchestrator synthesis bug. Spec is ready:
   - **Problem:** System prompt says "MUST call a tool on every response" — contradicts step-2 synthesis. After `fan_out_researchers` returns results, the LLM produces "I've called all the necessary tools..." instead of synthesizing.
   - **Fix:** On step 2+, when last message is a ToolMessage, inject a synthesis HumanMessage overriding the tool-call mandate before the LLM call.
   - **Scope:** One targeted block in `agent_node` in `src/agents/orchestrator.py`.
   - **Done when:** HackerNews prompt returns actual analysis, not placeholder.

### 🔴 Priority 2: Fix orchestrator synthesis bug (pre-v0.8.0 blocker)
After opening the issue, implement the fix. See spec in Priority 1. Run `make test-critical` before committing.

### 🔴 Priority 3: Retest T4.1 after synthesis fix
Resubmit the HackerNews headlines task. Should complete with actual research output.

### 🔴 Priority 4: Fix #266 — HITL UI (pre-v0.8.0 blocker)
Header badge + admin queue panel + approve/reject modal.

### Priority 5: Fix #268 — persist tool call events
Agent events not written to task_events table. Fix steps counter for sub-agent calls.

### Priority 6: `make sanity` / runtime health target
30s real checks: gateway /health, DB ping, valid API key round-trip, Ollama model loaded. Catches infrastructure failures that smoke tests miss.

### Priority 7: Fix postgres Keychain item missing
`security find-generic-password -s postgres -a api_key` returns not found. Password only lives in `~/.pgpass`. CLI tools (`make rotate-key`, `make create-user`) fail unless `POSTGRES_USER` + `POSTGRES_PASSWORD` are manually exported.

### Priority 8: Continue UAT T4 block (after synthesis fix)
- T4.1: researcher agent end-to-end (single web search task) — **currently blocked**
- T4.2: document ingestion + RAG retrieval
- T4.3: memory clear

---

## UAT Day 4 — completed (2026-03-17, second session)

### ✅ Fixed
- **Guardian POSTGRES_USER override** — `.env` sets `POSTGRES_USER=legionforge_admin` which docker-compose was substituting into `${POSTGRES_USER:-legionforge_guardian}`, connecting Guardian as the wrong role. Fixed: `guardian-start` now explicitly exports `POSTGRES_USER=legionforge_guardian`. Makefile modified, **not yet committed**.
- **Alias normalization confirmed working** — After Guardian restart, Guardian logs show `fan_out_researchers` (canonical name) in `/check` requests. The PR #279 normalization fix works end-to-end.

### 🔴 New blocker found
- **Orchestrator synthesis bug** — After `fan_out_researchers` runs (363s, 46K tokens), orchestrator LLM returns "I've called all the necessary tools to provide you with the information you requested about Y Combinator." Root cause: `_ORCHESTRATOR_SYSTEM_CONTENT` says "MUST call a tool on EVERY response — never answer from memory." This contradicts step-2 synthesis. No GitHub issue yet — open at start of Day 5.

### Root cause chain for #276 (full post-mortem)
What looked like one bug was actually three separate failures:
1. **Alias normalization** — qwen2.5 strips underscores (`fan_out_researchers` → `fanoutresearchers`). Fixed in PR #279 (SecureToolNode + verify_tool_before_invocation fallback).
2. **Guardian DB connectivity** — `POSTGRES_USER` from `.env` overrode docker-compose default, Guardian connected as `legionforge_admin` (wrong role, auth failed), cache stayed empty → all tools blocked. Fixed in Makefile.
3. **Orchestrator synthesis** — After tools ran, system prompt prevented LLM synthesis. New issue TBD.

---

## UAT Day 3 — completed (2026-03-17, first session)

### ✅ Merged
- PR #274 (worker startup reap — closes #272)
- PR #278 (get_user_connection %s — psycopg3 placeholder)
- PR #279 (fanoutresearchers alias normalization — closes #276)
- dev re-synced with origin/main after each merge

### ✅ Fixed and committed
- **#276 fanoutresearchers Guardian HALT** — PR #279 merged
- **copyOutput copies only status lines** — committed (8ac416f)
- **`make briefing` overhaul** — hardcoded repo, stale NEXT.md grep, sync check, end-of-session reminders

---

## UAT issues log

### Opened Day 4 (2026-03-17, session 2)
| Issue | Title | Priority |
|-------|-------|----------|
| TBD | Orchestrator synthesis — system prompt contradicts step-2 LLM call | **pre-v0.8.0 blocker — open at start of Day 5** |

### Opened Day 3 (2026-03-17, session 1)
| Issue | Title | Priority |
|-------|-------|----------|
| #273 | Multi-node worker architecture — PostgreSQL LISTEN/NOTIFY + worker_nodes | post-v1.0 |
| #275 | Bump actions/checkout to Node.js 24 compatible version | post-v0.8.0 (deadline Jun 2026) |
| #276 ✅ | fanoutresearchers alias normalization bypassed — Guardian HALT on fan-out tasks | pre-v0.8.0 blocker — merged PR #279 |
| #277 | Show logged-in username in UI header | pre-v0.8.0 |

### Opened Day 2 (2026-03-16)
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
- **Cloudflare bypass for `web_fetch_js` / headless browser** — some sites using Cloudflare CDN/bot protection block headless Chromium. Evaluate whether `web_fetch_js` needs stealth mode (e.g. undetected-chromedriver, playwright-stealth, or a dedicated bypass layer). Research refs:
  - https://stackoverflow.com/questions/68289474/selenium-headless-how-to-bypass-cloudflare-detection-using-selenium
  - https://www.zenrows.com/blog/selenium-cloudflare-bypass
  - https://www.nstbrowser.io/en/wiki/headless-browser-cloudflare-bypass-python-guide-2025
  - https://github.com/luminati-io/bypass-cloudflare

## At v0.8.0 — Public Release Prep
See bottom of previous NEXT.md for full history rewrite + org transfer steps.

## How to use this file
- **Start of session:** `make briefing` → tell Claude: `read NEXT.md and tell me where we are`
- **End of session:** tell Claude: `update NEXT.md`
