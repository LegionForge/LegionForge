# NEXT — Session Handoff
*Updated by Claude at end of each session. Read this first. Takes 30 seconds.*

---

## Last updated
2026-03-17 — UAT Day 3 complete. T2.5 ✅ T3.1–T3.5 ✅. 2 bugs fixed, 4 issues opened.

## State
- **Branch:** `dev` — 2 commits ahead of main (PRs #274 #278 open)
- **Smoke tests:** 2249/2249
- **Open PRs:** #274 (worker startup reap — closes #272), #278 (get_user_connection $1→%s)
- **Ship target:** v0.8.0 — Sunday 2026-03-22
- **Mode:** UAT + pre-v0.8.0 bug fixes

## UAT Day 3 issues opened (2026-03-17)
| Issue | Title | Priority |
|-------|-------|----------|
| #273 | Multi-node worker architecture — PostgreSQL LISTEN/NOTIFY + worker_nodes | post-v1.0 |
| #275 | Bump actions/checkout to Node.js 24 compatible version | post-v0.8.0 (deadline Jun 2026) |
| **#276** | **fanoutresearchers alias normalization bypassed — Guardian HALT on fan-out tasks** | **pre-v0.8.0 blocker** |
| #277 | Show logged-in username in UI header | pre-v0.8.0 |

## UAT Day 4 — start here (2026-03-18)

### 🔴 Priority 1: Merge PRs #274 + #278
Both are green. Merge, re-sync dev.

### 🔴 Priority 2: Fix #276 — fanoutresearchers alias normalization
`SecureToolNode._alias_map` builds `fanoutresearchers → fan_out_researchers` correctly,
but un-normalized name reaches Guardian. Investigate why `needs_rewrite` branch silently
fails, then add defensive fallback in `verify_tool_before_invocation`. Fix in `src/base_graph.py`
+ `src/security/core.py`. This blocks all orchestrator fan-out tasks.

### Priority 3: Fix #266 — HITL UI (pre-v0.8.0 blocker)
Header badge + admin queue panel + approve/reject modal.

### Priority 4: Fix #268 — persist tool call events

### Priority 5: Continue UAT T4 block (researcher + RAG)
- T4.1: researcher agent end-to-end (single web search task)
- T4.2: document ingestion + RAG retrieval
- T4.3: memory clear

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
| #272 ✅ | Worker startup stale task reap + LLM call timeout + asyncio cancellation | PR #274 open |

## UAT Day 3 — completed (2026-03-17)

### ✅ T2.5 — token budget
### ✅ T3.1–T3.5 — task management (list, notes, labels, cancel, sharing)

### Bugs found and fixed
- **get_user_connection `$1`→`%s`** — psycopg3 placeholder bug; caused HTTP 500 on all user-scoped writes (notes, annotations, sharing). PR #278.
- **#276** — fanoutresearchers reaches Guardian un-normalized; HALT fires on any orchestrator fan-out task. Issue open, not yet fixed.

### 🔴 Priority 1 (was): Fix #272 — worker startup stale task reap
On restart, worker must auto-fail `running` tasks older than 5 min before accepting queue.
This is a pre-v0.8.0 blocker — reproduced in UAT Day 2 via config change restart.
Fix is in `src/gateway/worker.py` startup path. After fix, add UAT test T_RESILIENCE.1.

### Priority 2: Fix #266 — HITL UI (pre-v0.8.0 blocker)
Add header badge + admin queue panel + approve/reject modal to index.html.
T_HITL.2 and T_HITL.3 are blocked on this.

### Priority 3: Fix #268 — persist tool call events
Agent events dispatched via `adispatch_custom_event` in base_graph.py are not written to task_events table. Also fix `steps` counter for sub-agent calls.

### Priority 4: Continue UAT T2.5 + T3 block
- T2.5: token budget check (one curl command — `GET /usage/me`)
- T3.1–T3.5: task management (Day 3 schedule block)

### Priority 3 (post-v0.8.0): Automated benchmark harness
> Jp's idea from UAT Day 2: "Is there a way to dynamically run 3-5 live-web queries
> in an automated fashion and measure how model/context/provider adjustments affect
> quality across multiple dimensions?"

**Answer: Yes. Design captured in jp.md "Automated Benchmark Harness" section.**

Dimensions to measure automatically (no human judgment needed):
- Tool call success rate (did step 1 call a tool, or did retry/fallback fire?)
- Grounding rate (did response cite URLs from fetched sources, not invented domains?)
- Fan-out completion rate (N/N researchers returned)
- Latency (wall clock, task submit → complete)
- Token count + estimated cost per provider
- Retry count (tool_call_retry events)

Dimensions requiring 1-min human scoring per run:
- Correctness (verify 1 fact against the actual source)
- Completeness (did it answer all sub-questions?)
- Quality (coherent, non-repetitive, well-organized)

Variables to sweep: model × context_size × provider

**GitHub issue to open:** `feat: benchmark eval harness for model/provider comparison`
**Milestone: v0.9.0** — not a blocker for v0.8.0

### Priority 3: Continue UAT T1.x
See jp_testing.md for full test matrix.

## Overnight review findings (still open)
Full reports in `docs/post_uat_review/`. Read before starting Day 1 UAT.
Summary of what must be fixed before v0.8.0 goes public:

| Priority | Finding | File |
|----------|---------|------|
| 🔴 Critical | `/docs` + `/redoc` live in production | `01_security.md` |
| 🔴 Critical | SSRF via `callback_url` — no IP validation | `01_security.md` |
| 🔴 Critical | Zero security response headers (CSP/HSTS/X-Frame) | `01_security.md` |
| 🔴 Critical | Plotly CDN load without SRI hash | `01_security.md` |
| 🔴 Critical | `smoke.yml` CI misses testlab/UI/bandit | `05_cicd.md` |
| 🔴 Critical | `--input-bg` CSS var undefined — inputs transparent | `06_uiux.md` |
| 🔴 Critical | HITL has no UI — safety flow requires raw curl | `06_uiux.md` |
| 🔴 Critical | WhatsApp HMAC uses wrong signing key | `02_stability.md` |
| 🟠 Blocker | `jp-cruz` identity in A2A Agent Card | `01_security.md` |
| 🟠 Blocker | `make briefing` hardcodes LegionForge/LegionForge | `05_cicd.md` |
| 🟠 Bug | `get_maintenance_pool()` undefined — bulk_delete crashes | `03_efficiency.md` |
| 🟠 Bug | Orchestrator JWT cross-contamination under concurrency | `02_stability.md` |
| 🟠 Bug | Auth does full table scan on every request | `03_efficiency.md` |

## Do these in order — Day 1 (today, 2026-03-15)

1. **Read `docs/post_uat_review/README.md`** — 5 min skim of all 7 findings files ✅ Done (session start)
2. ~~**T0.1 — Rename PostgreSQL `jp` → `legionforge_admin`**~~ ✅ **DONE (2026-03-15)**
   - PG user renamed via `jpc` superuser over TCP
   - `~/.pgpass` updated, `POSTGRES_USER=legionforge_admin` added to `.env`
   - Makefile updated (pgpass awk pattern + pg_isready fallback)
   - TEMPORARY test removed from test_smoke.py; baseline now 2246
   - All `jp` DB user references scrubbed from docs and source
3. **T9 — Observability sanity checks** (5 min, baseline before anything else)
4. **T1.1–T1.5 — Core task flow** (jp_testing.md Priority 1)

See jp_testing.md for full 8-day schedule. Fill in the Test Run Log as you go.

## Pre-v0.8.0 fix queue (open GitHub issues for each before acting)

From overnight review — these need issues before any code is written:
- Fix `/docs`/`/redoc` disable in gateway/app.py (1-liner)
- Add `validate_fetch_url()` at callback_url submission time
- Add security response headers middleware (CSP, HSTS, X-Frame-Options, etc.)
- Add SRI hash to Plotly CDN script tag
- Fix WhatsApp HMAC to use app secret, not bearer token
- Add `--input-bg` CSS variable to all themes
- Add basic HITL approve/reject UI panel
- Fix `get_maintenance_pool()` missing function
- Fix orchestrator module-level JWT dicts (concurrent task contamination)
- Fix auth full-table scan (add `WHERE username = $1`)
- Remove jp-cruz from A2A Agent Card
- Fix `make briefing` hardcoded repo reference
- Fix `smoke.yml` to run full `make ci` suite

## On deck (post-UAT, pre-v0.8.0)
- Telegram connector: bot token + gateway user not yet configured
- Cloud API keys: Anthropic + OpenAI in Keychain (waiting on keys)
- Demo/README: screenshot or GIF for public README
- MCP memory server setup: `@modelcontextprotocol/server-memory` pointed at shared JSONL
- JP_CONTEXT.md: finalize and store in Obsidian

## Post-v0.8.0 backlog (do not act on before ship)
- Agent/skill marketplace architecture (see `07_agent_marketplace.md` — 600 lines)
- HITL UI panel (full workflow, not just approve/reject buttons)
- bcrypt async in auth handlers (blocks event loop 100–300ms)
- Missing index on `api_usage.user_id`
- LangGraph graph compilation caching
- Property-based/fuzzing tests for security core (Hypothesis)
- HITL automated test (LangGraph halt → approve → resume)
- 6 proposed GitHub Actions workflows (see `05_cicd.md`)
- Mobile/responsive UI pass
- 381-panel admin search/filter

## At v0.8.0 — Public Release Prep (do in order, before transfer)

1. **Install git-filter-repo**
   ```bash
   pip install git-filter-repo
   ```

2. **Create safety backup branch**
   ```bash
   git branch backup-pre-rewrite
   ```

3. **Rewrite history** — removes all jp-cruz / jp@legionforge.org identity traces
   ```bash
   git filter-repo \
     --name-callback '
   name_map = {
       b"jp-cruz":  b"Jp Cruz",
       b"Jp Cruz": b"Jp Cruz",
       b"Jp":       b"Jp Cruz",
   }
   return name_map.get(name, name)
   ' \
     --email-callback '
   email_map = {
       b"jp@legionforge.org": b"jp@legionforge.org",
       b"115298310+jp-cruz@users.noreply.github.com": b"jp@legionforge.org",
   }
   return email_map.get(email, email)
   ' \
     --message-callback '
   return message.replace(b"jp-cruz/dev", b"dev").replace(b"jp-cruz/", b"")
   ' \
     --force
   ```

4. **Verify clean**
   ```bash
   git log --format="%an <%ae>" | sort -u
   git log --format="%s" | grep -i "jp-cruz\|legacy"
   # Expected: no output
   ```

5. **Re-add remote + force push**
   ```bash
   git remote add origin https://github.com/LegionForge/LegionForge.git
   git push origin main dev --force
   ```

6. **Transfer repo on GitHub** — LegionForge/LegionForge → Settings → Transfer → LegionForge

7. **Update local remote**
   ```bash
   git remote set-url origin https://github.com/LegionForge/LegionForge.git
   git push origin main dev
   ```

8. **Re-add GitHub Actions secrets** in LegionForge/LegionForge → Settings → Secrets:
   - `GUARDIAN_SYNC_PAT`

9. **Cleanup**
   ```bash
   git branch -D backup-pre-rewrite
   # Archive jp-cruz/LegionForge (teaser repo — now redundant)
   ```

## How to use this file
- **Start of session:** `make briefing` → tell Claude: `read NEXT.md and tell me where we are`
- **End of session:** tell Claude: `update NEXT.md`
