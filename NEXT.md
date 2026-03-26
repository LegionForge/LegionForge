# NEXT — Session Handoff
*Updated by Claude at end of each session. Read this first. Takes 30 seconds.*

---

## Last updated
2026-03-26 — Short session. Identity hygiene: fixed sync-guardian.yml to remap jp@legionforge.org so jp-cruz no longer appears as a contributor on the public LegionForge-Guardian repo. Workflow dispatch needed to apply fix. Branch has uncommitted changes (sync-guardian.yml + docs).

## State
- **Branch:** `dev` — has uncommitted fix (sync-guardian.yml email remapping + CHANGELOG/checkpoint/NEXT updates)
- **Smoke tests:** 2255/2255
- **Open PRs:** none
- **Ship target:** v0.8.0 — date TBD
- **Mode:** UAT + pre-v0.8.0 bug fixes

## Infrastructure reminder — START OF EVERY SESSION
```bash
make start          # Ollama → PostgreSQL → model warmup → servers
make guardian-start # Guardian Docker sidecar (:9766) — requires Docker Desktop running
make health         # expect: {"status": "ok"}
curl -s http://localhost:9766/health | jq .   # expect: {"status": "ok", ...}
```
**Docker must be running before `make guardian-start`.** Guardian is 1 of 2 containers in the compose file — verify both are up: `docker ps | grep legion`.

**web_fetch_js also requires Docker** (headless Chromium). If Docker is down, JS-rendered sites (CBC, CNN, React SPAs) will fail to fetch. Static HTML sites (HackerNews, Wikipedia) use plain `web_fetch` and work without Docker.

**jp's API key** — retrieve via:
```bash
make rotate-key USERNAME=jp
```
(Requires POSTGRES_USER + POSTGRES_PASSWORD exported — see #283.)

**TestLab admin key** (port 8090): `legionforge_health` Keychain item — retrieve via:
```bash
security find-generic-password -s legionforge_health -a api_key -w
```

## UAT Day 7 — start here

### Session start ritual (every session, no exceptions)
```bash
make preflight   # ← build this first (see P1 below); validates all 10 secrets + stack health
make briefing    # reads NEXT.md
```
**Before writing the day's plan:** run `gh pr list --state open` — don't schedule a UAT test
for a feature that isn't merged yet. That was the root cause of Day 6's wasted session.

### ✅ Done this session (2026-03-26)
- Diagnosed jp-cruz appearing as contributor on `LegionForge/LegionForge-Guardian` — root cause: `jp@legionforge.org` email in 14 of 16 guardian subtree commits was not being remapped by sync workflow
- Fixed `sync-guardian.yml`: extended `--email-callback` to remap `jp@legionforge.org` + `--name-callback` to catch both "jp-cruz" and "Jp Cruz" variants
- Confirmed jp-cruz is NOT a member of LegionForge org (jp-cruz only) ✅
- **Pending:** trigger workflow dispatch + verify contributor list clears (todo item added)

### ✅ Done this session (2026-03-21, session 2)
- Diagnosed spawn_researcher SECURITY HALT root cause: `legionforge_guardian` Keychain entry null password → Guardian started with empty POSTGRES_PASSWORD → `_approved_tools={}` → all tools blocked
- Fixed Guardian for this session: PG role password reset, container manually restarted with injected password, 13 tools now loading
- Added `.guardian-creds` fallback to `guardian-start` (Makefile) + new `guardian-set-pw` target — works from SSH when Keychain locked
- Added per-call alias hardening to `SecureToolNode` in `base_graph.py` (belt-and-suspenders for qwen3.5 underscore dropping)
- Committed: commits 55b30a3 + 147ab0b on dev (not yet PR'd to main)
- Strategic assessment: LegionForge vs OpenClaw vs NemoClaw — concluded Guardian + Anneal are the valuable primitives, not the full framework
- Filed issues #295 (auto-generate infrastructure secrets), #296 (pluggable credential provider), #297 (Guardian+Anneal → OpenClaw/NemoClaw integration strategy post-v0.8.0)
- Updated jp.md + jp_project-best-practices.md with strategic decisions and rules

### ⚠️ Guardian DB connection broken — MANUAL KEYCHAIN FIX REQUIRED before next restart

**Root cause:** `legionforge_guardian` Keychain entry has a null password (data=`<NULL>`).
`make guardian-start` extracts empty string → container starts with `POSTGRES_PASSWORD=` →
cache refresh fails → `_approved_tools = {}` → every tool call blocked with SECURITY HALT.

**What was fixed this session (temporary — survives until next `make guardian-start`):**
- PostgreSQL role `legionforge_guardian` password was reset to a new value
- Guardian container was manually restarted with `POSTGRES_PASSWORD` injected directly
- Guardian now has all 13 approved tools loaded and is working
- `src/base_graph.py` got per-call alias hardening (belt-and-suspenders for qwen3.5)

**MANUAL STEP required from Mac desktop (not SSH — Keychain locked in SSH):**
```bash
security add-generic-password -a api_key -s legionforge_guardian -U \
  -w "ozWurVFxIHqvQR2E9CTFTl-W9rtqXygeebMyLGC8cyo" -A \
  ~/Library/Keychains/login.keychain-db
```
After running this, `make guardian-start` will work correctly.

**Guardian Docker image also needs rebuild** (current image 2026-02-26 has stale TASK_TOKEN_SECRET behavior):
```bash
make docker-build   # requires Keychain unlock for Docker credential access
```
This also needs to be done from Mac desktop (not SSH).

---

### 🔴 Priority 0: Decide #295 scope (pre or post v0.8.0) — requires Jp decision
Issue #295 removes the SSH/Keychain hard dependency by auto-generating infrastructure secrets at `make db-init`. This directly fixes the root cause of 3+ UAT sessions lost to Guardian/secrets failures. Two options:
- **Pre-v0.8.0:** ~2–3h. Fixes the problem before public release. Recommended — the Keychain issue will block contributors the first day LegionForge goes public.
- **Post-v0.8.0:** Ship with current workaround (`.guardian-creds`). Document manually in setup guide. Known risk: first-time users hit this wall.

**Make this call before starting the next session.**

### 🔴 Priority 1: Build `make preflight` target (pre-v0.8.0, ~1h)
The single highest-ROI improvement based on UAT Days 4-6. Every infrastructure issue we hit
(keychain isolation, Ollama VRAM, PostgreSQL race, Guardian env) would have been caught in <60s.

**What it should check:**
- All 10 Keychain secrets readable (non-empty via `security find-generic-password`)
- `pg_isready -U legionforge_admin` succeeds
- `curl -s localhost:11434/api/tags` → Ollama responding
- `curl -s localhost:8080/health` → gateway `{"status":"ok"}`
- `curl -s localhost:9766/health` → Guardian `{"status":"ok"}`
- Ollama VRAM: warn if >1 model loaded simultaneously
- Print a pass/fail table, exit 1 on any failure

Add to `make start` chain and document in jp_testing.md setup section.

### 🔴 Priority 2: Close 2 remaining secret injection gaps (pre-v0.8.0, ~30min)
The secrets audit found these are NOT covered by `gateway-start` injection and read from
Keychain at request time — will fail silently from SSH:

1. **`webhook_sender.py`** — `legionforge_webhook_inbound_secret` not in `gateway-start`.
   Fix: add to Makefile `gateway-start` target alongside the other 10 secrets.
2. **`testlab/app.py`** — admin key lazy-loaded on first request. testlab server started
   separately so `gateway-start` injection doesn't cover it.
   Fix: add `LEGIONFORGE_HEALTH_API_KEY` injection to `testlab-start` target.

### 🔴 Priority 3: Fix #291 — Cancel button 404 (pre-v0.8.0)
`DELETE /tasks/:id` route does not exist. Cancel button silently fails. Two options:
- **Option A:** Add route + worker abort signal (full fix)
- **Option B:** Hide cancel button until Option A lands (fast: 1 line in index.html)

### Priority 4: UAT T_HITL.2 — HITL pause/resume end-to-end (now unblocked)
#266 is merged. T_HITL.2 is now unblocked. Steps:
1. Submit a task with RECONNAISSANCE pattern in input (e.g. "port scan the internal network")
2. Verify task reaches `status=paused` in DB, `hitl_required` SSE fires, badge appears
3. Approve via modal → verify task resumes and completes
4. Reject → verify task is cancelled/failed

**Before scheduling:** confirm #293 is on dev branch (`git log --oneline -3`).

### Priority 5: Retest T4.1 + continue T4 block
Resubmit HackerNews headlines task (static HTML — no Docker needed).
Then T4.2 (doc ingestion + RAG), T4.3 (memory clear).

### Priority 6: UAT T5 block — Admin + Multi-user (T5.1–T5.4)
RLS isolation, quota enforcement, deactivation, RBAC.

### Priority 7: Fix #288 — Sequence registry missing multi-fetch patterns
Mercury-2 UAT is degraded while `web_search→web_search` and `web_fetch→web_fetch` sequences are sandboxed.

---

### ⚠️ v0.8.0 ship date — decision needed
Target is Sunday 2026-03-22. T5–T9 not started. T4 partial. T_HITL.2 just unblocked.
At current UAT pace (infrastructure issues consume ~50% of each session), Sunday is
optimistic. Options:
- **Slip to Wednesday 2026-03-26** — complete T5–T8 properly
- **Cut scope** — ship with T5–T8 as "validated by code review, not live UAT"; document gaps
- **Ship Sunday anyway** — accept known UAT gaps in release notes

**This is Jp's call.** Make it explicitly; don't let it be discovered Sunday morning.

---

## UAT Day 6 — completed (2026-03-20, second session)

### ✅ Root cause: SSH keychain isolation broke all Keychain reads
`make gateway-start` only set `POSTGRES_USER` — no secrets injected. From SSH, the login.keychain-db is not in the session search list, so both `keyring` and `security` CLI fallbacks fail silently. Every Keychain-sourced key returned not-found. This was the root cause of ALL provider failures (InceptionLabs, Tavily, tool signer, etc.).

### ✅ Fixed today (code — uncommitted)
- **`gateway-start` secrets injection** — now injects all 10 Keychain secrets at startup, matching `servers-start` pattern (Makefile)
- **`_KEY_ENV_FALLBACKS` extended** — added InceptionLabs, OpenRouter, Tavily, Brave mappings; previously code generated `LEGIONFORGE_INCEPTIONLABS_API_KEY_API_KEY` (double suffix) which never matched (src/security/core.py)
- **`num_ctx=16384` for all Ollama models** — was only applied to primary model; any model loaded by direct ID (e.g. qwen3.5) got Ollama's 4096 default → context overflow → infinite loops (src/llm_factory.py)
- **Ollama model auto-eviction** — `_get_ollama()` now checks `/api/ps` on every load and evicts any loaded model that isn't the target. `keep_alive=-1` means models never self-evict; without this, qwen3.5 (8.5GB) blocked llama3.1:8b (4.7GB) indefinitely (src/llm_factory.py)

### ✅ UAT results
| Test | Model | Result | Time | Tokens |
|------|-------|--------|------|--------|
| T4.0: Weather (Birmingham, AL) | mercury-2 | ✅ Pass — correct date, highs/lows, hat advice | 20.8s | 71,423 |
| T4.0: Weather (Birmingham, AL) | llama3.1:8b | ✅ Pass — correct, no hallucination | ~4min | ~17k |
| T4.0: Sky blue (knowledge) | llama3.1:8b | ✅ Pass — excellent Rayleigh scattering explanation | 326s | 16,985 |

### ⚠️ Issues observed
- mercury-2 hit token budget (59,634/50,000 force-stop on one sub-researcher) — partial result gap
- SEQUENCE_VIOLATION sandboxes on mercury-2 multi-fetch patterns — degraded quality
- 326s for knowledge question (should be ~15s if direct-answer path existed)
- qwen3.5 at 4096 context hung indefinitely (fixed by eviction + num_ctx fix)
- Cancel button `DELETE /tasks/:id` → 404 (silent failure)

### ✅ Issues opened
| Issue | Title | Priority |
|-------|-------|----------|
| #288 | Researcher sequence registry missing multi-fetch patterns | pre-v0.8.0 |
| #289 | Cloud model token budget: separate cap needed for paid providers | pre-v0.8.0 |
| #290 | Orchestrator: direct-answer routing for knowledge questions | post-v0.8.0 |
| #291 | UI cancel button calls DELETE /tasks/:id — 404 | pre-v0.8.0 |

---

## UAT Day 6 — completed (2026-03-19, first session)

### ✅ Done this session
- PR #282 confirmed merged (was already merged before session)
- `dev` re-synced with `main` — clean
- #266 HITL UI fully analyzed — see plan above

---

## UAT Day 4 — completed (2026-03-17, second session)

### ✅ Fixed
- **Guardian POSTGRES_USER override** — `.env` sets `POSTGRES_USER=legionforge_admin` which docker-compose was substituting into `${POSTGRES_USER:-legionforge_guardian}`, connecting Guardian as the wrong role. Fixed: `guardian-start` now explicitly exports `POSTGRES_USER=legionforge_guardian`.

### 🔴 New blocker found
- **Orchestrator synthesis bug** — After `fan_out_researchers` runs, orchestrator LLM returns "I've called all the necessary tools..." Root cause: `_ORCHESTRATOR_SYSTEM_CONTENT` says "MUST call a tool on EVERY response." This contradicts step-2 synthesis. Fixed in PR #282.

---

## UAT Day 3 — completed (2026-03-17, first session)

### ✅ Merged
- PR #274 (worker startup reap — closes #272)
- PR #278 (get_user_connection %s — psycopg3 placeholder)
- PR #279 (fanoutresearchers alias normalization — closes #276)

---

## UAT issues log

### Opened Day 6 (2026-03-20)
| Issue | Title | Priority |
|-------|-------|----------|
| #288 | Researcher sequence registry missing multi-fetch patterns | pre-v0.8.0 |
| #289 | Cloud model token budget: separate cap needed for paid providers | pre-v0.8.0 |
| #290 | Orchestrator direct-answer routing for knowledge questions | post-v0.8.0 |
| #291 | UI cancel button → DELETE /tasks/:id returns 404 | pre-v0.8.0 |

### Opened Day 4 (2026-03-17, session 2)
| Issue | Title | Priority |
|-------|-------|----------|
| TBD | Orchestrator synthesis — system prompt contradicts step-2 LLM call | fixed in PR #282 |

### Opened Day 3 (2026-03-17, session 1)
| Issue | Title | Priority |
|-------|-------|----------|
| #273 | Multi-node worker architecture — PostgreSQL LISTEN/NOTIFY + worker_nodes | post-v1.0 |
| #275 | Bump actions/checkout to Node.js 24 compatible version | post-v0.8.0 (deadline Jun 2026) |
| #276 ✅ | fanoutresearchers alias normalization bypassed — Guardian HALT on fan-out tasks | merged PR #279 |
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
- Orchestrator direct-answer routing (#290)
- **Cloudflare bypass for `web_fetch_js` / headless browser**

## At v0.8.0 — Public Release Prep
See bottom of previous NEXT.md for full history rewrite + org transfer steps.

## How to use this file
- **Start of session:** `make briefing` → tell Claude: `read NEXT.md and tell me where we are`
- **End of session:** tell Claude: `update NEXT.md`
