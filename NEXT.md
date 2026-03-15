# NEXT — Session Handoff
*Updated by Claude at end of each session. Read this first. Takes 30 seconds.*

---

## Last updated
2026-03-15 — overnight codebase review complete (7 agents, read-only). Discipline rules added
to CLAUDE.md. jp_testing.md updated with T0.1, T_HITL, T8.3, and 8-day UAT schedule.
JP_CONTEXT.md template drafted. MCP memory server evaluated. No code changes made.

## State
- **Branch:** `dev` — 1 commit ahead of main (doc consolidation 99af2e0, not yet PR'd)
- **Smoke tests:** 2247/2247
- **Open PRs:** none
- **Ship target:** v0.8.0 — Sunday 2026-03-22
- **Mode:** UAT only — no new features

## Overnight review findings
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
