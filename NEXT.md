# NEXT — Session Handoff
*Updated by Claude at end of each session. Read this first. Takes 30 seconds.*

---

## Last updated
2026-03-14 — dev synced with main (00303b2). All PRs merged. No open PRs.

## State
- **Branch:** `dev` — clean, in sync with main
- **Smoke tests:** 2247/2247
- **Open PRs:** none
- **Stale local branches:** `chore/session-context-system`, `feat/hitl-approval-flow`, `feat/phase-j-whatsapp` — delete these first

## Do these in order next session

1. **Rename PostgreSQL `jp` superuser** (30 min, needs `make db-start` first)
   ```sql
   ALTER USER jp RENAME TO legionforge_admin;
   ```
   Then update `~/.pgpass` and Makefile `pg_isready` calls.
   Then remove TEMPORARY test `test_jp_not_hardcoded_in_production_configs`.

2. **Live UAT — HITL pause/resume** (needs `make start`)
   Submit a task with `rm -rf /` → check `GET /hitl/pending` → approve via
   `POST /hitl/{id}/approve` → confirm run resumes.

## On deck (no urgency, pre-v1.0)
- Telegram connector: bot token + gateway user not yet configured
- Cloud API keys: Anthropic + OpenAI in Keychain (waiting on keys)
- Demo/README: screenshot or GIF for public README
- After jp rename: remove TEMPORARY test from test_smoke.py

## How to use this file
- **Start of session:** `make briefing`
- **End of session:** tell Claude "update NEXT.md"
