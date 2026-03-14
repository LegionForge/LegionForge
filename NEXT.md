# NEXT — Session Handoff
*Updated by Claude at end of each session. Read this first. Takes 30 seconds.*

---

## Last updated
2026-03-14 — PRs #253 (HITL), #254 (WhatsApp), #255 (briefing system) all open and green.

## State
- **Branch:** `chore/session-context-system` (working). `main` is at PR #254.
- **Smoke tests:** 2247/2247
- **Open PRs:** #255 — `chore: session context system` — CI green, ready to merge

## Do these in order next session

1. **Merge PR #255** — CI green, no review needed (docs/Makefile only)
   Then: `git checkout main && git pull && git branch -D chore/session-context-system feat/hitl-approval-flow feat/phase-j-whatsapp`

2. **Sync dev with main** (2 min)
   ```
   git checkout dev && git merge origin/main && git push origin dev
   ```

3. **Fix `.env` tracked in git** — must do before v1.0 public release
   ```
   git rm --cached .env
   # verify .env is already in .gitignore, add it if not
   git commit -m "chore: stop tracking .env"
   ```

4. **Rename PostgreSQL `jp` superuser** (30 min, needs `make db-start`)
   ```sql
   ALTER USER jp RENAME TO legionforge_admin;
   ```
   Update `~/.pgpass`, Makefile `pg_isready` calls, then remove the
   TEMPORARY test `test_jp_not_hardcoded_in_production_configs`.

5. **Live UAT — HITL pause/resume** (needs `make start`)
   Submit a task containing `rm -rf` or similar → confirm it appears at
   `GET /hitl/pending` → approve via `POST /hitl/{id}/approve` → confirm run resumes.

## On deck (no urgency, pre-v1.0)
- Telegram connector: bot token + gateway user not yet configured
- Cloud API keys: Anthropic + OpenAI in Keychain (waiting on keys)
- Demo/README: screenshot or short GIF for public README
- After jp rename: remove TEMPORARY test from test_smoke.py

## How to use this file
- **Start of session:** `make briefing`
- **End of session:** tell Claude "update NEXT.md"
