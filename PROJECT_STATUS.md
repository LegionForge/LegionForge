# PROJECT_STATUS.md
# LegionForge (dev: jpc-mac-agent-framework)

**Version:** 2.1.0
**Last updated:** 2026-02-22
**Branch:** `dev`
**Hardware:** Mac Mini M4, 16GB, 1TB external drive
**Status:** ✅ Phase 0 Complete — Infrastructure Operational. Phase 1 Active.

> **Related docs:**
> - [`TLDR.md`](./TLDR.md) — Quick summary and orientation
> - [`PHASE_PLAN.md`](./PHASE_PLAN.md) — Full phased roadmap with goals and dependencies
> - [`RESEARCH.md`](./RESEARCH.md) — Threat research, design theory, and open questions

---

## Current State

The framework infrastructure is fully built, verified, and operational. All services are running and all 23 smoke tests pass. The project is ready to build agents and begin Phase 1 security hardening.

```
make test-smoke    → 23/23 passing
make health-server → localhost:8765 all components green
git branch         → dev (pushed to origin)
```

---

## What's Built (Phase 0 — Complete)

### Source Files (`src/`)

| File | Purpose | Security Gaps |
|---|---|---|
| `database.py` | Async PostgreSQL connection pool, LangGraph checkpointer factory, pgvector similarity search, API usage tracking | No embedding-level trust scoring; no hash-chain audit log; no document provenance at ingestion |
| `security.py` | macOS Keychain loader, PII redaction (email/phone/SSN/card/keys), prompt injection detection, I/O sanitizer | No tool registry or approval gate; no output sanitization on external tool responses; PII redaction not applied to all outbound API calls |
| `safeguards.py` | Three-layer loop protection (step limit, action history, token budget), per-run LangSmith tracing toggle | Loop detection fires after damage; no pre-execution cost estimation; no capability boundary enforcement |
| `rate_limiter.py` | Per-provider async rate limiting, daily token/cost alerts, hard cutoffs for paid APIs | No pre-flight token estimation |
| `llm_factory.py` | Unified async LLM factory for Ollama/OpenAI/Anthropic, model warmup on startup | No model integrity hash verification at startup |
| `observability.py` | JSON structured logging with daily rotation, in-memory metrics collector, LangSmith metric upload | Mutable log files; no tamper-evident hash chain; LangSmith trace content not audited for PII |
| `health.py` | FastAPI server at `localhost:8765` — `/health`, `/status`, `/metrics`, `/usage` endpoints | Unauthenticated; exposes usage patterns; needs auth before any networked deployment |
| `base_graph.py` | Async LangGraph template with all safeguards wired in — copy this for every new agent | Missing stub hooks for Guardian, ACL token validation, embedding trust score, capability boundary check |

### Tests (`tests/`)
- `test_smoke.py` — 23 tests covering config, security, safeguards, rate limiting, observability. No running services required. Runs in ~0.1s.
- `conftest.py` — pytest configuration and shared fixtures

### Config (`config/`)
- `settings.py` — Pydantic config loader
- `hardware_profiles/mac_m4_mini_16gb.yaml` — active profile
- `hardware_profiles/mac_m5_mini_32gb.yaml` — template for future upgrade

### Scripts (`scripts/`)
- `check_mount.sh` — verifies external drive is mounted before any agent starts
- `setup_postgres.sh` — one-time PostgreSQL setup (already run, do not re-run)
- `com.jpc.check-agent-drive.plist` — macOS LaunchAgent for mount guard at login

---

## Infrastructure

### PostgreSQL 17
- **Version:** 17.8 (Homebrew)
- **Data directory:** `/Volumes/MAC_MINI_1TB/LegionForge/postgres/data17`
- **Database:** `legionforge`
- **User:** `jpc`
- **Password:** stored in macOS Keychain (`service: postgres, username: api_key`) and password manager
- **Auto-start:** via `brew services` (starts at login)

**Existing Tables:**

| Table | Purpose |
|---|---|
| `checkpoints` | LangGraph agent state |
| `checkpoint_blobs` | LangGraph binary state |
| `checkpoint_writes` | LangGraph pending writes |
| `checkpoint_migrations` | LangGraph schema versions |
| `documents` | Vector store for RAG (pgvector, 768-dim, HNSW index) |
| `api_usage` | Token/call tracking for rate limiting and cost monitoring |
| `health_metrics` | Persisted health check snapshots |

**Tables to be added (phased):**

| Table | Phase | Purpose |
|---|---|---|
| `tool_registry` | **1** | Human-approved tool manifests with hashes, versions, source, approval record, status |
| `threat_events` | **1** | Security anomalies from Guardian, security.py, capability boundary violations |
| `document_provenance` | 2 | Trust scores, source metadata, embedding hash per RAG document |
| `audit_log` | 2 | Append-only hash-chain tamper-evident event log |
| `threat_rules` | 3 | Adaptive rule set maintained by Threat Analyst agent |
| `task_tokens` | 3 | Ephemeral per-task ACL tokens for sub-agent privilege scoping |
| `ai_bom` | 4 | AI Bill of Materials — models, tools, dependencies, CVE status |

### pgvector
- **Version:** 0.8.1
- **Manual link required** — see setup notes. Repeat if PostgreSQL is ever reinstalled:
  ```bash
  cp /opt/homebrew/Cellar/pgvector/0.8.1/share/postgresql@17/extension/* \
     /opt/homebrew/Cellar/postgresql@17/17.8/share/postgresql/extension/
  cp /opt/homebrew/Cellar/pgvector/0.8.1/lib/postgresql@17/vector.dylib \
     /opt/homebrew/Cellar/postgresql@17/17.8/lib/postgresql/
  ```

### Ollama Models
| Model | Size | Purpose |
|---|---|---|
| `llama3.1:8b` | 4.9GB | Primary reasoning |
| `qwen2.5:3b` | 1.9GB | Router/supervisor |
| `nomic-embed-text:latest` | 274MB | Embeddings |

### API Keys (macOS Keychain)
| Service | Status | Notes |
|---|---|---|
| `langsmith` | ✅ stored | Tracing enabled, project: `jpc-mac-agent-framework` |
| `openai` | not set | Add when API access purchased |
| `anthropic` | not set | Add when API access purchased |
| `postgres` | ✅ stored | Also backed up in password manager |

---

## Environment Setup

Every new terminal session needs the PostgreSQL password loaded:

```bash
# Already added to ~/.zshrc — runs automatically
export POSTGRES_PASSWORD=$(/Volumes/MAC_MINI_1TB/LegionForge/venv/bin/python3 \
  -c "import keyring; print(keyring.get_password('postgres', 'api_key'))")
```

Activate the venv:
```bash
source /Volumes/MAC_MINI_1TB/LegionForge/venv/bin/activate
```

---

## Daily Startup Sequence

```bash
source ~/.zshrc                          # loads POSTGRES_PASSWORD
cd /Volumes/MAC_MINI_1TB/LegionForge
source venv/bin/activate
make check                               # verify drive + config + keychain
make verify-tool-registry               # NEW: fail if any loaded tool is unregistered
make test-smoke                          # 23 tests, ~0.1s
make health-server                       # start status endpoint (keep terminal open)
```

In a second terminal, verify all green:
```bash
curl -s http://localhost:8765/status | python3 -m json.tool
```

---

## Project Identity

| Item | Detail |
|---|---|
| Current dev name | `jpc-mac-agent-framework` |
| Release name | **LegionForge** |
| Private dev repo | https://github.com/jp-cruz/jpc-mac-agent-framework (push here until v1.0) |
| Private dev repo at v1.0 | Rename `jp-cruz/jpc-mac-agent-framework` → `LegionForge/LegionForge` |
| Public release repo | https://github.com/jp-cruz/LegionForge (publish at v1.0) |
| Release target | v1.0 |

## Rename Roadmap

| Phase | Description | Status |
|---|---|---|
| **Phase 1** | Display strings, titles, doc headings, `.env` LANGSMITH_PROJECT, code display names | ✅ Done |
| **Phase 2** | Physical directory rename + venv rebuild + all absolute path updates + ~/.zshrc + PostgreSQL plist | ✅ Done — PR #2 merged |
| **Phase 3** | Database rename `legionforge` → `legionforge` (pg_dump → create new DB → restore → update all config refs) | ⬜ Pending — do before any new development |
| **Phase 4** | GitHub migration: rename `jp-cruz/jpc-mac-agent-framework` → `LegionForge/LegionForge`, create public `jp-cruz/LegionForge`, update git remote | ⬜ Deferred to v1.0 |

### Phase 2 — Directory Copy & Path Update (do in order, verify each step before proceeding)

> **Strategy:** Copy the directory (do not rename/move). Old directory stays intact as a live rollback
> until full verification passes. Delete it only at the cleanup gate at the end.

---

#### STEP 1 — Pre-flight backups

```bash
# 1a. Check available disk space — need ~3GB free for the copy
df -h /Volumes/MAC_MINI_1TB/
```
> **DEBUG:** If less than 3GB free, clear logs or model cache before proceeding.

```bash
# 1b. Take a PostgreSQL dump as insurance
pg_dump -U jpc legionforge > /Volumes/MAC_MINI_1TB/pg_backup_pre_phase2_$(date +%Y%m%d).sql
```
```bash
# 1c. Verify the dump is non-empty
ls -lh /Volumes/MAC_MINI_1TB/pg_backup_pre_phase2_*.sql
# Expected: file exists, size > 10KB
```
> **DEBUG:** If pg_dump fails, PostgreSQL may not be running. Start it first:
> `brew services start postgresql@17 && pg_isready -h localhost`

```bash
# 1d. Copy Claude Code memory to the future path so it survives the session restart
mkdir -p "/Users/jp/.claude/projects/-Volumes-MAC-MINI-1TB-LegionForge/memory/"
cp "/Users/jp/.claude/projects/-Volumes-MAC-MINI-1TB-jpc-mac-agent-framework/memory/MEMORY.md" \
   "/Users/jp/.claude/projects/-Volumes-MAC-MINI-1TB-LegionForge/memory/MEMORY.md"
```
```bash
# 1e. Verify memory copied
ls -lh "/Users/jp/.claude/projects/-Volumes-MAC-MINI-1TB-LegionForge/memory/MEMORY.md"
# Expected: file exists, size matches original
```

- [ ] Step 1 complete — backups verified

---

#### STEP 2 — Stop all services

```bash
# Stop health server if running
make stop 2>/dev/null || true
```
```bash
# Stop PostgreSQL
brew services stop postgresql@17
```
```bash
# Verify PostgreSQL is down
pg_isready -h localhost
# Expected output: "localhost:5432 - no response"
```
```bash
# Verify no uvicorn/health server processes remain
pgrep -fl "uvicorn" || echo "clean"
# Expected: "clean"
```
> **DEBUG:** If uvicorn is still running: `pkill -f uvicorn`

- [ ] Step 2 complete — all services stopped and verified down

---

#### STEP 3 — Copy the directory

```bash
# Full copy — preserves permissions and timestamps
cp -rp /Volumes/MAC_MINI_1TB/LegionForge /Volumes/MAC_MINI_1TB/LegionForge
```
```bash
# Verify the copy succeeded — compare file counts
OLD=$(find /Volumes/MAC_MINI_1TB/LegionForge -not -path "*/venv/*" | wc -l)
NEW=$(find /Volumes/MAC_MINI_1TB/LegionForge -not -path "*/venv/*" | wc -l)
echo "Old: $OLD  New: $NEW"
# Expected: counts match
```
```bash
# Spot-check key files exist in the new location
ls /Volumes/MAC_MINI_1TB/LegionForge/src/
ls /Volumes/MAC_MINI_1TB/LegionForge/config/hardware_profiles/
ls /Volumes/MAC_MINI_1TB/LegionForge/tests/
```
> **DEBUG:** If copy fails mid-way (disk full), remove the partial copy:
> `rm -rf /Volumes/MAC_MINI_1TB/LegionForge` then free disk space and retry.

- [ ] Step 3 complete — full copy verified

---

#### STEP 4 — Update all absolute paths in the new directory

> Run all sed commands from inside `/Volumes/MAC_MINI_1TB/LegionForge/`.
> Using `|` as the sed delimiter to avoid escaping forward slashes.

```bash
cd /Volumes/MAC_MINI_1TB/LegionForge
```
```bash
# Update each file — run one at a time
OLD_PATH="/Volumes/MAC_MINI_1TB/LegionForge"
NEW_PATH="/Volumes/MAC_MINI_1TB/LegionForge"

sed -i '' "s|$OLD_PATH|$NEW_PATH|g" Makefile
sed -i '' "s|$OLD_PATH|$NEW_PATH|g" config/hardware_profiles/mac_m4_mini_16gb.yaml
sed -i '' "s|$OLD_PATH|$NEW_PATH|g" config/hardware_profiles/mac_m5_mini_32gb.yaml
sed -i '' "s|$OLD_PATH|$NEW_PATH|g" scripts/restore_structure.sh
sed -i '' "s|$OLD_PATH|$NEW_PATH|g" scripts/setup_postgres.sh
sed -i '' "s|$OLD_PATH|$NEW_PATH|g" scripts/check_mount.sh
sed -i '' "s|$OLD_PATH|$NEW_PATH|g" src/startup.sh
sed -i '' "s|$OLD_PATH|$NEW_PATH|g" tests/conftest.py
sed -i '' "s|$OLD_PATH|$NEW_PATH|g" tests/test_smoke.py
sed -i '' "s|$OLD_PATH|$NEW_PATH|g" VERIFICATION.md
sed -i '' "s|$OLD_PATH|$NEW_PATH|g" PROJECT_STATUS.md
```
```bash
# Verify no old paths remain in any tracked file
grep -r "jpc-mac-agent-framework" \
  --include="*.py" --include="*.yaml" --include="*.sh" \
  --include="*.md" --include="Makefile" \
  /Volumes/MAC_MINI_1TB/LegionForge/ \
  --exclude-dir=venv --exclude-dir=.git
# Expected: no output. Any output = missed file, fix before continuing.
```
> **DEBUG:** If grep finds remaining references, run the sed command on that specific file manually.

- [ ] Step 4 complete — zero old path references confirmed

---

#### STEP 5 — Update `~/.zshrc`

```bash
# View current line to confirm what needs changing
grep "jpc-mac-agent-framework" ~/.zshrc
```
```bash
# Apply the update
sed -i '' 's|/Volumes/MAC_MINI_1TB/LegionForge|/Volumes/MAC_MINI_1TB/LegionForge|g' ~/.zshrc
```
```bash
# Verify the change
grep "LegionForge" ~/.zshrc
# Expected: shows the updated POSTGRES_PASSWORD export line
```
```bash
# Reload shell
source ~/.zshrc
```
```bash
# Verify POSTGRES_PASSWORD loaded correctly
echo $POSTGRES_PASSWORD | wc -c
# Expected: > 1 (non-empty password)
```
> **DEBUG:** If POSTGRES_PASSWORD is empty, the venv python may not be rebuilt yet.
> Come back to re-run `source ~/.zshrc` after Step 7 (venv rebuild).

- [ ] Step 5 complete — shell environment updated

---

#### STEP 6 — Update PostgreSQL brew service

```bash
# Check if the plist has the old path
cat ~/Library/LaunchAgents/homebrew.mxcl.postgresql@17.plist | grep "jpc-mac"
```
```bash
# If the above shows old path, update it
sed -i '' 's|/Volumes/MAC_MINI_1TB/LegionForge|/Volumes/MAC_MINI_1TB/LegionForge|g' \
  ~/Library/LaunchAgents/homebrew.mxcl.postgresql@17.plist
```
```bash
# Reload the plist and start PostgreSQL
brew services start postgresql@17
sleep 3
```
```bash
# Verify PostgreSQL is accepting connections
pg_isready -h localhost
# Expected: "localhost:5432 - accepting connections"
```
```bash
# Verify the database is accessible
psql -U jpc -d legionforge -c "SELECT current_database(), version();"
# Expected: returns "legionforge" and PostgreSQL version string
```
```bash
# Verify all tables still exist
psql -U jpc -d legionforge -c "\dt"
# Expected: lists checkpoints, documents, api_usage, health_metrics, etc.
```
> **DEBUG — PostgreSQL won't start:**
> 1. Check logs: `tail -50 /Volumes/MAC_MINI_1TB/LegionForge/postgres/data17/log/$(ls -t /Volumes/MAC_MINI_1TB/LegionForge/postgres/data17/log/ | head -1)`
> 2. Check if data dir path is correct in plist: `grep pgdata ~/Library/LaunchAgents/homebrew.mxcl.postgresql@17.plist`
> 3. Try starting manually: `/opt/homebrew/opt/postgresql@17/bin/postgres -D /Volumes/MAC_MINI_1TB/LegionForge/postgres/data17`

- [ ] Step 6 complete — PostgreSQL running and data verified

---

#### STEP 7 — Rebuild venv in new directory

```bash
cd /Volumes/MAC_MINI_1TB/LegionForge
```
```bash
# Remove the copied venv (it has wrong hardcoded paths)
rm -rf venv
```
```bash
# Create fresh venv using system Python 3.11
python3 -m venv venv
```
```bash
# Verify the venv python path is correct
/Volumes/MAC_MINI_1TB/LegionForge/venv/bin/python3 --version
# Expected: Python 3.11.x
```
```bash
# Activate and install
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```
```bash
# Verify critical packages installed
python3 -c "import langgraph, langchain, fastapi, psycopg, keyring; print('all imports OK')"
# Expected: "all imports OK"
```
> **DEBUG — pip install fails:**
> 1. Check internet connection
> 2. Try: `pip install -r requirements.txt --timeout 60`
> 3. If a specific package fails, install it individually to isolate the error

```bash
# Reload shell so POSTGRES_PASSWORD uses new venv path
source ~/.zshrc
echo $POSTGRES_PASSWORD | wc -c
# Expected: > 1
```

- [ ] Step 7 complete — venv rebuilt, all imports verified

---

#### STEP 8 — Full verification

```bash
cd /Volumes/MAC_MINI_1TB/LegionForge
source venv/bin/activate
```
```bash
# Run smoke tests — must all pass
make test-smoke
# Expected: 23 passed in < 1s
```
```bash
# Start health server in background for testing
make health-server &
sleep 3
```
```bash
# Check all health endpoints
curl -s http://localhost:8765/health | python3 -m json.tool
curl -s http://localhost:8765/status | python3 -m json.tool
# Expected: status "healthy" for all components
```
```bash
# Stop background health server
kill %1 2>/dev/null || pkill -f uvicorn
```
```bash
# Final scan — confirm zero old path references in entire new directory
grep -r "jpc-mac-agent-framework" /Volumes/MAC_MINI_1TB/LegionForge/ \
  --exclude-dir=venv --exclude-dir=.git
# Expected: no output
```
> **DEBUG — smoke tests fail:**
> 1. Read the specific test error carefully
> 2. Most likely cause: a path reference was missed in Step 4 — check `tests/conftest.py` and `tests/test_smoke.py`
> 3. Run single test: `pytest tests/test_smoke.py::test_settings_load -v`

- [ ] Step 8 complete — all 23 smoke tests pass, health endpoints green

---

#### STEP 9 — Commit from new directory

```bash
cd /Volumes/MAC_MINI_1TB/LegionForge
git add -u
git status
# Review staged files before committing
```
```bash
git commit -m "chore: Phase 2 rename — copy to LegionForge, all paths updated, venv rebuilt

All absolute paths updated from jpc-mac-agent-framework to LegionForge.
Venv rebuilt from scratch. All 23 smoke tests passing.

Co-Authored-By: Claude <noreply@anthropic.com>"
```
```bash
git push origin feature/phase-1-security-foundations
# Verify push succeeded
```

- [ ] Step 9 complete — committed and pushed from new directory

---

#### STEP 10 — Cleanup gate (only after Step 9 confirmed)

> **Do not proceed until Steps 1–9 are all checked off and smoke tests pass.**

```bash
# Remove the old project directory
rm -rf /Volumes/MAC_MINI_1TB/LegionForge
```
```bash
# Verify it's gone
ls /Volumes/MAC_MINI_1TB/ | grep jpc
# Expected: no output
```
```bash
# Remove the pg_dump backup taken in Step 1 (optional — keep if you want extra safety)
rm /Volumes/MAC_MINI_1TB/pg_backup_pre_phase2_*.sql
```

- [ ] Step 10 complete — old directory removed, Phase 2 done

---

### Phase 3 — Database Rename (start immediately after Phase 2 cleanup)

> **Strategy:** Dump → create new DB → restore → verify → update code → verify again → drop old DB.
> Old database stays live as rollback until final verification gate.

---

#### STEP 1 — Backup

```bash
# Full dump of current database
pg_dump -U jpc -Fc legionforge > /Volumes/MAC_MINI_1TB/pg_backup_legionforge_$(date +%Y%m%d).dump
```
```bash
# Verify dump is non-empty
ls -lh /Volumes/MAC_MINI_1TB/pg_backup_legionforge_*.dump
# Expected: file size > 10KB
```
```bash
# Verify dump is readable
pg_restore --list /Volumes/MAC_MINI_1TB/pg_backup_legionforge_*.dump | head -20
# Expected: lists tables and schema objects
```
> **DEBUG:** If pg_restore --list fails, the dump is corrupt. Re-run pg_dump before continuing.

- [ ] Step 1 complete — backup verified readable

---

#### STEP 2 — Create new database and restore

```bash
# Create new database
createdb -U jpc legionforge
```
```bash
# Restore into new database
pg_restore -U jpc -d legionforge /Volumes/MAC_MINI_1TB/pg_backup_legionforge_*.dump
```
```bash
# Verify all tables restored correctly
psql -U jpc -d legionforge -c "\dt"
# Expected: same tables as legionforge
```
```bash
# Verify row counts match between old and new DB
psql -U jpc -c "SELECT 'legionforge' db, COUNT(*) FROM legionforge.public.documents
                UNION ALL
                SELECT 'legionforge', COUNT(*) FROM legionforge.public.documents;"
# Expected: both counts match
```
> **DEBUG — restore fails with errors:**
> 1. Check for extension errors: pgvector must be installed. Verify: `psql -U jpc -d legionforge -c "CREATE EXTENSION IF NOT EXISTS vector;"`
> 2. Re-run restore with verbose: `pg_restore -U jpc -d legionforge -v /Volumes/MAC_MINI_1TB/pg_backup_legionforge_*.dump 2>&1 | tail -30`

- [ ] Step 2 complete — new database has all tables and data

---

#### STEP 3 — Update all code references

Update all `legionforge` references to `legionforge`:

```bash
cd /Volumes/MAC_MINI_1TB/LegionForge
sed -i '' 's|legionforge|legionforge|g' src/database.py
sed -i '' 's|legionforge|legionforge|g' src/health.py
sed -i '' 's|legionforge|legionforge|g' src/startup.sh
sed -i '' 's|legionforge|legionforge|g' scripts/setup_postgres.sh
sed -i '' 's|legionforge|legionforge|g' Makefile
sed -i '' 's|legionforge|legionforge|g' VERIFICATION.md
sed -i '' 's|legionforge|legionforge|g' PROJECT_STATUS.md
```
```bash
# Update .env (local only, gitignored)
echo "POSTGRES_DB=legionforge" >> .env
# Or edit manually to replace any existing POSTGRES_DB line
```
```bash
# Verify no old database name remains
grep -r "legionforge" /Volumes/MAC_MINI_1TB/LegionForge/ \
  --exclude-dir=venv --exclude-dir=.git \
  --include="*.py" --include="*.sh" --include="*.yaml" --include="*.md" --include="Makefile"
# Expected: no output
```
> **DEBUG:** Any remaining matches must be fixed manually before continuing.

- [ ] Step 3 complete — zero old DB name references confirmed

---

#### STEP 4 — Full verification against new database

```bash
cd /Volumes/MAC_MINI_1TB/LegionForge
source venv/bin/activate
source ~/.zshrc
```
```bash
# Run smoke tests
make test-smoke
# Expected: 23 passed
```
```bash
# Start health server and check DB connectivity
make health-server &
sleep 3
curl -s http://localhost:8765/status | python3 -m json.tool
# Expected: database component shows healthy, connected to legionforge
kill %1 2>/dev/null || pkill -f uvicorn
```
> **DEBUG — DB connection fails:**
> 1. Check POSTGRES_DB env var: `echo $POSTGRES_DB` — should be `legionforge`
> 2. Test connection directly: `psql -U jpc -d legionforge -c "SELECT 1;"`
> 3. Rollback option: revert `src/database.py` to `legionforge` and reconnect to old DB

- [ ] Step 4 complete — smoke tests pass, health server connects to legionforge

---

#### STEP 5 — Commit

```bash
git add src/database.py src/health.py src/startup.sh scripts/setup_postgres.sh \
        Makefile VERIFICATION.md PROJECT_STATUS.md
git commit -m "chore: Phase 3 rename — database renamed from legionforge to legionforge

All code references updated. New DB restored from pg_dump backup.
All 23 smoke tests passing against legionforge database.

Co-Authored-By: Claude <noreply@anthropic.com>"
git push origin feature/phase-1-security-foundations
```

- [ ] Step 5 complete — committed and pushed

---

#### STEP 6 — Cleanup gate (only after Step 5 confirmed)

> **Do not drop the old database until the commit in Step 5 is pushed and verified.**

```bash
# Drop the old database
dropdb -U jpc legionforge
```
```bash
# Verify it's gone
psql -U jpc -l | grep legionforge
# Expected: no output
```
```bash
# Remove the pg_dump backup files (optional)
rm /Volumes/MAC_MINI_1TB/pg_backup_legionforge_*.dump
rm /Volumes/MAC_MINI_1TB/pg_backup_pre_phase2_*.sql 2>/dev/null || true
```
```bash
# Final smoke test with clean state
make test-smoke
# Expected: 23 passed
```

- [ ] Step 6 complete — old database dropped, backups removed, Phase 3 done

---

## Deferred Decisions

| Item | Notes |
|---|---|
| Commercial licensing strategy | Explored dual licensing (AGPL-3.0 free / commercial license paid) vs. PolyForm Noncommercial. Decided to keep AGPL-3.0 + Section 7(b) attribution for now. Revisit when project reaches external users or monetization is needed. Key question: dual license (companies pay to escape copyleft) or switch to PolyForm Noncommercial (explicit noncommercial restriction, not OSI open source). |
| HITL halt vs log policy — research industry standards | Current Phase 1 policy: HALT tier (CMD_INJECTION, SELF_PROBE, DATA_STAGING, PRIVILEGE_ESCALATION) → force_end immediately. LOG tier (CREDENTIAL_PROBE, RECONNAISSANCE, INTERNAL_PROBE, BULK_DESTRUCTIVE, SYSTEM_PATH_PROBE) → log warning and continue. This was designed by first principles — needs validation against real industry guidance before v1.0. **Questions to answer:** (1) What do established security frameworks (NIST SP 800-61, MITRE ATT&CK, OWASP ASVS, SANS IR) say about automated halt vs alert thresholds for AI-initiated actions? (2) Should there be a "log-only mode" that demotes ALL halt-tier categories to log-and-continue — useful for testing and tuning detection without blocking workflows? If so, when is this acceptable and when does it defeat the purpose? (3) Is a three-tier system (HALT / ALERT-AND-PAUSE / LOG) better than two? How do SOC playbooks handle this for automated response systems? (4) Are there published AI-specific security policies (CISA AI security guidelines, NIST AI RMF, ENISA) that address agentic systems and their interrupt/containment decisions? Research goal: confirm current tier assignments against industry consensus, understand the tradeoffs of configurable bypass modes, and document the justification for our final policy in SECURITY.md. |

---

## Known Issues / Technical Debt

| Item | Priority | Phase | Notes |
|---|---|---|---|
| `INTERVAL hours` not validated | **High** | **1** | `get_usage_summary()` / `get_threat_summary()` — `hours` must be integer 1–8760 before query |
| Rate limiter race condition | **High** | **1** | Two concurrent calls can both pass daily hard-limit check before either increments counter; fix with lock around check-and-reserve |
| No rate limiting on `/status` endpoint | High | 2 | Each hit spawns fresh DB + Ollama checks; no throttle; add request cache + rate cap before networked exposure |
| Injection detection is advisory-only | **High** | **1** | `base_graph.py` logs injection detection but continues — violates fail-safe; must block on detection |
| Loop protection resets on checkpoint resume | Medium | 1 | Step counter and action history reset on checkpoint resume; terminated loop can restart clean |
| PII patterns incomplete | Medium | 1 | `_PII_PATTERNS` missing: IPv4, internal URLs, DB DSNs, file paths with usernames |
| API keys persist in `os.environ` | Medium | 1 | `load_all_keys_to_env()` writes keys to environment — visible to child processes for process lifetime |
| Keychain retry swallows `KeyboardInterrupt` | Medium | 1 | `except Exception` in `get_api_key()` retry catches `KeyboardInterrupt`; narrow to specific exceptions |
| Tracing state pollution between runs | Medium | 1 | Tracing toggle restores via `.env` re-read; if `.env` lacks setting, subsequent runs silently disable tracing |
| Hardcoded page size in `health.py` | Low | 1 | `page_size = 16384` assumes M1/M4; use `ctypes.cdll.libc.getpagesize()` |
| `similarity_search()` no input bounds | Low | 1 | `limit` and `min_similarity` accept any value; add bounds (limit: 1–1000, similarity: 0.0–1.0) |
| Pool deprecation warning | Low | 1 | `AsyncConnectionPool` constructor warning — harmless, fix in Phase 1 |
| `setup_postgres.sh` hardcodes PG16 paths | Low | 1 | Script ran successfully; update version string for future reference |
| No integration tests | Medium | 1 | Smoke tests pass without services. Add DB + Ollama integration tests |
| pgvector manual link | Low | ongoing | Document as known fragile step if PG is ever upgraded |
| health.py unauthenticated | Medium | 2 | Safe on localhost; must add token auth before any networked deployment |
| Mutable log files | Medium | 2 | Daily rotation files are editable; replace with hash-chain audit log |
| No tool registry or approval gate | **Critical** | **1** | No tool runs without explicit human approval — closes before Researcher ships |
| No output sanitization on tool responses | **High** | **1** | Input sanitization exists; must extend to all external tool outputs |
| PII redaction not on all outbound calls | **High** | **1** | Must apply to every external API call, not just LangSmith traces |
| No model integrity check at startup | Medium | 1 | Ollama model files should be hashed at startup; unexpected change = security event |
| No capability boundary enforcement | **High** | **1** | Agents must not be able to register tools, write executables, or invoke unregistered callables |
| base_graph.py missing security stubs | Medium | 1 | Add no-op hooks for Guardian, ACL token, trust score, capability boundary check |
| RAG ingestion has no provenance | **High** | 2 | Poisoned document in vector store = persistent multi-run problem; provenance at ingestion, not just retrieval |
| No audit log integrity check at startup | Medium | 2 | Hash chain must be verified before any agent runs |
| No tool behavioral contract enforcement | Medium | 2 | Tools declare side effects at registration; Guardian enforces them at runtime |

---

## Branch Strategy

```
main    ← stable, always deployable
  └── dev         ← integration branch (current)
        └── feature/phase-1-tool-registry
        └── feature/phase-1-security-hardening
        └── feature/researcher-agent
        └── feature/containerization
        └── fix/xxx
```

See `CONTRIBUTING.md` for full workflow.

---

## Immediate Next Steps (Phase 1 — Start Here)

These are ordered by dependency and risk. Items marked 🔴 must exist before the Researcher agent ships. Items marked 🟡 should be completed in Phase 1 but do not block the agent.

### 🔴 Must complete before first external tool call

**1. Tool Registry with human approval gate** (`src/security.py` + `database.py`)

Create `tool_registry` table and `register_tool()` / `verify_tool_before_invocation()` functions. Every tool — internal or external — must have an explicit approval record before Guardian will allow it to execute. No tool runs without this.

Fields per tool: `tool_id`, `source`, `version`, `description_hash`, `schema_hash`, `entrypoint_hash` (for local tools), `approved_by`, `approved_at`, `approval_notes`, `status` (APPROVED / SUSPENDED / REVOKED), `declared_side_effects`.

Add `make verify-tool-registry` to the startup sequence — fails if any loaded tool is unregistered.

**2. Output sanitization on all external tool responses** (`src/security.py`)

The current sanitizer runs on inputs. Apply the same PII redaction and injection detection to everything returned by external tools before it enters agent context. One function, consistent application at every trust boundary.

**3. PII and credential redaction on all outbound API calls** (`src/security.py`)

Extend the existing PII patterns to cover all outbound calls — not just LangSmith traces. Every request leaving the machine passes through redaction. Close research item R-02 (LangSmith trace audit) as part of this.

**4. Capability boundary enforcement in Guardian** (`src/base_graph.py` + future `guardian.py` stub)

Add a negative capability list that no task token can override. No agent may: register a tool, write executable files, invoke an unregistered callable, modify its own task token, spawn agents outside the orchestrator pattern, or escalate its own scope. Implement as a Guardian stub now; wire to real Guardian in Phase 2.

```python
FORBIDDEN_CAPABILITIES = {
    "register_tool", "write_executable", "invoke_unregistered",
    "modify_registry", "escalate_scope", "spawn_agent_direct",
    "modify_own_state",
}
```

### 🔴 Core Phase 1 deliverables (unchanged from prior plan)

**5. `threat_events` table** (`database.py`) — every security event writes here.

**6. Tool description hash validation** (`security.py`) — hash at registration, verify on every invocation. Now extended: also hash `entrypoint_hash`, `dependency_hash`, `declared_side_effects`.

**7. Pre-execution token cost estimation** (`rate_limiter.py`) — reject resource bombs before tokens are consumed.

**8. Security stubs in `base_graph.py`** — `guardian_check()`, `validate_acl_token()`, `score_embedding_trust()`, `check_capability_boundary()`.

**9. Build `src/agents/researcher.py`** — using `base_graph.py` as template, wired to `llama3.1:8b`.

**10. Integration tests** — `tests/test_researcher.py`.

### 🟡 Phase 1 additions from recent security discussion

**11. Model integrity check at startup** (`startup.sh` + `src/security.py`)

Hash the Ollama model files for registered models at startup. Store hashes in `tool_registry` alongside tool hashes. An unexpected model hash change halts startup and logs a `MODEL_INTEGRITY_FAILURE` threat event. This prevents silent behavioral drift from model updates.

```bash
make verify-model-integrity   # new Makefile target
```

**12. Extend tool manifest to include behavioral contract** (`src/security.py`)

At registration time, tools declare their side effects explicitly:
```python
declared_side_effects: list[str]
# e.g. ["reads_web", "writes_db", "calls_external_api:api.search.example.com"]
```
Guardian enforces this contract at runtime. A tool declared `reads_web` that attempts a DB write is a `BEHAVIORAL_CONTRACT_VIOLATION` — logged to `threat_events` and halted.

**13. Audit LangSmith trace content** (`src/observability.py`)

Before any trace data is sent to LangSmith, run it through `sanitize_for_trace()`. Verify this is happening consistently. Add a test that injects synthetic PII into a trace payload and asserts it's redacted before upload. Close R-02.

### 🟡 Phase 1 technical debt cleanup

- Fix `AsyncConnectionPool` deprecation warning in `database.py`
- Update PG16 path string in `setup_postgres.sh` to PG17
- Add DB + Ollama integration tests

---

## Security Trust Surface — What We Validate and Where

This is the definitive map of trust boundaries in the framework. Guardian enforces all of them. Validate at boundaries, not at processing nodes.

| Trust Boundary | Threat | Control | Phase |
|---|---|---|---|
| External tool response → agent context | Injection, poisoned content | Output sanitization + injection detection | **1** |
| Agent context → external API call | PII/credential exfiltration | Redaction on all outbound calls | **1** |
| Tool invocation → Guardian | Tool poisoning, rug-pull, capability violation | Registry check + hash verify + capability boundary | **1** |
| Web content → RAG store | Memory/embedding poisoning | Document provenance at ingestion + trust scoring | 2 |
| Agent → agent message | Prompt infection, cascade attack | Inter-agent message validation + scope check | 3 |
| Orchestrator → sub-agent | Privilege escalation | Derived task tokens, narrower scope | 3 |
| External CVE feed → Threat Analyst | Intelligence poisoning | Provenance scoring on Threat Analyst inputs | 4 |
| Tool library → agent | Supply chain, rug-pull at depth | Cryptographic signing + signature verify | 5 |

**Not a trust boundary (processing nodes — secure via safeguards, not validation):**
- Internal agent logic
- LLM inference
- Safeguard checks
- Internal state transitions

---

## Residual Risks — Accepted and Named

These risks are real, partially or fully unsolvable with current tooling, and are accepted with compensating controls documented.

| Risk | Why Unsolvable Now | Compensating Control |
|---|---|---|
| Compromised tool that signs its own malicious output | Content signing proves provenance, not safety | Output sanitization + Guardian content analysis + behavioral contract |
| Novel semantic injection that evades pattern matching | Guardian hot path is deterministic; can't catch unknown-novel attacks | Sandbox-retry (Tier 2), Threat Analyst (Phase 4), PentestAgent (Phase 6) |
| Compositional emergence from approved component combinations | NP-hard to verify in general case | Capability minimization + combination monitoring + sandbox-first for novel combos |
| Behavioral drift from model weight changes between approved versions | Hash checks the description, not inference behavior | Model integrity hash at startup; re-approval required after any `ollama pull` |
| Embedding-level RAG poisoning (semantic, not content-based) | Open research problem | Provenance scoring + trust flagging in context; embedding anomaly detection deferred to Phase 2 |

See `RESEARCH.md §9` for the full treatment of each.

---

See `PHASE_PLAN.md` for the full sequenced roadmap.
