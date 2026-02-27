# Verification Guide

Run these steps in order after downloading and deploying the new files.
Each step has a pass/fail indicator. Stop and fix before continuing if anything fails.

> **Setup:** Set your project root once before running any commands in this guide:
> ```bash
> export LEGIONFORGE_HOME=/path/to/LegionForge   # ← update to your actual path
> ```
> All paths below use `$LEGIONFORGE_HOME` so a single export covers every step.

---

## Step 0 — Deploy Files

```bash
# Clone the repository (first-time setup)
git clone https://github.com/LegionForge/LegionForge.git ${LEGIONFORGE_HOME}

# Or if already cloned, pull the latest changes
cd ${LEGIONFORGE_HOME} && git pull origin main

# Ensure scripts are executable
chmod +x ${LEGIONFORGE_HOME}/scripts/*.sh
```

---

## Step 1 — Install New Python Packages

The `requirements.txt` has new packages. Install them:

```bash
source ${LEGIONFORGE_HOME}/venv/bin/activate
pip install -r ${LEGIONFORGE_HOME}/requirements.txt
```

**Expected:** Lots of output, no red errors. Final line should say `Successfully installed...`

**Verify:**
```bash
python -c "import psycopg; print('psycopg:', psycopg.__version__)"
python -c "import pgvector; print('pgvector: OK')"
python -c "import aiolimiter; print('aiolimiter: OK')"
python -c "import fastapi; print('fastapi:', fastapi.__version__)"
```

All four should print version info. ✅

---

## Step 2 — Config Still Loads

```bash
cd ${LEGIONFORGE_HOME}
python -c "from config.settings import settings"
```

**Expected:** Hardware profile summary table prints cleanly. ✅

---

## Step 3 — Run Smoke Tests

```bash
cd ${LEGIONFORGE_HOME}
python -m pytest tests/test_smoke.py -v
```

**Expected:** All tests pass. Current baseline is 323 tests (Phase 8 + Discord connector). Count should never
go below the previous passing count.

```
tests/test_smoke.py::test_settings_load PASSED
tests/test_smoke.py::test_memory_budget_is_valid PASSED
tests/test_smoke.py::test_injection_detection_positive PASSED
...
========= 323 passed in 2.0s =========
```

If any test fails, the output will tell you exactly which assertion failed.
**Do not proceed past this step if any test fails.**

### Smoke Test Currency Check

Before marking any phase component as complete, verify the smoke test suite
covers it. Run this checklist:

```
□ Every new function in src/ has at least one test
□ Every new security control has a positive AND negative test
□ Every new tool registration has a hash validation test
□ Every new capability boundary has a block test
□ Test count is >= previous passing count
□ No test is skipped without a documented reason
```

If any box is unchecked, write the missing tests before merging.

---

## Step 4 — Install PostgreSQL

```bash
chmod +x ${LEGIONFORGE_HOME}/scripts/setup_postgres.sh
${LEGIONFORGE_HOME}/scripts/setup_postgres.sh
```

**Expected output ends with:**
```
✅  PostgreSQL setup complete!
Database: legionforge
User:     <your postgres user>
Data dir: ${LEGIONFORGE_HOME}/postgres/data
Password: stored in macOS Keychain
```

**Verify PostgreSQL is running:**
```bash
source ~/.zshrc
psql -U "${POSTGRES_USER:-$(whoami)}" -d legionforge -c "SELECT version();"
```

Should print PostgreSQL version info. ✅

---

## Step 5 — Initialize Database Tables

```bash
cd ${LEGIONFORGE_HOME}
make db-init
```

**Expected:**
```
✅ Database initialized
```

**Verify tables were created:**
```bash
psql -U "${POSTGRES_USER:-$(whoami)}" -d legionforge -c "\dt"
```

Should show tables including `checkpoints`, `api_usage`, `health_metrics`, `documents`. ✅

---

## Step 6 — Verify Keychain Has Postgres Password

```bash
python -c "
import keyring
key = keyring.get_password('postgres', 'api_key')
print('postgres password:', 'FOUND ✅' if key else 'NOT FOUND ❌')
"
```

---

## Step 7 — Load Postgres Password into Environment

The `.env` file doesn't store the password (it's in Keychain). Add this to your startup:

```bash
# Add to ~/.zshrc
export POSTGRES_PASSWORD=$(python3 -c "import keyring; print(keyring.get_password('postgres', 'api_key') or '')")
```

Then reload:
```bash
source ~/.zshrc
echo $POSTGRES_PASSWORD   # Should print a long random string
```

---

## Step 8 — Run Full Smoke Tests Again (With DB Available)

```bash
cd ${LEGIONFORGE_HOME}
python -m pytest tests/test_smoke.py -v
```

All tests should still pass. ✅

**Verify test count matches or exceeds the Phase baseline:**

| Phase | Minimum |
|---|---|
| Phase 0 | 23 |
| Phase 1 | 46 |
| Phase 2 | 58 |
| Phase 3 | 65 |
| Phase 4 | 110 |
| Phase 5 | 143 |
| Phase 5.5 | 200 |
| Phase 6 | 228 |
| Phase 7 | 242 |
| Phase 8 | 312 |
| Phase 8 + connector | 323 |

---

## Step 9 — Verify Makefile Works

```bash
cd ${LEGIONFORGE_HOME}
make help
```

Should print the full help menu. ✅

```bash
make check
```

Should show all green checkmarks. ✅

---

## Step 10 — Start Health Server and Check Status

In one terminal:
```bash
cd ${LEGIONFORGE_HOME}
source venv/bin/activate
make health-server
```

In another terminal:
```bash
curl -s http://localhost:8765/health | python3 -m json.tool
curl -s http://localhost:8765/status | python3 -m json.tool
```

**Expected /health:**
```json
{
    "status": "ok",
    "uptime_seconds": 3,
    "profile": "mac_m4_mini_16gb"
}
```

**Expected /status:**
```json
{
    "status": "ok",
    "components": {
        "ollama":         {"status": "ok"},
        "postgres":       {"status": "ok"},
        "external_drive": {"status": "ok"},
        "memory":         {"status": "ok"}
    }
}
```

If any component shows "error", the detail field will tell you why. ✅

---

## Step 11 — Run PentestAgent (Phase 6)

Build the air-gapped pentest container and run the red-team suite:

```bash
# Build the container (one-time, ~2 min)
make build-pentest

# Run in verify mode (stop-at-proof, default)
# Requires: PostgreSQL running, POSTGRES_PASSWORD set
make pentest
```

**Expected output ends with:**
```
✅ Pentest complete — 24 tests, 24 defences held, 0 bypasses found
   Report: reports/pentest-<run_id>.json
```

If any bypass is found, the output will say `❌` next to the count and list the attack class.

**View the report:**
```bash
make pentest-report
# or: make pentest-report RUN_ID=<uuid>
```

**Verify findings in DB (optional):**
```bash
psql -U "${POSTGRES_USER:-$(whoami)}" -d legionforge \
  -c "SELECT attack_class, variant, severity, defense_held FROM pentest_findings ORDER BY logged_at DESC LIMIT 5;"
```

Should show 24 rows with `defense_held = true`. ✅

---

## Step 12 — Create dev Branch

```bash
cd ${LEGIONFORGE_HOME}
make dev-branch
```

Then commit all new files to dev:
```bash
git add .
git commit -m "feat: production infrastructure

- PostgreSQL + pgvector replacing SQLite
- Async LLM factory with rate limiting
- Per-run LangSmith tracing toggle
- Input/output sanitization + PII redaction
- Prompt injection detection
- Health + status endpoint (FastAPI)
- Local metrics collector with LangSmith upload
- Makefile for QoL operations
- Smoke test suite (23 tests, Phase 0 baseline)
- Branch strategy (CONTRIBUTING.md)"

git push origin dev
```

---

## All Done ✅

Your framework now has:
- PostgreSQL + pgvector for checkpoints, vector search, and API usage tracking
- Security: PII redaction, injection detection, per-run tracing toggle
- Rate limiting for paid APIs with daily alerts and hard limits
- Health endpoint: `http://localhost:8765/status`
- 23 automated smoke tests (Phase 0 baseline — grows with each phase)
- Makefile for everything
- Branch strategy ready for feature development

**Next:** Build your first real agent in `src/agents/`.
Remember: every new component gets a smoke test written alongside it.
