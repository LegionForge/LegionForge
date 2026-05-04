# GUARDIAN_SPINOFF.md
# LegionForge — Guardian Package Spin-Off Plan

**Status:** G1 complete — guardian.py has zero src.* imports (module-level or lazy)
**Last updated:** 2026-03-06
**Author:** Jp Cruz

---

## Overview

`legionforge-guardian` will be published as a standalone open-source Python package and
Docker sidecar — a deterministic security layer any LLM agent framework can adopt,
regardless of whether they use LegionForge. Guardian is the only part of LegionForge
that solves a problem no other framework has solved correctly. It warrants its own
release track, versioning, and community.

This document covers:
1. GitHub organization strategy (where the repos live)
2. What Guardian becomes as a package
3. The four-phase execution plan
4. Choke points and incremental testing gates at each phase
5. Day-to-day development workflow after setup

---

## Part 1 — GitHub Organization Strategy

### Decision: Create a GitHub Organization named `LegionForge`

**Account map:**

| Account | Type | Role |
|---|---|---|
| `github.com/jp-cruz` | Personal (private) | Active dev — private repos, day-to-day work |
| `github.com/jp-cruz` | Personal (public) | Public professional profile, listed as founder |
| `github.com/LegionForge` | Organization | Public release target — all published repos live here |

**Public repo URLs:**
- `github.com/LegionForge/LegionForge` — the full framework
- `github.com/LegionForge/legionforge-guardian` — the security sidecar package

**Why an org, not a personal account:**
- Two repos (and eventually more: SDKs, rules repo, Docker images) belong under a
  single brand, not under a person's name
- `github.com/LegionForge/...` reads as "product." `github.com/jp-cruz/...` reads as
  "personal project." For a security tool especially, that distinction matters to
  potential adopters.
- GitHub orgs are free for public repos
- Ownership transfers are clean: jp-cruz and jp-cruz are both org owners;
  neither personal account is in any public URL

**Why not jp-cruz directly:**
The original plan was `jp-cruz/LegionForge`. That's fine for a single personal
project. With two repos sharing a brand, an org is the right structure. The `jp-cruz`
profile gets listed prominently in READMEs as founder — the org handles the repo URLs.

### Setup Steps (one-time, ~30 minutes)

```bash
# 1. Create the LegionForge org at github.com/organizations/new
#    - Name: LegionForge
#    - Plan: Free
#    - Add jp-cruz and jp-cruz as owners

# 2. Create the guardian repo under the org (empty for now)
#    github.com/LegionForge/legionforge-guardian
#    - Public, MIT or AGPL (see license decision below)
#    - No files yet — the subtree push will populate it

# 3. Create the main framework repo under the org (when ready for public release)
#    github.com/LegionForge/LegionForge
#    - Transfer from jp-cruz/LegionForge when v1.0 is ready, OR
#    - Create separately and push a cleaned public snapshot

# 4. jp-cruz/LegionForge stays private — dev work continues there unchanged
```

### License Decision (open question)

| Option | Effect |
|---|---|
| **MIT (Guardian only)** | Maximum adoption. Enterprise teams can use it in proprietary products. Full LegionForge framework stays AGPL. |
| **AGPL (Guardian + Framework)** | Consistent licensing. Anyone running a modified Guardian must release source. Slower enterprise adoption. |
| **Apache 2.0 (Guardian only)** | Enterprise-friendly (explicit patent grant), more explicit than MIT for a security tool. |

**Recommendation:** MIT for `legionforge-guardian`. AGPL for the full `LegionForge` framework.
The security layer should spread as widely as possible. The full platform is where
the commercial licensing conversation happens.

---

## Part 2 — What Guardian Becomes

### Current State

Guardian is `src/security/guardian.py` — a FastAPI sidecar (port 9766) that runs
7 deterministic checks before any tool invocation. It currently:
- Imports config from `config/settings.py` (LegionForge-specific hardware profiles)
- Connects to LegionForge's PostgreSQL using LegionForge's connection management
- References `tool_registry` and `threat_rules` tables (shared with LegionForge)

### Target State

`legionforge-guardian` is a self-contained Python package and Docker image. It:
- Reads config from environment variables only (no LegionForge dependency)
- Connects to any PostgreSQL via `GUARDIAN_DB_URL`
- Ships its own `init.sql` to create the two tables it needs
- Exposes a Python SDK (`from legionforge_guardian import guardian_check`) any
  framework can call
- Has its own tests, its own CI, its own releases, its own PyPI page

LegionForge installs it as a local editable package during development and as
a pinned PyPI package in production. The LegionForge codebase needs no changes
beyond the import paths.

### Package Structure (target)

```
packages/
  guardian/
    pyproject.toml
    README.md
    CHANGELOG.md
    LICENSE
    init.sql                         # standalone DB schema (tool_registry, threat_rules)
    Dockerfile                       # moves from guardian/Dockerfile
    docker-compose.yml               # standalone deployment
    src/
      legionforge_guardian/
        __init__.py                  # exports: guardian_check, GuardianClient
        app.py                       # FastAPI sidecar (main entry point)
        config.py                    # env-var config — no LegionForge deps
        audit.py                     # SHA-256 audit log
        rules.py                     # threat_rules hot-reload
        pii.py                       # PII redaction (from security/core.py)
        injection.py                 # injection detection, 29 patterns (from security/core.py)
        checks/
          __init__.py
          tool_revocation.py         # Check 0
          hash_validation.py         # Check 1
          capability_boundary.py     # Check 2
          destructive_pattern.py     # Check 3
          sequence_contracts.py      # Check 4
          ed25519_verify.py          # Check 5
          adaptive_rules.py          # Check 6
        sdk/
          client.py                  # guardian_check() — HTTP client for callers
    tests/
      test_checks.py
      test_audit.py
      test_pii.py
      test_injection.py
      test_sdk.py
```

### pyproject.toml

```toml
[project]
name = "legionforge-guardian"
version = "0.1.0"
description = "Deterministic security sidecar for LLM agent frameworks"
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.11"
dependencies = [
    "fastapi>=0.110",
    "uvicorn>=0.29",
    "asyncpg>=0.29",
    "cryptography>=46",
    "httpx>=0.27",
]

[project.optional-dependencies]
dev = ["pytest", "pytest-asyncio", "black", "httpx"]

[project.urls]
Homepage = "https://github.com/LegionForge/legionforge-guardian"
Documentation = "https://github.com/LegionForge/legionforge-guardian#readme"
"Bug Tracker" = "https://github.com/LegionForge/legionforge-guardian/issues"
```

### What Gets Moved vs. What Stays

| File | Action |
|---|---|
| `src/security/guardian.py` | Moves to `packages/guardian/src/legionforge_guardian/app.py` |
| `src/security/core.py` (PII + injection detection) | Split: PII → `pii.py`, injection → `injection.py`; LegionForge re-imports from package |
| `guardian/Dockerfile` | Moves to `packages/guardian/Dockerfile` |
| Config loading from `config/settings.py` | Replaced with `packages/guardian/src/legionforge_guardian/config.py` (env vars) |
| `src/database.py` DB connection | Guardian gets its own `asyncpg` pool via `GUARDIAN_DB_URL`; LegionForge DB unchanged |
| `tool_registry` + `threat_rules` tables | Stay in LegionForge's DB; Guardian connects to same DB via env var |

---

## Part 3 — Execution Plan

Four phases. Each phase is independently testable and produces a working system.
Do not start a phase until the previous phase's test gate passes.

---

### Phase G1 — Decouple Remaining src.* Imports ✅ COMPLETE (2026-03-06)

**Discovery (2026-03-06):** Guardian's config was ALREADY env-var based.
`_guardian_db_conninfo()` uses `os.environ` — there was never a `from config.settings`
import. The actual coupling points found and resolved:

| Import | Was | Resolved by |
|---|---|---|
| `from src.security.core import FORBIDDEN_CAPABILITIES, HITL_HALT_CATEGORIES, _compute_fast_hash, detect_destructive_pattern, _TOOL_REGISTRY, _TOOL_HASHES` | module top | Inlined into guardian.py as `_GUARDIAN_DESTRUCTIVE_PATTERNS` + `detect_destructive_pattern` + frozensets + stubs |
| `from src.security.acl import validate_task_token` | module top | Inlined as `_validate_task_token()` + `_GuardianTaskToken` dataclass; uses `TASK_TOKEN_ISSUER` env var |
| `from src.database import append_audit_log` | lazy (inside `/report` body) | Inlined as `_append_audit_log_direct()` — full hash chain maintained via `_compute_audit_row_hash_direct()` |

**Drift guards added (7 G1 smoke tests + 6 G1.5 smoke tests = 13 new tests):**
- `test_guardian_has_no_module_level_src_imports` — AST gate, col_offset=0 check
- `test_guardian_has_no_src_imports_anywhere` — comprehensive line-scan (catches lazy too)
- `test_guardian_destructive_patterns_count_matches_core` — pattern count parity
- `test_guardian_inlined_forbidden_capabilities_match_core` — frozenset equality
- `test_guardian_inlined_hitl_halt_categories_match_core` — frozenset equality
- `test_guardian_audit_log_genesis_matches_database` — genesis sentinel hash equality
- `test_guardian_compute_audit_row_hash_direct_matches_database` — hash function parity

**G1 final state:**
- `grep -n "from src\." src/security/guardian.py` → 0 results (only comments)
- `grep -n "import src\." src/security/guardian.py` → 0 results
- Smoke tests: 1982/1982

**Remaining `src/security/__init__.py` is G2 scope** — it re-exports from acl/core/bom
but is not guardian.py. The package `__init__.py` gets restructured in G2.

Do not proceed to G2 until: `make test-smoke` passes AND guardian health check responds.

---

### Phase G2 — Package Restructure (scaffold complete; code move pending)

**Goal:** Guardian code lives in `packages/guardian/`. LegionForge imports from it
via editable install. All existing imports in LegionForge continue to work.
**Scope:** File moves + import path changes + pyproject.toml.

**What's done (2026-03-06 scaffold):**
- `packages/guardian/pyproject.toml` — MIT license, Python 3.11+, correct deps
- `packages/guardian/init.sql` — 5-table standalone schema (tool_registry, threat_rules,
  agent_profiles, threat_events, audit_log). `CREATE TABLE IF NOT EXISTS` — safe on
  existing LegionForge DB.
- `packages/guardian/Dockerfile` — standalone container entry (Phase G3 replacement)
- `packages/guardian/docker-compose.yml` — standalone deploy with own PostgreSQL
- `packages/guardian/src/legionforge_guardian/sdk/client.py` — `GuardianClient` +
  `guardian_check()` — fail-safe async HTTP client (network error → synthetic halt)
- `packages/guardian/tests/test_sdk.py` — 11 mock-HTTP SDK tests
- Package installed as `-e packages/guardian` in LegionForge venv
- `from legionforge_guardian import GuardianClient, guardian_check` works today
- 7 G2 smoke tests added to LegionForge suite (1982 → 1989)

**What remains (code move):**

**What changes:**
1. Create `packages/guardian/` directory structure (see Part 2)
2. Move `guardian.py` → `packages/guardian/src/legionforge_guardian/app.py`
3. Split `src/security/core.py`:
   - PII redaction → `packages/guardian/src/legionforge_guardian/pii.py`
   - Injection detection → `packages/guardian/src/legionforge_guardian/injection.py`
   - LegionForge's `src/security/core.py` becomes a thin re-export:
     ```python
     # src/security/core.py — after split
     from legionforge_guardian.pii import redact_pii, sanitize_output
     from legionforge_guardian.injection import detect_injection, sanitize_input
     # All other LegionForge-specific functions remain here
     ```
4. Add to `requirements.txt`:
   ```
   -e packages/guardian   # editable install
   ```
5. Write `packages/guardian/pyproject.toml` (see Part 2)

**CHOKE POINT:** `src/security/core.py` is imported in ~15 places across the codebase.
The re-export wrapper in step 3 means none of those call sites need to change. Verify
this by grepping before and after:
```bash
grep -r "from src.security.core import" src/ tests/
# Every import must still resolve after the restructure
```

**CHOKE POINT:** The editable install (`-e packages/guardian`) must be installed in
the venv before running tests:
```bash
source venv/bin/activate
pip install -e packages/guardian
make test-smoke  # run immediately after pip install
```

**CHOKE POINT:** Black formatting — `packages/guardian/` must be included in Black's
scope. Add to `pyproject.toml` (root) or `Makefile lint` target:
```bash
black packages/guardian/src/ packages/guardian/tests/
```
The pre-commit Black hook will also need updating.

**Test Gate G2:**
```bash
# 1. Editable install resolves
python -c "from legionforge_guardian import guardian_check; print('ok')"

# 2. LegionForge's existing imports still resolve
python -c "from src.security.core import sanitize_input, sanitize_output; print('ok')"

# 3. Full smoke suite passes
make test-smoke

# 4. Integration tests pass (requires PostgreSQL)
make test-integration

# 5. Guardian sidecar starts from the new package location
make guardian-start
curl http://localhost:9766/health
```

Do not proceed to G3 until all five pass.

---

### Phase G3 — Standalone Deployment

**Goal:** Guardian can be deployed with no LegionForge code at all. A user with
only `docker compose up` and a PostgreSQL connection has a working sidecar.
**Scope:** `init.sql`, `Dockerfile` update, `docker-compose.yml`, SDK client.
**Estimated effort:** 3–4 hours, one PR.

**What changes:**
1. Write `packages/guardian/init.sql` — creates only the tables guardian needs:
   ```sql
   CREATE TABLE IF NOT EXISTS tool_registry (
       tool_id TEXT PRIMARY KEY,
       status TEXT NOT NULL DEFAULT 'APPROVED',
       description_hash TEXT,
       schema_hash TEXT,
       entrypoint_hash TEXT,
       signature TEXT,
       approved_at TIMESTAMPTZ DEFAULT now()
   );

   CREATE TABLE IF NOT EXISTS threat_rules (
       id BIGSERIAL PRIMARY KEY,
       rule_id TEXT UNIQUE NOT NULL,
       rule_type TEXT NOT NULL,
       pattern TEXT NOT NULL,
       action TEXT NOT NULL DEFAULT 'LOG',
       status TEXT NOT NULL DEFAULT 'APPROVED',
       created_at TIMESTAMPTZ DEFAULT now()
   );
   ```
   Note: These are subsets of LegionForge's full schemas. When deployed alongside
   LegionForge, Guardian uses LegionForge's existing tables. `init.sql` is only
   for standalone deploys.

2. Move `guardian/Dockerfile` → `packages/guardian/Dockerfile`

3. Write `packages/guardian/docker-compose.yml`:
   ```yaml
   services:
     guardian:
       build: .
       ports: ["9766:9766"]
       environment:
         GUARDIAN_DB_URL: ${GUARDIAN_DB_URL}
       depends_on: [db]
     db:
       image: postgres:17
       environment:
         POSTGRES_DB: guardian
         POSTGRES_USER: guardian
         POSTGRES_PASSWORD: ${GUARDIAN_DB_PASSWORD}
   ```

4. Write `packages/guardian/src/legionforge_guardian/sdk/client.py`:
   ```python
   import httpx

   class GuardianClient:
       def __init__(self, url: str = "http://localhost:9766"):
           self.url = url

       async def check(self, tool_name: str, tool_input: dict, agent_state: dict) -> dict:
           async with httpx.AsyncClient() as client:
               r = await client.post(f"{self.url}/check", json={
                   "tool_name": tool_name,
                   "tool_input": tool_input,
                   "agent_state": agent_state,
               })
               return r.json()

   async def guardian_check(tool_name, tool_input, agent_state, url="http://localhost:9766"):
       return await GuardianClient(url).check(tool_name, tool_input, agent_state)
   ```

**CHOKE POINT:** `init.sql` table schemas must be a strict subset of LegionForge's
existing schemas. A standalone deploy creates these tables. A LegionForge deploy
already has them. Running `init.sql` against a LegionForge DB must be a no-op
(`CREATE TABLE IF NOT EXISTS`). Verify:
```bash
psql legionforge -f packages/guardian/init.sql  # must produce no errors on existing DB
```

**CHOKE POINT:** The standalone `docker-compose.yml` starts its own PostgreSQL.
LegionForge's `docker-compose.yml` (for Guardian in production) must still use
LegionForge's DB, not the standalone one. These are two separate compose files
for two different deployment scenarios — they must not conflict.

**Test Gate G3:**
```bash
# 1. Standalone deploy works with no LegionForge code
cd packages/guardian
GUARDIAN_DB_URL=postgresql://guardian:testpw@localhost:5433/guardian \
  docker compose up -d

# 2. init.sql creates tables successfully
psql $GUARDIAN_DB_URL -f init.sql

# 3. Guardian health check responds
curl http://localhost:9766/health

# 4. SDK client can reach it
python3 -c "
import asyncio
from legionforge_guardian.sdk.client import guardian_check
result = asyncio.run(guardian_check('test_tool', {}, {}))
print(result)
"

# 5. Running init.sql against LegionForge's DB is a no-op
psql postgresql://legionforge:PASSWORD@localhost:5432/legionforge \
  -f packages/guardian/init.sql  # must produce no errors

# 6. Full LegionForge smoke suite still passes
cd /Volumes/MAC_MINI_1TB/LegionForge && make test-smoke
```

Do not proceed to G4 until all six pass.

---

### Phase G4 — Git Subtree + GitHub Org Setup

**Goal:** `packages/guardian/` automatically syncs to `github.com/LegionForge/legionforge-guardian`
on every merge to LegionForge main. Guardian has its own repo, releases, and CI.
**Scope:** Git configuration, GitHub Actions, org setup.
**Estimated effort:** 2–3 hours (mostly GitHub UI + config).

**Steps:**

1. Create `LegionForge` GitHub org (github.com/organizations/new, free)
2. Create `LegionForge/legionforge-guardian` repo (empty, public)
3. Add jp-cruz and jp-cruz as org owners
4. Create a GitHub PAT with `repo` scope on the guardian repo; store as
   `GUARDIAN_REPO_PAT` in jp-cruz/LegionForge's repository secrets
5. First subtree push (one-time):
   ```bash
   git remote add guardian-public https://github.com/LegionForge/legionforge-guardian.git
   git subtree push --prefix=packages/guardian guardian-public main
   ```
6. Add the sync Action to LegionForge:

```yaml
# .github/workflows/sync-guardian.yml
name: Sync legionforge-guardian
on:
  push:
    branches: [main]
    paths:
      - 'packages/guardian/**'

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Push guardian subtree to public repo
        run: |
          git config user.email "noreply@github.com"
          git config user.name "LegionForge Sync"
          git remote add guardian-public \
            https://x-access-token:${{ secrets.GUARDIAN_REPO_PAT }}@github.com/LegionForge/legionforge-guardian.git
          git subtree push --prefix=packages/guardian guardian-public main
```

7. Add PyPI publish Action to the guardian repo (triggers on version tags):

```yaml
# In LegionForge/legionforge-guardian repo:
# .github/workflows/publish.yml
name: Publish to PyPI
on:
  push:
    tags: ['v*']

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: '3.11'}
      - run: pip install build
      - run: python -m build
      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          password: ${{ secrets.PYPI_API_TOKEN }}
```

**CHOKE POINT:** The subtree push rewrites git history to contain only the commits
that touched `packages/guardian/`. The guardian repo's `main` must start as an
empty repo (no README, no initial commit) or the subtree push will conflict. If
GitHub auto-created a README on repo creation, delete it before step 5.

**CHOKE POINT:** The sync Action runs on push to `main` only — not on pushes to `dev`.
Guardian changes on `dev` reach the public repo only after the PR merges to `main`.
This is intentional: the public repo tracks release-quality code, not in-progress work.

**CHOKE POINT:** `git subtree push` is slow on large repos (it must inspect all
commits). LegionForge's history is already substantial. The first push may take
several minutes. Subsequent pushes are fast (only new commits). If it becomes a
bottleneck, replace with `git-subrepo` or a file-copy Action.

**Test Gate G4:**
```bash
# 1. First subtree push completes without error
git subtree push --prefix=packages/guardian guardian-public main

# 2. Guardian repo has correct file structure
# Visit github.com/LegionForge/legionforge-guardian — should show packages/guardian/ contents
# (pyproject.toml, README.md, src/, tests/, Dockerfile, docker-compose.yml, init.sql)

# 3. Make a small change to packages/guardian/README.md, commit, push to LegionForge dev
# Merge to main via PR
# Sync Action runs and the change appears in legionforge-guardian repo within ~2 minutes

# 4. Cut a test tag (v0.0.1-test) — confirm PyPI action triggers
# (Use PyPI test instance first: test.pypi.org)
```

---

## Part 4 — Day-to-Day Workflow After Setup

Nothing changes about how you write code.

```bash
# Edit guardian code exactly as before
vim packages/guardian/src/legionforge_guardian/checks/hash_validation.py

# Run LegionForge tests as before
make test-smoke

# Commit and push to jp-cruz/LegionForge dev as before
git add packages/guardian/
git commit -m "fix: guardian hash validation edge case with empty input"
git push origin dev

# Open PR dev → main, merge as normal
# Sync Action runs automatically — legionforge-guardian repo gets the commit
# Done. Nothing else needed until you want to cut a release.
```

**Cutting a Guardian release:**
```bash
# In the guardian repo (via GitHub UI or locally)
git tag v0.1.0 -m "Initial public release"
git push guardian-public v0.1.0
# PyPI Action triggers automatically
# pip install legionforge-guardian now works for anyone
```

---

## Part 5 — Future Repos Under LegionForge Org

The org structure supports growth without URL churn:

| Repo | Purpose | When |
|---|---|---|
| `LegionForge/LegionForge` | Full framework (public mirror of jp-cruz/LegionForge) | v1.0 |
| `LegionForge/legionforge-guardian` | Security sidecar package | Phase G4 |
| `LegionForge/guardian-rules` | Community-contributed threat rules | Post-v1.0 |
| `LegionForge/legionforge-guardian-ts` | TypeScript SDK for guardian_check | Post-v1.0 |
| `LegionForge/legionforge-mcp` | MCP server package (if Guardian ships as MCP tool) | Future |

---

## Summary Checklist

### Before Starting G1
- [ ] License decision made (MIT recommended for guardian, AGPL for framework)
- [ ] `LegionForge` GitHub org created
- [ ] `LegionForge/legionforge-guardian` repo created (empty, no auto-README)
- [ ] PAT created and stored as `GUARDIAN_REPO_PAT` in jp-cruz/LegionForge secrets

### Phase G1 — Config decoupling ✅ COMPLETE
- [x] All `from src.*` module-level imports removed from guardian.py
- [x] All lazy `from src.*` function-body imports removed (including `/report` endpoint)
- [x] `_GUARDIAN_DESTRUCTIVE_PATTERNS`, `_validate_task_token`, `_append_audit_log_direct` inlined
- [x] 13 drift-guard smoke tests added (1969 → 1982)
- [x] **Test gate G1 passes** — 1982/1982 smoke tests

### Phase G2 — Package restructure
- [x] `packages/guardian/` directory created with pyproject.toml, init.sql, Dockerfile, docker-compose.yml
- [x] `legionforge_guardian/sdk/client.py` — GuardianClient + guardian_check() SDK
- [x] `-e packages/guardian` in requirements.txt
- [x] 11 SDK tests + 7 LegionForge smoke tests (1989/1989)
- [x] Guardian code moved to `legionforge_guardian/app.py`
- [x] `src/security/guardian.py` becomes thin re-export shim
- [x] **Test gate G2 passes** — 1989/1989 smoke tests (commit c74ffc2)

### Phase G3 — Standalone deployment
- [x] `init.sql` tested against both fresh DB and LegionForge DB — no-op, no errors
- [x] `packages/guardian/Dockerfile` CMD is `python -m legionforge_guardian` (canonical entry point)
- [x] `python -m legionforge_guardian` imports and resolves `main()` cleanly
- [x] 6 G3 smoke tests added (entry point, __main__, FastAPI app, Dockerfile CMD, init.sql schema)
- [x] **Test gate G3 partial** — smoke tests pass 1995/1995; Docker compose requires live Docker

### Phase G4 — Git subtree + GitHub org
- [ ] First `git subtree push` completes
- [ ] Sync Action added to LegionForge CI
- [ ] PyPI publish Action added to guardian repo
- [ ] Test change flows end-to-end (LegionForge dev → main → guardian repo)
- [ ] **Test gate G4 passes** (4 checks)

---

*See also: `jp_todo.md` § 4 (Guardian opportunity), `docs/VISION.md` (product roadmap)*
