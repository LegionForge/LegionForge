# Contributing & Branch Strategy

## Branch Model

```
main          ← stable, always deployable
  └── dev     ← integration branch for features
        └── feature/xxx   ← individual feature branches
        └── fix/xxx        ← bug fixes
        └── refactor/xxx   ← refactoring
```

### Rules
- **Never commit directly to `main`** for anything beyond trivial config changes
- All agent code goes through a feature branch → PR → merge to `dev` → PR → `main`
- `main` must always pass all tests before merge
- Use descriptive branch names: `feature/postgres-checkpointer`, `fix/loop-detection-off-by-one`

---

## Smoke Test Requirements

**The smoke test suite (`tests/test_smoke.py`) must be kept current at all times.**

### The Rule
Every new component, function, or security control gets a smoke test written
alongside it — not after. A component without a test is not considered complete.

### What Requires a Test

| Added or changed | Required test |
|---|---|
| New function in any `src/` module | At least one test covering the happy path |
| New security control | Test for both detection (positive) and non-detection (negative) |
| New database table or migration | Test that the table exists and schema is correct |
| New Guardian check | Test that it blocks what it should block |
| New tool registered | Test that registration succeeds and hash validates |
| New capability boundary | Test that violation is detected |
| New agent | Integration test in `tests/test_<agent_name>.py` |
| Modified existing function | Verify existing tests still pass; add new test if behavior changed |
| Security fix or CVE response | Test that the vulnerable pattern is now blocked |

### What a Good Smoke Test Looks Like

Smoke tests are fast and deterministic — no network, no database, no LLM calls
unless explicitly marked as integration tests.

```python
# Good — fast, deterministic, no external dependencies
def test_tool_hash_mismatch_detected():
    manifest = register_tool("test_tool", description="desc", schema={})
    manifest.description_hash = "tampered"
    result = verify_tool_integrity("test_tool", manifest)
    assert result is False

# Good — tests both directions
def test_capability_boundary_blocks_register_tool():
    assert check_capability_boundary("register_tool") is False

def test_capability_boundary_allows_web_search():
    assert check_capability_boundary("web_search") is True

# Bad — requires live external service, belongs in integration tests instead
def test_researcher_fetches_url():   # ← move to tests/test_researcher.py
    ...
```

### Naming Convention

```
test_<module>_<what_it_does>         # happy path
test_<module>_<what_it_blocks>       # security negative case
test_<module>_<edge_case>            # boundary condition
```

Examples:
```
test_tool_registry_registers_tool
test_tool_registry_hash_mismatch_blocked
test_guardian_blocks_unregistered_tool
test_guardian_allows_registered_tool
test_capability_boundary_blocks_escalation
test_pii_redaction_on_tool_output
```

### Before Every Commit

```bash
pytest tests/test_smoke.py -v
```

All tests must pass. A failing smoke test is a merge blocker — fix the test
or fix the code, but don't commit a broken suite.

### Test Count Tracking

The current passing count is the floor — it never goes down. If a refactor
removes a function, remove its test AND add a replacement test for the new
implementation. The count should trend upward over time.

| Phase | Minimum test count |
|---|---|
| Phase 0 complete | 23 ✅ |
| Phase 1 complete | 35+ (tool registry, capability boundaries, output sanitization, cost estimation) |
| Phase 2 complete | 45+ (Guardian checks, audit log, RAG provenance) |
| Phase 3 complete | 55+ (ACL tokens, sub-agent spawning, privilege escalation blocks) |

---

## Starting a New Feature

```bash
# Always branch from dev, not main
git checkout dev
git pull origin dev
git checkout -b feature/your-feature-name

# ... do work ...
# ... write tests alongside the code ...

pytest tests/test_smoke.py -v   # must pass before committing

git add <specific files>        # never git add . without reviewing first
git status                      # verify staged list before committing
git commit -m "feat: description of change"
git push origin feature/your-feature-name

# Then open a PR on GitHub: feature/xxx → dev
```

---

## Commit Message Format

```
type: short description (50 chars max)

Optional longer body explaining WHY, not what.
```

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `perf`, `security`

Examples:
```
feat: add tool registry with human approval gate
fix: loop detection not firing on identical tool calls
security: pin langgraph-checkpoint-sqlite to fix CVE-2025-64104
test: add smoke tests for capability boundary enforcement
docs: update hardware profile comments
```

---

## Setting Up Branch Protection (GitHub)

Once you have regular workflow, enable in GitHub:
- Settings → Branches → Add rule for `main`
- ✅ Require pull request before merging
- ✅ Require status checks to pass
- ✅ Do not allow bypassing the above settings

---

## Creating the dev Branch

```bash
git checkout -b dev
git push origin dev
```

Set `dev` as the default branch for PRs in GitHub Settings → General.
