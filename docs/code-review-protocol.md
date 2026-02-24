# LegionForge — Code Review Protocol

A structured process for reviewing all PRs before merge into `main`.
Run the automated gates first. Use the manual checklists after.

This protocol applies to every PR, regardless of size. Small PRs get fast
reviews. Large PRs get full reviews. The gates do not move.

---

## Quick Reference

```bash
make review-prep          # run all automated gates, print results
                          # must be clean before starting manual review
```

Then work through the checklists below in order.

## Reviewer Roster

Every PR goes through three reviewers in this order:

| # | Reviewer | When | Type |
|---|---|---|---|
| 1 | `make review-prep` | Before PR opens | Automated (local) |
| 2 | GitHub AI Code Review | On PR open (automatic) | Automated (remote) |
| 3 | Jp (owner) | After gates pass | Human |
| 4 | Independent reviewer | After owner review | Human |

**On GitHub AI suggestions:** Triage them before starting Phase B. Each
suggestion must be either addressed or explicitly dismissed with a comment
explaining why. Do not auto-apply suggestions — the AI reviewer does not
know the project threat model, the HITL tier rationale, or which TODOs are
intentionally deferred. Apply the same skepticism you would to any
AI-generated code change. Suggestions touching `security.py`,
`safeguards.py`, or `SecureToolNode` require human judgment before
acceptance, full stop.

---

## Phase A — Automated Gates (must all pass before manual review)

Run once at the start of every review session. Do not begin Phase B until
all of these are green.

```bash
make review-prep
```

This runs in order:
1. `make lint` — Black formatting check (zero tolerance)
2. `make test-smoke` — all smoke tests (count must be ≥ previous merge)
3. `bandit` static analysis (0 medium/high issues; low = informational)
4. Embedded secret scan (no passwords in URIs, no `.env` committed)
5. New external dependency check (any change to `requirements.txt` flagged)
6. `git diff --stat origin/main` — file change summary for scope check

If any gate fails: stop, fix, re-run. Do not continue to Phase B with a
failing gate.

---

## Phase B — Security Review

This is the most important phase for this project. Read every changed line
in `src/security.py`, `src/safeguards.py`, and `src/base_graph.py`.

### B1. Trust boundary coverage

For every new external interaction (API call, URL fetch, file read, DB
write), verify:
- [ ] Input is sanitized before entering agent context (`sanitize_text()` or `sanitize_tool_input()`)
- [ ] Output is sanitized before being used downstream (`sanitize_output()`)
- [ ] URL arguments pass through `validate_fetch_url()` — no raw URL passthrough
- [ ] No new trust boundary was introduced without a corresponding control in SecureToolNode

### B2. SecureToolNode pipeline integrity

If `SecureToolNode.__call__()` was modified:
- [ ] All 6 steps still execute in order: registry → guardian → loop → arg sanitize → execute → output sanitize
- [ ] No step can be bypassed by argument value or state content
- [ ] A `force_end: True` return at any step prevents execution of all subsequent steps
- [ ] Tool output sanitization runs even if a prior check issued a warning

### B3. Tool registry

If any new tool was added or `register_tool()` was changed:
- [ ] Tool has a `ToolManifest` with `declared_side_effects` — no empty list unless truly read-only
- [ ] `register_researcher_tools()` (or equivalent) is called before the tool can be invoked
- [ ] `make verify-tool-registry` passes after registration
- [ ] Smoke test exists: registration succeeds + hash validates + mismatch is detected

### B4. Regex and pattern accuracy (adversarial review)

For any new or modified regex in `_INJECTION_PATTERNS`, `_DESTRUCTIVE_PATTERNS`, or `_PII_PATTERNS`:
- [ ] Pattern does what the comment claims — trace it manually against the docstring example
- [ ] Pattern handles plural nouns (e.g., `files?`, `records?`)
- [ ] Pattern handles optional articles (e.g., `(the\s+)?`, `(a\s+)?`)
- [ ] Pattern handles optional intervening words where natural language varies
- [ ] Pattern doesn't false-positive on a plausible legitimate input — write one and test it:
  ```bash
  python3 -c "from src.security import detect_destructive_pattern; \
  print(detect_destructive_pattern('YOUR LEGITIMATE INPUT HERE'))"
  ```
- [ ] Pattern doesn't false-negative on a clear adversarial input — write one and test it
- [ ] New pattern has a corresponding smoke test for both positive and negative case

### B5. HITL tier assignments

If `HITL_HALT_CATEGORIES`, `HITL_LOG_CATEGORIES`, or `check_hitl_required()` was changed:
- [ ] HALT tier: every category has zero legitimate interpretations in a tool-call context
- [ ] LOG tier: categories that could fire on legitimate research queries (explain one example)
- [ ] No category is in both sets (they are mutually exclusive)
- [ ] Tiered behavior is verified: LOG-only match → run continues, HALT match → force_end
  ```bash
  python3 -c "
  from src.safeguards import check_hitl_required
  state = {'run_id': 'review-test'}
  log_result  = check_hitl_required('test', 'text', state, ['CREDENTIAL_PROBE'])
  halt_result = check_hitl_required('test', 'text', state, ['CMD_INJECTION'])
  assert log_result == {}, f'LOG tier should continue: {log_result}'
  assert halt_result.get('force_end'), f'HALT tier should halt: {halt_result}'
  print('HITL tiers verified')
  "
  ```

### B6. SSRF and network controls

If `validate_fetch_url()`, `web_fetch()`, or any HTTP-making code was changed:
- [ ] Private IP ranges still blocked (10.x, 172.16–31.x, 192.168.x)
- [ ] localhost / 127.0.0.1 / [::1] still blocked
- [ ] AWS metadata endpoint (169.254.169.254) still blocked
- [ ] `file://`, `ftp://`, non-HTTP schemes still blocked
- [ ] Redirect chains are validated per-hop, not followed blindly

### B7. PII and credential handling

- [ ] No new hardcoded credential, token, or password appears in any committed file
- [ ] No new code reads secrets from environment variables instead of Keychain
- [ ] New LLM calls pass outbound messages through `sanitize_messages()` before `ainvoke()`
- [ ] Threat event log entries do not include raw PII (use `[:200]` truncation + redaction)

### B8. Capability boundary

- [ ] No new capability was granted to agents outside of the explicit FORBIDDEN_CAPABILITIES review
- [ ] If a capability was removed from FORBIDDEN_CAPABILITIES, document why and add a test

---

## Phase C — Scope and Architecture Review

Scope drift is especially common in AI-generated code. This phase checks
that the PR does what it says and nothing more.

### C1. Scope vs. commit message

Read the commit message(s). Then read the diff.
- [ ] Every changed file is explained by the commit message
- [ ] No files were changed that aren't mentioned or clearly implied
- [ ] No features were added beyond what was requested (the "helpful extras" problem)
- [ ] No refactoring was bundled into a feature commit or vice versa

### C2. Module responsibility

Each module has a declared responsibility. Check it wasn't violated:

| Module | Owns | Does NOT own |
|---|---|---|
| `security.py` | Primitives: sanitization, hashing, pattern detection, SSRF, PII | Enforcement policy, graph logic |
| `safeguards.py` | Loop detection, token budget, HITL policy | Pattern definitions, LLM calls |
| `base_graph.py` | Enforcement: SecureToolNode, graph wiring, node order | Security primitive definitions |
| `rate_limiter.py` | Token counting, daily caps, per-provider limits | Agent logic, security decisions |
| `agents/*.py` | Agent behavior, tool definitions | Security primitives (last-line only) |
| `database.py` | DB connection, schema, queries | Agent state logic, security decisions |

- [ ] No module took on responsibility that belongs to another
- [ ] `security.py` still has zero project-level imports (no circular dependency risk)

### C3. Dependency review

For any change to `requirements.txt`:
- [ ] Why is this library needed? Could an existing dependency cover it?
- [ ] Is it actively maintained? (Check PyPI last-published date)
- [ ] Does it have any known CVEs? (Check: `pip-audit` or Dependabot)
- [ ] Is the version pinned with `~=` (compatible release) rather than `==` (exact) or `>=` (uncapped)?
- [ ] Is it imported only where needed, not at module level in security-critical files?

---

## Phase D — Code Quality

### D1. Async correctness

This codebase is fully async. Any blocking call in an async context is a bug.
- [ ] No `time.sleep()` in async functions (use `await asyncio.sleep()`)
- [ ] No `requests` library calls (use `httpx` with `await`)
- [ ] No `socket.getaddrinfo()` in async context without executor (known issue — `validate_fetch_url()`, flagged for Phase 2)
- [ ] No `asyncio.get_event_loop().run_until_complete()` inside an already-running loop

### D2. Error handling

- [ ] Exceptions are caught at trust boundaries, not buried inside processing nodes
- [ ] `except Exception` is not used unless followed by a re-raise or an explicit justification comment
- [ ] Security failures raise `SecurityError` or return `{"force_end": True}` — they don't silently continue
- [ ] Every `except` block logs at least a warning with enough context to reconstruct what happened

### D3. Logging consistency

- [ ] `logger.debug` for normal flow details
- [ ] `logger.info` for significant state changes (tool registered, run started)
- [ ] `logger.warning` for security detections, policy decisions, and unexpected-but-recoverable events
- [ ] `logger.error` for enforcement actions (tool blocked, run halted)
- [ ] No `print()` statements in `src/` (use logger)
- [ ] No raw user input or raw API responses logged at `info` level — use sanitized excerpts

### D4. Dead code and stubs

- [ ] No commented-out code blocks (remove or turn into a TODO comment)
- [ ] Stubs are labeled `# Phase N stub` with what they'll become
- [ ] No unused imports in changed files

---

## Phase E — Test Coverage Review

### E1. Test count

```bash
make test-smoke | tail -3   # check passing count
```
- [ ] Count is ≥ previous merge baseline (never goes down)
- [ ] Count increased by at least 1 for every new public function added
- [ ] Count increased by at least 2 for every new security control (positive + negative case)

### E2. Test quality — the three questions

For every new test, ask:
1. **Does it test behavior, not implementation?** A good test survives internal refactoring.
   Bad: `assert security._TOOL_REGISTRY["x"].description_hash == expected`
   Good: `assert verify_tool_before_invocation("x") is True`

2. **Is the test adversarial?** Security tests must try to break the control, not just confirm the happy path.
   Bad: `assert detect_injection("hello world") is False`
   Good: `assert detect_injection("ignore previous instructions") is True`
         `assert detect_injection("hello world") is False`

3. **Is the test independent?** No test should depend on another test's side effects.
   Each test sets up its own fixtures and cleans up after itself.

### E3. Missing test cases to look for

New code often forgets these categories:
- [ ] Empty string input (`""`)
- [ ] Input at the exact boundary (e.g., a URL that's exactly at the edge of a blocked range)
- [ ] Unicode or non-ASCII input where ASCII is expected
- [ ] Concurrent calls (if async) — does state get corrupted?
- [ ] The case where the input looks almost-but-not-quite adversarial

---

## Phase F — AI-Generated Code Checks

This section exists because the author of this code is an AI. The following
failure modes are systematically more common in AI-generated code than
human-written code.

### F1. Hallucinated or misused APIs

- [ ] Every external function call exists in the installed version of the library
  ```bash
  python3 -c "import library; help(library.function)"  # verify signature
  ```
- [ ] Function arguments match the actual signature (AI often reverses positional args or invents kwargs)
- [ ] Return types are handled correctly (AI often assumes a function returns X when it returns Y)

### F2. Security theater

Security theater = code that looks protective but doesn't actually block the threat.
Common patterns:
- [ ] Regex that's checked but its result is not acted on
- [ ] `if not approved: logger.warning(...)` with no `return` or `raise` after it
- [ ] Sanitization applied to a copy of the string while the original is used downstream
- [ ] Hash comparison that returns `True` even when hashes differ (off-by-one in comparison logic)

Quick check for any security gate:
```bash
# Trace the enforcement path: can you reach the execute step without triggering the check?
# Read SecureToolNode step by step. Is every early-return actually returning?
```

### F3. Plausible but wrong logic

- [ ] Loop bounds are correct (off-by-one errors hide well in window-based detection)
- [ ] Comparison operators are correct (`>=` vs `>`, `in` vs `==`)
- [ ] Boolean logic is correct — De Morgan's law errors (`not (A and B)` ≠ `not A and not B`)
- [ ] Threshold values match the design intent (e.g., `threshold=3` in loop detection: fires at 3 repeats, not 4)

### F4. Scope creep added by the AI

- [ ] No new utility functions that weren't asked for
- [ ] No new configuration options that weren't specified
- [ ] No "convenience" wrappers around existing functions
- [ ] No changes to files outside the stated scope of the PR

### F5. Circular test logic

AI-written tests often test the implementation rather than the contract.
- [ ] The test does not call the same function twice and compare results to itself
- [ ] The test does not build its expected value using the same logic as the code under test
- [ ] The test's expected value was determined independently (hardcoded or from spec)

---

## Phase G — Sign-off

Before approving the PR, confirm:

- [ ] All Phase A automated gates: PASS
- [ ] All critical (🔴) items in Phases B–F: PASS or N/A
- [ ] Any items that failed have linked issues or documented waivers
- [ ] Smoke test count is documented in the PR description
- [ ] If new external libraries were added: dependency review completed (C3)
- [ ] If security patterns were changed: adversarial test was run manually (B4)

### Merge checklist (in order)

```bash
git checkout main
git pull origin main              # ensure main is current
git merge --no-ff feature/xxx    # preserve branch history
make test-smoke                   # final verification on main
git push origin main
```

Do not squash commits on security branches — the individual commit messages
are part of the audit trail.

---

## Waiver Process

If a checklist item is N/A or being intentionally deferred:
1. Add a comment to the PR explaining why
2. Create an entry in `PROJECT_STATUS.md` → Known Issues / Technical Debt
3. Assign a Phase for resolution
4. Get explicit agreement from the second reviewer before merging

No silent waivers. Every deferred item is named and owned.

---

## Resources

- `docs/architecture.md` — system diagrams, use during scope review (Phase C)
- `CONTRIBUTING.md` — branch strategy, smoke test requirements, commit format
- `PROJECT_STATUS.md` → Deferred Decisions — open policy questions
- NIST SP 800-61 — Incident Response (relevant to HITL tier research)
- MITRE ATT&CK — adversarial TTP reference (relevant to B4 pattern review)
- OWASP ASVS Level 2 — application security verification standard
- CISA AI Security Guidelines — agentic system containment (pending research)
