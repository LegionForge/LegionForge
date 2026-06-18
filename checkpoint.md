VERSION: 0.7.1-alpha
UPDATE: 347
BRANCH: main
COMMIT: 9a6cc2c
TIMESTAMP: 2026-06-15T04:30Z
LAST_OP: CI hardening — three PRs merged closing the correctness slice of issue #29: #43 (F811/F821 ruff fixes — real undefined-name bugs), #44 (fastapi~=0.135.0 pin — 0.137 broke route enumeration in `app.routes`), #45 (F401/F541/F841/E402 cosmetic ruff cleanup). Smoke tests on main now green again; bandit (99 LOW), pytest CVE, semgrep, and test-infra decision remain open from #29. Filed Guardian issues #18–#21 (multi-turn / multi-modal / synthesis attacks + ADR for security-layer architecture).
NEXT_OP: triage bandit 99 LOW findings (likely mostly `# nosec`-justifiable) as separate PR; then pytest 9.x bump for CVE-2025-71176; then semgrep review pass. Test-infra decision (skip markers vs service containers) needs Jp's architectural call.
SMOKE_TESTS: 2255/2255
INTEGRATION_TESTS: 41/41
KERBEROS_TESTS: 5/5
UI_TESTS: 40/40
TESTLAB_SUITE: 104/104
TOOL_ACCURACY_TESTS: 79/79 (29 existing + 50 web_fetch_js)
HALLUCINATION_TESTS: 12 (live web + UUID nonce anti-fabrication; manually run)
TOOL_INTEGRITY_TESTS: 43 (schema conformance 12 + result injection 4 + Guardian e2e 5 + sandbox 16 + memory isolation 6)
CRYSTALLIZATION_TESTS: 114/114 (observer 30 + crystallizer 24 + analyzer 29 + hitl 18 + security 13)
