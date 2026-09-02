VERSION: 0.7.1-alpha
UPDATE: 348
BRANCH: main
COMMIT: 967f592
TIMESTAMP: 2026-09-01T13:30Z
LAST_OP: Org-wide Dependabot/CI sweep — merged a large batch of dependency bumps (redis, psycopg, numpy, pyjwt, langchain, pytest-asyncio, aiohttp, sse-starlette, actions/checkout, actions/setup-python), a real CodeQL fix (clear-text-logging + log-injection, #55), the sast job permissions fix (#62, closes the org-wide dev-rig startup_failure bug — see lessons-legionforge LF-13), a dev-rig SHA pin (#61), the README donate-link addition + footer move, and a Python 3.11→3.14-slim sandbox base image bump (#37) with its matching test fix. `dev` branch no longer exists on origin — all work lands on `main` via feature branches now.
NEXT_OP: bandit 99 LOW findings, pytest CVE-2025-71176 bump, and semgrep review pass from #29 are still untriaged (predate this session, not addressed here). Issue numbering has shifted since this file was last accurate — see issues #24/#25/#26 (renumbered from what earlier notes call #295/#296/#297) for the Guardian+Anneal / credential-provider / infra-secrets decisions, still open.
SMOKE_TESTS: 2255/2255
INTEGRATION_TESTS: 41/41
KERBEROS_TESTS: 5/5
UI_TESTS: 40/40
TESTLAB_SUITE: 104/104
TOOL_ACCURACY_TESTS: 79/79 (29 existing + 50 web_fetch_js)
HALLUCINATION_TESTS: 12 (live web + UUID nonce anti-fabrication; manually run)
TOOL_INTEGRITY_TESTS: 43 (schema conformance 12 + result injection 4 + Guardian e2e 5 + sandbox 16 + memory isolation 6)
CRYSTALLIZATION_TESTS: 114/114 (observer 30 + crystallizer 24 + analyzer 29 + hitl 18 + security 13)
