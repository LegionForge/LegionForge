VERSION: 0.7.1-alpha
UPDATE: 340
BRANCH: dev
COMMIT: 75cfa93 (uncommitted changes pending — see NEXT.md)
TIMESTAMP: 2026-03-20T23:30Z
LAST_OP: UAT Day 6 (session 2) — SSH keychain isolation root cause fixed; gateway-start now injects all 10 secrets; Ollama auto-eviction added; num_ctx=16384 for all Ollama models; issues #288–#291 opened; mercury-2 + llama3.1:8b weather/knowledge tests passed.
NEXT_OP: Commit today's fixes (Makefile + core.py + llm_factory.py) → PR → complete #266 HITL backend → fix #291 cancel button 404 → T4 UAT block
SMOKE_TESTS: 2252/2252
INTEGRATION_TESTS: 41/41
KERBEROS_TESTS: 5/5
UI_TESTS: 40/40
TESTLAB_SUITE: 104/104
TOOL_ACCURACY_TESTS: 79/79 (29 existing + 50 web_fetch_js)
HALLUCINATION_TESTS: 12 (live web + UUID nonce anti-fabrication; manually run)
TOOL_INTEGRITY_TESTS: 43 (schema conformance 12 + result injection 4 + Guardian e2e 5 + sandbox 16 + memory isolation 6)
CRYSTALLIZATION_TESTS: 114/114 (observer 30 + crystallizer 24 + analyzer 29 + hitl 18 + security 13)
