# Test Bench & Integrity Review Findings

**Reviewed:** 2026-03-15
**Reviewer:** Automated analysis (read-only)
**Scope:** Full test suite — smoke (2247), testlab (104), UI/Playwright (40), integration (41), tool_accuracy (79), crystallization (114), tool_integrity, hallucination

---

## Critical Gaps (untested code that could ship broken)

**1. Worker concurrency and watchdog paths have no unit tests.**
`src/gateway/worker.py` implements configurable concurrency (`WORKER_CONCURRENCY`), a 5-minute watchdog heartbeat that reaps stuck `running` tasks (`reap_stuck_tasks`), and the purge heartbeat for `stream_tokens`. The smoke suite verifies importability and that `record_api_usage` is called — it does not test the watchdog, the concurrency semaphore, or what happens when two workers race for the same task. The only end-to-end worker test (`test_task_worker_completes_and_writes_result`) is `@pytest.mark.ollama` and skipped in CI when Ollama is absent. A stuck-task scenario (worker dies mid-run) is completely untested outside of a live run.

*Suggested approach:* Mock `claim_next_queued_task` / `mark_task_running` / `mark_task_failed` and drive `task_worker()` with injected tasks; assert the watchdog fires and `reap_stuck_tasks` is called. No Ollama required.

**2. Gateway route modules with zero behavioral test coverage.**
The following routes in `src/gateway/routes/` have no integration or testlab tests that exercise their actual logic against the real gateway app:
- `sessions.py` — session management endpoints
- `models.py` — LLM model listing
- `annotations.py` — annotation endpoints
- `templates.py` — template handling
- `schedules.py` — schedule CRUD (only importability smoked)
- `pipelines.py` — pipeline runner endpoints

The smoke suite verifies import paths and structural assertions (source inspection). No HTTP-level tests exist for these routes. A regression in any route handler would only surface in a live run.

*Suggested approach:* Add testlab functional tests for each route's happy path and at least one error path, using the existing mock gateway pattern.

**3. Scheduler daemon has no behavioral tests.**
`src/scheduler.py` has importability and cron-expression validation smoke tests. There are no tests for:
- The poll loop (`Scheduler._loop`) actually firing a due job
- `next_run_at` advancement after a job fires
- `@every N` interval syntax expanding correctly end-to-end
- Scheduler behavior when `create_task()` raises (does it crash or continue?)

*Suggested approach:* Test `Scheduler` with a mock DB that returns a due job once, assert `create_task` was called and `next_run_at` was advanced.

**4. Connector resilience has no tests for mid-stream disconnect.**
`src/connectors/discord.py`, `telegram.py`, `slack.py`, and `whatsapp.py` all stream SSE from the gateway and edit messages as tokens arrive. There are no tests for:
- Gateway SSE stream drops mid-task (connection reset)
- Token limit exceeded mid-stream
- Discord rate-limit (429) on message edits

WhatsApp has solid smoke coverage (HMAC, verify token, message routing). Discord has importability and function-signature tests. Telegram and Slack have only importability tests (`test_p16_telegram_connector_importable`, `test_p16_slack_connector_importable`) — no behavioral coverage at all.

*Suggested approach:* For Telegram and Slack, port the WhatsApp-style smoke test pattern: build_app() with test config, send mock webhook payloads via ASGI transport, assert routing and PII handling.

**5. HITL approval/reject flow has no end-to-end integration test.**
The HITL smoke tests (`TestHITLApprovalFlow`) verify structural wiring: that `AgentState` has the right fields, that `hitl_gate_node` is async, that `check_hitl_required` returns `hitl_pending=True`. The `crystallization/test_hitl_api.py` tests the health-server HITL endpoints with mocked DB. But there is no test that runs a real agent graph, triggers HITL (by injecting a destructive action), and then approves or rejects it through the API to verify the graph resumes or terminates correctly. The gate node wiring is tested structurally, not behaviorally.

*Suggested approach:* Integration test using mocked LLM + real gateway: submit task, wait for `hitl_pending`, POST to `/hitl/{id}/approve`, assert task transitions to `running` then `complete`.

---

## Coverage Gaps (important but not critical)

**6. `src/gateway/auth.py` token expiry edge cases not tested.**
Integration tests cover `create_stream_token`, `resolve_stream_token` (expired, unknown), and `purge_expired_stream_tokens`. Not tested: stream tokens that expire exactly at the boundary (now = expires_at), the race between a token being resolved and then expiring, or behavior when the DB is unavailable during `resolve_stream_token`.

**7. `src/rate_limiter.py` per-user Redis path is not integration-tested.**
The smoke suite tests the in-process `DailyCounter` class and the `preflight_budget_check` function. There are no tests for the Redis-backed global budget counter path (Phase 14 Redis counters). If the Redis connection is missing or stale, the fallback behavior is not tested.

**8. `src/agents/orchestrator.py` fan-out path has no behavioral test.**
The `fan_out_researchers` tool (parallel sub-agent dispatch via `asyncio.gather`) has importability and manifest smoke tests but no test that actually drives `run_orchestrator` through the fan-out path with a mocked LLM and asserts that multiple sub-tasks were dispatched and their results merged.

**9. `src/agents/threat_analyst.py` has only structural smoke tests.**
State fields, tool IDs, escalation policy, and importability are tested. There are no tests that run `run_threat_analyst()` — even with mocked LLM and DB — to verify it reads threat events, produces a report, and handles an empty threat log.

**10. `src/agents/pentest_agent.py` and `src/agents/pentest_report.py` have only importability tests.**
The pentest graph (`build_pentest_graph`) and the full pentest agent pipeline have no behavioral tests. Given these agents produce security reports, regressions in their output format or tool usage would be invisible.

**11. `src/pipeline_runner.py` has no tests.**
No smoke or integration test covers `PipelineRunner` or the pipelines route behavior.

**12. `src/ingestor.py` chunk logic is smoke-tested but DB write path is not.**
`chunk_text` is tested with edge cases. `DocumentIngestor.ingest()` (the actual DB write path for RAG documents) is not tested. A regression in the pgvector upsert logic would be silent.

**13. `src/task_cache.py` hash function is tested, but cache hit/miss path is not.**
`compute_task_hash` is smoke-tested. The actual `use_cache=True` gateway path — serving a cached result instead of spawning the agent — is untested beyond structural inspection.

**14. `src/memory.py` `MemoryStore.search` sanitization check is structural only.**
The smoke test (`test_memory_search_sanitizes_retrieved_chunks`) uses `inspect.getsource` to assert `sanitize_output` is called. There is no behavioral test that passes a chunk containing a prompt-injection payload through the full `search()` path and verifies the output is redacted.

**15. `src/observability.py` Prometheus /metrics endpoint not exercised in testlab.**
Smoke tests verify `MetricsCollector` records metrics correctly. The Prometheus `/metrics` endpoint (Phase 14) is tested only via importability and source inspection of the middleware. No HTTP test hits the endpoint and validates the output format.

**16. A2A and MCP endpoints have only structural smoke tests.**
`test_a2a_agent_card_has_required_fields` and `test_gateway_mcp_router_has_tools_endpoint` check data shapes. There are no testlab or integration tests that POST to `/a2a/tasks` or `/mcp/tools/invoke` and verify the response.

---

## Test Quality Issues (tests that exist but are weak)

**17. 175 tests use `inspect.getsource()` to assert implementation details.**
`tests/test_smoke.py` contains at least 175 tests that grep the source of a module for a string (e.g., `"await check_hitl_required("`, `"sanitize_log_value"`, `"append_audit_log"`). These tests verify that a symbol appears in the source text — not that it is actually called or produces the correct result. A refactor that changes the call site name without changing behavior would break these tests; a change that removes the call without changing the symbol name would let the test pass silently. These are brittle maintenance traps, not behavioral guards.
- Files/examples: `tests/test_smoke.py:729`, `23868`, `23883`, `23892`, `23903`, `23915`, and ~168 more.
- *Improvement:* Replace source-inspection tests with behavioral equivalents where the function under test is actually invoked with controlled input.

**18. `test_zshrc_does_not_export_postgres_password` and `test_lf_restart_function_in_zshrc` are machine-specific.**
These tests read `~/.zshrc` from the developer's home directory. They pass trivially on any machine that doesn't have a `.zshrc`, and they produce false failures on a CI runner or another developer's machine. They are implementation checks masquerading as portability tests.
- File: `tests/test_smoke.py:24104`, `24135`.
- *Improvement:* Move to a separate `make dev-check` target, not part of `make ci`.

**19. `test_ollama_ps_endpoint_reachable` silently passes when Ollama is down.**
The test (`tests/test_smoke.py:24122`) wraps everything in `except Exception: pass` — it always passes, providing zero signal.
- *Improvement:* Remove from smoke suite or convert to an explicit `pytest.skip` with a reason.

**20. `test_jp_not_hardcoded_in_production_configs` — RESOLVED (2026-03-15).**
The PostgreSQL superuser has been renamed from `jp` to `legionforge_admin`. The TEMPORARY test has been removed. Smoke baseline is now 2246.

**21. DoS tests assert `< 500` (no 5xx) but not `< 4xx` for valid inputs.**
`test_concurrent_task_flood` sends 20 concurrent tasks with valid auth and asserts only `r.status_code < 500`. If the gateway returns 429 (rate limit) or 503 (capacity), the test still passes. This is appropriate resilience testing but should be distinguished from correctness testing.

**22. `test_task_list_returns_only_own_tasks` has a weak isolation assertion.**
The assertion `task.get("user_id") == test_user["user_id"] or "user_id" not in task` permits tasks without a `user_id` field to pass silently. If the API stops returning `user_id` in task objects, the cross-user isolation check becomes vacuous.
- File: `tests/test_integration.py:466`.

**23. The mock gateway in testlab uses a different injection pattern list than production.**
`tests/testlab_suite/conftest.py:40` defines 7 `_INJECTION_PATTERNS` that are a partial, simplified version of the actual `src.security.core._INJECTION_PATTERNS` (29 patterns in production). Tests that rely on the mock gateway's injection detection cannot catch regressions in the real injection patterns. An attacker payload blocked by production but not in the mock would produce a false negative test result.

---

## Missing Test Categories (entire test types not present)

**24. No property-based or fuzzing tests for the security core.**
The injection detection, PII redaction, and SSRF validation logic in `src/security/core.py` is tested with handpicked examples. There are no property-based tests (e.g., using Hypothesis) that generate:
- Random Unicode strings and assert they don't crash `detect_injection`
- Encoded variants (base64, URL-encoding, Unicode escapes) of known patterns
- URLs with unusual encodings and assert SSRF detection is not bypassed

*Suggested approach:* Add `tests/test_security_property.py` using Hypothesis to fuzz `detect_injection`, `validate_fetch_url`, and `sanitize_text` with generated inputs.

**25. No contract tests for external service interfaces (Guardian, Ollama, PostgreSQL).**
If the Guardian sidecar changes its `/check` response schema (adds a required field, renames `tier`), the framework would silently mishandle responses. There are no schema-validation contract tests that run against the real Guardian sidecar (beyond the 4 `tool_integrity/test_guardian_e2e.py` tests). Similarly, there are no contract tests for the Ollama `/api/chat` response format or psycopg pool behavior under connection exhaustion.

**26. No concurrency tests for the production gateway (not the mock).**
`test_dos.py` runs concurrency tests against the `TestlabMockGateway`. There are no concurrency tests against the real FastAPI gateway with a real DB pool, which is where pool exhaustion, connection leaks, and event-loop blocking would actually surface.

**27. No chaos / fault-injection tests for database failure mid-task.**
There is no test that simulates a PostgreSQL connection drop while a task is in the `running` state and verifies:
- The worker catches the exception and marks the task `failed`
- The SSE subscriber receives a `task_error` event
- No task is left stuck in `running` after the DB recovers

**28. No load or stress tests.**
The project has DoS resilience tests but no load tests that measure throughput, latency percentiles, or memory growth under sustained load. There is no baseline to detect performance regressions introduced by new middleware or DB queries.

**29. No snapshot/regression tests for UI output.**
UI tests verify DOM structure and interaction flows but have no visual snapshot tests. A CSS change that breaks the output display would not be caught. Playwright supports screenshot-based regression tests.

**30. No negative tests for the crystallization pipeline's Ed25519 signing.**
`src/tools/signing.py` handles Ed25519 signature generation for crystallized tools. There are no tests for:
- Signing with a missing/corrupt key
- Verifying a signature after the key is rotated
- Tampered signature detection in the tool registry check after crystallization approval

**31. No tests for `src/gateway/routes/hitl.py` resume behavior with LangGraph checkpointer.**
The HITL route calls LangGraph's graph resume mechanism. There are no tests that verify the checkpoint is correctly restored and the graph continues from the right node after approval. This is the most critical behavioral gap in the HITL feature.

---

## Nice-to-Have (polish)

**32. No test for the `use_cache=True` gateway path producing a cache hit.**
The `task_cache` module is smoke-tested for hash stability but the actual cache-hit serving path is untested.

**33. No test for the Prometheus `/metrics` output format validity.**
Prometheus scrape format is strict. A stray newline or missing HELP line would cause the scraper to fail silently. A test that parses the output with the `prometheus_client` parser would catch this.

**34. No test for `src/cost_estimator.py` accuracy.**
Token estimation is used for pre-flight budget checks. There are no tests that feed known prompts to `estimate_tokens` and assert the output is within a reasonable bound.

**35. The `TestHITLApprovalFlow.test_hitl_log_tier_still_returns_empty` assertion is ambiguous.**
`assert result == {} or not result.get("hitl_pending")` — this passes if `result` is `None`, an empty dict, or any dict without `hitl_pending`. The intent (LOG tier should not interrupt the run) would be better expressed as an explicit assertion that `result` is `{}` exactly.
- File: `tests/test_smoke.py:24217`.

**36. `test_novel_llm.py` and `test_novel_security.py` generate and execute LLM-written code.**
These tests call `exec()` on LLM-generated pytest functions inside a subprocess. The security of the generated test execution environment is not hardened (no sandbox, no timeout per generated test). This is a low-risk developer tool but worth noting for the v1.0 security audit.

---

## Test Infrastructure Improvements

**37. The known asyncio event-loop pollution footgun has no automated guard.**
The CLAUDE.md documents that `asyncio.run()` calls in sync smoke tests can null the thread-local event loop and break session-scoped async fixtures in a subsequent testlab run. There is no CI step that runs `pytest tests/test_smoke.py tests/testlab_suite/` in a single session to confirm the isolation holds after any new `asyncio.run()` addition. The `make ci` target uses separate sessions, which is the fix — but the `test_smoke.py` file has 68 `asyncio.run()` calls, and any new one could break combined-session runs silently.

*Suggested:* Add a `make test-combined-smoke-testlab` target that intentionally runs both suites in one session and is run as a canary before the separate-session `make ci` run.

**38. The `@requires_*` skip decorators in `tool_integrity/conftest.py` evaluate at collection time.**
`requires_llm_stack`, `requires_guardian`, `requires_docker_sandbox`, and `requires_postgres` call external services (`httpx.get`, `subprocess.run`) at import time during test collection. If the service is briefly unavailable during collection but available by the time the test runs, the test is skipped unnecessarily. On a fast developer machine this is usually fine, but on a slow CI runner with cold-start services, tests will be silently skipped.

*Suggested:* Convert to `pytest.mark.skipif` with a deferred lambda or use `pytest.skip()` inside the test body after a quick availability check.

**39. No fixture for a deterministic mock LLM that returns a specific tool call sequence.**
`mock_llm_with_tool_call` in the root conftest is a factory for a single tool call. There is no fixture for a stateful mock LLM that returns tool call A on the first invocation, tool result B on the second, etc. This makes it difficult to write unit tests for multi-step agent graphs without pulling in Ollama.

*Suggested:* Add a `mock_llm_sequence` fixture to the root `conftest.py` that accepts a list of `AIMessage` responses and returns them in order.

**40. `admin_conn` fixture in root conftest is function-scoped but creates a new TCP connection per test.**
The admin connection is expensive and only needed for DELETE operations. On 41 integration tests, this creates up to 41 connections. This is acceptable at current scale but could be a bottleneck if the integration suite grows significantly. A session-scoped admin connection with explicit transaction boundaries per test would be more efficient.

**41. Session-scoped fixtures in `testlab_suite/conftest.py` share state across tests.**
The `TestlabMockGateway._tasks` dict is reset via `gateway_server.reset()` — but `reset()` is not automatically called between tests; tests must call it explicitly. If a test fails before calling reset, state leaks into the next test. This is currently mitigated by most tests not checking pre-existing tasks, but it is a latent isolation issue.

*Suggested:* Add an autouse function-scoped fixture in `testlab_suite/conftest.py` that calls `gateway_server.reset()` before each test.

---

## Already Well-Tested (do not regress)

- **Injection detection** — 29 patterns tested with positive and negative cases, pattern count regression guard, tier 1/tier 2 detection, encoding bypass variants, and hypothetical framing
- **SSRF protection** — `validate_fetch_url` tested for RFC 1918, loopback, link-local, metadata endpoints, and non-HTTP schemes; async variant also tested
- **Task token ACL** — issue/validate roundtrip, tamper detection, privilege escalation block, subset derivation, escalation policy defaults
- **Tool registry integrity** — hash determinism, mismatch detection, capability boundary enforcement, forbidden capabilities set
- **Audit log hash chain** — genesis sentinel stability, row hash determinism, mutation detection
- **PostgreSQL RLS** — user isolation on tasks table, BYPASSRLS worker pool, maintenance role SELECT denied
- **Auth: API key bcrypt** — verified constant-time comparison, no plain-text comparison
- **Guardian check pipeline** — request/response model validation, Check 0 (token validation), Check 1 (tool revocation), Check 2 (destructive patterns); schema conformance tested
- **Safeguards** — all three loop-protection layers tested: step counter, action history hash, token budget
- **Rate limiter** — hard daily limit, per-call limit, per-user budget check, preflight block
- **SSE event delivery** — stream open, event delivery, terminal event close tested in integration
- **HITL API endpoints** — all four CRUD operations (list, get, approve, reject, revise) tested with mocked DB, auth enforcement, DB failure 503 handling
- **WhatsApp connector** — HMAC validation, verify token challenge, wrong token rejection, text message routing, PII phone hash, health endpoint
- **Crystallization analyzer** — forbidden construct detection (exec, eval, subprocess, socket, open write, getattr bypass, sys.modules, subclass escape), cyclomatic complexity, syntax error capture
- **Crystallization security** — observer and crystallizer cannot call register_tool or sign_manifest; analyzer is stdlib-only
- **Memory isolation** — cross-agent and cross-user namespace isolation (requires PostgreSQL)
- **Code sandbox** — network isolation, filesystem read-only, memory cap enforcement (requires Docker)
- **Tool result injection** — Tier 1 injection in fetched page halts the researcher run (requires Ollama)
- **PII redaction** — email, phone, SSN redacted in sanitize_text, sanitize_output, sanitize_tool_input
- **UI task flow** — submit, SSE streaming, completion, cancel, error states, history persistence
