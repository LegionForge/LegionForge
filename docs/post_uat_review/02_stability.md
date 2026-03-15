# Stability Review Findings
**Reviewed:** 2026-03-15
**Reviewer:** Automated analysis (read-only)
**Scope:** src/gateway/, src/database.py, src/agents/, src/safeguards.py, src/connectors/, src/health.py, src/security/guardian.py, config/settings.py, src/llm_factory.py, src/rate_limiter.py

---

## Critical (could cause data loss or unrecoverable state)

**1. `src/gateway/worker.py:298-299` — Bare `except Exception as exc: raise` swallows no error but leaks stack without DB cleanup on certain failure paths**

`_stream_agent()` has a `try/except Exception as exc: raise` block (lines 298–299) that does nothing except re-raise. If an exception is raised _after_ `mark_task_running()` (line 89) but _before_ the `async with get_checkpointer()` block exits cleanly (e.g. a `CancelledError` converted to another exception by LangGraph internals, or an `asyncio.CancelledError` during `astream_events()`), the task row remains `status='running'` until the 30-minute watchdog fires. The bare re-raise is a leftover stub that provides no value. The actual recovery path depends entirely on `run_task()`'s outer `except Exception` (line 449), which does call `mark_task_failed()`. However, `asyncio.CancelledError` is NOT a subclass of `Exception` in Python 3.8+, so if the worker task is cancelled (e.g. on SIGTERM), the outer `except Exception` does NOT catch it, leaving the task permanently stuck in `running` state — the watchdog is the only recovery and that takes up to 30 minutes.

**Recommended fix:** Add an explicit `except asyncio.CancelledError` handler in `run_task()` that calls `mark_task_failed(task_id, "Worker cancelled during task execution")` before re-raising.

---

**2. `src/connectors/whatsapp.py:450-460` — Deprecated `asyncio.get_event_loop()` in FastAPI BackgroundTask context**

The WhatsApp inbound webhook uses `background_tasks.add_task(asyncio.get_event_loop().create_task, _process_message(...))`. This pattern is incorrect for two reasons:
- `asyncio.get_event_loop()` is deprecated in Python 3.10+ and raises a deprecation warning in async contexts where no running loop exists.
- Passing `loop.create_task` as the callable to `BackgroundTasks.add_task()` means `BackgroundTasks` will call `loop.create_task(coroutine)` as a regular function call — this works but is fragile and the coroutine result (the Task object) is discarded, meaning any exception raised inside `_process_message` after creation is silently swallowed unless the Task itself has an exception handler.
- If the event loop is replaced (e.g. uvicorn restart without process restart), `get_event_loop()` may return a closed loop.

**Recommended fix:** Use `asyncio.create_task(_process_message(...))` directly inside the async route handler, or use a proper `BackgroundTasks.add_task(lambda: asyncio.ensure_future(_process_message(...)))`.

---

**3. `src/safeguards.py:167-168` — Global `os.environ` mutation for per-run tracing toggle creates race condition under concurrent tasks**

`create_run_config()` sets `os.environ["LANGCHAIN_TRACING_V2"] = "false"` to disable tracing for a specific run. Since `os.environ` is a process-global mutable dict and the gateway runs multiple tasks concurrently (default `WORKER_CONCURRENCY=3`), one task disabling tracing will silently disable it for all concurrently running tasks at that moment. The re-enable path (line 171-174) loads `.env` to restore, which is also not concurrency-safe. This is a silent correctness issue — audit/tracing data will be missing from LangSmith for tasks that ran concurrently with a `tracing_enabled=False` task.

**Recommended fix:** Use a per-task `ContextVar` for the tracing flag instead of mutating `os.environ`. Pass the flag through LangChain's `config["callbacks"]` mechanism rather than the global env.

---

## High (causes task failures or service restarts)

**4. `src/gateway/worker.py:282` — Final state extraction from last `lg_event` is brittle and may return `[No result]` on success**

After `astream_events()` completes, the result is extracted from the last `lg_event` dict (line 282): `final_state = lg_event.get("data", {}).get("output", {}) if lg_event else {}`. The variable `lg_event` is only updated inside the `async for` loop. If the graph emits no events (e.g., immediate force-end on step 1, or LangGraph emits only internal events that are all filtered by `build_sse_event()`), `lg_event` will be `{}` (initialized at line 229), resulting in `result_text = "[No result]"` even if the task technically ran. This is a real edge case for tasks where the LLM immediately triggers HITL halt or loop detection.

**Recommended fix:** After `astream_events()` completes, do a direct DB read of the task's LangGraph checkpoint to extract the final state rather than relying on the last streaming event.

---

**5. `src/gateway/worker.py:89` — `mark_task_running()` called before agent graph is built, causing status/state divergence on import errors**

`mark_task_running(task_id, run_id)` is called on line 89 (inside `_stream_agent()`), before agent imports, graph building, and the checkpointer context manager. If `build_researcher_graph()` or `build_orchestrator_graph()` raises (e.g., a missing dependency or registry check failure), the exception propagates out of `_stream_agent()` through the bare `raise` at line 299, and is caught by `run_task()`'s outer handler which calls `mark_task_failed()`. This works _only if_ the exception is a subclass of `Exception`. If it is a `BaseException` (e.g. `SystemExit`, `KeyboardInterrupt`), or if the code between `mark_task_running` and `run_task()`'s outer handler raises `asyncio.CancelledError`, the task is stuck running.

Additionally, `task_start` SSE event is published at line 92 (after `mark_task_running`), which means SSE subscribers see a `task_start` event even for tasks that will immediately fail due to import errors — the subscriber then never sees a terminal event and hangs until the SSE timeout.

---

**6. `src/connectors/base.py:200` — SSE consumer has no fallback when stream completes without a terminal event**

`_run_task()` in `src/connectors/base.py` breaks out of the SSE loop on `task_complete` or `task_error` events (lines 188-198), but if the SSE stream closes cleanly (server closes connection, httpx `aiter_lines()` ends) without a terminal event, the function returns without putting anything on `on_token`. The consumer side (`_stream_to_slack`, `_stream_to_telegram`, `_stream_to_discord`) waits with a 60-second timeout and then breaks — so the user sees `*(working...)*` with no result or error. This happens on gateway restart mid-task.

**Recommended fix:** After the `async for` loop exits without a terminal event, put a `{"error": "Stream closed without completion"}` sentinel on `on_token`.

---

**7. `src/connectors/discord.py:366` — `asyncio.gather()` propagates first exception from either coroutine, potentially silencing the other**

`asyncio.gather(_run_task_and_stream(...), _stream_to_discord(...))` without `return_exceptions=True` means if `_run_task_and_stream` raises, the `_stream_to_discord` coroutine is cancelled before it can post the error message. The user's Discord message stays as `*Thinking...*` indefinitely. The same pattern applies to Slack (`slack.py:200`) and Telegram (`telegram.py:192`).

**Recommended fix:** Use `return_exceptions=True` and check results, or wrap the coroutines in individual try/except that post error messages.

---

**8. `src/rate_limiter.py:_check_soft_alerts` — Alert fires on every call at >80% usage, not just once**

`_check_soft_alerts()` (lines 213-239) fires a `logger.warning()` on every single call when usage is between 80–100% of the soft limit, rather than using a flag similar to `alert_sent`. A high-frequency agent task submitting many LLM calls could emit thousands of warning log lines in a burst, potentially overwhelming log aggregators or obscuring other critical log entries.

---

**9. `src/gateway/worker.py:540` — `asyncio.get_event_loop().time()` is a deprecated API call in the worker loop**

Line 540: `now = asyncio.get_event_loop().time()` is called inside `task_worker()` which runs as a proper asyncio coroutine. The correct async-safe form is `asyncio.get_running_loop().time()` or simply `asyncio.get_event_loop().time()` (which in Python 3.10+ will issue a deprecation warning if called from a coroutine that has a running loop). This is a latent deprecation that will become a warning or error in a future Python version.

---

**10. `src/database.py:2460-2473` — `get_checkpointer()` shares the worker pool's connections without size protection**

`get_checkpointer()` instantiates `AsyncPostgresSaver(pool)` using the worker pool directly. LangGraph's `AsyncPostgresSaver` holds connections from the pool during `astream_events()` for the entire duration of a task (which can be many minutes). With `WORKER_CONCURRENCY=3` and the worker pool `max_size=8`, three concurrently running tasks each holding 1-2 checkpointer connections can leave only 2-5 connections for all other worker pool operations (`mark_task_running`, `mark_task_complete`, `record_api_usage`, `fail_dependent_tasks`, etc.). Under sustained load this creates pool starvation where `mark_task_complete` blocks indefinitely waiting for a connection, preventing task completion.

**Recommended fix:** Create a dedicated small pool (`max_size=WORKER_CONCURRENCY+2`) for the checkpointer, separate from the worker pool used for DB operations.

---

## Medium (degraded behavior, not crashes)

**11. `src/gateway/app.py:91-92` — `_llm_status["ok"]` is set to `True` at startup before first health check**

The Ollama health check loop (`_llm_health_loop`) runs every 30 seconds. For the first 30 seconds after gateway startup, `_llm_status["ok"]` is `True` (optimistic default, line 77) even if Ollama is not running. Tasks submitted immediately after gateway start will appear to have a healthy LLM and will only fail when the agent actually tries to make an LLM call. The `/health` endpoint will also report `"llm": "ok"` for the first 30 seconds regardless of actual Ollama state.

---

**12. `src/gateway/worker.py:214` — `increment_session_turn = None` assigned but never used, creating dead code risk**

On line 214, `increment_session_turn = None` is assigned as a "no-op reference" comment. The actual call at line 406-410 imports `increment_session_turn` from `src.database` directly, so the module-level `None` assignment has no effect on the import. However, if `session_id` is truthy, `increment_session_turn` from the import inside the `if` block at line 208 shadows the outer assignment. The code works correctly, but the `None` assignment is misleading dead code that suggests the import at line 406 would use it — it doesn't.

---

**13. `src/agents/orchestrator.py:181-182` — Module-level mutable dicts for token/run-id state are not concurrency-isolated**

`_master_token_ref` and `_run_id_ref` are module-level dicts mutated by the orchestrator at graph run start. With `WORKER_CONCURRENCY > 1`, two concurrent orchestrator tasks will overwrite each other's token and run_id references. Task B's `spawn_researcher` tool closure will see Task A's master JWT (or vice versa). This means:
- Sub-agent token derivation may use the wrong parent JWT, potentially granting wrong privilege scope.
- The `run_id` used in `fan_out_researchers` may be Task A's run_id while processing Task B.

**Recommended fix:** Use `contextvars.ContextVar` (same pattern as `_task_model_pref` in `llm_factory.py`) to isolate these per-task.

---

**14. `src/connectors/whatsapp.py:357-370` — HMAC validation uses `api_token` (bearer token) as secret instead of a dedicated signing secret**

The HMAC-SHA256 signature verification at line 357-364 checks `if api_token:` and uses `api_token` as the HMAC key. The Meta Graph API bearer token is the _sending_ credential; it is NOT the webhook app secret. Meta expects the webhook payload to be signed with the app's **app secret**, not the bearer token. This means the HMAC check will always fail for legitimate Meta webhooks (the signature will never match), silently degrading to the unsigned path at line 365-368 or always rejecting requests.

---

**15. `src/safeguards.py:163-174` — `create_run_config()` re-enables tracing by calling `load_dotenv()` which may override settings changed after startup**

When re-enabling tracing after a disabled-tracing run, `create_run_config()` calls `load_dotenv()` (line 174) to restore the `LANGCHAIN_TRACING_V2` value. `load_dotenv()` re-reads `.env` from disk, which may override any other environment variables set after application startup (e.g., by tests or runtime config changes). This is also synchronous I/O inside what may be an async call path.

---

**16. `src/database.py` — Worker pool `idle_in_transaction_session_timeout` guards against hung transactions but does not guard against hung connections in autocommit mode**

The pool is opened with `autocommit=True` (line 1155), which means there are no explicit transactions. `idle_in_transaction_session_timeout` only fires for connections that are inside a transaction (i.e., have begun a transaction block). With `autocommit=True`, a connection that is idle-in-query (waiting for a long query to complete) is NOT subject to this timeout. Long-running LangGraph checkpoint queries under heavy load could hold connections indefinitely without the timeout firing.

**Recommended fix:** Also set `statement_timeout` at the pool level (not just at the role level) so individual queries have a hard limit. Note that the role-level `statement_timeout` is set via `ALTER ROLE` (line 681), which does apply per-session, so this may already be covered — verify that the role-level setting is in effect for all pool connections.

---

**17. `src/gateway/worker.py` — No in-flight task tracking on graceful shutdown (SIGTERM)**

The lifespan `finally` block (app.py lines 178-190) calls `worker_task.cancel()` and awaits it. `task_worker()` catches `CancelledError` and breaks (line 563-565). However, any tasks launched via `asyncio.create_task(_run_task_tracked(task))` (line 530) are NOT cancelled — they continue running (or are silently abandoned) after the worker loop exits. There is no mechanism to wait for in-flight `_run_task_tracked` tasks to complete before the gateway process exits. On SIGTERM, the event loop is closed, abandoning in-flight tasks mid-execution. LangGraph checkpoint state for those tasks may be partially written.

**Recommended fix:** Track all active `_run_task_tracked` asyncio Tasks in a set, and in the shutdown path, await `asyncio.gather(*active_task_set, return_exceptions=True)` with a timeout before closing.

---

**18. `src/connectors/base.py` — No reconnection logic for SSE stream disconnection (network interruption)**

The SSE consumer in `_run_task()` (`base.py:176-200`) connects once and streams until the task completes or an `httpx.HTTPError` is raised. If the network connection drops mid-stream (e.g., WiFi dropout), the `aiter_lines()` generator will raise a connection error, which is caught by `except httpx.HTTPError as exc:` and converted to an error sentinel. The connector posts a `Stream connection failed` error message to the user and does not attempt to reconnect. Since the task continues running on the gateway, the result is computed but never delivered — the user gets an error message even though the task succeeded.

**Recommended fix:** After an `httpx.HTTPError` during streaming, check the task status via `GET /tasks/{task_id}` and, if still running, reconnect to the SSE stream with exponential backoff (up to 3 attempts).

---

**19. `src/agents/researcher.py:459-467` — Exception handler in `agent_node` only handles exceptions from LLM calls; exceptions from `sanitize_messages()` or `preflight_budget_check()` propagate unhandled**

The `try/except` block starts at line 345 and wraps the LLM invocation, but `sanitize_messages()` (line 347) and `preflight_budget_check()` (line 354) are also inside the try block. `preflight_budget_check()` raises `RuntimeError` on budget exceeded — this is correctly caught by the `except Exception as e:` handler. However, if `sanitize_messages()` raises (e.g. due to a malformed message object), it is also caught — but the handler adds an `AIMessage` with an error description (line 466), which may confuse the graph into continuing on a path expecting tool_calls. This is low-severity but worth noting.

---

**20. `src/health.py` — Health checks use subprocess calls to `make status` which may block the event loop**

(Based on the file structure — the health server starts as a FastAPI app with its own uvicorn process.) Review confirmed that `src/health.py` contains async handlers, but some status checks spawn subprocesses. Subprocess calls using `subprocess.run()` (synchronous) inside an async handler block the event loop. Specifically: the `security find-generic-password` calls in credential loading paths, and any `brew services` calls for status checks, if they occur in async context.

---

## Low (edge cases, minor)

**21. `src/gateway/worker.py:282-293` — `lg_event` extraction logic has multiple fallback layers that could mask actual `None` results**

The result extraction chain (lines 282-294) tries `final_answer`, then `result`, then `_last_content`, then `"[No result]"`. If the last message's `.content` is an empty list (which LangChain can return for multimodal responses), `_last_content` will be `[]`, which is falsy, and the result will be `"[No result]"` even though the agent produced output.

---

**22. `src/database.py:99-103` — `_read_pgpass()` splits on `:` which breaks passwords containing colons even with the "join from index 4" workaround**

The pgpass parser at line 100-103 does `parts = line.split(":")` then `pw = ":".join(parts[4:])`. The comment says "password may contain colons (escaped not required here)". However, per the pgpass format spec, passwords containing colons should be escaped as `\:`. The current implementation does NOT unescape `\:` back to `:` — it treats `\:` literally, which means passwords with escaped colons will be read incorrectly.

---

**23. `src/gateway/worker.py:331-335` — Webhook fire-and-forget tasks are not tracked; failed webhooks produce no user-facing signal**

`asyncio.create_task(send_callback(...))` and `asyncio.create_task(_fire_user_webhooks(...))` create tasks that are not tracked anywhere. If the tasks raise an unhandled exception, Python will emit an `asyncio.exceptions.CancelledError` or `Task exception was never retrieved` warning to stderr, but this is not wired to any monitoring or alerting. Webhook delivery failures are silent.

---

**24. `src/rate_limiter.py:109-110` — `DailyCounter._lock` using `asyncio.Lock` created at dataclass instantiation may be tied to the wrong event loop in test environments**

`asyncio.Lock()` created at dataclass field initialization time is fine for production (single event loop), but in test environments where multiple event loops are created per test session, the Lock may be bound to the first event loop and become unusable in subsequent test event loops without re-initialization.

---

**25. `src/connectors/whatsapp.py:472-477` — Module-level `build_app()` call at import time with empty credentials**

The WhatsApp connector creates a no-op FastAPI app at module import time (line 472). If any import-time initialization inside `build_app()` were to fail (e.g. a middleware that checks credentials), the entire module import would fail, breaking smoke tests that `import app from src.connectors.whatsapp`. Currently harmless, but fragile.

---

**26. `src/gateway/worker.py:33-38` — `WORKER_CONCURRENCY` and `TASK_WATCHDOG_TIMEOUT` are module-level constants read at import time**

These are evaluated once at module import, meaning changes to `WORKER_CONCURRENCY` or `TASK_WATCHDOG_TIMEOUT` environment variables after the gateway starts have no effect without a full restart. This is documented behavior but worth noting — there's no hot-reload path for these settings.

---

**27. `src/safeguards.py:262-266` — Action loop detection uses SHA-256 truncated to 12 chars (48 bits), creating theoretical hash collision risk**

`_action_signature()` uses `hashlib.sha256(payload.encode()).hexdigest()[:12]` — a 12-character hex string = 48 bits of entropy. With a loop window of 5 and threshold of 3, a collision between two _different_ tool calls would prevent loop detection from firing when it should, or vice versa. At practical scales (< 100 tool calls per run) this is extremely low probability but worth documenting.

---

## Already Robust (do not regress)

The following stability controls are well-implemented and should be preserved:

- **Three-layer loop protection** (`src/safeguards.py`): step counter (LangGraph recursion limit), MD5 action hash loop detection, and token budget guard operate independently. Any one can terminate a runaway agent.

- **Watchdog task reaper** (`src/gateway/worker.py:549-561`, `src/database.py:6007-6051`): `reap_stuck_tasks()` runs every 5 minutes and marks tasks stuck in `running` for >30 minutes as failed. Provides recovery from worker crashes.

- **`FOR UPDATE SKIP LOCKED` task claim** (`src/database.py:4762-4786`): the task claim query is safe for concurrent workers and cannot produce duplicate claims.

- **Five-role DB privilege model** with RLS (`src/database.py`): worker/gateway/maintenance/guardian/readonly roles with `BYPASSRLS` only where needed. Fail-closed RLS (empty `app.user_id` returns zero rows).

- **Postgres startup retry with backoff** (`src/database.py:1079-1101`): 4 attempts with 2s/4s/8s backoff before failing startup. Guards against the cold-start race.

- **Guardian fails-closed on capability boundary, tool revocation, hash mismatch, and sequence contract violations** — critical security checks are blocking, not advisory.

- **TOCTOU protection in rate limiter** (`src/rate_limiter.py:124-151`): `check_and_reserve()` is atomic under `asyncio.Lock`, preventing concurrent callers from both passing the daily budget check before either commits tokens.

- **SSE late-subscriber race protection** (`src/gateway/events.py:291-331`): `_terminal_events` OrderedDict cache (2000-entry FIFO) ensures subscribers that arrive after task completion still receive the terminal event.

- **`per_user_budget_check()` with Redis path** (`src/rate_limiter.py:389-460`): Redis-backed budget checks use atomic `INCRBY` to prevent concurrent submission races; DB fallback is documented as TOCTOU-prone.

- **Graceful tool failure handling in orchestrator and researcher** (`src/agents/orchestrator.py:197-212`): `spawn_researcher` wraps sub-agent failures and returns a structured error string rather than propagating exceptions.

- **Deterministic LLM fallback** (`src/agents/researcher.py:415-438`, `src/agents/orchestrator.py:443-472`): after two failed attempts to get tool_calls from the model, a synthetic `web_search` / `spawn_researcher` call is injected programmatically.

- **Webhook sender with retry** (`src/webhook_sender.py`): 3 attempts with 2s/4s/8s exponential backoff, 10-second per-attempt timeout. Errors logged but never propagated.

- **SSE per-user stream slot cap** (`src/gateway/routes/stream.py:45-84`): prevents unbounded asyncio queue accumulation from a single user holding many SSE connections.

- **Audit log SHA-256 hash chain with startup integrity check** (`src/database.py:1229-1250`): tampered audit log halts startup rather than continuing with unreliable forensic data.

- **`idle_in_transaction_session_timeout` on all role pools** (`src/database.py:1147-1159`): prevents hung transactions from holding row locks indefinitely across all five DB roles.
