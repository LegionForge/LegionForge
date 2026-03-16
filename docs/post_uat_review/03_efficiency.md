# Efficiency Review Findings
**Reviewed:** 2026-03-15
**Reviewer:** Automated analysis (read-only)
**Scope:** Runtime efficiency and performance improvement opportunities

---

## Quick Wins (low effort, measurable impact)

### 1. Auth: Full table scan on every request — `get_gateway_user_for_auth`
**File:** `src/database.py:5031–5041`

`get_gateway_user_for_auth(username)` ignores its `username` parameter and issues:
```sql
SELECT ... FROM gateway_users WHERE is_active = true
```
It fetches **every active user row** and returns the list to the caller (the ApiKey backend), which then iterates over all users doing bcrypt comparisons. On a small deployment this is hidden by table size, but the SQL ignores the username argument entirely. Even a minimal `WHERE username = %s` filter would eliminate all but one row before the bcrypt comparison, and an index on `gateway_users(username)` already exists (UNIQUE constraint). This is the single hottest DB query since it runs on **every authenticated request**.

**Expected improvement:** Eliminates N−1 bcrypt comparisons and N−1 row transfers per request (where N = number of active users). Bcrypt is deliberately slow (~100 ms/hash); comparing one hash instead of N is significant even at N=3.

**Recommended fix:** Add `AND username = %s` to the WHERE clause and remove the list return — return a single row or None.

---

### 2. Audit log: Two round-trips on every `append_audit_log` call
**File:** `src/database.py:2900–2939`

`append_audit_log` does:
1. `SELECT seq, row_hash FROM audit_log ORDER BY seq DESC LIMIT 1` — get last hash
2. `INSERT ... row_hash='PENDING' ... RETURNING seq, ts` — insert placeholder
3. `UPDATE audit_log SET row_hash = %s WHERE seq = %s` — write real hash

This is 3 round-trips (2 queries + 1 update) per audit event, plus a table scan for the previous hash on every call. The pattern is necessary for the hash chain, but the final UPDATE is a separate statement that could be avoided. The SELECT could use the index `idx_audit_log_seq` (already exists) efficiently, but reading it on every single audit event is still a hot path since threat events, tool calls, and task state changes all log to audit_log.

**Expected improvement:** Saves 1 DB round-trip per audit event. At peak load (multiple concurrent tool calls each logging threat events), this reduces contention on the audit_log table.

**Recommended fix:** Use a CTE or a single transaction that computes the hash in-database via a `WITH prev AS (SELECT ...)` sub-select and inserts in one statement.

---

### 3. Worker: `record_api_usage` called twice per completed task
**File:** `src/gateway/worker.py:370–387` and `src/rate_limiter.py:316–330`

When a task completes, `record_api_usage` is called:
- Once from `worker.py:run_task()` explicitly (with `user_id`)
- Potentially once more from `rate_limiter.record_actual_usage()` if the rate limiter is used

Both calls INSERT rows into `api_usage`. The comment in worker.py says "internal LLM factory calls produce rows with `user_id=NULL`" to prevent double-counting, but this relies on the LLM factory NOT setting user_id — an implicit contract that is easy to break. Verify no double-INSERT is happening by checking that `llm_factory`'s `record_actual_usage()` does not set `user_id` when called from the agent path.

**Expected improvement:** If double-writes are confirmed, eliminating one halves the `api_usage` table write rate.

---

### 4. `estimate_tokens` re-encodes tiktoken on every call
**File:** `src/rate_limiter.py:372–386`

```python
def estimate_tokens(text: str, model: str = "gpt-3.5-turbo") -> int:
    enc = tiktoken.encoding_for_model(model)
    return len(enc.encode(text))
```

`tiktoken.encoding_for_model()` loads the encoding on every call. tiktoken caches this internally, but calling `encoding_for_model` unconditionally on every `estimate_tokens` invocation adds unnecessary function call overhead. At Ollama-only scale (local model, no tiktoken needed), the entire tiktoken import is an unnecessary 30–50 MB dependency.

**Expected improvement:** Cache the encoder at module level; or, for Ollama-only deployments, skip tiktoken entirely and use the `len(text) // 4` fast path (already the fallback). The `cl100k_base` approximation for qwen2.5 is not meaningfully more accurate than the `//4` estimate given that qwen uses a different tokenizer.

**Recommended fix:** Module-level `_enc = tiktoken.encoding_for_model("gpt-3.5-turbo")` (loaded once). Or gate tiktoken on `provider != "ollama"` to skip the import for local-only deployments.

---

### 5. `/ui` endpoint: reads index.html from disk on every request
**File:** `src/gateway/app.py:337–338`

```python
@app.get("/ui", ...)
async def web_ui() -> HTMLResponse:
    if _UI_PATH.exists():
        return HTMLResponse(_UI_PATH.read_text())
```

The 14,315-line `index.html` (≈ 380 KB) is read from disk on every page load. Since the file is static and never changes at runtime, it should be read once at startup (or module load) and cached in memory.

**Expected improvement:** Eliminates one disk read per page load. On an SSD this is sub-millisecond but it also triggers file stat + open/read syscalls unnecessarily on every browser refresh.

**Recommended fix:** Store `_UI_CONTENT = _UI_PATH.read_text()` at module startup time (after the path is known) and serve from the variable.

---

### 6. `get_worker_connection`: 2–4 separate SET statements per connection checkout
**File:** `src/database.py:2404–2420`

Every `get_worker_connection()` call executes `setup_sql` items sequentially in a loop:
```python
for sql, param in zip(setup_sql, setup_params):
    await conn.execute(sql, [param])
```
With `task_id`, `agent_id`, and `request_id` all set, this is 4 round-trips (SET application_name, SET statement_timeout, set_config agent_id, set_config request_id) before any actual query runs. These could be combined into a single parameterized query.

**Expected improvement:** Reduces connection setup from 4 round-trips to 1, saving ~3 network RTTs per task connection checkout. In async PostgreSQL over localhost the RTT is small (~0.1 ms) but multiplied across many connections it adds up.

---

## High Impact (worth the effort)

### 7. Auth cache: bcrypt verification blocks the async event loop
**File:** `src/gateway/backends/api_key.py` (inferred from auth.py structure)

bcrypt.checkpw is a synchronous, deliberately slow operation (~100–300 ms for cost factor 12). The gateway's `require_user` dependency is called on **every authenticated request**. Even with pool-level connection reuse, running bcrypt synchronously inside an async handler blocks the event loop for all concurrent requests during that 100–300 ms window.

**Expected improvement:** Moving bcrypt to `asyncio.get_event_loop().run_in_executor()` or using a short-TTL in-memory cache keyed on `hash(token)` would release the event loop during verification. A 60-second token cache (keyed on the token prefix, never the full token) would eliminate bcrypt on repeat requests from the same client.

**Note:** Any token cache must be bounded and use constant-time comparison on the cache key to avoid timing attacks.

---

### 8. `similarity_search`: query_embedding passed 3–4 times in temporal_decay path
**File:** `src/database.py:2532–2583`

The temporal decay branch passes `query_embedding` as a parameter **4 times** in one query:
```python
(query_embedding, query_embedding, namespace, query_embedding, min_similarity, limit)
```
Each `%s::vector` substitution causes the embedding (768 floats ≈ 6 KB of text) to be serialized, sent to PostgreSQL, and deserialized in the query. PostgreSQL cannot deduplicate query parameters.

**Expected improvement:** A CTE (`WITH q AS (SELECT %s::vector AS emb)`) lets the query reference `q.emb` once; the embedding is sent to PostgreSQL once. Saves ~18 KB of parameter data per temporal-decay search call.

**Recommended fix:**
```sql
WITH q AS (SELECT %s::vector AS emb)
SELECT id, content, metadata, created_at,
       1 - (embedding <=> q.emb) AS similarity,
       (1 - (embedding <=> q.emb)) * EXP(...) AS decayed_score
FROM documents, q
WHERE namespace = %s
  AND 1 - (embedding <=> q.emb) >= %s
ORDER BY decayed_score DESC
LIMIT %s
```

---

### 9. Graph recompilation on every task: `uncompiled.compile(checkpointer=...)` inside the worker loop
**File:** `src/gateway/worker.py:234–236`

```python
async with get_checkpointer() as checkpointer:
    graph = uncompiled.compile(checkpointer=checkpointer)
    async for lg_event in graph.astream_events(...)
```

Every task invocation recompiles the agent graph. `compile()` in LangGraph is not free — it traverses the node graph, validates edges, and sets up state schemas. With 3 concurrent workers each running a task, this runs 3 times simultaneously. The checkpointer is the reason the graph is recompiled (it must be passed at compile time for LangGraph's PostgreSQL checkpointing).

**Expected improvement:** Investigate whether LangGraph's `AsyncPostgresSaver` supports being shared across compiled graph instances (it uses connection pools internally). If yes, compile each graph once at startup and pass the shared checkpointer. Saves ~10–50 ms per task and reduces CPU spike at task start.

**Caveat:** Verify thread/async safety of the compiled graph object when reused across concurrent `astream_events` calls with different `config["configurable"]["thread_id"]` values.

---

### 10. `append_audit_log` serializes `payload` twice
**File:** `src/database.py:2920–2934`

The function calls `json.dumps(payload, sort_keys=True)` inside the INSERT parameters, then calls `json.dumps(payload, sort_keys=True)` again inside `_compute_audit_row_hash()` to canonicalize for hashing. The payload is serialized twice with identical parameters. At high audit event rates (every tool call is logged), this is wasteful.

**Recommended fix:** Serialize once to a `canonical_json` string, reuse it for both the INSERT and the hash computation.

---

### 11. Missing index on `api_usage.user_id`
**File:** `src/database.py:1262–1288`

`api_usage` has indexes on `(ts DESC)` and `(provider, ts DESC)` but no index on `user_id`. The functions `get_user_actual_usage_today()` and `get_user_inflight_tokens()` both query by `user_id` (used in per-user budget checks on every task submission). Without an index, these are full sequential scans on what will be the largest table in the database.

**Expected improvement:** An index on `api_usage(user_id, ts DESC)` would make per-user budget queries use an index scan. At 100k rows/month (100k tasks × 1 record each) a seq scan costs ~50–200 ms; an index scan is <1 ms.

**Recommended fix:**
```sql
CREATE INDEX IF NOT EXISTS api_usage_user_ts_idx ON api_usage (user_id, ts DESC);
```
Add to `_create_app_tables()`.

---

### 12. `claim_next_queued_task`: correlated subquery checks dependency on every claim
**File:** `src/database.py:4762–4786`

The SKIP LOCKED claim query includes:
```sql
AND (
    t.depends_on IS NULL
    OR EXISTS (
        SELECT 1 FROM tasks dep
        WHERE dep.task_id = t.depends_on AND dep.status = 'complete'
    )
)
```
This correlated subquery re-executes a `tasks` lookup for every queued row scanned. With a large queue and many dependent tasks, this degrades. The existing composite index `idx_tasks_priority_queue ON tasks(status, priority DESC, created_at ASC)` handles the queue scan efficiently, but the EXISTS sub-select hits a separate lookup per row.

**Expected improvement:** At small scale (household deployment) this is fine. Flag for profiling once queue depth regularly exceeds 50+ rows.

---

## Medium (incremental gains)

### 13. `get_worker_connection` setup overhead on hot paths
**File:** `src/database.py:2401–2433`

Every single database function that uses `get_worker_connection()` pays 2–4 SET round-trips before any query. The majority of database functions use the simpler `pool.connection()` pattern directly (bypassing the setup overhead), but any code path that wants `application_name` tracking and `statement_timeout` pays this cost. Consider a lighter-weight connection setup using PostgreSQL's `connection_parameters` at pool creation time for the static settings (application_name, statement_timeout).

---

### 14. Worker polling: 1-second sleep when queue is empty
**File:** `src/gateway/worker.py:534`

When the task queue is empty:
```python
await asyncio.sleep(1)
```
This limits task pickup latency to up to 1 second after submission. For interactive use (user submits task, expects near-immediate start), this is noticeable. PostgreSQL `LISTEN`/`NOTIFY` would allow the worker to wake immediately when a task is inserted, eliminating the 0–1s startup delay per task.

**Expected improvement:** Reduces task pickup latency from 0–1000 ms to ~5 ms. Noticeable for short tasks (researcher on a cached query takes 2–4 s total; a 1 s queue delay is 25–50% overhead).

**Complexity:** Medium. Requires a `NOTIFY` trigger on tasks INSERT + `LISTEN` in the worker loop.

---

### 15. Frontend: `/health` polled every 30 seconds unconditionally
**File:** `src/gateway/static/index.html:4834`

```javascript
setInterval(_pollHealth, 30000);
```
The health poll runs forever, even when the browser tab is in the background. While the endpoint is cheap (no DB call, returns a cached LLM status flag), it does generate an HTTP request + connection overhead every 30 s for every open tab.

**Recommended fix:** Use `document.addEventListener('visibilitychange', ...)` to pause polling when the tab is hidden and resume when it becomes visible.

---

### 16. `tiktoken` imported on every `estimate_tokens` call (import not cached)
**File:** `src/rate_limiter.py:381`

```python
import tiktoken
enc = tiktoken.encoding_for_model(model)
```
The `import tiktoken` inside the function body is a module-level import (Python caches it after first import), but `encoding_for_model(model)` is called fresh every time. The encoding object construction is the slow part. See item #4 above — this is the fix location.

---

### 17. `prune_audit_log` opens an admin connection without a pool
**File:** `src/database.py:3047–3051`

```python
admin_conn = await psycopg.AsyncConnection.connect(
    _build_conninfo_no_password(),
    password=_get_postgres_password(),
    autocommit=False,
)
```
Each pruning operation opens a fresh direct connection (not from any pool), which means a full TCP + TLS + PostgreSQL authentication handshake. This runs nightly during maintenance, so performance impact is low, but it is an architectural inconsistency. The maintenance pool (`legionforge_maintenance`) exists precisely for scheduled pruning operations.

**Note:** The comment explains this is because legionforge_maintenance has zero SELECT — but the SELECT to find the boundary row is essential. The maintenance pool design would need to be extended if you want to eliminate the admin connection here. Low priority.

---

### 18. `get_user_connection` issues two `set_config` calls on every connection acquire and release
**File:** `src/database.py:2327–2343`

```python
await conn.execute(
    "SELECT set_config('app.user_id', $1, false),"
    " set_config('app.bypass_rls', 'off', false)",
    [user_id],
)
```
These two `set_config` calls are issued on every user-scoped DB operation (every gateway route). The cleanup in `finally` also issues two more. At the async level these are single-statement calls (two set_config in one SELECT), which is already efficient. This is documented here as "already optimized per call" — see the Already Optimized section below.

---

### 19. `build_researcher_graph()` / `build_base_graph()` called fresh per task
**File:** `src/gateway/worker.py:106–117`

```python
if agent_type == "researcher":
    from src.agents.researcher import build_researcher_graph
    uncompiled = build_researcher_graph()
```
The graph builder function is called on every task, reconstructing the LangGraph `StateGraph`, adding all nodes and edges. This is pure Python object construction (no DB calls), but it could be memoized since the graph structure is static. Measured cost depends on node complexity but is likely 1–10 ms per call.

**Recommended fix:** Module-level `_RESEARCHER_GRAPH = build_researcher_graph()` in the worker module (or in the agent module), then compile with the per-task checkpointer each time. This separates the static graph construction from the dynamic compilation.

---

### 20. `_now()` called on every SSE event (datetime + isoformat + string replace)
**File:** `src/gateway/events.py:55–56`

```python
def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
```
This is called for every LangGraph event streamed to the browser (token, chain_start, chain_end, tool_start, tool_end). A typical multi-step researcher task emits 50–200 events. `datetime.now()` + `.isoformat()` + `.replace()` is not free — it involves a syscall and string allocations. Consider caching the result for 1 second or accepting the UTC offset format (`+00:00`) directly without the replace, which is valid ISO 8601.

**Expected improvement:** Marginal for single tasks; noticeable at 3 concurrent streaming tasks with 200 events each.

---

## Low / Micro-optimizations (only if profiling confirms bottleneck)

### 21. `detect_injection`: 29 regex patterns applied sequentially, no early exit on Tier 1 match
**File:** `src/security/core.py:303–319`

All 29 patterns are always checked even after a Tier 1 (halt-worthy) match is found. For the hot path (every task submission + every tool argument), consider breaking early on the first Tier 1 match since the result is deterministic: halt, regardless of other matches.

**Expected improvement:** ~50% pattern scan cost on Tier 1 matches (most injections match one of the first few patterns).

---

### 22. `_normalize_for_detection` NFKC normalization on every scan
**File:** `src/security/core.py:252–255`

`unicodedata.normalize("NFKC", text)` is called on every injection check. For ASCII-only inputs (the common case for legitimate tasks), NFKC normalization is a no-op but costs a full string traversal. A fast pre-check (`if text.isascii(): skip_normalize`) could avoid the normalization overhead for the majority of inputs.

---

### 23. `get_maintenance_pool()` doesn't exist — `_maintenance_pool` accessed directly
**File:** `src/database.py:4946`

`bulk_delete_tasks` accesses `get_maintenance_pool()` which is not defined as a public function (unlike `get_worker_pool()`, `get_gateway_pool()`, `get_readonly_pool()`). This will raise `AttributeError` at runtime if called. Either `get_maintenance_pool()` needs to be defined or the call needs to be replaced with `get_maintenance_connection()`. This is a latent bug, not a performance issue.

---

### 24. Prometheus `inc_counter` on every HTTP response
**File:** `src/gateway/middleware.py:136–145`

`MetricsMiddleware` calls `inc_counter(...)` after every response. The `inc_counter` function and Prometheus counter update are in-memory operations (no I/O), so overhead is minimal (~1 µs). No action needed.

---

### 25. `_ZERO_WIDTH_RE.sub("", text)` in injection detection
**File:** `src/security/core.py:255`

Regex substitution over the full input text on every injection check. The zero-width character set is rare in practice. A `text.translate()` approach with a deletion table for those specific code points would be faster than a compiled regex sub. Micro-optimization only.

---

## Already Optimized (do not regress)

The following performance controls are well-implemented and should be preserved:

- **SKIP LOCKED on task claim** (`src/database.py:4779`): Correct pattern for concurrent worker access; prevents lock contention with zero polling overhead.

- **HNSW index on documents** (`src/database.py:1319–1327`): `WITH (m=16, ef_construction=64)` is a reasonable default for 768-dim embeddings. The index is already in place.

- **GIN index on tasks.tags and tasks.labels**: Correct approach for array containment queries.

- **Composite priority queue index** (`idx_tasks_priority_queue ON tasks(status, priority DESC, created_at ASC)`): Matches the ORDER BY in `claim_next_queued_task` exactly.

- **Partial index on content_hash** (`WHERE status = 'complete'`): Correct — only completed tasks are candidates for cache hits.

- **keep_alive=-1 in ChatOllama** (`src/llm_factory.py:201`): Prevents Ollama model eviction between tasks on this dedicated machine.

- **In-memory SSE pub/sub with asyncio.Queue** (`src/gateway/events.py`): No DB round-trip per SSE event; correct for single-process deployment.

- **2,000-entry OrderedDict FIFO for terminal event cache** (`src/gateway/events.py:48`): Bounded; prevents unbounded memory growth; closes the late-subscriber race.

- **`asyncio.get_event_loop().time()` for watchdog/purge intervals** (`src/gateway/worker.py:540`): Monotonic clock — correct choice for interval tracking.

- **Worker concurrency counter via `_active_tasks`** (`src/gateway/worker.py:498–505`): Simple, correct, non-blocking.

- **`asyncio.sleep(0.2)` when all slots busy** (`src/gateway/worker.py:537`): Brief yield rather than 1-second sleep; correct back-off when at capacity.

- **DailyCounter lock for TOCTOU protection** (`src/rate_limiter.py:137–146`): Correct atomic reserve-before-check pattern.

- **`_role_pw_cache` in-process password cache** (`src/database.py:352`): Prevents repeated Keychain/pgpass lookups within the same process lifetime.

- **CredentialStore fast path** (`src/security/core.py:86–100`): Avoids Keychain subprocess spawns after initialization.

- **Partial index on `idx_tasks_depends_on WHERE depends_on IS NOT NULL`**: Correct — only tasks with dependencies need this lookup.

- **`SET statement_timeout` per worker connection** (`src/database.py:2407–2409`): Kills runaway SQL before it starves the pool.

- **Redis INCRBY for per-user budget** (`src/rate_limiter.py:422–431`): Atomic, shared across instances, correct TOCTOU fix.

- **Partial WHERE clause on scheduled_tasks index** (`idx_sched_tasks_next_run WHERE enabled = true`): Correct optimization — disabled schedules are never scanned.

- **Task result inline in `task_complete` SSE event** (Phase 69): Eliminates the browser's second REST round-trip after task completion.

---

## Summary Table

| # | Location | Category | Estimated Impact |
|---|----------|----------|-----------------|
| 1 | `database.py:5031` | Auth full-table scan | High — eliminates N bcrypt comparisons per request |
| 2 | `database.py:2900` | Audit log 3 round-trips | Medium — saves 1 RTT per audit event |
| 3 | `worker.py:370` | Double `record_api_usage` | Medium — verify if double-write occurring |
| 4 | `rate_limiter.py:382` | tiktoken re-encodes | Low–Medium — cache encoder object |
| 5 | `app.py:337` | index.html disk read per request | Low — cache 380 KB file at startup |
| 6 | `database.py:2419` | 4 SET statements per connection | Low — batch into 1 query |
| 7 | `auth.py` / backends | bcrypt blocks event loop | High — run in executor or add cache |
| 8 | `database.py:2532` | Vector sent 4× per query | Medium — use CTE |
| 9 | `worker.py:236` | Graph recompiled per task | Medium — cache uncompiled graph |
| 10 | `database.py:2920` | JSON serialized twice per audit | Low — reuse string |
| 11 | `database.py:1262` | Missing `api_usage.user_id` index | High for budget checks at scale |
| 12 | `database.py:4768` | Correlated subquery on claim | Low at current scale |
| 13 | `database.py:2401` | Connection setup overhead | Low |
| 14 | `worker.py:534` | 1 s polling when queue empty | Medium — LISTEN/NOTIFY |
| 15 | `index.html:4834` | Health poll ignores tab visibility | Low |
| 16 | `rate_limiter.py:381` | tiktoken encoder not cached | Low |
| 17 | `database.py:3047` | Admin conn per prune (no pool) | Low — runs nightly |
| 19 | `worker.py:106` | Graph rebuilt per task | Low–Medium |
| 20 | `events.py:55` | `_now()` per SSE event | Micro |
| 21 | `security/core.py:315` | All 29 patterns scanned on Tier 1 | Micro |
| 23 | `database.py:4946` | `get_maintenance_pool()` undefined | Bug (not perf) |
