# Phase 8 — Gateway, Streaming, Task Queue, and Web UI

**Status:** ✅ Complete (committed `1e4ea02` + `a8dfd55`, merged to `main` in PR #20)
**Target:** Make LegionForge accessible to users, not just CLI operators
**Smoke tests:** 271 → 312 actual (target was ~295)

---

## The Problem Phase 8 Solves

After Phase 7, LegionForge has a complete security stack and a working agent runtime. There is no way for a user to submit a task without direct Python CLI access. There is no way to watch an agent work in real time. There is no task history.

Phase 8 adds the user-facing layer: a gateway API, a streaming interface, a minimal web UI, and interoperability with the A2A and MCP standards. It does not add new agent capabilities — that is Phase 9.

---

## Architecture Overview

```
User (browser / Discord / Signal / API client)
        │
        │ HTTPS
        ▼
┌─────────────────────────────────┐
│     GATEWAY SERVICE  (:8080)    │
│                                 │
│  POST /tasks                    │
│  GET  /tasks/{id}/stream  (SSE) │
│  GET  /tasks/{id}               │
│  GET  /tasks                    │
│  GET  /.well-known/agent.json   │
│  POST /a2a/tasks                │
│  POST /mcp/tools/invoke         │
└──────┬──────────────────────────┘
       │ internal
       ├──────────────────────────────────┐
       ▼                                  ▼
┌──────────────┐            ┌─────────────────────────┐
│  TASK QUEUE  │            │     AGENT RUNTIME        │
│              │            │                          │
│  tasks table │            │  run_orchestrator()      │
│  in postgres │            │  run_researcher()        │
│              │            │  astream_events() output │
└──────┬───────┘            └──────────┬───────────────┘
       │                               │
       └───────────────────────────────┘
                       │ (every tool call)
               ┌───────▼───────┐
               │  GUARDIAN     │
               │  (:9766)      │
               └───────────────┘
```

The gateway is a **new FastAPI service** (`src/gateway/`). It is separate from the existing operator health service (`src/health.py`, `:8765`). They serve different audiences:

| Service | Port | Audience | Auth |
|---|---|---|---|
| Gateway (new) | :8080 | Users — task submission and streaming | Per-user Bearer token |
| Operator health (existing) | :8765 | Operator — system health and security admin | Single shared Bearer token |

---

## Step 1 — API Contract

Design the full API surface before writing any code.

### Core task API

```
POST   /tasks
GET    /tasks/{task_id}/stream
GET    /tasks/{task_id}
GET    /tasks
DELETE /tasks/{task_id}     (cancel a queued task)
```

### A2A interoperability

```
GET    /.well-known/agent.json     (A2A Agent Card)
POST   /a2a/tasks                  (A2A task submission)
GET    /a2a/tasks/{task_id}        (A2A task status)
GET    /a2a/tasks/{task_id}/stream (A2A SSE stream)
```

### MCP interoperability

```
GET    /mcp/tools                  (list available tools)
POST   /mcp/tools/invoke           (invoke a tool via MCP)
```

### Endpoint specs

#### `POST /tasks`

Submit a task to the queue.

**Request:**
```json
{
  "task": "Research the latest developments in LLM security for 2026",
  "agent_type": "orchestrator",
  "config": {
    "tracing_enabled": true,
    "max_steps": null
  }
}
```

**Response:** `202 Accepted`
```json
{
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "created_at": "2026-02-27T09:00:00Z",
  "stream_url": "/tasks/550e8400-e29b-41d4-a716-446655440000/stream"
}
```

**Validation:**
- `task` — required, 1–4000 characters, sanitized through `sanitize_text()` before storage
- `agent_type` — enum: `"orchestrator"` | `"researcher"` | `"base_agent"` (default: `"orchestrator"`)
- `config` — all fields optional; unknown fields rejected

**Errors:**
- `400` — validation failure (task too long, unknown agent_type, injection detected)
- `401` — missing/invalid Bearer token
- `429` — rate limit exceeded

#### `GET /tasks/{task_id}/stream`

Server-Sent Events stream. The client subscribes immediately after `POST /tasks` and receives events as they are emitted by LangGraph's `astream_events()`.

**Headers:**
```
Accept: text/event-stream
Cache-Control: no-cache
Authorization: Bearer {token}
```

**SSE event format:**

Each event has an `event:` type field and a `data:` JSON payload.

```
event: task_start
data: {"task_id": "...", "agent_type": "orchestrator", "timestamp": "..."}

event: chain_start
data: {"node": "agent_node", "run_id": "...", "timestamp": "..."}

event: tool_start
data: {"tool": "web_search", "input": {"query": "..."}, "timestamp": "..."}

event: tool_end
data: {"tool": "web_search", "output_preview": "First 200 chars...", "timestamp": "..."}

event: token
data: {"delta": "The", "accumulated": "The latest", "timestamp": "..."}

event: chain_end
data: {"node": "agent_node", "timestamp": "..."}

event: task_complete
data: {"task_id": "...", "status": "complete", "result_url": "/tasks/{id}", "timestamp": "..."}

event: task_error
data: {"task_id": "...", "status": "failed", "error": "Guardian halted: injection detected", "timestamp": "..."}

event: task_cancelled
data: {"task_id": "...", "status": "cancelled", "timestamp": "..."}

event: heartbeat
data: {}
```

**Notes:**
- `token` events are emitted per `on_chat_model_stream` LangGraph event
- `tool_start` / `tool_end` omit raw tool input/output for security — full data is in the task result
- Output from tools is not streamed character-by-character; only LLM generation tokens are streamed
- Heartbeat sent every 15 seconds to keep the connection alive through proxies
- Stream closes on `task_complete`, `task_error`, or `task_cancelled`

#### `GET /tasks/{task_id}`

Poll for the final result.

**Response:** `200 OK`
```json
{
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "complete",
  "agent_type": "orchestrator",
  "input": "Research the latest developments in LLM security for 2026",
  "result": "...",
  "created_at": "2026-02-27T09:00:00Z",
  "completed_at": "2026-02-27T09:02:34Z",
  "steps": 8,
  "tokens": {"input": 4200, "output": 1100}
}
```

**Status values:** `queued` | `running` | `complete` | `failed` | `cancelled`

#### `GET /tasks`

Task history for the authenticated user.

**Query params:** `limit` (default 20, max 100), `offset`, `status`

**Response:** `200 OK`
```json
{
  "tasks": [...],
  "total": 42,
  "limit": 20,
  "offset": 0
}
```

---

## Step 2 — Task Queue Schema

New table in the existing `legionforge` PostgreSQL database.

```sql
CREATE TABLE tasks (
    task_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued', 'running', 'complete', 'failed', 'cancelled')),
    agent_type      TEXT NOT NULL DEFAULT 'orchestrator',
    input           TEXT NOT NULL,
    result          TEXT,
    error           TEXT,
    config          JSONB NOT NULL DEFAULT '{}',
    run_id          UUID,               -- set when agent run starts
    steps           INTEGER,
    tokens          JSONB,              -- {"input": N, "output": N}
    stream_events   JSONB NOT NULL DEFAULT '[]',  -- archived SSE event log
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX idx_tasks_user_id ON tasks (user_id);
CREATE INDEX idx_tasks_status ON tasks (status);
CREATE INDEX idx_tasks_created_at ON tasks (created_at DESC);
```

**Notes:**
- `stream_events` stores the SSE event log after task completion — useful for task replay and debugging
- `run_id` links to LangGraph checkpoint (via `checkpoints` table) for resumption
- `legionforge_app` role gets SELECT/INSERT/UPDATE on `tasks`; no DELETE (only operator can delete)

---

## Step 3 — Gateway Service Structure

```
src/gateway/
├── __init__.py
├── app.py          # FastAPI app factory; mounts routers; lifespan context
├── auth.py         # Bearer token extraction, user_id resolution, per-user rate limits
├── routes/
│   ├── tasks.py    # POST /tasks, GET /tasks/{id}, GET /tasks, DELETE /tasks/{id}
│   ├── stream.py   # GET /tasks/{id}/stream — SSE logic
│   ├── a2a.py      # /.well-known/agent.json, /a2a/tasks/*
│   └── mcp.py      # /mcp/tools, /mcp/tools/invoke
├── worker.py       # Background task runner — pulls queued tasks, calls run_* functions
└── events.py       # SSE event builders; heartbeat logic
```

### `app.py` sketch

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
from src.gateway.routes import tasks, stream, a2a, mcp
from src.database import init_db

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(title="LegionForge Gateway", version="0.1.0", lifespan=lifespan)
app.include_router(tasks.router, prefix="/tasks", tags=["tasks"])
app.include_router(stream.router, prefix="/tasks", tags=["stream"])
app.include_router(a2a.router, tags=["a2a"])
app.include_router(mcp.router, prefix="/mcp", tags=["mcp"])
```

### `worker.py` — task runner

The worker polls the `tasks` table for queued tasks and runs them. At household scale, a simple polling loop is sufficient:

```python
async def task_worker():
    """Pull queued tasks and run them, one at a time per instance."""
    while True:
        task = await claim_next_queued_task()
        if task:
            await run_task(task)
        else:
            await asyncio.sleep(1)
```

For Phase 8, a single worker instance is sufficient. Phase 10 (multi-user scale) adds worker pools and queue depth monitoring.

**`run_task()` — the bridge between queue and agent runtime:**
```python
async def run_task(task: dict):
    """Run a task and stream events to the tasks table."""
    run_fn = {
        "orchestrator": run_orchestrator,
        "researcher":   run_researcher,
        "base_agent":   run_agent,
    }[task["agent_type"]]

    # Switch from ainvoke() → astream_events() for streaming
    events = []
    async for event in graph.astream_events(state, config=config, version="v2"):
        sse_event = build_sse_event(event)
        events.append(sse_event)
        await publish_event(task["task_id"], sse_event)   # pushes to SSE subscribers

    await mark_task_complete(task["task_id"], result=result, events=events)
```

---

## Step 4 — LangGraph Streaming

### Switch `ainvoke()` → `astream_events()`

Current `run_*` functions call `graph.ainvoke(state, config)` and return a final dict. Phase 8 adds a streaming path alongside the existing invoke path.

**Strategy:** keep `ainvoke()` in the existing `run_*` functions for backward compatibility (CLI, tests). Add a parallel `stream_*` variant (or an `as_stream=True` flag) that calls `graph.astream_events()`.

### LangGraph event types (v2 API)

| Event name | When emitted | Useful data |
|---|---|---|
| `on_chain_start` | Node enters | `name` (node name), `run_id` |
| `on_chain_end` | Node exits | `name`, `output` |
| `on_chat_model_start` | LLM call starts | `name`, `inputs` |
| `on_chat_model_stream` | Per-token | `chunk.content` — the delta |
| `on_chat_model_end` | LLM call ends | `outputs` |
| `on_tool_start` | Tool call begins | `name` (tool name), `input` |
| `on_tool_end` | Tool call ends | `output` |

### SSE event mapping

```python
def build_sse_event(lg_event: dict) -> dict | None:
    """Map a LangGraph astream_events event to an SSE event dict."""
    kind = lg_event.get("event")
    name = lg_event.get("name", "")
    ts = datetime.utcnow().isoformat() + "Z"

    if kind == "on_chain_start":
        return {"event": "chain_start", "data": {"node": name, "timestamp": ts}}
    elif kind == "on_chain_end":
        return {"event": "chain_end", "data": {"node": name, "timestamp": ts}}
    elif kind == "on_chat_model_stream":
        delta = lg_event.get("data", {}).get("chunk", {}).content or ""
        return {"event": "token", "data": {"delta": delta, "timestamp": ts}}
    elif kind == "on_tool_start":
        return {"event": "tool_start", "data": {"tool": name, "timestamp": ts}}
    elif kind == "on_tool_end":
        return {"event": "tool_end", "data": {"tool": name, "timestamp": ts}}
    return None   # filter internal events not intended for the client
```

### SSE delivery with `sse-starlette`

```python
from sse_starlette.sse import EventSourceResponse
import asyncio

@router.get("/{task_id}/stream")
async def stream_task(task_id: str, request: Request, user=Depends(get_current_user)):
    async def event_generator():
        async for event in subscribe_task_events(task_id):
            if await request.is_disconnected():
                break
            yield {"event": event["event"], "data": json.dumps(event["data"])}
        # Heartbeat while waiting
    return EventSourceResponse(event_generator())
```

**Package:** `sse-starlette` (already a FastAPI ecosystem standard; add to `requirements.txt`)

---

## Step 5 — Auth Model

### Phase 8 starting point: simple per-user Bearer tokens

- Each user has a stable API key stored in the `users` table (or initially, in a `gateway_tokens` table)
- Token is passed as `Authorization: Bearer {token}`
- The gateway resolves `user_id` from the token on every request
- No OAuth, no sessions — just long-lived API keys to start

**`users` table (minimal):**
```sql
CREATE TABLE users (
    user_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username    TEXT NOT NULL UNIQUE,
    api_key     TEXT NOT NULL UNIQUE,   -- stored hashed (bcrypt)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active   BOOLEAN NOT NULL DEFAULT true
);
```

**First users:** created by operator via a management CLI command (`make create-user USERNAME=jp`). No self-registration in Phase 8.

**Rate limits:** extend existing `rate_limiter.py` — per-user daily token budget and per-minute request cap. Limits are per `user_id`, not per IP.

### Phase 10: OAuth / OIDC

Delegate to an identity provider (Authentik, Authelia, or Cloudflare Access) when multi-household scale is needed. The gateway's `auth.py` module is designed to be swapped without touching route logic.

---

## Step 6 — A2A Conformance

### Agent Card (`GET /.well-known/agent.json`)

```json
{
  "name": "LegionForge",
  "description": "Security-native multi-agent framework. Supports web research, threat analysis, and task orchestration.",
  "url": "https://{host}",
  "version": "1.0.0",
  "provider": {
    "organization": "LegionForge",
    "url": "https://github.com/jp-cruz/LegionForge"
  },
  "capabilities": {
    "streaming": true,
    "pushNotifications": false,
    "stateTransitionHistory": true
  },
  "authentication": {
    "schemes": ["Bearer"]
  },
  "defaultInputModes": ["text/plain"],
  "defaultOutputModes": ["text/plain", "application/json"],
  "skills": [
    {
      "id": "web-research",
      "name": "Web Research",
      "description": "Search the web and synthesize findings from multiple sources.",
      "inputModes": ["text/plain"],
      "outputModes": ["text/plain"]
    },
    {
      "id": "orchestrated-task",
      "name": "Orchestrated Task",
      "description": "Break a complex task into sub-tasks and delegate to specialized agents.",
      "inputModes": ["text/plain"],
      "outputModes": ["text/plain"]
    }
  ]
}
```

### A2A task lifecycle

A2A tasks map directly onto the internal `tasks` table:

| A2A state | Internal status |
|---|---|
| `submitted` | `queued` |
| `working` | `running` |
| `completed` | `complete` |
| `failed` | `failed` |
| `canceled` | `cancelled` |

The A2A endpoint (`POST /a2a/tasks`) is a thin adapter over `POST /tasks` — same auth, same queue, same worker.

Full conformance checklist: [`docs/A2A_CONFORMANCE.md`](./A2A_CONFORMANCE.md)

---

## Step 7 — Minimal Web UI

**Goal:** Prove the streaming architecture works before building a real UI.

**Implementation:** Single HTML file served by the gateway at `GET /ui`.

```html
<!DOCTYPE html>
<html>
<head><title>LegionForge</title></head>
<body>
  <h1>LegionForge</h1>
  <textarea id="task" rows="4" cols="60" placeholder="Enter a task..."></textarea>
  <br>
  <button onclick="submit()">Submit</button>
  <hr>
  <pre id="log"></pre>

  <script>
    async function submit() {
      const task = document.getElementById('task').value;
      const res = await fetch('/tasks', {
        method: 'POST',
        headers: {'Content-Type': 'application/json',
                  'Authorization': `Bearer ${localStorage.getItem('token')}`},
        body: JSON.stringify({task})
      });
      const {task_id, stream_url} = await res.json();

      const es = new EventSource(stream_url + `?token=${localStorage.getItem('token')}`);
      es.addEventListener('token', e => {
        document.getElementById('log').textContent += JSON.parse(e.data).delta;
      });
      es.addEventListener('tool_start', e => {
        const d = JSON.parse(e.data);
        document.getElementById('log').textContent += `\n[tool: ${d.tool}]\n`;
      });
      es.addEventListener('task_complete', () => es.close());
      es.addEventListener('task_error', e => {
        document.getElementById('log').textContent += `\nERROR: ${JSON.parse(e.data).error}`;
        es.close();
      });
    }
  </script>
</body>
</html>
```

**No framework.** The goal is to prove SSE → browser rendering works. A proper frontend (React, Vue, or htmx) is Phase 9+.

---

## Step 8 — First Channel Connector (Discord)

A thin service (`src/connectors/discord.py`) that bridges the Discord API and the gateway:

```
Discord message → POST /tasks → poll SSE → post chunks back to channel
```

**Implementation:** `discord.py` library. Listen for messages in designated channels. POST to gateway. Subscribe to SSE. Send message updates as the agent generates content (rate-limited to avoid Discord API limits).

**Security:** the connector uses its own user account in the `users` table; it does not have operator access. Tasks submitted via Discord are indistinguishable from API tasks.

---

## Security Considerations

### What changes at the gateway boundary

1. **User input sanitization** — `POST /tasks` must call `sanitize_text()` on `task` input before storing or passing to agent. Injection detected → `400` (not `401` — don't leak that detection happened).

2. **Output filtering** — SSE `tool_end` events must not echo raw tool output. Only emit `output_preview` (first 200 chars). Full output goes to the task result in the DB, accessible via `GET /tasks/{id}` to authenticated users only.

3. **Rate limiting** — Gateway has two rate limit layers:
   - Request rate: 10 requests/minute per user (configurable)
   - Token budget: extends existing `rate_limiter.py` per-user daily cap

4. **Task isolation** — A user can only access their own tasks. `GET /tasks/{task_id}` verifies `task.user_id == authenticated_user.user_id`. 404 (not 403) on mismatch — don't confirm task existence to unauthorized users.

5. **SSE auth** — `EventSource` in browsers cannot set `Authorization` headers. Options:
   - Token in URL query param (acceptable for short-lived stream tokens; log as opaque ID not the token itself)
   - Short-lived stream token issued by `POST /tasks` response (preferred)
   - Cookie-based auth for browser clients

   **Phase 8 decision:** issue a short-lived `stream_token` (30-minute TTL, single-use) in the `POST /tasks` response. Stream endpoint accepts either Bearer or stream_token.

6. **Guardian still validates everything** — Gateway calls `run_*` functions which call the same `SecureToolNode` → Guardian pipeline. The gateway is not a trust bypass.

7. **CORS** — restrict to known origins in production. `*` only for local dev (`CORS_ALLOW_ORIGINS=*` in dev profile, locked down in production).

---

## Guardian Gaps Closed in Phase 8 ✅

Both gaps were closed alongside Phase 8 (commit `a8dfd55`):

**Gap 1: Guardian receives `args: {}`** — ✅ Fixed. `guardian_check()` now accepts an explicit `args: dict` parameter. `SecureToolNode` passes `tool_input` (the real tool call arguments). Checks 3 (destructive patterns), 5 (hash tamper), and 6 (adaptive regex rules) now see actual tool arguments.

**Gap 2: Guardian `action` field is hardcoded to `"invoke"`** — ✅ Fixed (two sub-fixes):
- `_check_2_capability_boundary()` now also checks `tool_id` against `FORBIDDEN_CAPABILITIES` — blocks any attempt to invoke a tool whose name is a forbidden capability (e.g. `"register_tool"`).
- `action` is read from `state.get("action", "invoke")` so gateway-submitted A2A and Discord tasks can carry their real source action type.

---

## Smoke Test Additions (target: ~295)

```python
# ── Gateway: schema ────────────────────────────────────────────────────────
def test_gateway_tasks_table_sql_has_required_columns():
    """tasks table DDL contains the required columns."""
    ddl_path = "src/gateway/migrations/001_tasks.sql"
    text = open(ddl_path).read()
    for col in ["task_id", "user_id", "status", "input", "result",
                "agent_type", "stream_events", "created_at"]:
        assert col in text, f"Missing column: {col}"

def test_tasks_status_enum_values_are_correct():
    from src.gateway.routes.tasks import VALID_STATUSES
    assert VALID_STATUSES == {"queued", "running", "complete", "failed", "cancelled"}

# ── Gateway: auth ──────────────────────────────────────────────────────────
def test_gateway_auth_rejects_missing_token():
    """Requests without Authorization header return 401."""
    from src.gateway.auth import extract_bearer_token
    assert extract_bearer_token(None) is None

def test_gateway_auth_rejects_malformed_token():
    from src.gateway.auth import extract_bearer_token
    assert extract_bearer_token("NotBearer abc") is None

# ── SSE: event builder ─────────────────────────────────────────────────────
def test_sse_token_event_built_from_chat_model_stream():
    from src.gateway.events import build_sse_event
    lg_event = {
        "event": "on_chat_model_stream",
        "name": "ChatOllama",
        "data": {"chunk": type("C", (), {"content": "hello"})()},
    }
    result = build_sse_event(lg_event)
    assert result["event"] == "token"
    assert result["data"]["delta"] == "hello"

def test_sse_tool_start_event_built_correctly():
    from src.gateway.events import build_sse_event
    lg_event = {"event": "on_tool_start", "name": "web_search", "data": {}}
    result = build_sse_event(lg_event)
    assert result["event"] == "tool_start"
    assert result["data"]["tool"] == "web_search"

def test_sse_returns_none_for_unknown_event():
    from src.gateway.events import build_sse_event
    result = build_sse_event({"event": "on_retry", "name": "x", "data": {}})
    assert result is None

# ── A2A: agent card ────────────────────────────────────────────────────────
def test_a2a_agent_card_has_required_fields():
    from src.gateway.routes.a2a import build_agent_card
    card = build_agent_card()
    for field in ["name", "description", "url", "version", "capabilities",
                  "authentication", "skills"]:
        assert field in card, f"Agent card missing field: {field}"

def test_a2a_agent_card_streaming_is_true():
    from src.gateway.routes.a2a import build_agent_card
    card = build_agent_card()
    assert card["capabilities"]["streaming"] is True

def test_a2a_agent_card_has_at_least_one_skill():
    from src.gateway.routes.a2a import build_agent_card
    card = build_agent_card()
    assert len(card["skills"]) >= 1

# ── A2A: status mapping ────────────────────────────────────────────────────
def test_a2a_status_mapping_covers_all_internal_statuses():
    from src.gateway.routes.a2a import INTERNAL_TO_A2A_STATUS
    internal = {"queued", "running", "complete", "failed", "cancelled"}
    assert internal == set(INTERNAL_TO_A2A_STATUS.keys())
```

That is 13 new tests → ~284 total. Additional integration tests (requires gateway running) are tracked separately.

---

## Implementation Order

| Step | File(s) | Unblocks |
|---|---|---|
| 1 | `src/gateway/migrations/001_tasks.sql` | Step 2 |
| 2 | `src/database.py` — `create_task()`, `get_task()`, `claim_next_queued_task()`, `mark_task_*()` | Step 3 |
| 3 | `src/gateway/auth.py` — token extraction, user resolution | Step 4 |
| 4 | `src/gateway/events.py` — `build_sse_event()` | Step 5 |
| 5 | `src/gateway/routes/tasks.py` — POST + GET endpoints | Step 6 |
| 6 | `src/gateway/routes/stream.py` — SSE endpoint | Step 7 |
| 7 | `src/gateway/worker.py` — background task runner | Step 8 |
| 8 | `src/gateway/app.py` — FastAPI app factory | Step 9 |
| 9 | `src/gateway/routes/a2a.py` — Agent Card + A2A endpoints | Step 10 |
| 10 | `src/gateway/routes/mcp.py` — tool discovery + invocation | Web UI |
| 11 | Web UI — `src/gateway/static/index.html` | Discord connector |
| 12 | Discord connector — `src/connectors/discord.py` | — |
| 13 | Smoke tests for all above | — |

---

## Open Questions (before coding begins)

1. **Auth model** — who are the initial users? Operator-created API keys, or should there be a registration path? This determines the `users` table design and the `make create-user` UX.

2. **Worker model** — single background `asyncio.Task` in the gateway process, or separate worker process? For Phase 8 (household scale, 1–2 users), embedded is simpler. For Phase 10, separate.

3. **Docker** — does the gateway run as a separate Docker container immediately, or is it started locally (like the health server is today) until Phase 8 is stable? Recommendation: local first, containerize after the streaming plumbing is proven.

4. **Stream token vs query-param token** — the SSE stream_token approach (30-minute TTL, issued at task creation) is recommended. Requires a `stream_tokens` table or Redis. Alternative: accept Bearer token as a query param (simpler but slightly weaker — tokens appear in server access logs).

---

*Related docs:*
- [`docs/VISION.md`](./VISION.md) — full product architecture and rationale
- [`docs/A2A_CONFORMANCE.md`](./A2A_CONFORMANCE.md) — A2A protocol gap analysis
- [`PHASE_PLAN.md`](../PHASE_PLAN.md) — phases 0–7 detail
- [`PROJECT_STATUS.md`](../PROJECT_STATUS.md) — current build state
