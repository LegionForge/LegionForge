# A2A Protocol Conformance Checklist — LegionForge

**Protocol:** Agent2Agent (A2A) — [a2a-protocol.org](https://a2a-protocol.org/latest/specification/)
**License:** Apache 2.0 / Linux Foundation
**LegionForge target:** Phase 8 gateway (`src/gateway/`)
**Last updated:** 2026-02-27

---

## Overview

A2A (Agent2Agent) is an open interoperability standard for agent-to-agent communication.
It defines:
- An **Agent Card** — a JSON capability advertisement published at a well-known URL
- A **task lifecycle** — submitted → working → complete/failed/canceled
- **Streaming** via Server-Sent Events (SSE)
- **Authentication** via Bearer, OAuth 2.0, or API key

This document tracks LegionForge's conformance to the A2A specification, identifies gaps,
and records implementation decisions where the spec allows flexibility.

---

## Conformance Summary

| Area | Status | Notes |
|---|---|---|
| Agent Card — required fields | ⬜ Not implemented | Phase 8 |
| Agent Card — hosting at `/.well-known/agent.json` | ⬜ Not implemented | Phase 8 |
| Task lifecycle — all states | ⬜ Not implemented | Phase 8 |
| Task submission endpoint | ⬜ Not implemented | Phase 8 |
| Task status endpoint | ⬜ Not implemented | Phase 8 |
| Task cancellation endpoint | ⬜ Not implemented | Phase 8 |
| SSE streaming | ⬜ Not implemented | Phase 8 |
| Authentication (Bearer) | ⬜ Not implemented | Phase 8 |
| Push notifications | 🔵 Deferred | Phase 9+ |
| Multi-turn / `input_required` | 🔵 Deferred | Phase 9+ |
| OAuth 2.0 auth | 🔵 Deferred | Phase 10 |
| gRPC binding | 🔵 Not planned | HTTP/SSE only |

**Legend:** ✅ Done · ⬜ Planned (Phase 8) · 🔵 Deferred · ❌ Not planned

---

## 1. Agent Card

### Specification

The A2A server MUST publish a JSON document at:
```
GET /.well-known/agent.json
```
(Note: the spec specifies `agent.json`, not `agent-card.json`; LegionForge follows this.)

### Required Fields Checklist

| Field | Required? | LegionForge value | Status |
|---|---|---|---|
| `name` | MUST | `"LegionForge"` | ⬜ |
| `description` | MUST | Short capability summary | ⬜ |
| `url` | MUST | `"https://{host}"` | ⬜ |
| `version` | MUST | `"1.0.0"` | ⬜ |
| `provider.organization` | SHOULD | `"LegionForge"` | ⬜ |
| `provider.url` | SHOULD | GitHub URL | ⬜ |
| `capabilities.streaming` | MUST if supported | `true` | ⬜ |
| `capabilities.pushNotifications` | MUST if supported | `false` (deferred) | ⬜ |
| `capabilities.stateTransitionHistory` | MUST if supported | `true` | ⬜ |
| `authentication.schemes` | MUST | `["Bearer"]` | ⬜ |
| `defaultInputModes` | SHOULD | `["text/plain"]` | ⬜ |
| `defaultOutputModes` | SHOULD | `["text/plain"]` | ⬜ |
| `skills` | MUST (at least one) | See §1.1 | ⬜ |

### 1.1 Skills

Each skill declares a capability unit the agent can perform.

| Field | Required? | Notes |
|---|---|---|
| `id` | MUST | Unique within the agent's skills list |
| `name` | MUST | Human-readable |
| `description` | SHOULD | What the skill does |
| `inputModes` | SHOULD | Default to agent defaults if omitted |
| `outputModes` | SHOULD | Default to agent defaults if omitted |
| `tags` | MAY | Freeform categorization |
| `examples` | MAY | Sample inputs |

**LegionForge initial skills:**
```json
[
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
```

### 1.2 Agent Card — Security Note

The A2A spec recommends signing Agent Cards. LegionForge already has Ed25519 signing infrastructure (`src/tools/signing.py`). The Agent Card should be signed with the same key and include a `signature` field. This prevents a MITM from advertising false capabilities.

**Gap:** Signature field not in the initial A2A spec schema — track upstream. For Phase 8, serve Agent Card over TLS only; no additional signature required.

---

## 2. Task Lifecycle

### Specification

A2A defines the following task states:

| State | Category | Description |
|---|---|---|
| `submitted` | Active | Task received, not yet started |
| `working` | Active | Agent is processing |
| `input_required` | Active | Agent needs additional input from user |
| `auth_required` | Active | Agent needs auth credential from user |
| `completed` | Terminal | Task finished successfully |
| `failed` | Terminal | Task failed; `error` field present |
| `canceled` | Terminal | Task was cancelled |
| `rejected` | Terminal | Server declined the task |

Terminal states MUST NOT accept further messages.

### LegionForge Mapping

| A2A state | LegionForge `tasks.status` | Notes |
|---|---|---|
| `submitted` | `queued` | Task received, in queue |
| `working` | `running` | Worker picked it up |
| `input_required` | Not yet implemented | Phase 9+ (HITL mid-task) |
| `auth_required` | Not yet implemented | Phase 9+ |
| `completed` | `complete` | Typo-safe: spec uses `completed` |
| `failed` | `failed` | |
| `canceled` | `cancelled` | Note: spec uses single `l`; store as `cancelled` internally, map to `canceled` in A2A responses |
| `rejected` | Not exposed via A2A | Injection-detected tasks return `400`, not `rejected` |

**Gap:** LegionForge uses `complete` internally; A2A uses `completed`. The A2A adapter MUST translate. Do not rename the internal column — the mapping is cheap and renaming breaks non-A2A clients.

### 2.1 State Transition Rules

| From | To | Allowed | Condition |
|---|---|---|---|
| `queued` | `running` | ✅ | Worker claims the task |
| `queued` | `cancelled` | ✅ | User cancels before worker picks up |
| `running` | `complete` | ✅ | Agent run finishes successfully |
| `running` | `failed` | ✅ | Agent run throws uncaught error or Guardian halts |
| `running` | `cancelled` | ✅ | User cancels; worker receives signal |
| Any terminal | Any | ❌ | Terminal states are final |

---

## 3. Endpoints

### 3.1 Required A2A Endpoints

| Operation | A2A spec pattern | LegionForge endpoint | Status |
|---|---|---|---|
| Send message / create task | `POST /tasks` | `POST /a2a/tasks` | ⬜ |
| Get task | `GET /tasks/{taskId}` | `GET /a2a/tasks/{task_id}` | ⬜ |
| List tasks | `GET /tasks` | `GET /a2a/tasks` | ⬜ |
| Cancel task | `POST /tasks/{taskId}:cancel` | `POST /a2a/tasks/{task_id}/cancel` | ⬜ |
| Subscribe (streaming) | `GET /tasks/{taskId}:subscribe` | `GET /a2a/tasks/{task_id}/stream` | ⬜ |
| Agent Card | `GET /.well-known/agent.json` | `GET /.well-known/agent.json` | ⬜ |

**Implementation note:** The A2A spec uses the `:cancel` and `:subscribe` suffixes (Google API Design Guide "custom methods" pattern). LegionForge uses `/cancel` and `/stream` subpaths instead — equivalent semantics, cleaner URL for a FastAPI implementation.

### 3.2 Response Schemas

#### Task object (A2A)
```json
{
  "taskId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "working",
  "messages": [],
  "artifacts": [],
  "metadata": {}
}
```

**LegionForge mapping:**
- `taskId` ← `tasks.task_id`
- `status` ← translated from `tasks.status` (see §2)
- `messages` ← `[{"role": "user", "content": [{"type": "text", "text": task.input}]}]` initially
- `artifacts` ← `[{"artifactId": "result", "parts": [{"type": "text", "text": task.result}]}]` when complete

---

## 4. Streaming (SSE)

### Specification Requirements

- Streaming MUST use Server-Sent Events (SSE)
- Each SSE event MUST contain exactly one of: `task`, `message`, `statusUpdate`, `artifactUpdate`
- Events MUST be delivered in the order they were generated
- Multiple concurrent subscribers to the same task stream are permitted

### A2A SSE Event Types

| Event type | When | Description |
|---|---|---|
| `TaskStatusUpdateEvent` | Status transitions | `{"type": "status_update", "taskId": "...", "status": {...}}` |
| `TaskArtifactUpdateEvent` | New artifact or artifact chunk | `{"type": "artifact_update", "taskId": "...", "artifact": {...}}` |

### LegionForge → A2A SSE Mapping

LegionForge emits rich internal SSE events (token, tool_start, tool_end, etc.) that are richer than what A2A requires. For the A2A endpoint, we apply a filter:

| LegionForge SSE event | A2A event | Notes |
|---|---|---|
| `task_start` | `TaskStatusUpdateEvent {status: "working"}` | Status transition |
| `token` | `TaskArtifactUpdateEvent` (streaming artifact chunk) | Partial output |
| `tool_start` / `tool_end` | *(not emitted on A2A stream)* | Internal detail; not in A2A spec |
| `task_complete` | `TaskStatusUpdateEvent {status: "completed"}` + `TaskArtifactUpdateEvent` (final) | Two events |
| `task_error` | `TaskStatusUpdateEvent {status: "failed"}` | |
| `task_cancelled` | `TaskStatusUpdateEvent {status: "canceled"}` | |

**Implementation:** The A2A stream endpoint applies a `a2a_sse_filter()` transform over the internal event stream. The internal stream (for the LegionForge web UI) remains unchanged.

---

## 5. Authentication

### Specification Requirements

- Servers MUST reject requests with invalid or missing credentials
- TLS REQUIRED for all production deployments
- Supported schemes: Bearer, OAuth 2.0, API Key, mTLS

### LegionForge Phase 8 Position

| Requirement | Status | Notes |
|---|---|---|
| Bearer token auth | ⬜ Phase 8 | Per-user API key as Bearer token |
| TLS in production | ⬜ Phase 8 | Reverse proxy (Caddy or nginx) terminates TLS |
| Token validation on every request | ⬜ Phase 8 | `auth.py` dependency |
| Reject missing credentials: 401 | ⬜ Phase 8 | |
| Reject invalid credentials: 401 | ⬜ Phase 8 | |
| OAuth 2.0 | 🔵 Phase 10 | |
| mTLS | 🔵 Not planned | |

**Gap:** The A2A spec requires the Agent Card to advertise authentication schemes accurately. If Bearer auth is required, `authentication.schemes: ["Bearer"]` must be in the Agent Card, and the Agent Card endpoint itself must be unauthenticated (so clients can discover auth requirements before they have credentials).

**Decision:** `GET /.well-known/agent.json` is always unauthenticated. All other A2A endpoints require Bearer auth.

---

## 6. Push Notifications (Deferred)

The A2A spec supports push notifications — the server POSTs task updates to a client-supplied webhook URL. This enables async workflows where the client doesn't maintain a long-lived SSE connection.

**LegionForge position:** Deferred to Phase 9+. Phase 8 implements SSE polling only.

The `capabilities.pushNotifications: false` field in the Agent Card signals this to A2A clients — they MUST NOT configure push notification webhooks against this server.

---

## 7. Multi-Turn Tasks / `input_required` (Deferred)

A2A supports tasks that pause and request additional user input (`input_required` state). This is the mechanism for HITL mid-task interaction — the agent signals it needs a decision from the user before proceeding.

**LegionForge position:** Deferred to Phase 9+. All Phase 8 tasks are single-turn (user submits → agent completes without additional input).

**Design note:** When Phase 9 implements mid-task HITL, the existing human approval gate (currently operator-only via `/crystallization/candidates/{id}/approve`) will be extended to user-facing HITL prompts. The A2A `input_required` state is the interoperability surface for this.

---

## 8. Known Gaps and Decisions

### Gap 1: `task_id` generation

A2A REQUIRES that `taskId` be server-generated (the server generates a UUID on task creation). LegionForge's internal `tasks` table uses `gen_random_uuid()` as the default — compliant.

**Decision:** The A2A endpoint MUST NOT accept client-supplied `taskId`. If the request includes a `taskId` field, it MUST be ignored; the server generates its own.

### Gap 2: `canceled` vs `cancelled` spelling

A2A spec uses `canceled` (one `l`). LegionForge stores `cancelled` (two `l`). The A2A adapter MUST translate.

### Gap 3: Message/artifact schema

A2A has a richer message schema (parts, roles, multi-modal content). LegionForge currently produces plain text output. Phase 8 maps result text to `[{"type": "text", "text": "..."}]` parts. Richer output (tables, code, structured data) is Phase 9+.

### Gap 4: Agent Card signing

The A2A community is discussing Agent Card signing standards. LegionForge has Ed25519 infrastructure but will not implement signing until a standard emerges. TLS + hosted at well-known URL is the current best practice.

### Gap 5: `stateTransitionHistory`

`capabilities.stateTransitionHistory: true` means clients can request the full history of state transitions for a task. LegionForge stores `stream_events` (JSONB) on the tasks table — this can be exposed as the transition history. Implementation needed: `GET /a2a/tasks/{id}/history` endpoint.

---

## 9. Test Coverage Target

All A2A-specific behavior must be covered by smoke tests. Tests go in `tests/test_smoke.py` and require no running services.

| Test | Target |
|---|---|
| Agent Card has all required fields | ⬜ |
| Agent Card streaming=true | ⬜ |
| Agent Card pushNotifications=false | ⬜ |
| Agent Card has ≥1 skill | ⬜ |
| A2A status mapping covers all internal statuses | ⬜ |
| `canceled` spelling in A2A output (not `cancelled`) | ⬜ |
| A2A task endpoint returns 401 without token | ⬜ |
| Agent Card endpoint returns 200 without token | ⬜ |
| SSE filter maps `task_complete` → `TaskStatusUpdateEvent` | ⬜ |
| SSE filter drops `tool_start` from A2A stream | ⬜ |

---

## Sources

- [A2A Protocol Specification](https://a2a-protocol.org/latest/specification/)
- [A2A GitHub](https://github.com/a2aproject/A2A)
- [AgentCard spec](https://agent2agent.info/docs/concepts/agentcard/)

*Related docs:*
- [`docs/PHASE_8_GATEWAY_SPEC.md`](./PHASE_8_GATEWAY_SPEC.md) — Phase 8 implementation plan
- [`docs/VISION.md`](./VISION.md) — product architecture
