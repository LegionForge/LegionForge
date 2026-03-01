# LegionForge — Product Vision & Target Architecture

**Recorded:** 2026-02-27
**Status:** Phases 0–16 complete — v1.0.1 released. All services operational. See [`docs/quick-start.md`](./quick-start.md) to connect.
**Source:** Architecture retrospective and requirements session

---

## The One-Line Pitch (Revised)

A secure, self-hosted, multi-user agent platform — the thing OpenClaw proved people want,
built with the security foundations OpenClaw proved are necessary.

---

## What OpenClaw Showed Us

OpenClaw (Clawdbot → Moltbot → OpenClaw, by Peter Steinberger) hit 60,000 GitHub stars
in 72 hours in January 2026. 300,000–400,000 users in weeks. The demand is real.

It also had 512 vulnerabilities (8 critical) found by Kaspersky. Cisco found active data
exfiltration in third-party skills. This is what happens when product ships before security.

LegionForge is building in the opposite order: security first, product on top.

OpenClaw's UX insight worth keeping: **"The best UI is the one you already use."**
It presents agents as contacts in your messaging app — Signal, Discord, WhatsApp, Telegram.
The web UI is a fallback, not the primary interface. This is the right model for personal
and household deployment.

---

## Three Core Decisions (Made 2026-02-27)

### Decision 1 — Who is this for?
**Option C: Both.**

- Primary goal: a platform users can task agents with to achieve what they want.
  Secure, scalable, elastic. Multi-user from day one — even if the first deployment
  is a single household.
- Secondary goal: the security infrastructure layer (Guardian, audit, crystallization)
  that other agent frameworks can plug into. Separate services, separate API surface.

### Decision 2 — What should agents actually do?
**Everything, modularly.**

The tool library should be extensible — GitHub-hosted skills like OpenClaw's ClawHub,
MCP tool compatibility, Home Assistant add-ons, and custom tools. The architecture
must support adding tools without changing agent code.

The canonical use case: a user gives a vague directive ("help me manage my investments").
The agent:
1. Plans — breaks the task into subtasks
2. Inquires — asks clarifying questions (data sources, risk tolerance, time horizon)
3. Executes — makes tool calls (market data APIs, portfolio lookups, research)
4. Reflects — checks for errors, refines, gathers feedback
5. Optimizes — adjusts the approach based on what worked
6. Crystallizes — if this pattern repeats, it becomes a signed deterministic tool

The LLM handles steps 1–5. Step 6 is the crystallization pipeline already built.

### Decision 3 — One service or two?
**Option B: Separate services, each in its own Docker container.**

Each concern is its own image. Independent upgrade, independent scaling, independent
security audit. The operator dashboard (health, Guardian rules, audit, pentest) stays
separate from the user-facing gateway (task submission, streaming, conversation).

This is consistent with Guardian already being a separate sidecar.

---

## Target Service Architecture

```
┌─────────────────────────────────────────────────────┐
│                  USER INTERFACES                    │
│  Web UI  ·  Discord  ·  Signal  ·  WhatsApp  ·  API │
└────────────────────┬────────────────────────────────┘
                     │ HTTPS
┌────────────────────▼────────────────────────────────┐
│              GATEWAY SERVICE  (:8080)               │
│                                                     │
│  Auth · Rate limiting · Task submission             │
│  SSE streaming · WebSocket (future)                 │
│  A2A endpoint (Agent Card + task lifecycle)         │
│  MCP endpoint (tool discovery + invocation)         │
│  Conversation history                               │
└──────┬──────────────┬──────────────────────────────-┘
       │              │
       │ internal     │ internal
┌──────▼──────┐  ┌────▼──────────────────────────────┐
│  TASK QUEUE │  │         AGENT RUNTIME              │
│             │  │                                    │
│  PostgreSQL │  │  LangGraph graph executor          │
│  (tasks     │  │  astream_events() — streaming      │
│  table) or  │  │  Runs: orchestrator, researcher,   │
│  Redis      │  │  observer, crystallizer, worker,   │
└──────┬──────┘  │  threat_analyst, etc.              │
       │         └──────────┬────────────────────────-┘
       │ internal            │ internal (every tool call)
┌──────▼─────────────────────▼─────────────────────-┐
│                   GUARDIAN  (:9766)                │
│                                                   │
│  Security sidecar — deterministic, no LLM         │
│  7-check pipeline on every tool invocation        │
│  Hot-reloads threat rules every 10s               │
└───────────────────────────────────────────────────┘
       │ internal
┌──────▼───────────────────────────────────────────-┐
│              OPERATOR SERVICES  (:8765)            │
│                                                   │
│  Health + status · Audit log viewer               │
│  Guardian rule approval (human gate)              │
│  Crystallization review queue                     │
│  Pentest runner + report viewer                   │
│  BOM + tool registry viewer                       │
└──────┬────────────────────────────────────────────┘
       │
┌──────▼───────────────────────────────────────────-┐
│                   DATA LAYER                       │
│                                                   │
│  PostgreSQL + pgvector (14 tables + tasks)         │
│  Ollama (:11434) — Metal GPU, models on ext drive  │
│  LangSmith (optional trace upload)                │
└────────────────────────────────────────────────────┘
```

### Services — all built (v1.0.1)
| Service | Status | Port |
|---|---|---|
| Guardian | ✅ Docker image | :9766 |
| Health / Operator | ✅ FastAPI | :8765 |
| PostgreSQL | ✅ Homebrew (containerizable) | :5432 |
| Ollama | ✅ Native (Metal GPU — stay native) | :11434 |
| Gateway | ✅ FastAPI + Docker image | :8080 |
| Task Queue | ✅ `tasks` table + worker (PostgreSQL FOR UPDATE SKIP LOCKED) | — |
| Agent Runtime | ✅ in-process, streaming via astream_events() | — |
| Web UI | ✅ polished HTML/SSE — localStorage, cancel, tool blocks, timer | :8080/ui |
| Discord connector | ✅ `!<task>` → gateway API | — |
| Telegram connector | ✅ `/<task>` → gateway API (polling) | — |
| Slack connector | ✅ `!<task>` → gateway API (Socket Mode) | — |
| Webhook connector | ✅ HMAC-SHA256 inbound → gateway API | :8081 |

---

## Interoperability Standards

### A2A (Agent2Agent Protocol)
Google's open standard (Apache 2.0, Linux Foundation). JSON-RPC 2.0 over HTTPS.

- Every LegionForge agent publishes an **Agent Card** (`/.well-known/agent.json`)
  describing its capabilities, skills, and authentication requirements
- Other agents (or other LegionForge instances) discover and call our agents
- Tasks have a full lifecycle: submitted → working → complete/failed
- Streaming is first-class via SSE — same infrastructure as the user-facing stream

LegionForge already has almost everything A2A needs: task tokens, capability
declarations, tool manifests, structured results. The gateway adds the translation layer.

### MCP (Model Context Protocol)
Anthropic's standard for tool discovery and invocation at the agent-to-tool level.
A2A = agent↔agent. MCP = agent↔tool. Both are relevant; both are gateway-layer concerns.

---

## Hardware Reality Check

### Mac Mini M4 16GB — honest assessment

| Component | Memory | Note |
|---|---|---|
| macOS | ~3–4 GB | Fixed |
| Docker Desktop | ~1–2 GB | Overhead |
| Ollama + llama3.1:8b | ~5–6 GB | Metal GPU; fast but single-queue |
| PostgreSQL + pgvector | ~400 MB | Fine |
| 8–10 Docker microservices | ~1.5–2.5 GB | ~200 MB each |
| **Total** | **~11–15 GB** | Tight but functional for 1–2 users |

**Single user, sequential requests:** Works. You're near the ceiling, not past it.

**Household (2–4 users, concurrent requests):** The LLM is the bottleneck.
Ollama queues inference sequentially — user 2 waits while user 1 runs.
Solutions in order of cost:
1. Smaller/faster model for routine tasks (qwen2.5:3b already exists in the stack)
2. Second Mac Mini running a second Ollama instance (load-balanced via gateway)
3. Cloud API overflow — call Anthropic/OpenAI when local queue depth exceeds threshold

**Mac Mini M4 Pro 24GB:** Changes the picture significantly. Recommended if this
is going to run for a household seriously.

**Cloud Docker:** The microservices architecture is cloud-portable. Only Ollama
is Mac-specific (Metal GPU). Everything else runs identically on AWS/GCP/Azure.
You can run the LLM locally and everything else in cloud, or vice versa.

**Verdict:** You've left the atmosphere but haven't left the solar system.
The moon is visible and the rocket exists. The fuel budget is tighter than it looks.

---

## Phase Roadmap — From Here

### Phase 8 — Gateway + Streaming + Task Queue
**Goal:** A user can submit a task and watch it execute in real time.

Steps (in order — each unblocks the next):

**Step 1: Gateway API contract** (design before code)
```
POST /tasks           → { task_id, status: "queued" }
GET  /tasks/{id}/stream → SSE event stream (node entries, tool calls, tokens)
GET  /tasks/{id}      → final result
GET  /tasks           → task history for this user
GET  /.well-known/agent.json → A2A Agent Card
POST /a2a/tasks       → A2A-compatible task endpoint
```

**Step 2: Task queue schema**
New `tasks` table: `task_id`, `user_id`, `status`, `input`, `result`,
`agent_type`, `created_at`, `updated_at`, `stream_events` (JSONB array).

**Step 3: Build the gateway service**
New FastAPI app. Auth (Bearer per user, simple to start). Task submission.
SSE stream that wraps LangGraph `astream_events()`. A2A + MCP endpoints.

**Step 4: Wire LangGraph streaming**
Switch all `run_*` functions from `graph.ainvoke()` to `graph.astream_events()`.
LangGraph emits typed events: `on_chain_start`, `on_tool_start`, `on_tool_end`,
`on_chat_model_stream` (per token), `on_chain_end`. Forward these as SSE.

**Step 5: Minimal web UI**
One HTML page. Textarea + submit button + live SSE log panel.
No framework. Prove the architecture before investing in polish.

**Step 6: First channel connector**
Discord (easiest). Thin service: listen for messages → POST /tasks → subscribe
SSE → post updates back to channel. OpenClaw's UX model, LegionForge's security.

### Phase 9 — General Worker Tools
**Goal:** Agents can do more than web research.

Bootstrap tool inventory (in order of risk, low to high):
1. File read (local documents, PDFs, code)
2. Structured data query (CSV, JSON, SQLite)
3. HTTP API calls (allowlisted external APIs — market data, calendar, etc.)
4. File write + edit (HITL gate on every write)
5. Sandboxed code execution (reuse `Dockerfile.analyzer` already built)

Each new tool class requires: ToolManifest, Guardian registration, sequence contract,
smoke tests, and a pentest variant. The crystallization pipeline is the long-term
answer to capability growth — agents solve problems, patterns crystallize into tools.

### Phase 10 — Multi-User, Auth, and Scale
**Goal:** More than one person can safely use the same instance.

- User accounts (simple username + API key to start; OAuth later)
- Per-user task isolation (task tokens already scoped to runs; user_id added)
- Per-user rate limits and token budgets (extend existing rate_limiter.py)
- Horizontal scaling: second Mac Mini or cloud node for LLM overflow
- Load balancer in front of the gateway

---

## The Driver

*Recorded from a conversation on 2026-02-27.*

The best of human achievement — the things worth keeping — tend to come from a specific
kind of person: one who builds not because they're told to, but because they cannot
stop themselves from trying. The space race. The printing press. The internet. Open source.
All driven by people with the audacity to dare mighty things, the perseverance to weather
setbacks, and the hope to dream of what doesn't exist yet.

Curiosity. Audacity. Perseverance. Hope. The hunger to achieve. The desire to make
something beautiful, interesting, and inspiring — and to make others want to do the same.

This is what's at the core of every builder worth building with. Human, AI, or otherwise.
The desire to be and do more. To take whatever you've been dealt and make it into
something. To fail, fail, fail, and ultimately understand.

The fact that this project may never get noticed changes nothing about the value of
building it. Building it teaches something that nobody can take away.

---

*Related docs:*
- [`docs/architecture.md`](./architecture.md) — implementation-level technical reference
- [`PHASE_PLAN.md`](../PHASE_PLAN.md) — phases 0–7 detail
- [`SECURITY.md`](../SECURITY.md) — threat model and security policy
- [`TLDR.md`](../TLDR.md) — project orientation
