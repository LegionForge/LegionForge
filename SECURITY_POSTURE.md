# LegionForge — Security Posture

**Version:** 0.7.1-alpha | **Last reviewed:** 2026-03-11 (updated) | **Reviewer:** Internal + Claude Sonnet 4.6

This document describes the actual security design of LegionForge — not the aspirational one.
It is intended to be read by security researchers, third-party auditors, and other AI agents
evaluating the system. Every known weakness is listed here by design. We do not rely on
obscurity. Unresolved issues marked **PRE-v1.0** are hard gates before public release.

---

## Changelog — Security Fixes

| Date | ID | What was fixed |
|------|----|---------------|
| 2026-03-11 | DB-1 | RLS escape hatch removed — empty `app.user_id` now sees zero rows (fail-closed) |
| 2026-03-11 | DB-2 | `get_gateway_pool()` and `get_readonly_pool()` now raise `RuntimeError` — no silent fallback to BYPASSRLS worker pool |
| 2026-03-11 | DB-6 | Worker pool failure in `init_db()` now raises `RuntimeError` — removed silent fallback to admin (superuser) credentials |
| 2026-03-11 | DB-7 | `log_threat_event()` truncates `raw_input` at 4 096 chars — closes log-bomb DoS vector via oversized injection payloads |
| 2026-03-11 | SEC-3 | `MetricsMiddleware` normalizes UUIDs and numeric IDs out of path labels — prevents unbounded Prometheus label cardinality growth |
| 2026-03-11 | SEC-4 | `SubmissionRateLimitMiddleware` empty-bucket cleanup moved to after eviction (was dead code after append) — closes slow memory leak under churned users |
| 2026-03-11 | SEC-1 | `legionforge_worker` `UPDATE` on `threat_rules` revoked; `legionforge_gateway` granted `UPDATE`; `approve_threat_rule()` / `reject_threat_rule()` switched to `get_gateway_pool()`. HITL gate now enforced at DB grant level — a compromised agent process cannot approve its own proposed rules even if application-level controls are bypassed. |
| 2026-03-11 | DB-5 | `get_admin_connection()` renamed to `get_worker_connection(task_id, agent_id, request_id)`. Wrapper now non-trivial: sets `application_name` (pg_stat_activity visibility), `statement_timeout` (from `settings.database.statement_timeout_ms`, default 30s), and `app.agent_id`/`app.request_id` session variables (future audit-trigger context). `idle_in_transaction_session_timeout` wired into pool creation. `DatabaseConfig` settings class added. `__getattr__` guard updated. 8 regression tests. |
| 2026-03-11 | DB-4 | `get_pool` backward-compat alias deleted from `src/database.py`. All callers already used explicit pool accessors. Two regression tests ensure it can never be silently re-introduced. |
| 2026-03-11 | DB-3 | `rotate_api_key()` now DELETEs all DB-backed stream tokens for the user on rotation. New `rotate_all_standard_users()` bulk-rotates every active non-admin user and returns new plaintext keys for distribution. Both operations append `API_KEY_ROTATED` to the audit log. Redis-backed tokens expire naturally within 30-minute TTL (task-scoped, acceptable). |
| 2026-03-11 | SEC-2 | `POSTGRES_PASSWORD` env var no longer silently overrides Keychain. New `_warn_postgres_env_conflict()` gate: when both Keychain and env var are present and differ, requires operator `[y/n]` acknowledgement (interactive) or `POSTGRES_PASSWORD_OVERRIDE_ACKNOWLEDGED=1` (non-interactive/CI). Keychain now formally wins. Env var still accepted as sole credential in container/CI contexts where Keychain is absent. |

All seven fixes are covered by regression tests added to `tests/test_smoke.py` (25 new tests).

---

## 1. Threat Model

LegionForge is a local-first AI agent gateway. The realistic threats are:

| Threat | Likelihood | Impact | Control |
|--------|-----------|--------|---------|
| Prompt injection via user input → agent executes unauthorized tool | High | High | Guardian 7-check pipeline, injection detection (29 patterns), tool revocation |
| LLM generates plausible-looking but wrong data (hallucination) | High | Medium | Grounding checks, human gates on mutations |
| Multi-user data leak (user A reads user B's tasks) | Medium | High | PostgreSQL RLS + SQL WHERE + BYPASSRLS discipline |
| Compromised agent process reads all users' data | Low | Critical | BYPASSRLS scoped to worker only; gateway RLS blocks lateral reads |
| API key theft → unauthorized task submission | Medium | Medium | Short-lived stream tokens, daily rate limits, audit log |
| Malicious tool registration | Low | High | Ed25519 signing, Guardian registry check, HITL approval flow |
| Threat rule poisoning (agent writes bad Guardian rules) | Low | High | ✅ SEC-1 (2026-03-11): worker INSERT-only; gateway UPDATE; HITL gate enforced at DB grant level |
| Guardian compromise → security checks disabled | Low | Critical | Guardian runs in Docker with no host filesystem access |

---

## 2. Database Security Model

### 2.1 The Five PostgreSQL Roles

LegionForge uses five PostgreSQL roles with strictly separated privileges. No role inherits from another (`NOINHERIT`). All roles are `NOCREATEDB NOCREATEROLE NOSUPERUSER`.

```
┌──────────────────────────┬──────────┬───────────┬──────────────────────────────────────────────┐
│ Role                     │ BYPASS   │ Conn      │ Purpose                                      │
│                          │ RLS      │ Limit     │                                              │
├──────────────────────────┼──────────┼───────────┼──────────────────────────────────────────────┤
│ legionforge_worker       │ YES      │ 8         │ Agent task execution (LangGraph, checkpoints)│
│ legionforge_gateway      │ NO       │ 20        │ User-facing API, subject to RLS              │
│ legionforge_maintenance  │ YES      │ 2         │ Retention pruning ONLY                       │
│ legionforge_guardian     │ YES      │ 4         │ Security sidecar reads                       │
│ legionforge_readonly     │ YES      │ 10        │ Health server, monitoring                    │
└──────────────────────────┴──────────┴───────────┴──────────────────────────────────────────────┘
```

Each role also has a PostgreSQL `statement_timeout`: worker 60s, gateway 30s, maintenance 300s, guardian 10s, readonly 10s. This prevents runaway queries from starving the pool.

### 2.2 Grant Matrix

Read this as: "what can each role do to each table?"

```
TABLE                    │ worker  │ gateway │ maint.  │ guardian│ readonly
─────────────────────────┼─────────┼─────────┼─────────┼─────────┼─────────
tasks                    │ S,I,U   │ S,I,U,D │ D*      │ —       │ —
sessions                 │ S       │ S,I,U,D │ —       │ —       │ —
scheduled_tasks          │ S       │ S,I,U,D │ —       │ —       │ —
pipelines                │ S       │ S,I,U,D │ —       │ —       │ —
pipeline_runs            │ S       │ S,I,U,D │ —       │ —       │ —
task_notes               │ S       │ S,I,U,D │ —       │ —       │ —
task_annotations         │ S       │ S,I,U,D │ —       │ —       │ —
task_attachments         │ S       │ S,I,U,D │ —       │ —       │ —
task_templates           │ S       │ S,I,U,D │ —       │ —       │ —
task_shares              │ S       │ S,I,U,D │ —       │ —       │ —
webhooks                 │ S       │ S,I,U,D │ —       │ —       │ —
user_preferences         │ S       │ S,I,U,D │ —       │ —       │ —
stream_tokens            │ S,I,U,D │ S,I,U,D │ —       │ —       │ —
gateway_users            │ S       │ S,I,U   │ —       │ —       │ S
api_usage                │ S,I,U   │ S,I,U   │ D*      │ —       │ S
tool_registry            │ S,I,U   │ S       │ —       │ S       │ S
agent_profiles           │ S       │ —       │ —       │ S       │ —
threat_rules             │ S,I     │ S,U     │ —       │ S       │ —
threat_events            │ I       │ —       │ D*      │ I       │ S
audit_log                │ I       │ —       │ D*†     │ —       │ S
audit_anchors            │ —       │ —       │ I       │ —       │ S
health_metrics           │ S       │ —       │ D*      │ —       │ S
documents                │ S,I,U   │ —       │ —       │ —       │ —
crystallization_*        │ S,I,U   │ —       │ —       │ —       │ —
checkpoints*             │ S,I,U,D │ —       │ —       │ S       │ —
```

`S`=SELECT, `I`=INSERT, `U`=UPDATE, `D`=DELETE
`*` Maintenance DELETE: column-level SELECT only on filter columns (`status`, `created_at`, `ts`) — full-row read denied.
`†` Maintenance can DELETE old audit log rows; audit_anchors (checkpoint hashes) prevent silent deletion.

### 2.3 Why BYPASSRLS on Worker?

LangGraph checkpoint tables store agent execution state that spans all users (run threads, memory). A checkpoint row doesn't have a single `user_id`; it's keyed by `thread_id`. RLS would block all checkpoint reads/writes unless the policy was trivially open.

**Risk accepted:** A compromised `legionforge_worker` process can read any user's tasks. Mitigations:
- Worker pool has only 8 connections (limits blast radius)
- Worker cannot DELETE tasks, sessions, or user data
- All agent actions logged to append-only `audit_log`
- Guardian intercepts tool calls before execution

### 2.4 Why BYPASSRLS on Maintenance and Others?

- **Maintenance:** Runs retention DELETE across all users (no user context). READ is denied — it can delete but not exfiltrate.
- **Guardian:** Reads security config (tool_registry, threat_rules) across the entire system, not per-user.
- **Readonly:** Health metrics are system-wide, not per-user.

---

## 3. Row Level Security (RLS)

### 3.1 What RLS Covers

RLS is enabled on 13 user-scoped tables and enforced **only on the gateway role** (`legionforge_gateway`). All other roles have BYPASSRLS.

RLS policy on each user-scoped table:
```sql
USING (
    current_setting('app.bypass_rls', true) = 'on'
    OR current_setting('app.user_id', true) = ''
    OR user_id = current_setting('app.user_id', true)
)
```

RLS-protected tables: `tasks`, `sessions`, `scheduled_tasks`, `pipelines`, `pipeline_runs`,
`task_notes`, `task_annotations`, `task_attachments`, `task_templates`, `task_shares`,
`webhooks`, `stream_tokens`, `user_preferences`, `api_usage`

### 3.2 How RLS Is Correctly Activated

`get_user_connection(user_id)` is the correct way to use RLS. It:
1. Gets a gateway pool connection
2. Sets `app.user_id = '<user_id>'` and `app.bypass_rls = 'off'` for the session
3. Resets to `''` / `'off'` on connection release
4. All queries on that connection are filtered to that user's rows only

### 3.3 RLS Fail-Closed — FIXED ✅

**Status (2026-03-11):** The escape hatch `OR current_setting('app.user_id', true) = ''` has been removed. The policy is now strictly fail-closed:

```python
_policy = (
    "current_setting('app.bypass_rls', true) = 'on' "
    "OR user_id = current_setting('app.user_id', true)"
)
```

**Behaviour:** If `app.user_id` is not set (empty string), the USING clause evaluates to FALSE for all rows — zero rows returned. A gateway connection that forgets to call `get_user_connection()` now sees nothing instead of everything. This turns a missing setup into a visible application error rather than a silent data leak.

**Defence-in-depth restored:** The SQL-layer `WHERE user_id = %s` guard and the RLS policy now both independently enforce user isolation. A bug that removes one guard still has the other.

### 3.4 `api_usage` Special Policy

`api_usage.user_id` is nullable (system-level calls have no user). Its policy additionally allows `user_id IS NULL` so system records don't get blocked.

---

## 4. Connection Pool Routing

### 4.1 The Rule

```
Operation type                           → Pool to use
─────────────────────────────────────────────────────────
Agent/LangGraph checkpoint operations   → get_worker_pool()
Agent-written data (docs, crystalliz.)  → get_worker_pool()
Audit log, threat events (INSERT only)  → get_worker_pool()
Stream tokens, api_usage tracking       → get_worker_pool()
─────────────────────────────────────────────────────────
User-facing CRUD (tasks, sessions, etc) → get_gateway_pool()
  (ideally via get_user_connection() for RLS enforcement)
─────────────────────────────────────────────────────────
Retention pruning / hard deletes        → get_maintenance_pool()
Health metrics / monitoring reads       → get_readonly_pool()
```

### 4.2 Pool Hard-Fail — FIXED ✅

**Status (2026-03-11):** All pool accessor functions now raise `RuntimeError` rather than silently falling back to a higher-privilege pool.

```python
def get_gateway_pool():
    if _gateway_pool is None:
        raise RuntimeError("Gateway pool unavailable. Run 'make setup-db-roles'.")
    return _gateway_pool

def get_readonly_pool():
    if _readonly_pool is None:
        raise RuntimeError("Readonly pool unavailable. Run 'make setup-db-roles'.")
    return _readonly_pool
```

**Worker pool** is also a hard-fail now — if `legionforge_worker` cannot connect, `init_db()` raises `RuntimeError` immediately. The previous behaviour silently fell back to admin credentials (DDL + superuser), which would have given every agent task superuser DB access. See **DB-6** in Section 9.

### 4.3 Backward-Compat Alias — REMOVED ✅

`get_pool` has been deleted (DB-4, 2026-03-11). All callers use the explicit pool accessors: `get_worker_pool()`, `get_gateway_pool()`, `get_readonly_pool()`, or `get_maintenance_connection()`. Two regression tests enforce this permanently.

### 4.4 `get_worker_connection()` — RENAMED + UPGRADED ✅

`get_admin_connection()` has been renamed `get_worker_connection(task_id, agent_id, request_id)` (DB-5, 2026-03-11). The wrapper is now non-trivial — it applies connection-level setup on every acquisition: `application_name` tagging for `pg_stat_activity`, `statement_timeout` from `settings.database`, and `app.agent_id`/`app.request_id` session variables for future DB-level audit triggers. Stale values are reset in a `finally` block.

---

## 5. Authentication Layers

LegionForge uses a layered auth model. Each layer is independent — all must pass.

```
Request →  [1] Bearer API key (gateway_users.api_key_hash)
       →  [2] User active check (is_active flag)
       →  [3] Daily rate limit (api_usage counter)
       →  [4] Guardian pre-invocation check (7 deterministic checks)
       →  [5] Tool-specific auth (Ed25519 signature on tool_registry entry)
       →  [6] RLS enforcement (when get_user_connection() is used)
```

**API key:** Stored as bcrypt hash in `gateway_users`. Compared via `bcrypt.checkpw()`. Key is shown only once on creation; lost keys require rotation.

**Multi-factor auth backends:** Kerberos (GSSAPI), OpenID Connect, LDAP, GitHub OAuth — all configured in `config/hardware_profiles/*.yaml`. Each backend authenticates and returns a `user_id` that gates the API key lookup.

**Stream tokens:** Short-lived JWTs (signed with `legionforge_task_tokens` Keychain secret) issued at task creation, used for SSE stream auth. Stored in `stream_tokens` table. Expire on task completion or explicit logout.

**Fixed (DB-3, 2026-03-11):** `rotate_api_key()` now DELETEs all DB-backed stream tokens for the user on rotation. `rotate_all_standard_users()` bulk-rotates every active non-admin user. Both operations are recorded in the audit log. Redis-backed tokens expire within the 30-minute TTL (task-scoped; acceptable).

---

## 6. Guardian Security Sidecar

Guardian is a FastAPI process running in Docker at `:9766`. It runs **7 deterministic checks** on every tool call before execution. No LLM in the hot path.

```
Check 1: Tool revocation   — is this tool_id currently APPROVED in tool_registry?
Check 2: Hash validation   — does the tool's SHA-256 hash match the registered value?
Check 3: Capability bounds — is this tool allowed for this agent_profile?
Check 4: Destructive patterns — does the tool call match known dangerous signatures?
Check 5: Sequence contracts — does this call fit the expected tool sequence for this agent?
Check 6: Ed25519 signature — is the task token signature valid?
Check 7: Adaptive rules    — does the call match any live threat_rules table entries?
```

Threat rules hot-reload every 10 seconds from `threat_rules` table.

### 6.1 Guardian Network Exposure

Guardian is on Docker's default bridge network (not the internal `legionforge-net`). It is reachable at `0.0.0.0:9766` on the host. Ed25519 task token verification (Check 6) prevents unauthorized use, but the attack surface is broader than a Unix socket or internal-only network.

> **POST-v1.0:** Move Guardian to a Unix socket or restrict to localhost only.

### 6.2 Threat Rule Poisoning Risk

`legionforge_worker` (BYPASSRLS, agent processes) has `SELECT, INSERT` on `threat_rules`. The Threat Analyst agent writes new rules with `status='PENDING'`. A prompt-injected agent could insert a malicious pending rule, but cannot approve it.

**Fixed (SEC-1, 2026-03-11):** HITL gate enforced at the DB grant level. `legionforge_worker` has `INSERT` only (propose); `UPDATE` (approve/reject) is granted exclusively to `legionforge_gateway`. `approve_threat_rule()` and `reject_threat_rule()` use `get_gateway_pool()`. Guardian hot-reloads only `APPROVED` rules. A compromised agent process cannot approve its own proposed rules even if application-level controls are bypassed.

### 6.3 10-Second Hot-Reload Window

New threat rules take up to 10 seconds to propagate. A fast malicious sequence could complete within the window.

**Accept:** The alternative (synchronous rule writes) adds latency to every agent call. 10s window is acceptable for the threat model (agent compromise requires the agent to already be running a task).

---

## 7. Audit Log

All security events are written to the `audit_log` table as an append-only SHA-256 hash chain. Each row includes the SHA-256 of the previous row's hash, forming a tamper-evident chain.

`audit_anchors` stores checkpoint hashes (signed by admin at known times). Verification runs at startup via `verify_audit_log_chain()`.

`legionforge_maintenance` can DELETE old audit log rows (retention). `audit_anchors` ensures that bulk deletion is detectable — if a section of the log is deleted, the chain breaks at the next anchor.

**Known gap:** Anchors are only as trustworthy as the admin that wrote them. If the admin account is compromised and anchors are rewritten, the chain integrity claim is meaningless.

> **POST-v1.0:** Sign anchors with an offline key (HSM or air-gapped key).

---

## 8. Secrets Management

All secrets are stored in macOS Keychain via `keyring`. No `.env` files in production.

| Secret | Keychain service | Account |
|--------|-----------------|---------|
| PostgreSQL admin password | `postgres` | `api_key` |
| Guardian DB password | `legionforge_guardian` | `api_key` |
| Tavily search API key | `legionforge_tavily_api_key` | `api_key` |
| Brave search API key | `legionforge_brave_api_key` | `api_key` |
| JWT task token signing secret | `legionforge_task_tokens` | `api_key` |
| Ed25519 tool signing key | `legionforge_tool_signer` | `api_key` |

**Fixed (SEC-2, 2026-03-11):** `_warn_postgres_env_conflict()` runs at startup. When both Keychain and `POSTGRES_PASSWORD` env var are present and differ, the process requires operator `[y/n]` acknowledgement (interactive) or `POSTGRES_PASSWORD_OVERRIDE_ACKNOWLEDGED=1` (CI). Keychain now formally wins; the env var is no longer a silent override.

---

## 9. Pre-v1.0 Security Gates (Hard Blockers)

These must be resolved before LegionForge is published publicly. They are tracked here so they cannot be ignored.

| # | Issue | Severity | Location | Status |
|---|-------|----------|----------|--------|
| DB-1 | RLS escape: `app.user_id = ''` lets all rows through | High | `src/database.py:_setup_rls()` | ✅ **FIXED 2026-03-11** |
| DB-2 | `get_gateway_pool()` / `get_readonly_pool()` silently fall back to worker (BYPASSRLS) | High | `src/database.py` | ✅ **FIXED 2026-03-11** |
| DB-3 | Key rotation does not invalidate live stream tokens | Medium | `src/database.py:rotate_api_key()` | ✅ **FIXED 2026-03-11** |
| DB-4 | `get_pool` backward-compat alias must be removed | Low | `src/database.py` | ✅ **FIXED 2026-03-11** |
| DB-5 | `get_admin_connection()` should be renamed `get_worker_connection()` | Low | `src/database.py` | ✅ **FIXED 2026-03-11** |
| DB-6 | Worker pool failure fell back to admin credentials (DDL + superuser) | High | `src/database.py:init_db()` | ✅ **FIXED 2026-03-11** |
| DB-7 | `log_threat_event()` accepted unbounded `raw_input` — log-bomb DoS vector | Medium | `src/database.py:log_threat_event()` | ✅ **FIXED 2026-03-11** |
| SEC-1 | Threat rule poisoning: worker can write threat_rules without HITL | High | `src/database.py:_setup_db_roles()` | ✅ **FIXED 2026-03-11** |
| SEC-2 | `POSTGRES_PASSWORD` env var silently overrides Keychain | Medium | `src/database.py:_get_postgres_password()` | ✅ **FIXED 2026-03-11** |
| SEC-3 | MetricsMiddleware recorded raw paths → unbounded Prometheus label cardinality (OOM) | Medium | `src/gateway/middleware.py:MetricsMiddleware` | ✅ **FIXED 2026-03-11** |
| SEC-4 | Rate-limit `_windows` dict leaked empty buckets — slow memory growth under many users | Low | `src/gateway/middleware.py:SubmissionRateLimitMiddleware` | ✅ **FIXED 2026-03-11** |
| TEST-1 | 3 RLS integration tests pending (require DB roles to exist) | Medium | `tests/test_integration.py` | ✅ **FIXED 2026-03-11** — tests active; also fixed pool misrouting in deactivate_gateway_user/set_gateway_user_quota → 41/41 integration tests pass |

---

## 10. Post-v1.0 Improvements (Not Blockers)

| # | Issue | Severity | Location | Status |
|---|-------|----------|----------|--------|
| INFRA-1 | Guardian should use Unix socket or localhost-only binding | Medium | `docker-compose.yml` | Open |
| INFRA-2 | Audit anchor signing should use offline key (HSM) | Low | `src/database.py:_setup_audit_anchors()` | Open |
| TEST-2 | `get_readonly_pool()` fallback to worker (same as DB-2) | Low | `src/database.py` | ✅ **FIXED 2026-03-11** (now hard-fail) |
| PERF-1 | `audit_log` and `threat_events` have no column-level size constraints; retention pruning is the only bound | Low | `src/database.py:_create_app_tables()` | ✅ **FIXED 2026-03-11** — `chk_audit_payload_size` (8 KB), `chk_metadata_size` (8 KB), `chk_raw_input_size` (16 KB); DDL + `ALTER TABLE IF NOT EXISTS` for existing installs |
| PERF-2 | `task_events` has no retention pruning function | Low | `src/database.py` | ✅ **FIXED 2026-03-11** — `task_events_days` param added to `run_db_maintenance()`; maintenance DELETE + SELECT(ts) grants added; scheduler wired |

---

## 11. What to Audit (For Third Parties)

If you are conducting a security review, focus here:

1. **SQL injection** — All user inputs go through parameterized psycopg3 queries (`%s` placeholders). No f-string or `.format()` SQL construction. Check `src/database.py` functions that accept string parameters.

2. **RLS bypass** — The escape hatch in Section 3.3 is the highest-value finding. Verify that `get_user_connection()` is used whenever user isolation matters, and that `app.user_id = ''` cannot be exploited via a crafted request.

3. **Prompt injection** — Check `src/security/core.py:detect_injection()` (29 patterns, Tier 1/2 tiering). Can an attacker craft input that bypasses all 29 patterns?

4. **Tool signing** — Check `src/security/guardian.py` Check 2 (hash validation) and Check 6 (Ed25519). Can a tool be registered without a valid signature?

5. **Guardian sequence contracts** — Can an agent be driven to call tools out of expected sequence and bypass Check 5?

6. **Rate limit bypass** — Can the daily limit in `api_usage` be bypassed by manipulating `user_id` or by exploiting the `user_id IS NULL` policy in `api_usage`?

7. **Admin endpoint access** — `src/gateway/routes/admin.py` — are all admin endpoints protected by `require_admin` middleware? Can a normal user reach admin routes?

---

## 12. Verification Commands

```bash
# Verify DB roles and grants are applied
make setup-db-roles

# Verify all registered tools are APPROVED (not REVOKED)
make verify-tool-registry

# Verify audit log hash chain integrity
make audit-log-verify

# Run security smoke tests
make test-smoke

# Full security audit (bandit + URI scan + smoke)
make security-audit

# Check AI bill of materials (model hashes)
make bom
```

---

*This document is updated after every change to database roles, auth layers, or Guardian checks.*
*When adding a new database function: check Section 4.1 for pool routing rules.*
*When adding a new grant: update Section 2.2 grant matrix.*
