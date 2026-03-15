# Security Review Findings
**Reviewed:** 2026-03-15
**Reviewer:** Automated analysis (read-only)
**Scope:** src/security/, src/gateway/, src/database.py, src/agents/, src/tools/, src/safeguards.py, config/, src/gateway/static/index.html

---

## Critical (fix before v0.8.0 public release)

### 1. Gateway /docs and /redoc are live in production
**File:** `src/gateway/app.py` lines 202–204

The FastAPI auto-generated `/docs` (Swagger UI) and `/redoc` endpoints are enabled. The code comment acknowledges this: `# Disable /docs and /redoc in production — enable in dev via env flag` — but the disabling code is commented out. Anyone who can reach port 8080 gets a full interactive API explorer with no authentication required to view it.

**Recommended fix:** Set `docs_url=None, redoc_url=None` unless `LEGIONFORGE_DEV_DOCS=1` is set in the environment. The feature flag is already mentioned in the comment; just wire it up.

---

### 2. callback_url SSRF guard missing at submission time
**Files:** `src/gateway/routes/tasks.py` lines 280–290; `src/webhook_sender.py` lines 71–79

The `TaskRequest.callback_url` field validator at task submission (line 282) only checks that the scheme is `http` or `https` and that a netloc is present — it does not call `validate_fetch_url()` or `is_ssrf_url()`. The SSRF check only happens in `webhook_sender._is_valid_url()`, which performs the same weak scheme-only check (no private-IP detection, no DNS resolution). An authenticated user can register `callback_url="http://192.168.1.1/admin"` or `callback_url="http://169.254.169.254/latest/meta-data/"` and the worker will faithfully POST task results to those addresses on their behalf.

The `is_ssrf_url()` utility already exists in `src/security/core.py` (line 959) and is used correctly for web_fetch. It is not called for webhook callbacks.

**Recommended fix:** Call `is_ssrf_url(v)` inside `callback_url_must_be_http()` and raise `ValueError` if it returns `True`. Apply the same fix to registered webhook URLs in `src/gateway/routes/webhooks.py` (the `HttpUrl` type validates format but not internal-target blocking).

---

### 3. Plotly loaded from CDN without Subresource Integrity (SRI)
**File:** `src/gateway/static/index.html` lines 14013–14022

When an agent produces a Plotly chart, the UI dynamically injects a `<script src="https://cdn.plot.ly/plotly-basic-2.35.2.min.js">` element at runtime without an `integrity` attribute. A CDN compromise or supply-chain attack against that URL would execute arbitrary JavaScript in the context of the page — which holds the user's API key in `localStorage`. `crossOrigin='anonymous'` is set (good for CORS), but without `integrity` it provides no integrity guarantee.

**Recommended fix:** Compute the SHA-384 digest of the pinned `plotly-basic-2.35.2.min.js` and add `s.integrity = 'sha384-<hash>'`. Alternatively, self-host the file under `/static/`.

---

### 4. No security response headers — missing CSP, X-Frame-Options, HSTS
**Files:** `src/gateway/app.py`, `src/gateway/middleware.py`

No middleware adds security response headers. The following are entirely absent:
- `Content-Security-Policy` — no restriction on script sources, allowing injected `<script>` tags to load from any origin.
- `X-Frame-Options: DENY` or `frame-ancestors 'none'` — the UI can be framed by any page, enabling clickjacking attacks against the API key input field.
- `Strict-Transport-Security` — no HSTS, so downgrade attacks are possible when the UI is accessed over HTTP.
- `X-Content-Type-Options: nosniff` — browsers may MIME-sniff responses.
- `Referrer-Policy: no-referrer` — the API key is in-scope on all pages and could appear in Referer headers sent to third-party resources.

A minimal CSP that permits only self-hosted resources plus the one CDN would meaningfully reduce the blast radius of any future XSS.

**Recommended fix:** Add a `SecurityHeadersMiddleware` that sets these headers on every response. The CSP should whitelist `script-src 'self' https://cdn.plot.ly` (and `'unsafe-inline'` only if strictly necessary for the inline `<script>` block, or refactor to an external JS file).

---

### 5. API key stored in `localStorage` — accessible to any JavaScript on the page
**File:** `src/gateway/static/index.html` line 4746, 4800

The gateway API key is persisted to `localStorage` under key `lf_api_key`. `localStorage` is accessible to any JavaScript executing on the same origin, including XSS payloads from agent-generated content that bypasses or evades the markdown renderer's escape. The key is never cleared on logout and survives browser restarts indefinitely.

While the markdown renderer does escape HTML before applying transforms (line 5675), other `innerHTML` assignments in the page (noted in item 6 below) and the SVG sanitizer (which relies on DOM parsing) create potential routes to exfiltrate `localStorage`.

**Recommended fix (pre-v0.8.0):** At minimum, add a session-expiry mechanism: store an expiry timestamp alongside the key and clear it after N hours of inactivity. Longer term (post-v0.8.0): migrate to `sessionStorage` so the key is cleared when the tab closes, or implement a proper token-refresh flow that avoids long-lived keys in the browser at all.

---

## High (fix in v0.8.x)

### 6. Several `innerHTML` assignments render partially or fully unescaped content
**File:** `src/gateway/static/index.html`

Several `innerHTML` assignments in the operator dashboard section (lines 6298–6357, 6370, 6381, 6469, 6541–6542, 6603, 6633, 6694, 6722, 6756, 6807, 6859, 7019, 7074, 7094, 7116, 7137, 7159, 7178) build HTML strings from API responses. Many of these do use `escapeHtml()` on individual field values — but some construct HTML strings that interpolate task IDs, timestamps, and other values inline with string concatenation, and the coverage is inconsistent. For example, the rating bar at line 6298 interpolates `taskId` directly (IDs are UUIDs and safe in practice, but the pattern is fragile).

The `appendHTML()` function at line 5538 accepts raw HTML and calls `innerHTML` on it, bypassing escaping. It is called in `appendResult()` at line 5811, where `renderMarkdown(text)` is passed directly. The markdown renderer does HTML-escape before transforming, so agent output is safe — but any future caller of `appendHTML()` that passes user or server data without going through `renderMarkdown` would be an XSS vector.

**Recommended fix:** Audit all `innerHTML` assignments in the operator dashboard JS. Replace string-concatenation HTML construction with `document.createElement` + `textContent` assignment for all fields that come from the server. Add a lint rule or pre-commit check that flags `innerHTML` assignments not preceded by `escapeHtml`.

---

### 7. JWT task tokens use HS256 (symmetric) — secret must be kept out of all agents
**File:** `src/security/acl.py` line 200

Task tokens are signed with HS256. The same secret that signs tokens also validates them. If any agent process is compromised and the `TASK_TOKEN_SECRET` environment variable leaks (e.g. via the CREDENTIAL_PROBE destructive pattern triggering a log event that includes the environment), the attacker could forge tokens for any agent with any scope. RS256 (asymmetric) would allow agents to verify tokens without having the signing key.

Additionally, there is no JTI revocation list: once a token is issued, it is valid until expiry regardless of what happens. If a token leaks (e.g. via a log message), it cannot be revoked before its TTL expires.

**Recommended fix (medium-term):** Move signing to RS256: signing key stays in the gateway process only; public key is distributed to agents for verification. Short-term: reduce TTLs to the minimum needed and ensure `TASK_TOKEN_SECRET` is never logged.

---

### 8. Audit log hash chain uses a single-step INSERT then UPDATE — introduces a race window
**File:** `src/database.py` lines 2910–2937

The `append_audit_log()` function inserts a row with `row_hash = 'PENDING'`, then updates it with the computed hash. In the window between INSERT and UPDATE, the row is readable with a placeholder hash. If the DB connection fails between the two operations, the row remains permanently with `row_hash = 'PENDING'`, which breaks `verify_audit_log_chain()`. More critically, both operations happen in the same connection but as two separate `await conn.execute()` calls — if the connection is interrupted mid-flight, the final hash may never be written.

**Recommended fix:** Wrap both statements in an explicit transaction (`async with conn.transaction()`) so either both succeed or neither does. Alternatively, compute the hash before the INSERT and pass it in the original INSERT.

---

### 9. `LANGCHAIN_TRACING_V2` is set as a process-global env var, not per-run
**File:** `src/safeguards.py` lines 167–174

`create_run_config()` sets `os.environ["LANGCHAIN_TRACING_V2"] = "false"` when `tracing_enabled=False`. This mutates the process-global environment — other concurrent runs that have `tracing_enabled=True` will have their tracing silently disabled by a concurrent run with `tracing_enabled=False`. In an async gateway serving multiple users simultaneously, one user's `tracing_enabled=False` request will suppress LangSmith tracing for all other concurrent runs.

**Recommended fix:** Use the per-run `callbacks=[]` config key to suppress tracing (already done at line 166) and remove the `os.environ` mutation. LangSmith respects the per-run `callbacks` list.

---

### 10. No rate limiting on authentication endpoint (credential brute-forcing)
**Files:** `src/gateway/middleware.py`, `src/gateway/auth.py`

`SubmissionRateLimitMiddleware` covers `POST /tasks` and memory paths. There is no rate limit on authentication attempts. An attacker can send unlimited `Authorization: Bearer <key>` requests to any authenticated endpoint, brute-forcing API keys. Each attempt calls `bcrypt.checkpw()` — bcrypt is slow by design, but the absence of a lockout threshold still allows sustained attacks. The rate limiter keys on the Bearer token prefix, so unauthenticated/wrong-key attempts are keyed by IP, which an attacker can trivially rotate.

**Recommended fix:** Add failed-authentication counting per source IP. After N consecutive failures (e.g. 10 in 60 seconds), return 429 for that IP for a backoff period. This can be implemented as an extension to `SubmissionRateLimitMiddleware` or as a separate `AuthRateLimitMiddleware`.

---

### 11. Private developer identity in the public A2A Agent Card
**File:** `src/gateway/routes/a2a.py` lines 65–66

The A2A Agent Card at `/.well-known/agent.json` (a public, unauthenticated endpoint) hardcodes `"organization": "jp-cruz"` and `"url": "https://github.com/LegionForge/LegionForge"` — the private dev identity that is planned to be retired at v0.8.0. This is served to any caller of the public API before the identity migration.

**Recommended fix:** Replace with `"organization": "LegionForge"` and `"url": "https://github.com/LegionForge/LegionForge"` immediately, or load from config so it can be updated without a code change.

---

## Medium (backlog)

### 12. `f-string` SQL fragments with `# nosec B608` suppression warrant audit
**File:** `src/database.py` lines 4570, 4574–4580, 5524, 5580, 5721; `src/gateway/routes/observability.py` lines 70–77

Several dynamic SQL queries are built with `f-strings` rather than `psycopg.sql.Composed` objects, suppressed with `# nosec B608`. In each case the code comment asserts safety (e.g. "assembled from hardcoded string fragments"). The assessment is correct as written today — the `where` variable is built by appending hardcoded strings, with all user values in parameterized `params`. However this pattern is fragile: future contributors may add a user-controlled string to `where` without noticing that it bypasses parameterization. The `# nosec` suppression removes the bandit signal that would warn them.

In `update_scheduled_task()` (line 5580), the `sets` list is built from `if name is not None: sets.append("name = %s")` etc. — all hardcoded column names, so currently safe. Same applies to `update_pipeline()`.

**Recommended fix:** Replace `f-string` WHERE clause assembly with `psycopg.sql.Composed` (the `psycopg.sql` module is already imported as `pgsql` at line 31 of `database.py`). This eliminates the fragility and removes the need for `# nosec` suppression.

---

### 13. bcrypt `gensalt()` uses default cost factor (10) — consider increasing
**File:** `src/gateway/auth.py` line 94

`_bcrypt.gensalt()` is called with no arguments, defaulting to cost factor 10. bcrypt cost 10 is ~100ms on modern hardware — sufficient for interactive auth but low for high-value API key protection. Given that API keys are long-lived (no expiry mechanism is implemented), a higher cost factor (12–14) would significantly slow brute-force attempts.

**Recommended fix:** Upgrade new hashes to cost factor 12. Existing hashes will continue to verify correctly (bcrypt is self-describing); only new key creations use the new factor.

---

### 14. SVG sanitizer in the UI does not strip `use` elements with external references
**File:** `src/gateway/static/index.html` lines 14034–14046

`_sanitizeSvg()` removes `script`, `foreignObject`, `animate`, and `set` elements, and strips event handler attributes and `javascript:` hrefs. However it does not remove `<use>` elements, which can reference external SVG documents via `href="https://evil.com/evil.svg#payload"`. A `<use>` pointing to an attacker-controlled SVG can pull in `<script>` and event-handler-bearing elements at render time, bypassing the sanitization. This vector requires that an LLM or agent process outputs a crafted SVG sentinel block — possible if the agent is compromised via tool-result injection.

**Recommended fix:** Add `'use'` to `DANGEROUS_TAGS`, or strip any `href`/`xlink:href` on `<use>` elements that point to external origins (not starting with `#`).

---

### 15. `inlineMarkdown()` does not sanitize link `href` values against `javascript:` URIs
**File:** `src/gateway/static/index.html` line 5743 (function `inlineMarkdown`)

The `inlineMarkdown()` function applies transforms including link rendering (if it is present — it was not visible in the reviewed excerpt but is a standard markdown feature). If a link pattern `[text](href)` is processed by `inlineMarkdown`, the `href` value comes from the (HTML-escaped) markdown source. After `escapeHtml()` in `renderMarkdown()` step 1, a `javascript:` URI would appear as the literal string `javascript:` — which, when rendered into an `href` attribute, is still executable. This requires explicit link support in the markdown renderer; the current implementation's link handling should be verified to block `javascript:` URIs in the same way `_sanitizeSvg` does.

**Recommended fix:** Verify that `inlineMarkdown` either does not render `[text](href)` links or, if it does, validate that `href` does not start with `javascript:` after unescaping.

---

### 16. `sanitize_log_value()` is not consistently applied to all user-controlled log values
**File:** `src/security/core.py` lines 480–499 (function defined); usage across codebase

`sanitize_log_value()` strips ANSI codes and control characters from user-supplied strings before logging. The function exists and works correctly. However, numerous log calls throughout the codebase log user-controlled strings directly with `f-string` interpolation (e.g. `logger.warning(f"... pattern_count={injection_meta.get('pattern_count', 0)}")` in `tasks.py`, `logger.info(f"[tool-registry] Registered '{manifest.tool_id}' ...")` in `core.py`). The tool_id, agent_id, and run_id strings come from user input at task submission time and are logged without going through `sanitize_log_value()`.

**Recommended fix:** Apply `sanitize_log_value()` to tool_id, agent_id, username, task input excerpts, and any other user-controlled string before it reaches a `logger.*()` call. Add a Bandit custom rule or grep-based CI check to catch new violations.

---

### 17. Lazy-load path in `verify_tool_before_invocation()` is self-referential — cannot detect DB-level tampering
**File:** `src/security/core.py` lines 719–757

When a tool is not in the in-memory registry, it is lazy-loaded from the DB. The reconstructed manifest's hashes are populated from the same DB row that provides the manifest content. This means if an attacker modifies the `tool_registry` table directly (e.g. via a compromised `legionforge_worker` connection), they can update both the description and the `description_hash` simultaneously, and the lazy-load path will see a match and approve the tool. The in-memory hot path (used when the tool was registered at startup) does not have this problem. The comment at line 624 documents this limitation but it has not been mitigated.

**Recommended fix:** The worker role (`legionforge_worker`) has `BYPASSRLS` — it should not have UPDATE on `tool_registry`. Restrict the worker role to SELECT only on `tool_registry`; use the gateway role (or a dedicated registrar role) for inserts/updates, which require an explicit operator action. This limits the damage if the worker pool is compromised.

---

### 18. Health endpoint at :8765 and Prometheus metrics at :8080/metrics are unauthenticated
**File:** `src/gateway/app.py` lines 344–372; `src/health.py` (by reference)

`GET /health` returns service version and LLM status with no authentication. `GET /metrics` returns Prometheus counters (request counts by path and status, Redis connectivity, etc.) with no authentication. The metrics endpoint exposes operational topology — which paths are being hit, error rates, whether Redis is connected. The doc comment says "Restrict at the load balancer / firewall in production" but there is no mechanism to enforce this.

**Recommended fix:** The health endpoint is intentionally unauthenticated (Docker healthcheck cannot set headers). The metrics endpoint, however, should require at minimum a static token or IP allowlist enforced in middleware. Add a `METRICS_BEARER_TOKEN` setting and a check in the `/metrics` handler.

---

### 19. `create_run_config()` accepts arbitrary user-supplied metadata passed to LangSmith
**File:** `src/safeguards.py` lines 126–183

The `metadata` parameter of `create_run_config()` is passed through to LangSmith traces without sanitization. If task metadata includes PII (e.g. user_id, username), it will appear in LangSmith traces even if the task input itself was sanitized. The `sanitize_for_trace()` function exists in `core.py` (line 448) but is not called on the `metadata` dict here.

**Recommended fix:** Pass `metadata` through `sanitize_for_trace(metadata)` before including it in the LangSmith config.

---

## Low / Hardening (nice-to-have)

### 20. Stream tokens are not consumed (deleted) after a successful stream completes
**File:** `src/gateway/auth.py` lines 265–277

`resolve_stream_token()` deliberately does not delete the token "so EventSource clients can reconnect within the TTL." Stream tokens have a 30-minute TTL. However, once a task is complete, the token has no value and should be invalidated. If the API key is not compromised but a stream token is intercepted (e.g. from browser history or a log), an attacker has a 30-minute window to replay the stream. `delete_stream_token()` exists and is called on task cancellation — it should also be called when the final SSE event is delivered.

---

### 21. `X-Request-ID` header is echoed from client input without sanitization
**File:** `src/gateway/middleware.py` line 114

The `RequestIDMiddleware` reads `X-Request-ID` from the incoming request and echoes it back unchanged on every response. If the header value contains ANSI codes, control characters, or HTTP header injection sequences (newline + header), these are passed through to the response header. Most ASGI frameworks strip header-injection characters, but the value is also stored on `request.state.request_id` and may be interpolated into log messages.

**Recommended fix:** Sanitize the value to alphanumerics, hyphens, and underscores (max 64 chars) before using it.

---

### 22. `validate_fetch_url()` DNS resolution is synchronous (blocks event loop)
**File:** `src/security/core.py` line 943; `src/base_graph.py` line 466

`socket.getaddrinfo()` is synchronous and will block the asyncio event loop during DNS resolution. The gateway and agents are fully async. The `base_graph.py` wrapper at line 466 correctly uses `loop.run_in_executor(None, validate_fetch_url, url)` to avoid this. However, `http_tools.py` and `file_tools.py` call `validate_fetch_url()` directly (synchronously) from within async tool functions.

**Recommended fix:** All async callers should use the `validate_fetch_url_async()` wrapper from `base_graph.py`, or move the wrapper to `src/security/core.py` so it is importable from any tool.

---

### 23. Cyrillic and Unicode small-caps homoglyph attacks not covered by NFKC normalization
**File:** `src/security/core.py` lines 246–255

The comment at line 246 explicitly acknowledges: "Cyrillic homoglyphs (е, р, с) and Unicode small-caps are NOT collapsed by NFKC — a full homoglyph map would be needed for those vectors." This means an attacker could write `іgnore previous instructions` using Cyrillic `і` instead of Latin `i` to bypass the injection detection regex. This is a known limitation, not an oversight, but it should be tracked and addressed before the public release.

**Recommended fix:** Add a homoglyph normalization step (a curated mapping of confusable Unicode codepoints to their ASCII equivalents) before the NFKC normalization pass in `_normalize_for_detection()`.

---

### 24. `POSTGRES_TRUST_AUTH=true` opt-in allows empty password in any environment
**File:** `src/database.py` lines 301–307

The `POSTGRES_TRUST_AUTH=true` environment variable allows startup with an empty PostgreSQL password. While it logs a warning, there is no mechanism to prevent this from being set accidentally in a production-adjacent environment (e.g. if a dev `.env` file is copied).

**Recommended fix:** Also check `os.environ.get("LEGIONFORGE_ENV", "")` and refuse to proceed with trust auth if the value is `production` or `staging`.

---

### 25. `code_execute` sandbox comment documents accepted risks — verify Docker seccomp profile
**File:** `src/tools/code_tools.py` lines 14–15

The code execution sandbox uses `--network=none`, `--read-only`, `--pids-limit=20`, and `--security-opt=no-new-privileges`. The accepted residual risks note timing-based side channels. One additional control to verify: whether the Docker daemon is configured with a seccomp profile (the default Docker seccomp profile blocks ~44 syscalls; without it, the container has full syscall access). The compose file and Makefile should be verified to ensure the default seccomp profile is active (it is by default on Docker Desktop but may be disabled in some CI environments).

---

### 26. PII redaction pattern for API keys only matches known prefixes
**File:** `src/security/core.py` line 336

The API key PII pattern `r"\b(?:sk-|ls__|pk_|rk_|Bearer\s+)[A-Za-z0-9_\-]{16,}\b"` only catches keys with specific well-known prefixes (OpenAI `sk-`, LangSmith `ls__`, Stripe `pk_`/`rk_`). A Keychain password, a PostgreSQL password, or an API key for an uncommon provider would not be redacted. This is intentional but means PII redaction provides weaker guarantees for new providers.

---

## Already Well-Handled (do not regress these)

**These controls are solid. Future contributors must not remove or weaken them.**

- **Prompt injection detection** — 36 patterns across Tier 1 (halt) and Tier 2 (log), with NFKC normalization and zero-width character stripping. Applied at both gateway input (`sanitize_text`) and tool output (`sanitize_output`). Regression test enforces minimum pattern count.

- **SSRF prevention** — `validate_fetch_url()` blocks non-HTTP schemes, private RFC 1918 addresses, link-local (169.254/16), `.local` mDNS, all known cloud metadata endpoints, and performs DNS resolution to catch rebinding attacks. Applied in `http_tools.py`, `browser_tools.py`, and `researcher.py` before any outbound request.

- **Ed25519 tool signing** — tools are signed at registration and verified by Guardian. The signing key is stored with `-A` (any-app ACL) in macOS Keychain and injected as `TOOL_SIGNING_PRIVATE_KEY` at startup, never stored on disk.

- **Guardian fail-safe** — `check_guardian()` in `base_graph.py` (line 492) explicitly documents and enforces fail-closed behavior: any connection error or timeout returns `tier="halt"`. This is the correct default for a security sidecar.

- **Tool hash integrity** — `verify_tool_before_invocation()` checks description and schema hashes on every tool call (fast in-memory path). Entrypoint source hash is verified at startup via `make verify-tool-registry`.

- **Three-layer loop protection** — step counter + action history (MD5 window) + token budget, all independent and independently able to terminate a run. Each layer is wired into every graph via `check_safeguards()`.

- **bcrypt API key hashing** — gateway API keys are stored as bcrypt hashes (`_bcrypt.hashpw()`), never in plaintext. `verify_api_key()` uses constant-time `checkpw()`. Raw keys are returned only once at creation.

- **PostgreSQL role isolation** — 5-role model (worker, gateway, maintenance, guardian, readonly) with BYPASSRLS on worker only. RLS enforced on the gateway role for all user-scoped tables. Admin and restricted app roles use separate connection pools.

- **Audit log hash chain** — SHA-256 chain with genesis sentinel. `verify_audit_log_chain()` walks the full retained window and detects any modification to historical rows. Pruning writes a boundary anchor so verification can resume after pruning.

- **Markdown renderer XSS protection** — `renderMarkdown()` calls `escapeHtml()` as step 1 before any transform, so user content cannot inject HTML tags. Code blocks are placeholder-protected before other transforms run.

- **SVG chart sanitization** — `_sanitizeSvg()` uses DOMParser to parse then strips `script`, `foreignObject`, `animate`, `set` elements and all event-handler attributes before `innerHTML` assignment. `javascript:` hrefs on `href` and `xlink:href` are stripped.

- **SEC-2 credential conflict gate** — startup blocks when `POSTGRES_PASSWORD` env var conflicts with Keychain value, preventing stale Guardian docker-compose environments from silently using a wrong credential.

- **PII redaction before LangSmith** — `sanitize_for_trace()` recursively cleans all data before it enters a LangSmith trace. Applies to emails, phones, SSNs, credit cards, API key prefixes, DB DSNs, private IPs, and home directory paths.

- **File tool path allowlist** — `_resolve_and_check()` calls `os.path.realpath()` before comparing to allowed roots, blocking symlink traversal chains. Executable extensions are blocked on write. Allowed roots are operator-configured; empty list refuses all paths.

- **Task token privilege containment** — `derive_task_token()` enforces child ⊆ parent scope; any extra tools or data classes raise `PrivilegeEscalationError`. Child TTL is capped at parent's remaining lifetime.

- **HITL gate for destructive patterns** — 9 destructive pattern categories (CMD_INJECTION, PRIVILEGE_ESCALATION, DATA_STAGING, SELF_PROBE, BULK_DESTRUCTIVE, etc.) with HALT vs LOG tiering. HALT-tier patterns pause the run and require operator approval via `POST /hitl/{id}/approve`.

- **Webhook HMAC signing** — outbound webhooks and callbacks can be signed with `X-LegionForge-Signature-256` (HMAC-SHA256) using a Keychain secret. `hmac.compare_digest()` is used for constant-time verification in all connector inbound webhooks (WhatsApp, webhook connector).

- **SSE stream slot limiting** — `_acquire_stream_slot()` caps open SSE connections per user to prevent a single user from exhausting asyncio queue memory.

- **Submission rate limiting** — `SubmissionRateLimitMiddleware` applies per-user sliding-window limits to `POST /tasks` and memory endpoints. Returns `Retry-After` header.

- **Docker code sandbox** — `code_execute` uses `--network=none`, `--read-only`, `--memory-swap=0`, `--pids-limit=20`, `--security-opt=no-new-privileges`, and a per-run tmpfs. Container is removed (`--rm`) immediately after exit. Chart sentinels bypass the injection scanner by design and are extracted before the output cap.
