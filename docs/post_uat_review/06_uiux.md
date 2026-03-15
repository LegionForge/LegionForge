# UI/UX Review Findings

**Reviewed:** 2026-03-15
**Reviewer:** Automated analysis (read-only)
**File under review:** `src/gateway/static/index.html` (14,315 lines, single-file vanilla JS)

---

## Critical UX Issues (confusing or broken for end users)

**1. Undefined CSS variable `--input-bg` used in 130+ places**
Location: Line 880 (chat-followup textarea), lines 1394–4700+ (all inline-styled admin card inputs).
`--input-bg` is never defined in `:root` or any theme override block. Browsers fall back to `transparent`, making affected inputs invisible against panel backgrounds in certain themes (particularly light mode and high-contrast). The correctly named variable is `--panel2`.
Recommended fix: define `--input-bg: var(--panel2)` in `:root`, or do a project-wide replace of `var(--input-bg)` with `var(--panel2)`.

**2. API key expiry mid-session is silently ignored**
Location: `apiFetch()` (line 4875), `submitTask()` (line 5870).
When an API key expires or is rotated externally while a session is active, the next `POST /tasks` returns HTTP 401. The UI calls `finishRun('error', msg)` with the raw FastAPI `{"detail": "Invalid or expired API key"}` string — the user sees `[error] Invalid or expired API key` in the output pane with no UI affordance to re-enter their key (the API key input is buried at the top of the page). There is no 401-specific handler that scrolls to or highlights the API key field.
Recommended fix: in `submitTask()`, detect `res.status === 401` explicitly, highlight `#api-key` with a red border and focus it, and display a user-friendly banner.

**3. HITL (Human-in-the-Loop) approval has no UI panel**
Location: API routes at `/hitl/pending`, `/hitl/{id}/approve`, `/hitl/{id}/reject` (src/gateway/routes/hitl.py lines 37, 79, 174). Index.html has zero references to `hitl`.
When an agent pauses at the HITL gate, the pending approval is invisible to any admin using the web UI. The admin must use raw API calls (curl/Swagger). This is a functional gap for the only safety-critical interactive workflow in the system.
Recommended fix: add a "HITL Approvals" card in the operator dashboard that polls `/hitl/pending` and renders each request with Approve / Reject buttons.

**4. Task output area maximum height is 600px with no expand control**
Location: `#output` CSS (line 619): `max-height: 600px; overflow-y: auto`.
Long agent results (multi-section research reports, code with explanations) are clipped at 600px. Users must scroll inside the output box while the surrounding page is also scrollable — creating a "scroll inside scroll" problem. There is no "expand to full" or "view in new tab" control.
Recommended fix: add a "Expand" toggle button next to the Copy button in `#output-header` that removes the max-height constraint.

**5. Error messages in admin panels show raw HTTP status codes**
Location: Every admin card function (e.g., `loadUserActivity()`, `loadThreatEventDetail()`, line 6052+): pattern is `'Error ' + res.status + ' — ...'` or `'Error: ' + (e.detail || res.status)`.
Users see messages like `Error 403 — Forbidden` or `Error 422`. For a public-release product, these should be translated to actionable messages (e.g., "You do not have admin access to this panel").
Recommended fix: create a shared `formatApiError(res, json)` utility that maps 401 → "Not authenticated", 403 → "Admin access required", 422 → "Invalid input", 500 → "Server error — check gateway logs".

---

## High Priority (polish needed before public release)

**1. No onboarding or first-run experience for new users**
A brand-new user who visits `/ui` sees a blank `API key` field, an empty output pane with `Ready.`, and an accordion-collapsed history section. There is no indication of what an API key is, how to obtain one, or which agent to select for which use case. The agent descriptions are only visible in the `<select>` dropdown options and nowhere else at-a-glance.
Recommended fix: show a first-run banner (once, dismissed via localStorage) linking to setup docs and explaining the three agent types.

**2. Operator Dashboard panel count makes the page unusable for new admins**
The operator dashboard (`#op-dashboard`) lazy-injects ~381 cards. These are all collapsed `<details>` elements with no grouping, search, or filter. An admin looking for "User Activity" must scroll through hundreds of identically-styled summary rows. The keyboard shortcuts modal (`?`) does not mention any dashboard navigation.
Recommended fix: add a text filter input at the top of the operator dashboard that hides non-matching `<details>` elements by `card-title` text (client-side, instant).

**3. Theme cycle button gives no visual preview of the next theme**
Location: `toggleTheme()` (line 4913), `#theme-toggle` button (line 1139).
Clicking the `🌙` button cycles through 6 themes (Dark → Light → Solarized → Warm → Nord → Contrast) with no preview. The button icon updates to reflect the current theme after transition, but users cannot predict what they will get. The `aria-label` is updated dynamically (line 4933) but the title tooltip still says "Cycle theme (Dark → Light → Solarized...)" which lists all themes in sequence — fine, but the current theme name is not visible until after the click.
Recommended fix: add a small theme name label next to the toggle button showing the active theme (e.g., "Dark"), or add a `title` that reads "Current: Dark. Click for Light."

**4. Bulk Cancel has no confirmation dialog**
Location: `bulkCancel()` (line 13178).
`bulkDelete()` correctly calls `confirm(...)` before proceeding. `bulkCancel()` does not. Cancelling a running task terminates it and its result is lost. This is a destructive action.
Recommended fix: add `if (!confirm('Cancel ' + ids.length + ' task(s)?')) return;` at the start of `bulkCancel()`.

**5. API key rotation button appears in two places with inconsistent behavior**
Location: Line 1466 (`rotateApiKey()` in the config card — minimal) and line 3371 (`loadApiKeyRotation()` in the operator dashboard — a separate card with more detail).
The config-card button calls `rotateApiKey()` which shows the new key inline. The dashboard button calls `loadApiKeyRotation()` which is a different, more detailed flow. Users who find the config-card button first may not realize there is a richer dashboard version. The config-card version also auto-updates the API key input with the new value, but the dashboard version does not.
Recommended fix: consolidate to one interaction; remove the config-card rotate button or make it redirect to the dashboard card.

**6. `schedules` PUT (enable/disable toggle) is buried in the admin dashboard**
The primary schedule list (line 6454, `loadSchedules()`) in the config card area shows schedules with a delete button only. The enable/disable toggle is only available in the "Schedule Detail" admin card, which requires the user to know and type the schedule ID. The common action (pause/resume a schedule) takes 4 extra steps.
Recommended fix: add an enable/disable toggle button directly in the schedule list rows alongside the existing delete button.

**7. Session sidebar has no rename affordance**
Location: `#session-sidebar`, `loadSessions()` (line 5372), `newSession()` / `newConversation()`.
Sessions are created with auto-generated names. There is no way to rename a session from the sidebar. The only rename capability is in the "Session Detail" admin card (which requires knowing the session ID). Users building long-running projects will accumulate unnamed sessions.
Recommended fix: add an inline double-click-to-edit or a rename button (`✏`) on each sidebar session item.

**8. No feedback when admin panel data loads succeed with zero results vs. has never been loaded**
Many admin panels (e.g., Pipeline Success Rate, Document Ingest Rate, User Activity) show `Loading…` text initially and are blank after load if there is no data. The blank state is indistinguishable from "still loading" unless the user manually checks timing. Several panels show a generic `(No data)` or nothing at all.
Recommended fix: standardize empty states — after every successful fetch that returns zero results, show a styled empty-state message (e.g., "No pipeline runs yet.") with a non-italic, distinct visual treatment.

---

## Medium (quality improvements)

**1. Font size 9px and 10px used extensively in admin cards**
Locations: Lines 49, 54, 67, 75, 89, 102, 103, 109, 113, 121, 126, 681, 698 (CSS classes), and inline `font-size:10px`/`font-size:11px` across hundreds of admin card elements.
At the default 13px body size, 10px is ~77% and 9px is ~69% of base. WCAG 2.1 SC 1.4.4 (Resize Text, AA) requires text to be resizable to 200% without loss of content. At 9–10px, text becomes genuinely unreadable for users with moderate visual impairment even before considering scaling.
Recommended fix: minimum 11px for all visible text; use `font-size: 0.85em` (relative) rather than fixed pixel values in admin cards to respect user browser preferences.

**2. Markdown renderer has a custom implementation instead of using an established library**
Location: `renderMarkdown()` (line 5673) — ~120 lines of hand-rolled regex-based markdown.
The implementation correctly HTML-escapes before applying transforms (XSS-safe). However, it does not handle: nested lists, blockquotes, table rendering, link detection (URLs remain plain text), or inline HTML pass-through. Agent results that include markdown tables or links render as raw text.
Noted: The security model (escape-first) is correct and should be preserved if a library is introduced (configure marked.js to use the escape renderer, not raw HTML).

**3. Help modal (`?`) is missing keyboard shortcuts for admin functionality**
Location: `#help-modal-box` (line 1117). The modal lists only 5 shortcuts (Submit, Escape, Copy, Clear, theme/notifications). There is no mention of: Chat mode toggle (`💬`), session creation (`+`), or any admin panel shortcuts. The keyboard shortcuts modal at line 4841 also only handles Escape and Cmd+Enter.
Recommended fix: add Chat mode toggle (`Ctrl+Shift+Space` or similar) and document it in the help modal.

**4. The chat mode toggle is a page-level mode switch with no visual confirmation of state**
Location: `toggleChatMode()` (line 14285), `#chat-mode-btn` (line 1140).
When chat mode is active, the button label still reads "💬 Chat" with no active/pressed visual state. The body class `chat-mode` hides all admin panels, which is a dramatic layout shift. Users who accidentally activate chat mode may not understand how to exit it.
Recommended fix: toggle button text/style to show active state (e.g., border-color change or "Exit Chat" label when active); add `aria-pressed` attribute.

**5. Connection dot (`#conn-dot`) uses only color to convey state**
Location: Lines 462–469 (CSS), line 1142 (HTML). States: grey (idle), green (`live`), orange (LLM unavailable), red (`error`), pulse animation (transitioning).
Color alone to convey status fails WCAG 2.1 SC 1.4.1 (Use of Color, A). Screen readers have `role="status"` but the inner text is never set — the dot is always empty, so screen reader announcements are empty strings.
Recommended fix: set `textContent` on the dot for each state change (e.g., "●" with a `visually-hidden` accessible name), or update `aria-label` dynamically.

**6. Plotly is loaded from an external CDN without subresource integrity (SRI)**
Location: `_loadPlotlyJs()` (line 14009): `s.src = 'https://cdn.plot.ly/plotly-basic-2.35.2.min.js'`.
No `integrity` attribute is set. If cdn.plot.ly is compromised or the URL is intercepted (in contexts without HTTPS), arbitrary JS could be injected. The same applies transitively — any chart render triggers the CDN load.
Recommended fix: add `s.integrity = 'sha384-...'` (compute hash from the pinned version) and `s.crossOrigin = 'anonymous'`. Alternatively, bundle Plotly and serve it from `/static/`.

**7. Draft auto-save only saves task input text, not the selected agent type or session**
Location: `saveDraft()` (line 6982), `restoreDraft()` (line 6988).
When a user is mid-composition and reloads the page, the task text is restored from `_DRAFT_KEY` in localStorage, but the agent type selection and session context are not. The user may unknowingly submit a complex prompt to the wrong agent.
Recommended fix: save `agent_type` and `session_id` as part of the draft object.

**8. Share link generation has no expiry UI**
Location: `shareTask()` (line 6587). The share token is generated with a server-side default expiry (likely database-defined), but the UI shows the generated URL with no indication of when it expires.
Recommended fix: display the expiry date from the API response (if provided) next to the share URL.

**9. Output copy button (`⎘`) tooltip says "Copy output to clipboard" but copies only plain text, not formatted markdown**
Location: `copyOutput()` (referenced at line 1229). The `S.outputBuffer` accumulates plain text fragments during SSE streaming.
Recommended fix: add a second copy mode (or toggle) that copies the rendered markdown source (the raw `result` field from the task), which is more useful for pasting into documents.

---

## Low / Nice-to-Have

**1. `<details>`-based accordion disclosure is not scrolled into view when opened**
When a user opens a collapsed `<details>` card deep in the admin dashboard, the browser scrolls to the element but the summary row ends up at the very top of the viewport, cutting off the opened content below the fold. Using `scrollIntoView({ block: 'nearest' })` on toggle would keep opened content visible.

**2. Image attachment preview shows filename with a fixed 64px height — no way to see the full image before submit**
Location: `#img-preview img` (line 570): `max-height:64px`. Users cannot enlarge the preview to verify the right image was attached.
Recommended fix: clicking the thumbnail opens a lightbox or uses `window.open(URL.createObjectURL(...))`.

**3. History section is limited to 20 items (client-side `MAX_HISTORY = 20`) with no pagination**
Location: line 4749. Tasks beyond 20 are silently dropped from the in-memory list. The history section label says "History (N)" but N is capped at 20 even if the server has 200 tasks. The search panel (`doSearch()`) can find older tasks from the server, but users who don't know this will assume history is lost.
Recommended fix: show a "Load more from server…" button when local history is at the cap.

**4. Cron expression input for schedule creation has no validation or helper text**
Location: schedule create form (line 1290+). Users must know cron syntax (`*/5 * * * *`) with no inline documentation, example, or validation before submit. An invalid cron expression results in a server-side 422 error shown as raw text.
Recommended fix: add a `title` attribute with a cron syntax example, or validate the pattern client-side with a regex before submit.

**5. The `?` help modal does not list the `Ctrl+Shift+C` and `Ctrl+Shift+T` shortcuts in a discoverable way**
These shortcuts are listed in the help modal, but they only fire in non-chat mode. In chat mode they silently no-op because the output structure is different. The modal does not indicate mode-specific shortcuts.

**6. Character count shows `11 chars` with no maximum indicator**
Location: `#char-count` (line 580), updated by `onTaskKeydown`. There is a server-side limit on task input length, but no client-side maximum is enforced or displayed. A user who writes a 50,000-character prompt gets no warning before submission.

**7. The operator dashboard body is injected via a `<template>` tag on first open**
Location: `#op-dashboard-tmpl` (implied by lines 4856–4861). This means all 381 cards are in the DOM as a hidden `<template>` on every page load (adding parsing overhead), and then cloned once into the live DOM. The initial parse cost is unavoidable with this architecture but could be reduced by splitting the template into fetch-on-demand HTML fragments.

**8. No favicon color adaptation for light mode**
Location: line 7 (`<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">`). The SVG favicon presumably uses dark-mode colors; no `<link media="(prefers-color-scheme: light)">` alternate is provided.

---

## Accessibility Gaps

**1. Help modal lacks `role="dialog"`, `aria-modal="true"`, and a focus trap (WCAG 2.1 SC 4.1.2)**
Location: `#help-modal` (line 1116), `#help-modal-box`.
The modal is visually displayed over the page, but there is no `role="dialog"` or `aria-modal="true"` to inform screen readers. Tab focus is not trapped inside the modal — keyboard users can tab through the entire page behind it. When the modal closes, focus is not returned to the `?` button that opened it (`#help-btn`).
Recommended fix: add `role="dialog" aria-modal="true" aria-labelledby="help-modal-title"` to `#help-modal-box`; implement focus trap with a `keydown` listener; return focus to `#help-btn` on close.

**2. Many action buttons in admin cards lack `aria-label` or meaningful text content (WCAG 2.1 SC 4.1.2)**
Location: Examples at lines 1435, 1455, 1488, 1518, 1538, 1558 — all icon-only refresh buttons (`↻`). Lines 1501–1505 (bulk Cancel / Delete / Tag) have text but some inline-generated delete buttons (e.g., schedule delete `sched-del`, line 6469) use `✕` with only a `title` attribute. `title` is not reliably announced by screen readers.
Recommended fix: add `aria-label="Delete schedule"` (etc.) to all icon-only buttons; do not rely on `title` alone for accessibility.

**3. Color is the sole differentiator for tool block states (WCAG 2.1 SC 1.4.1)**
Location: `.tool-block` (line 669), `.tool-block.done` (opacity), `.tool-block.blocked` (red). The running vs. done vs. blocked states rely entirely on color and opacity changes. Screen readers read the tool name but not its current state (running / done / blocked).
Recommended fix: update `aria-label` on tool blocks dynamically as state changes (e.g., `aria-label="tool http_get — running"` → `"tool http_get — done"`).

**4. Status indicator `#status-indicator` uses text color only to convey running/complete/error state (WCAG 2.1 SC 1.4.1)**
Location: lines 599–602. The `.running`, `.complete`, `.error`, `.cancelled` classes change text color. `role="status"` is not set on this element (it is set on `#conn-dot` instead).
Recommended fix: add `role="status"` or `aria-live="polite"` to `#status-indicator` so screen readers announce task state changes.

**5. Very small text in admin panels is likely below minimum WCAG target size (WCAG 2.1 SC 1.4.4)**
As noted in the Medium section, 364 occurrences of `font-size: 10px` and below. At browser default (16px), 10px is 62.5% — not resizable to 200% without triggering overflow in fixed-grid admin rows.

**6. Syntax-highlighted code colors in default dark theme are hardcoded, not theme-variable-aware (partial)**
Location: lines 662–665 (`.syn-kw`, `.syn-str`, etc.) have hardcoded hex values (`#c792ea`, `#c3e88d`, `#546e7a`) that are **not** overridden in all theme blocks. Only `light`, `solarized`, `warm`, `nord`, and `contrast` override these values. In the `warm` and `nord` themes the default hardcoded dark-mode colors are overridden (lines 339–343, 362–366), but the override completeness should be verified. The hardcoded dark-mode colors will appear in the default dark theme and may have insufficient contrast in some non-standard OS color schemes.

**7. `<select>` elements in chat mode lose their visible labels entirely**
Location: lines 933–936: `body.chat-mode #config .field-row label { display: none }`. The agent type and model preference selects have their `<label>` elements hidden in chat mode with no `aria-label` fallback on the `<select>` elements themselves.
Recommended fix: add `aria-label="Agent type"` and `aria-label="Model preference"` directly on the `<select>` elements.

**8. Rating buttons (thumbs up/down) are dynamically injected with no accessible text (WCAG 2.1 SC 1.1.1)**
Location: `finishRun()` (line 6298): buttons `👍` and `👎` with `title="Thumbs up"` / `title="Thumbs down"`. As with other icon-only buttons, `title` is not read reliably by all screen readers.
Recommended fix: wrap emoji in `<span aria-hidden="true">` and add visible (or `visually-hidden`) text, or use `aria-label="Rate task positively"`.

---

## Mobile / Responsive Issues

**1. Only one media query exists for the entire 14,315-line UI**
Location: lines 1092–1095:
```css
@media (max-width: 600px) {
  .field-row label { width: 56px; }
  .history-item { grid-template-columns: 12px 1fr 50px; }
  .history-item .hi-id, .history-item .hi-agent { display: none; }
}
```
This single query adjusts two elements. The session sidebar (`#session-sidebar`, 220px), the operator dashboard cards with multi-column grids, the `#page-layout` flexrow, and the fixed-width operator card grids (e.g., `.health-grid: repeat(3,1fr)`, `.stats-grid: repeat(3,1fr)`) all break on viewports narrower than ~700px. The main task submission flow is partially usable on tablet, but the sidebar pushes `#main` below ~460px usable width.

**2. Session sidebar is permanently visible on desktop and entirely hidden in chat mode — no collapsed/drawer state for mobile**
On a 375px-wide phone, the 220px sidebar leaves only ~155px for the main content. There is no hamburger menu or swipe-to-open pattern. Chat mode (`body.chat-mode`) hides the sidebar but requires navigating to it first.

**3. The action bar buttons (`Submit`, `Cancel`, `Clear`) and char-count use `white-space: nowrap` and can overflow on narrow screens**
Location: `#action-bar` (line 575): `display: flex; gap: 8px`. No `flex-wrap: wrap`. On small screens the row overflows horizontally.

**4. Admin card grids use fixed pixel widths inline on hundreds of elements**
The operator dashboard cards use `style="width:80px"`, `style="width:160px"` etc. inline on inputs. These do not adapt to narrow viewports and will cause horizontal scroll inside collapsed `<details>` on mobile.

**5. The output box (`#output`) has a fixed `min-height: 200px` in dashboard mode**
On a phone held portrait, this consumes most of the visible viewport before the user has typed anything, requiring scrolling past the output placeholder just to reach the task input.

---

## API Features Not Exposed in UI

The following API endpoints exist in the gateway but have no corresponding UI panel in `index.html`:

| Endpoint | Route file | Notes |
|---|---|---|
| `GET /hitl/pending` | hitl.py | No HITL approval panel exists anywhere |
| `POST /hitl/{id}/approve` | hitl.py | Approve action not in UI |
| `POST /hitl/{id}/reject` | hitl.py | Reject action not in UI |
| `GET /admin/audit/verify` | observability.py:100 | Audit chain integrity — a separate "Audit Hash Verify" card exists (`#audit-hash-verify-card`, line 3043) but the primary "Audit Chain Integrity" card (`#audit-verify-card`, line 1442) calls the same endpoint; there appear to be two cards for the same thing |
| `GET /admin/threats/summary` | observability.py:189 | Threat summary endpoint — a "Threat Rule Summary" card exists but its function name suggests it reads threat rules, not the `/admin/threats/summary` endpoint specifically; needs verification |
| `PUT /pipelines/{id}` | pipelines.py:259 | Update pipeline — no pipeline edit form in UI (delete exists) |
| `GET /tasks/{id}/stream` direct URL | stream.py | Stream URL not surfaced for direct access/sharing |
| `GET /.well-known/agent.json` | a2a.py | Agent card is shown in the A2A/MCP Discovery card, but the raw JSON is not linked |
| `GET /metrics` | app.py:357 | Prometheus endpoint not mentioned in the admin UI |
| `PUT /schedules/{id}` | schedules.py:10 | Schedule enable/disable toggle not surfaced inline in the schedule list (only via "Schedule Detail" admin card) |

---

## Already Well-Done

- **XSS protection in markdown renderer**: `renderMarkdown()` (line 5673) escapes HTML before applying transforms — the correct order that prevents injection even if the LLM returns malicious output.
- **SVG sanitization**: `_sanitizeSvg()` (line 14026) removes script/foreignObject/animate tags and dangerous event-handler attributes before inline rendering. This is thoughtful defense-in-depth.
- **Friendly error translation**: `friendlyError()` (line 6151) maps technical error strings (connection refused, model not found, daily budget exceeded) to human-readable messages. The `_ERROR_HINTS` table is well-curated for the likely failure modes.
- **Confirmation dialogs on destructive actions**: `deleteTemplate()`, `deleteCurrentSession()`, `deleteSchedule()`, `deleteWebhook()`, `deleteTask()`, `bulkDelete()`, `rotateApiKey()`, `clearAllMemory()`, `deleteOldTasks()` all call `confirm()` or `window.confirm()` before proceeding. Coverage is good (the only missing case found was `bulkCancel()`).
- **Draft auto-save**: Task input is saved to localStorage as the user types (`_DRAFT_KEY`) and restored on reload — prevents accidental loss of long prompts.
- **Connection resilience**: SSE stream reconnects once on disconnect, then falls back to polling every 5s. The transition is communicated to the user with an inline `[switching to polling…]` message.
- **Token budget progress bar**: Visual bar with green/yellow/red states (`.token-bar-fill`, line 158) gives real-time feedback on budget consumption during tasks.
- **Keyboard shortcuts implementation**: `⌘+Enter` to submit, `Escape` to cancel, `⌘+Shift+C` to copy, `⌘+Shift+T` to clear — these work correctly and are documented in the help modal.
- **Theme persistence and system preference detection**: `initTheme()` (line 4938) respects `prefers-color-scheme` as the initial default and persists user choice to `localStorage['lf-theme']`. High-contrast theme is available for accessibility.
- **High-contrast theme**: The `contrast` theme (lines 368–389) provides pure black/white backgrounds with bright accent colors — a genuine effort at visual accessibility not commonly seen in developer tools.
- **Operator dashboard lazy-loading**: The 381-panel dashboard is loaded on first open via `<template>` cloneNode, not on page load. This prevents all those panels from blocking initial render.
- **Live token streaming with cursor**: The `o-stream::after` CSS cursor (`▋` with blink animation, line 654) gives real-time visual feedback during token generation, which is a polished UX detail.
- **Session sidebar turn count badge**: The `.turn-badge` (line 237) shows conversation depth at a glance — useful for multi-turn debugging.
- **`aria-hidden="true"` on decorative emoji**: Header buttons consistently use `<span aria-hidden="true">emoji</span>` so screen readers skip decorative icons (lines 1138–1141).
- **Plotly loaded lazily from CDN**: `_loadPlotlyJs()` (line 14009) only loads the 3MB+ Plotly library when a chart is actually rendered, avoiding cold-load overhead for the 99% of sessions that don't produce charts.
