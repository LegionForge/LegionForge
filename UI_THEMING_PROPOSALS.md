# UI Theming Proposals — LegionForge

Generated: 2026-03-13
Source: `src/gateway/static/index.html` — `:root` and `body.light-mode` blocks

---

## 1. Current Theme Inventory

### Dark Theme (`:root` — default)

| Variable | Value | Controls |
|---|---|---|
| `--bg` | `#0d1117` | Page background (outermost layer) |
| `--panel` | `#161b22` | Card/panel backgrounds (one level up) |
| `--panel2` | `#1c2128` | Nested panel backgrounds (code blocks, sub-rows) |
| `--border` | `#30363d` | Primary border color (card outlines, inputs) |
| `--border2` | `#21262d` | Secondary border (inner dividers, row separators) |
| `--text` | `#c9d1d9` | Primary body text |
| `--text-dim` | `#8b949e` | Secondary/muted text (labels, hints) |
| `--text-xdim` | `#484f58` | Tertiary/placeholder text (timestamps, dimmed labels) |
| `--blue` | `#58a6ff` | Links, interactive elements, `chain_start` events |
| `--green` | `#3fb950` | Success states, APPROVED badges, positive indicators |
| `--orange` | `#f0883e` | Warning states, threat-type labels, admin badges |
| `--red` | `#f85149` | Error states, REVOKED badges, destructive actions |
| `--purple` | `#d2a8ff` | Syntax highlighting (strings), secondary accent |
| `--yellow` | `#e3b341` | PENDING badges, warning accents |
| `--radius` | `6px` | Global border-radius for all cards and inputs |
| `--mono` | SFMono-Regular, Consolas, Liberation Mono, Menlo... | Monospace font stack (code, tool names, event types) |

### Light Theme (`body.light-mode`)

Overrides all color variables with GitHub-inspired light palette. The `--radius` and `--mono`
variables inherit from `:root` (no override needed). Additional syntax highlighting rules
added for `.syn-kw`, `.syn-str`, `.syn-cmt`, `.syn-num`, `.syn-bi` under `.light-mode`.

---

## 2. Theme Expansion Proposals

Four additional named themes beyond dark/light. Each lists values for every CSS variable.

### Theme: Solarized Dark

Inspired by Ethan Schoonover's Solarized palette — distinctive blue-grey base with warm accent tones.

| Variable | Value |
|---|---|
| `--bg` | `#002b36` |
| `--panel` | `#073642` |
| `--panel2` | `#0a4050` |
| `--border` | `#586e75` |
| `--border2` | `#3d5a62` |
| `--text` | `#839496` |
| `--text-dim` | `#657b83` |
| `--text-xdim` | `#4a6068` |
| `--blue` | `#268bd2` |
| `--green` | `#859900` |
| `--orange` | `#cb4b16` |
| `--red` | `#dc322f` |
| `--purple` | `#6c71c4` |
| `--yellow` | `#b58900` |
| `--radius` | `6px` |

Syntax highlight overrides: `--syn-kw: #268bd2`, `--syn-str: #2aa198`, `--syn-cmt: #586e75`,
`--syn-num: #d33682`, `--syn-bi: #859900`.

---

### Theme: High Contrast (Accessibility)

WCAG AA/AAA compliant — pure blacks/whites with high-chroma accents. Minimum 7:1 contrast ratio.

| Variable | Value |
|---|---|
| `--bg` | `#000000` |
| `--panel` | `#0a0a0a` |
| `--panel2` | `#111111` |
| `--border` | `#ffffff` |
| `--border2` | `#cccccc` |
| `--text` | `#ffffff` |
| `--text-dim` | `#e0e0e0` |
| `--text-xdim` | `#b0b0b0` |
| `--blue` | `#4fc3f7` |
| `--green` | `#69f0ae` |
| `--orange` | `#ffcc02` |
| `--red` | `#ff5252` |
| `--purple` | `#ea80fc` |
| `--yellow` | `#ffff00` |
| `--radius` | `4px` |

Rationale: Thicker borders (`--border: #ffffff`) and higher text contrast improve usability for
low-vision users. The reduced radius also aids users who rely on sharp corners as visual anchors.

---

### Theme: Warm (Amber/Sepia)

Terminal-inspired warm amber palette — comfortable for extended night use.

| Variable | Value |
|---|---|
| `--bg` | `#1a1008` |
| `--panel` | `#241808` |
| `--panel2` | `#2e2010` |
| `--border` | `#5a3e18` |
| `--border2` | `#3e2a0e` |
| `--text` | `#e8c88a` |
| `--text-dim` | `#b89060` |
| `--text-xdim` | `#7a5c30` |
| `--blue` | `#f0b040` |
| `--green` | `#a8c030` |
| `--orange` | `#e87820` |
| `--red` | `#d04020` |
| `--purple` | `#c080e0` |
| `--yellow` | `#f0c820` |
| `--radius` | `6px` |

Syntax highlights: `--syn-kw: #f0b040` (amber), `--syn-str: #a8c030` (green), `--syn-cmt: #7a5c30`
(muted brown), `--syn-num: #e87820` (orange), `--syn-bi: #c080e0` (purple).

---

### Theme: Nord

Based on Arctic Studio's Nord palette — cool, muted blue-grey tones with soft accents.

| Variable | Value |
|---|---|
| `--bg` | `#2e3440` |
| `--panel` | `#3b4252` |
| `--panel2` | `#434c5e` |
| `--border` | `#4c566a` |
| `--border2` | `#3b4252` |
| `--text` | `#eceff4` |
| `--text-dim` | `#d8dee9` |
| `--text-xdim` | `#677591` |
| `--blue` | `#81a1c1` |
| `--green` | `#a3be8c` |
| `--orange` | `#d08770` |
| `--red` | `#bf616a` |
| `--purple` | `#b48ead` |
| `--yellow` | `#ebcb8b` |
| `--radius` | `6px` |

Syntax highlights: `--syn-kw: #81a1c1` (blue), `--syn-str: #a3be8c` (green),
`--syn-cmt: #677591` (grey), `--syn-num: #b48ead` (purple), `--syn-bi: #88c0d0` (bright blue).

---

## 3. Theme Switcher Enhancement

### Current Implementation

The current `toggleTheme()` (Phase 72) is a binary toggle between dark (`<body>` default) and
`body.light-mode`. State is stored in `localStorage` key `lf-theme` as `"dark"` or `"light"`.

### Proposed Multi-Theme Cycling

**Storage:** Change `localStorage` key `lf-theme` from a binary string to a theme name:
`"dark"` | `"light"` | `"solarized"` | `"highcontrast"` | `"warm"` | `"nord"`.

**CSS:** Replace single `body.light-mode` block with named `data-theme` attributes:
```css
[data-theme="light"] { --bg: #f6f8fa; ... }
[data-theme="solarized"] { --bg: #002b36; ... }
[data-theme="highcontrast"] { --bg: #000000; ... }
[data-theme="warm"] { --bg: #1a1008; ... }
[data-theme="nord"] { --bg: #2e3440; ... }
/* :root remains the default dark theme */
```

**JS theme cycle function:**
```javascript
const THEMES = ['dark', 'light', 'solarized', 'highcontrast', 'warm', 'nord'];
const THEME_ICONS = {
  dark: '🌙', light: '☀️', solarized: '🌅', highcontrast: '◑', warm: '🕯️', nord: '❄️'
};
const THEME_NAMES = {
  dark: 'Dark', light: 'Light', solarized: 'Solarized Dark',
  highcontrast: 'High Contrast', warm: 'Warm', nord: 'Nord'
};

function toggleTheme() {
  const current = document.body.dataset.theme || 'dark';
  const next = THEMES[(THEMES.indexOf(current) + 1) % THEMES.length];
  document.body.dataset.theme = next;
  if (next === 'dark') {
    document.body.removeAttribute('data-theme'); // restore :root default
  }
  localStorage.setItem('lf-theme', next);
  const btn = document.getElementById('theme-toggle');
  btn.textContent = THEME_ICONS[next];
  btn.title = `Theme: ${THEME_NAMES[next]} (click to cycle)`;
}

function initTheme() {
  const saved = localStorage.getItem('lf-theme');
  const preferLight = !saved && window.matchMedia &&
    window.matchMedia('(prefers-color-scheme: light)').matches;
  const theme = saved || (preferLight ? 'light' : 'dark');
  if (theme !== 'dark') document.body.dataset.theme = theme;
  const btn = document.getElementById('theme-toggle');
  btn.textContent = THEME_ICONS[theme] || '🌙';
  btn.title = `Theme: ${THEME_NAMES[theme] || 'Dark'} (click to cycle)`;
}
```

**Compatibility:** The `body.light-mode` class can remain as an alias for `[data-theme="light"]`
to avoid breaking any external CSS that targets it directly.

---

## 4. UI Component Improvement Suggestions

Based on reading the current `index.html` HTML and CSS:

### 1. Mobile/Tablet Responsiveness

The layout uses fixed pixel widths and `grid-template-columns` without responsive breakpoints.
On screens narrower than ~900px the three-column grids (`.stats-grid`, `.health-grid`) collapse
awkwardly. Add `@media (max-width: 640px)` breakpoints that switch these to single-column:
```css
@media (max-width: 640px) {
  .stats-grid, .health-grid { grid-template-columns: 1fr; }
  .user-row { grid-template-columns: 1fr 60px; } /* drop smaller cols */
}
```

### 2. Keyboard Navigation for Cards

The `<details>` cards in the Operator Dashboard (`#op-dashboard`) are navigable by keyboard
since `<summary>` elements are naturally focusable. However, the main task submit button and
API key input have no visible focus ring (only `outline: none` in the reset). Add focus-visible
outlines:
```css
:focus-visible { outline: 2px solid var(--blue); outline-offset: 2px; }
```
This is a WCAG 2.4.7 (Focus Visible) compliance fix.

### 3. Streaming Indicator Accessibility

The `#conn-dot` connection status indicator is a colored circle with no ARIA live region or
text fallback. It currently has `role="status"` but no `aria-label` that updates dynamically.
Update JS to set `conn-dot.setAttribute('aria-label', status_text)` whenever the dot color
changes so screen reader users know connection state.

### 4. Input Character Counter

The task input `<textarea id="task-input">` has no visible character limit feedback.
Adding a lightweight counter (e.g. `X / 8000 chars`) next to the submit button would help
users who write long prompts and hit the truncation limit silently.

### 5. Copy-to-Clipboard Feedback

The `.result-copy-btn` copy button currently appears on hover. After clicking, it changes
to "Copied!" via JS but there is no ARIA live announcement for screen readers. Add
`aria-live="polite"` to a hidden span that announces "Copied to clipboard" on activation.

### 6. Task Card Status Badges

Task status strings (`RUNNING`, `COMPLETE`, `ERROR`) are displayed as plain `<span>` text with
color only (no shape differentiation). Color-blind users may not distinguish `RUNNING` (green)
from `ERROR` (red). Add a shape/icon prefix: `▶ RUNNING`, `✓ COMPLETE`, `✗ ERROR`.

### 7. Operator Dashboard Lazy-Load Indicator

The operator dashboard cards (`#op-dashboard`) initialize lazily on first open. There is no
loading spinner shown during the first load — the panels flash in with data. Add a brief
skeleton/shimmer state or a spinner for cards that make API calls on open.

### 8. Dark Mode Transition

Setting `body { transition: none }` currently means theme switches are instant, which can
cause visual jarring on large pages. Add a short CSS transition:
```css
body { transition: background-color 0.2s ease, color 0.2s ease; }
```
Note: avoid transitioning `--border` and box-shadow properties as they fire on every
hover/focus event and create jank.

### 9. SSE Stream Error Toast

When the SSE stream disconnects mid-task, the current code sets the `#conn-dot` to red and
logs to console. A brief non-blocking toast notification visible in the UI would make this
failure mode obvious to users who aren't watching the dot.

### 10. API Key Input Autofill Suppression

The `<input id="api-key">` accepts the API key but browsers may autofill it with saved
credentials incorrectly. Add `autocomplete="one-time-code"` (or `autocomplete="off"`) to
prevent unintended credential fills, and ensure the paste-from-clipboard path clears the
field first to avoid duplication.
