---
layout: default
title: LegionForge — Security-Native AI Agent Framework
description: A local-first, open-source framework for building hardened AI agent systems. Security enforced in the execution path — not layered on afterward.
permalink: /
---

<style>
  :root {
    --accent:   #00ff88;
    --accent2:  #00ccff;
    --danger:   #ff4444;
    --bg:       #0d1117;
    --surface:  #161b22;
    --border:   #30363d;
    --text:     #c9d1d9;
    --dim:      #8b949e;
    --mono:     'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
  }

  * { box-sizing: border-box; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    margin: 0;
    padding: 0;
    line-height: 1.6;
  }

  /* ── Header ── */
  .hero {
    border-bottom: 1px solid var(--border);
    padding: 5rem 2rem 4rem;
    text-align: center;
    background: radial-gradient(ellipse at 50% 0%, rgba(0,255,136,0.07) 0%, transparent 70%);
    position: relative;
    overflow: hidden;
  }

  .hero::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background-image:
      linear-gradient(rgba(0,255,136,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,255,136,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
  }

  .badge {
    display: inline-block;
    border: 1px solid var(--accent);
    color: var(--accent);
    font-family: var(--mono);
    font-size: 0.7rem;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    padding: 0.25rem 0.75rem;
    border-radius: 2px;
    margin-bottom: 1.5rem;
    background: rgba(0,255,136,0.05);
  }

  .hero h1 {
    font-size: clamp(2rem, 6vw, 3.5rem);
    font-weight: 700;
    margin: 0 0 1rem;
    letter-spacing: -0.02em;
    color: #fff;
  }

  .hero h1 span {
    color: var(--accent);
  }

  .tagline {
    font-size: clamp(1rem, 2.5vw, 1.25rem);
    color: var(--dim);
    max-width: 620px;
    margin: 0 auto 0.75rem;
  }

  .subtagline {
    font-family: var(--mono);
    font-size: 0.85rem;
    color: var(--accent2);
    margin-bottom: 2.5rem;
  }

  .cta-group {
    display: flex;
    gap: 1rem;
    justify-content: center;
    flex-wrap: wrap;
  }

  .btn {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.65rem 1.5rem;
    border-radius: 4px;
    font-weight: 600;
    font-size: 0.9rem;
    text-decoration: none;
    transition: opacity 0.15s, transform 0.15s;
  }

  .btn:hover { opacity: 0.85; transform: translateY(-1px); }

  .btn-primary {
    background: var(--accent);
    color: #0d1117;
  }

  .btn-secondary {
    background: transparent;
    color: var(--text);
    border: 1px solid var(--border);
  }

  /* ── Sections ── */
  .container {
    max-width: 1100px;
    margin: 0 auto;
    padding: 0 2rem;
  }

  section {
    padding: 4rem 0;
    border-bottom: 1px solid var(--border);
  }

  section:last-child { border-bottom: none; }

  h2 {
    font-size: 1.5rem;
    font-weight: 700;
    color: #fff;
    margin: 0 0 2rem;
    display: flex;
    align-items: center;
    gap: 0.6rem;
  }

  h2 .icon { color: var(--accent); font-size: 1.2rem; }

  /* ── Pipeline diagram ── */
  .pipeline {
    font-family: var(--mono);
    font-size: 0.85rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1.5rem 2rem;
    overflow-x: auto;
    line-height: 2;
    white-space: nowrap;
  }

  .pipeline .step   { color: var(--accent2); }
  .pipeline .arrow  { color: var(--dim); }
  .pipeline .signed { color: var(--accent); font-weight: 700; }
  .pipeline .gate   { color: #f9c74f; }

  /* ── Feature grid ── */
  .grid-3 {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 1.25rem;
  }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1.5rem;
    transition: border-color 0.2s;
  }

  .card:hover { border-color: var(--accent); }

  .card-icon {
    font-size: 1.4rem;
    margin-bottom: 0.75rem;
  }

  .card h3 {
    font-size: 0.95rem;
    font-weight: 700;
    color: #fff;
    margin: 0 0 0.5rem;
  }

  .card p {
    font-size: 0.85rem;
    color: var(--dim);
    margin: 0;
  }

  /* ── Phase table ── */
  .phase-list {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }

  .phase-row {
    display: grid;
    grid-template-columns: 90px 1fr 90px;
    gap: 1rem;
    align-items: center;
    padding: 0.75rem 1rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: 0.85rem;
  }

  .phase-num {
    font-family: var(--mono);
    color: var(--accent2);
    font-weight: 700;
  }

  .phase-desc { color: var(--text); }

  .status-done {
    color: var(--accent);
    text-align: right;
    font-family: var(--mono);
    font-size: 0.78rem;
  }

  .status-next {
    color: #f9c74f;
    text-align: right;
    font-family: var(--mono);
    font-size: 0.78rem;
  }

  /* ── Threat grid ── */
  .threat-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 0.75rem;
  }

  .threat-card {
    background: var(--surface);
    border-left: 3px solid var(--danger);
    border-top: 1px solid var(--border);
    border-right: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
    border-radius: 0 4px 4px 0;
    padding: 1rem;
    font-size: 0.82rem;
  }

  .threat-card.high    { border-left-color: #ff8c00; }
  .threat-card.medium  { border-left-color: #f9c74f; }

  .threat-name { font-weight: 700; color: #fff; margin-bottom: 0.25rem; }
  .threat-def  { color: var(--dim); }

  /* ── Code block ── */
  .code-block {
    font-family: var(--mono);
    font-size: 0.82rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1.5rem;
    overflow-x: auto;
    line-height: 1.8;
  }

  .code-block .comment { color: var(--dim); }
  .code-block .cmd     { color: var(--accent2); }
  .code-block .kw      { color: var(--accent); }

  /* ── Stats bar ── */
  .stats {
    display: flex;
    gap: 2rem;
    flex-wrap: wrap;
    padding: 2rem 0;
  }

  .stat { text-align: center; }
  .stat-value {
    font-family: var(--mono);
    font-size: 2rem;
    font-weight: 700;
    color: var(--accent);
    display: block;
  }
  .stat-label {
    font-size: 0.78rem;
    color: var(--dim);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }

  /* ── Footer ── */
  footer {
    text-align: center;
    padding: 3rem 2rem;
    color: var(--dim);
    font-size: 0.8rem;
    border-top: 1px solid var(--border);
  }

  footer a { color: var(--accent2); text-decoration: none; }
  footer a:hover { text-decoration: underline; }

  /* ── Responsive ── */
  @media (max-width: 600px) {
    .phase-row { grid-template-columns: 70px 1fr; }
    .status-done, .status-next { display: none; }
    .stats { gap: 1.5rem; }
  }
</style>

<header class="hero">
  <div class="badge">Open Source · AGPL-3.0 · Local-First</div>
  <h1><span>Legion</span>Forge</h1>
  <p class="tagline">A security-native AI agent framework built on LangGraph.<br>Security enforced in the execution path — not layered on afterward.</p>
  <p class="subtagline">// local-first · deterministic controls · human gates · 2192/2192 smoke tests passing</p>
  <div class="cta-group">
    <a class="btn btn-primary" href="https://github.com/LegionForge/LegionForge">
      View on GitHub →
    </a>
    <a class="btn btn-secondary" href="https://github.com/LegionForge/LegionForge#quick-start">
      Quick Start
    </a>
  </div>
</header>

<main>

<section>
<div class="container">
  <div class="stats">
    <div class="stat"><span class="stat-value">2192</span><span class="stat-label">Smoke Tests Passing</span></div>
    <div class="stat"><span class="stat-value">7</span><span class="stat-label">Guardian Security Checks</span></div>
    <div class="stat"><span class="stat-value">11</span><span class="stat-label">Threat Classes Covered</span></div>
    <div class="stat"><span class="stat-value">0</span><span class="stat-value" style="font-size:1rem; color: var(--accent)">LLM calls</span><span class="stat-label">in security hot path</span></div>
  </div>
</div>
</section>

<section>
<div class="container">
  <h2><span class="icon">⛓</span> Crystallization Pipeline</h2>
  <p style="color: var(--dim); margin-bottom: 1.5rem;">When agents solve the same deterministic problem repeatedly, LegionForge crystallizes the solution into a signed, containerized tool — zero LLM overhead for routine work.</p>
  <div class="pipeline">
    <span class="step">Observer</span>
    <span class="arrow"> ──▶ </span>
    <span class="step">Crystallizer</span>
    <span class="arrow"> ──▶ </span>
    <span class="step">Pre-HITL Analyzer</span>
    <span class="arrow"> ──▶ </span>
    <span class="gate">Human Gate ⏸</span>
    <span class="arrow"> ──▶ </span>
    <span class="signed">Ed25519-Signed Tool ✓</span>
  </div>
  <p style="font-size: 0.8rem; color: var(--dim); margin-top: 0.75rem;">The Pre-HITL Analyzer runs AST guards (subscript bypass, MRO traversal, globals/locals hijack) and behavioral diffs before any human sees a proposal.</p>
</div>
</section>

<section>
<div class="container">
  <h2><span class="icon">🛡</span> Guardian Security Sidecar</h2>
  <p style="color: var(--dim); margin-bottom: 1.5rem;">A standalone FastAPI process (<code>:9766</code>) with a deterministic-only 7-check pipeline. No LLM calls. Unpoisonable. Fails safe to <strong>halt</strong> on any error.</p>
  <div class="grid-3">
    <div class="card">
      <div class="card-icon">🚫</div>
      <h3>Check 0 — Revocation</h3>
      <p>REVOKED tools are blocked before any other check. Cache TTL: 10 seconds.</p>
    </div>
    <div class="card">
      <div class="card-icon">🔐</div>
      <h3>Check 1 — Registry + Hash</h3>
      <p>Tool must be APPROVED in registry. SHA-256 hash must match registration record.</p>
    </div>
    <div class="card">
      <div class="card-icon">🧱</div>
      <h3>Check 2 — Capability Boundary</h3>
      <p>Negative capability list blocks unauthorized tool categories per agent profile.</p>
    </div>
    <div class="card">
      <div class="card-icon">🔍</div>
      <h3>Check 3 — Destructive Patterns</h3>
      <p>Regex-based detection of destructive command patterns in tool calls.</p>
    </div>
    <div class="card">
      <div class="card-icon">📋</div>
      <h3>Check 4 — Sequence Contract</h3>
      <p>Agent sequences are registered at startup. Deviations trigger a sandbox retry tier.</p>
    </div>
    <div class="card">
      <div class="card-icon">✍️</div>
      <h3>Check 5 — Ed25519 Signature</h3>
      <p>Crystallized tools must carry a valid Ed25519 signature from the signing keypair.</p>
    </div>
    <div class="card">
      <div class="card-icon">⚡</div>
      <h3>Check 6 — Adaptive Threat Rules</h3>
      <p>Human-approved rules from the Threat Analyst agent hot-reload every 10 seconds. No Guardian restart needed.</p>
    </div>
  </div>
</div>
</section>

<section>
<div class="container">
  <h2><span class="icon">⚠️</span> Threat Coverage</h2>
  <div class="threat-grid">
    <div class="threat-card">
      <div class="threat-name">Tool Poisoning</div>
      <div class="threat-def">Hash validation at registration + cryptographic signing</div>
    </div>
    <div class="threat-card">
      <div class="threat-name">Rug-Pull</div>
      <div class="threat-def">Hash mismatch detection + signed tool versioning</div>
    </div>
    <div class="threat-card">
      <div class="threat-name">Prompt Injection</div>
      <div class="threat-def">Sanitizer (29 patterns, 2-tier) + NFKC normalization + RAG provenance scoring</div>
    </div>
    <div class="threat-card">
      <div class="threat-name">Capability Amplification</div>
      <div class="threat-def">Negative capability list enforced by Guardian</div>
    </div>
    <div class="threat-card high">
      <div class="threat-name">Resource Bomb</div>
      <div class="threat-def">Pre-execution token cost estimator + per-provider rate limiter</div>
    </div>
    <div class="threat-card high">
      <div class="threat-name">Credential Theft</div>
      <div class="threat-def">Keychain storage + PII redaction on all outbound calls</div>
    </div>
    <div class="threat-card high">
      <div class="threat-name">RAG / Memory Poisoning</div>
      <div class="threat-def">Document provenance + embedding trust scoring</div>
    </div>
    <div class="threat-card high">
      <div class="threat-name">Multi-Agent Cascade</div>
      <div class="threat-def">Orchestrator-only routing + signed inter-agent messages</div>
    </div>
    <div class="threat-card medium">
      <div class="threat-name">Supply Chain</div>
      <div class="threat-def">AI-BOM + signed tool library + SHA256 GGUF verification</div>
    </div>
    <div class="threat-card medium">
      <div class="threat-name">TOCTOU</div>
      <div class="threat-def">approved_snapshot verified post-execution in SecureToolNode</div>
    </div>
    <div class="threat-card medium">
      <div class="threat-name">AST Bypass</div>
      <div class="threat-def">Subscript, MRO traversal, globals()/locals() hijack detection</div>
    </div>
  </div>
</div>
</section>

<section>
<div class="container">
  <h2><span class="icon">🗺</span> Phase Roadmap</h2>
  <div class="phase-list">
    <div class="phase-row">
      <div class="phase-num">Phase 0</div>
      <div class="phase-desc">PostgreSQL + pgvector, async LLM factory, health server</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 1</div>
      <div class="phase-desc">Researcher agent, tool registry + hash validation, capability boundaries</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 2</div>
      <div class="phase-desc">Docker, Guardian sidecar, immutable audit log (SHA-256 hash chain), RAG provenance</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 3</div>
      <div class="phase-desc">JWT task tokens + ACLs, sub-agent orchestrator, sandbox retry tier</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 4</div>
      <div class="phase-desc">Threat Analyst agent, adaptive Guardian rules, AI Bill of Materials</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 5</div>
      <div class="phase-desc">Crystallization Pipeline — Observer → Crystallizer → Analyzer → Ed25519-signed tools</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 5.5</div>
      <div class="phase-desc">DB RBAC, AST bypass guards, tool revocation, TOCTOU mitigation, model integrity</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 6</div>
      <div class="phase-desc">PentestAgent — air-gapped red-team bot, 8 attack classes × 3 variants, stop-at-proof</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 7</div>
      <div class="phase-desc">Guardian feedback loop, SECURITY.md threat model, v1.0 readiness hardening</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 8</div>
      <div class="phase-desc">Gateway (:8080), task queue, SSE streaming, web UI, A2A + MCP, Discord connector</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 9–16</div>
      <div class="phase-desc">Multi-user auth, 5 auth backends, Kerberos, Redis, Prometheus, polished UI, channel connectors</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 60–381</div>
      <div class="phase-desc">381-tool operator dashboard — every gateway API endpoint surfaced as a UI function</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Guardian G1–G4</div>
      <div class="phase-desc">Standalone <code>legionforge-guardian</code> package — PyPI published, public repo, auto-sync CI, dual MIT license</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Chat UI</div>
      <div class="phase-desc">Chat-mode toggle — persistent conversation bubbles, session auto-create, localStorage state, pinned input bar</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Tool Integrity</div>
      <div class="phase-desc">33 runtime integrity tests — schema conformance, result injection, Guardian e2e, Docker sandbox containment, memory isolation</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Hallucination</div>
      <div class="phase-desc">12 live anti-hallucination tests — UUID nonce grounding, source citation verification, 404 non-fabrication (manually run)</div>
      <div class="status-done">✓ complete</div>
    </div>
  </div>
</div>
</section>

<section>
<div class="container">
  <h2><span class="icon">⚡</span> Quick Start</h2>
  <div class="code-block">
<span class="comment"># Clone and bootstrap</span><br>
<span class="cmd">git clone</span> https://github.com/LegionForge/LegionForge.git<br>
<span class="cmd">cd</span> LegionForge<br>
<span class="cmd">python -m venv</span> venv <span class="cmd">&amp;&amp; source</span> venv/bin/activate<br>
<span class="cmd">pip install -r</span> requirements.txt<br>
<br>
<span class="comment"># Set hardware profile + initialize database</span><br>
<span class="kw">export</span> AGENT_HARDWARE_PROFILE=mac_m4_mini_16gb<br>
<span class="cmd">make</span> db-init<br>
<br>
<span class="comment"># Run smoke tests (no services needed)</span><br>
<span class="cmd">make</span> test-smoke<br>
<span class="comment"># ✓ 2192 passed in ~21s</span><br>
<br>
<span class="comment"># Start health server</span><br>
<span class="cmd">make</span> health-server<br>
<span class="comment"># curl http://localhost:8765/health → {"status":"ok"}</span>
  </div>
</div>
</section>

<section>
<div class="container">
  <h2><span class="icon">📬</span> Status &amp; Updates</h2>
  <p style="color: var(--dim);">
    LegionForge is available now. All pre-v1.0 security blockers are resolved.
    <strong style="color: var(--text);">2192/2192 smoke tests passing.</strong>
    Phases 0–381 + Guardian G1–G4 (PyPI published) + chat UI + tool integrity test suites complete.
  </p>
  <p style="color: var(--dim);">
    Clone from
    <a href="https://github.com/LegionForge/LegionForge" style="color: var(--accent2);">github.com/LegionForge/LegionForge</a>,
    or browse the docs at
    <a href="https://legionforge.org" style="color: var(--accent2);">legionforge.org</a>.
    Bugs, questions, and commercial licensing inquiries via
    <a href="https://github.com/LegionForge/LegionForge/issues" style="color: var(--accent2);">GitHub Issues</a>.
  </p>
</div>
</section>

</main>

<footer>
  <p>
    LegionForge · AGPL-3.0 · Copyright 2026 <a href="https://github.com/jp-cruz">John Paul "Jp" Cruz</a><br>
    Built on <a href="https://github.com/langchain-ai/langgraph">LangGraph</a> ·
    Runs on Apple Silicon via <a href="https://ollama.com">Ollama</a>
  </p>
</footer>
