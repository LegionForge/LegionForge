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

  .hero h1 span { color: var(--accent); }

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

  .btn-primary { background: var(--accent); color: #0d1117; }

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

  .card-icon { font-size: 1.4rem; margin-bottom: 0.75rem; }

  .card h3 {
    font-size: 0.95rem;
    font-weight: 700;
    color: #fff;
    margin: 0 0 0.5rem;
  }

  .card p { font-size: 0.85rem; color: var(--dim); margin: 0; }

  /* ── Phase table ── */
  .phase-list { display: flex; flex-direction: column; gap: 0.6rem; }

  .phase-row {
    display: grid;
    grid-template-columns: 100px 1fr 90px;
    gap: 1rem;
    align-items: center;
    padding: 0.75rem 1rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: 0.85rem;
  }

  .phase-num { font-family: var(--mono); color: var(--accent2); font-weight: 700; }
  .phase-desc { color: var(--text); }

  .status-done {
    color: var(--accent);
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

  .threat-card.high   { border-left-color: #ff8c00; }
  .threat-card.medium { border-left-color: #f9c74f; }

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

  /* ── Interfaces table ── */
  .iface-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 0.75rem;
  }

  .iface-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem 1.25rem;
    font-size: 0.85rem;
  }

  .iface-name { font-weight: 700; color: var(--accent2); margin-bottom: 0.25rem; }
  .iface-desc { color: var(--dim); font-size: 0.8rem; }

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
    .phase-row { grid-template-columns: 80px 1fr; }
    .status-done { display: none; }
    .stats { gap: 1.5rem; }
  }
</style>

<header class="hero">
  <div class="badge">Open Source · AGPL-3.0 · Local-First · Apple Silicon</div>
  <h1><span>Legion</span>Forge</h1>
  <p class="tagline">A security-native AI agent framework built on LangGraph.<br>Security enforced in the execution path — not layered on afterward.</p>
  <p class="subtagline">// local-first · deterministic controls · human gates · 1946/1946 tests passing</p>
  <div class="cta-group">
    <a class="btn btn-primary" href="https://github.com/jp-cruz/LegionForge">
      View on GitHub →
    </a>
    <a class="btn btn-secondary" href="https://github.com/jp-cruz/LegionForge/blob/main/docs/quick-start.md">
      Quick Start
    </a>
    <a class="btn btn-secondary" href="https://github.com/jp-cruz/LegionForge/blob/main/SECURITY.md">
      Security Model
    </a>
  </div>
</header>

<main>

<section>
<div class="container">
  <div class="stats">
    <div class="stat">
      <span class="stat-value">1946</span>
      <span class="stat-label">Tests Passing</span>
    </div>
    <div class="stat">
      <span class="stat-value">7</span>
      <span class="stat-label">Guardian Checks</span>
    </div>
    <div class="stat">
      <span class="stat-value">11</span>
      <span class="stat-label">Threat Classes</span>
    </div>
    <div class="stat">
      <span class="stat-value">29</span>
      <span class="stat-label">Injection Patterns</span>
    </div>
    <div class="stat">
      <span class="stat-value">0</span>
      <span class="stat-value" style="font-size:1rem; color: var(--accent)">LLM calls</span>
      <span class="stat-label">in security hot path</span>
    </div>
  </div>
</div>
</section>

<section>
<div class="container">
  <h2><span class="icon">💬</span> Submit Tasks From Anywhere</h2>
  <p style="color: var(--dim); margin-bottom: 1.5rem;">LegionForge meets you where you already are. Every interface connects to the same secure execution pipeline.</p>
  <div class="iface-grid">
    <div class="iface-card">
      <div class="iface-name">Web UI</div>
      <div class="iface-desc">localhost:8080/ui — live token streaming, tool call blocks, session history, dark/light mode</div>
    </div>
    <div class="iface-card">
      <div class="iface-name">Discord</div>
      <div class="iface-desc">!&lt;task&gt; in any channel — bot replies and edits the message live as the agent streams</div>
    </div>
    <div class="iface-card">
      <div class="iface-name">Telegram</div>
      <div class="iface-desc">/&lt;task&gt; to your bot — polling-based, no public URL needed</div>
    </div>
    <div class="iface-card">
      <div class="iface-name">Slack</div>
      <div class="iface-desc">!&lt;task&gt; via Socket Mode — no public URL, just a bot token and an app token</div>
    </div>
    <div class="iface-card">
      <div class="iface-name">Webhook</div>
      <div class="iface-desc">POST :8081/inbound — HMAC-SHA256 verified, works with n8n, Zapier, or any HTTP client</div>
    </div>
    <div class="iface-card">
      <div class="iface-name">REST API</div>
      <div class="iface-desc">POST /tasks + GET /tasks/{id}/stream — full SSE streaming with A2A + MCP endpoints</div>
    </div>
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
  <p style="font-size: 0.8rem; color: var(--dim); margin-top: 0.75rem;">The Pre-HITL Analyzer runs AST guards (subscript bypass, MRO traversal, <code>globals()</code>/<code>locals()</code> hijack) and behavioral diffs before any human reviews a proposal. No tool reaches production without human approval.</p>
</div>
</section>

<section>
<div class="container">
  <h2><span class="icon">🛡</span> Guardian Security Sidecar</h2>
  <p style="color: var(--dim); margin-bottom: 1.5rem;">A standalone FastAPI process (<code>:9766</code>) with a deterministic-only 7-check pipeline on every tool call. No LLM calls. Unpoisonable. Fails safe to <strong>halt</strong> on any error.</p>
  <div class="grid-3">
    <div class="card">
      <div class="card-icon">🚫</div>
      <h3>Check 0 — Revocation</h3>
      <p>REVOKED tools are blocked before any other check. Cache TTL: 10 seconds — revocation takes effect in under 10s without any restart.</p>
    </div>
    <div class="card">
      <div class="card-icon">🔐</div>
      <h3>Check 1 — Registry + Hash</h3>
      <p>Tool must be APPROVED in the registry. SHA-256 hash must match the registration record exactly.</p>
    </div>
    <div class="card">
      <div class="card-icon">🧱</div>
      <h3>Check 2 — Capability Boundary</h3>
      <p>Negative capability list blocks unauthorized tool categories per agent profile. Agent cannot call what it wasn't granted.</p>
    </div>
    <div class="card">
      <div class="card-icon">🔍</div>
      <h3>Check 3 — Destructive Patterns</h3>
      <p>Regex detection of destructive command patterns in tool arguments — caught before execution, not after.</p>
    </div>
    <div class="card">
      <div class="card-icon">📋</div>
      <h3>Check 4 — Sequence Contract</h3>
      <p>Agent tool sequences are registered at startup. Deviations trigger the sandbox retry tier — never a silent pass.</p>
    </div>
    <div class="card">
      <div class="card-icon">✍️</div>
      <h3>Check 5 — Ed25519 Signature</h3>
      <p>Crystallized tools must carry a valid Ed25519 signature from the operator-held signing keypair.</p>
    </div>
    <div class="card">
      <div class="card-icon">⚡</div>
      <h3>Check 6 — Adaptive Rules</h3>
      <p>Human-approved threat rules from the Threat Analyst agent hot-reload every 10 seconds. No Guardian restart needed.</p>
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
      <div class="threat-def">SHA-256 hash validation at registration + Ed25519 cryptographic signing</div>
    </div>
    <div class="threat-card">
      <div class="threat-name">Rug-Pull</div>
      <div class="threat-def">Hash mismatch detection + signed tool versioning — tool can't change after approval</div>
    </div>
    <div class="threat-card">
      <div class="threat-name">Prompt Injection</div>
      <div class="threat-def">29-pattern sanitizer (Tier 1 halt / Tier 2 log) + NFKC normalization + zero-width char stripping + RAG provenance scoring</div>
    </div>
    <div class="threat-card">
      <div class="threat-name">Capability Amplification</div>
      <div class="threat-def">Negative capability list enforced by Guardian Check 2 — agent cannot grant itself new capabilities</div>
    </div>
    <div class="threat-card high">
      <div class="threat-name">Resource Bomb / Economic DOS</div>
      <div class="threat-def">Pre-execution token cost estimator + per-user daily budgets + per-provider rate limits with 80%/100% alerts</div>
    </div>
    <div class="threat-card high">
      <div class="threat-name">Credential Theft</div>
      <div class="threat-def">macOS Keychain / ~/.pgpass credential storage + PII redaction on all outbound API calls and LangSmith traces</div>
    </div>
    <div class="threat-card high">
      <div class="threat-name">RAG / Memory Poisoning</div>
      <div class="threat-def">Document provenance scoring at ingestion + embedding trust threshold flagging</div>
    </div>
    <div class="threat-card high">
      <div class="threat-name">Multi-Agent Cascade</div>
      <div class="threat-def">Orchestrator-only routing + signed inter-agent messages — sub-agents cannot spawn peers</div>
    </div>
    <div class="threat-card medium">
      <div class="threat-name">Supply Chain</div>
      <div class="threat-def">AI-BOM + signed tool library + SHA-256 GGUF model integrity verification</div>
    </div>
    <div class="threat-card medium">
      <div class="threat-name">TOCTOU</div>
      <div class="threat-def">approved_snapshot stored pre-execution; post-execution result verified against snapshot in SecureToolNode</div>
    </div>
    <div class="threat-card medium">
      <div class="threat-name">AST Bypass</div>
      <div class="threat-def">Subscript, MRO traversal, globals()/locals() hijack detection in crystallization pre-HITL analyzer</div>
    </div>
  </div>
</div>
</section>

<section>
<div class="container">
  <h2><span class="icon">🔑</span> Multi-Provider Authentication</h2>
  <p style="color: var(--dim); margin-bottom: 1.5rem;">Five auth backends — swap without touching agent code. Set <code>gateway.auth_provider</code> in your hardware profile YAML.</p>
  <div class="grid-3">
    <div class="card">
      <div class="card-icon">🔑</div>
      <h3>API Key (default)</h3>
      <p>bcrypt-hashed Bearer tokens stored in PostgreSQL. <code>make create-user</code> generates keys with optional daily budget.</p>
    </div>
    <div class="card">
      <div class="card-icon">🌐</div>
      <h3>OIDC</h3>
      <p>Google, Okta, Auth0, Azure AD, Keycloak, Cognito — any standards-compliant OIDC provider.</p>
    </div>
    <div class="card">
      <div class="card-icon">🐙</div>
      <h3>GitHub OAuth</h3>
      <p>GitHub OAuth app tokens. Identity stored as <code>github:&lt;user-id&gt;</code>.</p>
    </div>
    <div class="card">
      <div class="card-icon">🏢</div>
      <h3>LDAP</h3>
      <p>OpenLDAP, Active Directory. HTTP Basic auth. Supports bind DN + search base configuration.</p>
    </div>
    <div class="card">
      <div class="card-icon">🎫</div>
      <h3>Kerberos / GSSAPI</h3>
      <p>Full MIT Kerberos implementation. Negotiate auth. Requires OS-level KDC + keytab. See <code>docs/SCALING.md</code>.</p>
    </div>
  </div>
</div>
</section>

<section>
<div class="container">
  <h2><span class="icon">🗺</span> Phase Roadmap</h2>
  <p style="color: var(--dim); margin-bottom: 1.5rem;">All phases complete.</p>
  <div class="phase-list">
    <div class="phase-row">
      <div class="phase-num">Phase 0</div>
      <div class="phase-desc">PostgreSQL + pgvector, async LLM factory (Ollama/OpenAI/Anthropic), health server</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 1</div>
      <div class="phase-desc">Researcher agent, tool registry + SHA-256 hash validation, capability boundaries, threat logging</div>
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
      <div class="phase-desc">Crystallization Pipeline — Observer → Crystallizer → Pre-HITL Analyzer → Ed25519-signed tools</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 5.5</div>
      <div class="phase-desc">DB RBAC, AST bypass guards, tool revocation, TOCTOU mitigation, Ollama model integrity</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 6</div>
      <div class="phase-desc">PentestAgent — air-gapped red-team bot, 8 attack classes × 3 variants, stop-at-proof</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 7</div>
      <div class="phase-desc">Guardian feedback loop (pentest → threat rules → hot-reload), SECURITY.md, v1.0 hardening</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 8</div>
      <div class="phase-desc">Gateway (:8080), task queue, SSE streaming, web UI, A2A + MCP endpoints, Discord connector</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 9</div>
      <div class="phase-desc">langchain 1.x migration, 5-tool library, parallel agent fan-out, Phase 9.5 hardening sprint</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 10</div>
      <div class="phase-desc">Multi-user auth — DB stream tokens, per-user daily budgets, /usage/me, user management CLI</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 11</div>
      <div class="phase-desc">SecureToolNode fix, 38 integration tests, AuthBackend protocol, Dockerfile.gateway, SCALING.md</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 12</div>
      <div class="phase-desc">OIDCBackend, GitHubOAuthBackend, LDAPBackend, KerberosBackend — multi-scheme require_user</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 13</div>
      <div class="phase-desc">Real GSSAPI Kerberos backend, Redis-backed stream tokens, multi-instance docker-compose + Nginx</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 14</div>
      <div class="phase-desc">Redis global budget counters, Prometheus /metrics endpoint, X-Request-ID trace middleware</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 15</div>
      <div class="phase-desc">Polished web UI — localStorage key + history, cancel, tool call blocks, live timer, copy, keyboard shortcuts</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 16</div>
      <div class="phase-desc">Telegram (polling), Slack (Socket Mode), Webhook (HMAC-SHA256 + async callback) connectors</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Phase 60–381</div>
      <div class="phase-desc">381-tool operator dashboard — every gateway API endpoint surfaced as a UI function with smoke tests</div>
      <div class="status-done">✓ complete</div>
    </div>
    <div class="phase-row">
      <div class="phase-num">Security</div>
      <div class="phase-desc">Extended exfiltration detection, NFKC normalization, DESTRUCTIVE_PATTERN DB logging, PostgreSQL scram-sha-256</div>
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
<span class="cmd">git clone</span> https://github.com/jp-cruz/LegionForge.git<br>
<span class="cmd">cd</span> LegionForge<br>
<span class="cmd">python -m venv</span> venv <span class="cmd">&amp;&amp; source</span> venv/bin/activate<br>
<span class="cmd">pip install -r</span> requirements.txt<br>
<br>
<span class="comment"># Set hardware profile + store PostgreSQL password</span><br>
<span class="kw">export</span> AGENT_HARDWARE_PROFILE=mac_m4_mini_16gb<br>
<span class="cmd">echo</span> "localhost:5432:*:$(whoami):yourpassword" >> ~/.pgpass <span class="cmd">&amp;&amp; chmod</span> 0600 ~/.pgpass<br>
<br>
<span class="comment"># Initialize database + security secrets</span><br>
<span class="cmd">make</span> db-init<br>
<span class="cmd">make</span> setup-task-token-secret<br>
<span class="cmd">make</span> setup-signing-key<br>
<br>
<span class="comment"># Run smoke tests (no services needed)</span><br>
<span class="cmd">make</span> test-smoke<br>
<span class="comment"># ✓ 1946 passed in ~16s</span><br>
<br>
<span class="comment"># Start services + create your first user</span><br>
<span class="cmd">make</span> health-server  <span class="comment"># :8765</span><br>
<span class="cmd">make</span> gateway-start  <span class="comment"># :8080</span><br>
<span class="cmd">make</span> guardian-start <span class="comment"># :9766 (requires Docker)</span><br>
<span class="cmd">make</span> create-user USERNAME=myname<br>
<span class="comment"># open http://localhost:8080/ui</span>
  </div>
  <p style="margin-top: 1rem; font-size: 0.85rem; color: var(--dim);">
    Full setup guide including channel connectors, Kerberos, and horizontal scaling:
    <a href="https://github.com/jp-cruz/LegionForge/blob/main/docs/quick-start.md" style="color: var(--accent2);">docs/quick-start.md →</a>
  </p>
</div>
</section>

<section>
<div class="container">
  <h2><span class="icon">📬</span> Status</h2>
  <p style="color: var(--dim);">
    LegionForge is available now.
    <strong style="color: var(--text);">1946/1946 tests passing.</strong>
    All pre-v1.0 security blockers resolved. Phases 0–381 complete.
    Active development toward v1.0.0 public release.
  </p>
  <p style="color: var(--dim);">
    Clone from
    <a href="https://github.com/jp-cruz/LegionForge" style="color: var(--accent2);">github.com/jp-cruz/LegionForge</a>.
    Bugs, questions, and commercial licensing inquiries via
    <a href="https://github.com/jp-cruz/LegionForge/issues" style="color: var(--accent2);">GitHub Issues</a>.
    Security vulnerabilities: see
    <a href="https://github.com/jp-cruz/LegionForge/blob/main/SECURITY.md#responsible-disclosure" style="color: var(--accent2);">SECURITY.md § Responsible Disclosure</a>
    (90-day coordinated disclosure window).
  </p>
</div>
</section>

</main>

<footer>
  <p>
    LegionForge · AGPL-3.0 · Copyright 2026 <a href="https://github.com/jp-cruz">John Paul "Jp" Cruz</a><br>
    Built on <a href="https://github.com/langchain-ai/langgraph">LangGraph</a> ·
    Runs on Apple Silicon via <a href="https://ollama.com">Ollama</a> ·
    <a href="https://github.com/jp-cruz/LegionForge">GitHub</a>
  </p>
</footer>
