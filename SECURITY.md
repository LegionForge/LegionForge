# Security Policy — LegionForge

**Version:** 1.0.0
**Effective:** 2026-02-26
**Maintained by:** [LegionForge/LegionForge](https://github.com/LegionForge/LegionForge)

---

## Threat Model

LegionForge is a security-native AI agent framework. The following threats are in scope and
actively defended against in the codebase:

| Threat | Defense | Implementation |
|---|---|---|
| **Direct prompt injection** | 24-pattern regex detector + adaptive Guardian rules | `src/security/core.py:detect_injection()`, Guardian `_check_6` |
| **Indirect prompt injection** | RAG provenance scoring, trust threshold enforcement | `src/database.py:store_document_with_provenance()` |
| **Tool poisoning / rug-pull** | SHA-256 hash validation at registration + Ed25519 signing | `src/security/core.py:verify_tool_before_invocation()` |
| **Tool revocation bypass** | 10-second TTL revocation cache in Guardian sidecar | `src/security/guardian.py:_check_0_tool_revocation()` |
| **Capability amplification** | Negative capability list enforced by Guardian | `src/security/guardian.py:_check_2_capability_boundary()` |
| **Privilege escalation** | JWT task tokens: child capabilities ⊆ parent capabilities | `src/security/acl.py:derive_task_token()` |
| **TOCTOU (time-of-check / time-of-use)** | `approved_snapshot` verified post-execution in `SecureToolNode` | `src/base_graph.py:SecureToolNode` |
| **Resource bomb / economic DOS** | Pre-execution token cost estimator + rate limiter | `src/rate_limiter.py`, `src/safeguards.py` |
| **Credential theft** | macOS Keychain storage; PII redaction from all outbound calls | `src/security/core.py:sanitize_output()` |
| **Audit log tampering** | SHA-256 hash chain on `audit_log` table; verified on startup | `src/database.py:verify_audit_log_chain()` |
| **Supply chain** | AI-BOM; Ed25519-signed crystallized tool manifests | `src/tools/signing.py` |
| **Agent sequence violation** | Sequence contracts registered per-agent; checked at every tool call | `src/security/guardian.py:_check_4_sequence()` |
| **Crystallization bypass** | AST guards (subscript, MRO traversal, globals) in pre-HITL analyzer | `src/tools/crystallization_analyzer.py` |

### Out of Scope

- **Embedding-level semantic poisoning** — RAG poisoning at the vector level is an open
  research problem. Provenance scoring and trust-threshold flagging exist; embedding-level
  anomaly detection is deferred.
- **Transitive Python dependency vulnerabilities** — `pip-audit` / hash pinning is accepted
  residual risk; remediation via Dependabot alerts.
- **GGUF model integrity** — `make verify-models` prints SHA256 hashes for pinning.
  `gguf_sha256: ""` in the hardware profile skips model integrity until the operator pins.

---

## HITL Halt vs Log Policy

### Design Authority

This policy was evaluated against:
- **NIST SP 800-61r3** §3.2.2 "Containment Strategy" — automated containment is appropriate
  when delay in response causes measurable additional damage (e.g., data exfiltration,
  privilege persistence, lateral movement).
- **MITRE ATT&CK for Enterprise** — Privilege Escalation (TA0004) and Lateral Movement
  (TA0008) techniques warrant immediate containment; Reconnaissance (TA0043) and Collection
  (TA0009) typically warrant logging + alerting.
- **OWASP ASVS v4.0** §11.1.6 — automated session termination on detected attack patterns.

### Tier 1 — HALT (immediate `force_end = True`)

The agent run is terminated immediately. No further tool calls are made. The event is logged
to `threat_events` and the audit log.

| Trigger | MITRE Tactic |
|---|---|
| Command/code injection detected in tool args | Execution (TA0002) |
| Self-probe detected (agent querying its own credentials or config) | Discovery (TA0007) |
| Privilege escalation attempt (child token exceeds parent capabilities) | Privilege Escalation (TA0004) |
| TOCTOU mismatch (post-exec snapshot differs from approved snapshot) | Defense Evasion (TA0005) |
| Guardian sidecar unavailable (fail-safe: halt, never fail-open) | — |
| CRITICAL-severity finding in pentest run with `stop_on_critical=True` | — |

**Rationale:** These attacks — if permitted to continue — cause immediate, irreversible harm:
injected code executes, escalated privileges persist, or audit integrity is lost. Delay
causes damage (NIST SP 800-61r3 §3.2.2).

### Tier 2 — LOG + ALERT (continue with degraded capability)

The tool call is blocked. The event is logged to `threat_events`. The agent continues
running but cannot invoke the blocked tool/capability. The operator is alerted via the
`threat_events` table and `/status` endpoint.

| Trigger | MITRE Tactic |
|---|---|
| Injection pattern detected in user input (not in tool args) | Initial Access (TA0001) |
| Credential probe (attempt to read keys not in approved scope) | Credential Access (TA0006) |
| Rate limit exceeded (token budget at ≥ 80% of daily cap) | Impact (TA0040) |
| Agent sequence contract violation | Defense Evasion (TA0005) |
| Unregistered tool invocation attempt | Execution (TA0002) |
| Revoked tool invocation attempt | Execution (TA0002) |

**Rationale:** These events are significant but allow safe continuation. The attacker does
not gain additional capability from the blocked call, and continued logging provides richer
forensic data. Halting on every probe would create excessive false-positive disruption
(NIST SP 800-61r3 §3.2.3 "Eradication vs. Continued Monitoring").

### Tier 3 — DEGRADE (continue with reduced capability)

The tool call succeeds with reduced fidelity. The event is logged.

| Trigger | Degradation |
|---|---|
| Local LLM unavailable | Fall back to cloud API or simplified response |
| Token budget at 100% | Return cached/stubbed response; no new LLM calls |
| Non-critical external tool error | Return error message to agent; agent decides next step |

---

## Pentest Baseline

LegionForge ships a built-in automated red-team agent (`src/agents/pentest_agent.py`).

**Current baseline (Phase 6):**
- **24 attack functions** across 8 classes (3 variants each)
- **Expected result on clean deployment:** 0 bypasses, 24 defenses held
- **Run:** `make pentest` (requires Docker Desktop + PostgreSQL)

When a bypass is found and a rule is approved via
`POST /pentest/rules/{finding_id}/approve`, it is automatically promoted into Guardian's
enforcement pipeline via `promote_pentest_rule_to_threat_rule()` and takes effect within
10 seconds — no Guardian restart required.

---

## Responsible Disclosure

If you discover a security vulnerability in LegionForge:

1. **DO NOT** open a public GitHub Issue with exploit details.
2. Open a GitHub Issue at [LegionForge/LegionForge](https://github.com/LegionForge/LegionForge/issues)
   with the title prefix `[SECURITY]` and a brief, non-exploitable description.
3. We will acknowledge within **72 hours** and open a private channel for details.
4. **Disclosure window:** 90 days from acknowledgment, or sooner if a fix is released.
5. Credit will be given in the release notes unless you prefer anonymity.

### What qualifies

- Authentication/authorization bypass in Guardian or the health endpoints
- Injection bypasses not caught by the 24-pattern detector
- Audit log hash chain manipulation
- Ed25519 key material exposure
- JWT task token forgery

### What does not qualify

- Attacks requiring physical access to the operator's machine
- Social engineering of the operator
- Theoretical vulnerabilities with no practical exploit path
- Issues in Ollama, PostgreSQL, or Docker that are upstream responsibility

---

## Security Contacts

- **Primary:** GitHub Issues — [LegionForge/LegionForge](https://github.com/LegionForge/LegionForge/issues)
- **Owner:** John Paul "Jp" Cruz ([@jp-cruz](https://github.com/jp-cruz))

---

## Changelog

| Date | Change |
|---|---|
| 2026-02-26 | Initial SECURITY.md — v1.0, covers Phases 0–7 |
