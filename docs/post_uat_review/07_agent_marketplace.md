# Agent/Skill Marketplace Research
**Researched:** 2026-03-15
**Author:** Research pass via Claude Sonnet 4.6 (claude-sonnet-4-6)

---

## ClawdBot / OpenClaw / Moltbot — What They Are

OpenClaw (formerly Clawdbot, then Moltbot) is the primary open-source personal AI assistant framework that inspired LegionForge's multi-channel connector architecture. Understanding it deeply is essential for planning LegionForge's own marketplace strategy.

### Project History & Identity

| Name | Status | Notes |
|------|--------|-------|
| **Clawdbot** | Original name | Created by Peter Steinberger; self-hosted AI living inside messaging apps |
| **Moltbot** | Intermediate name | Clawdbot officially renamed to Moltbot; GitHub at `github.com/moltbot/moltbot` |
| **OpenClaw** | Current name | Final rename; `github.com/openclaw/openclaw`; 247,000 stars, 47,700 forks as of March 2026 |

All three names refer to the same project lineage. External articles referencing "Clawdbot" or "Moltbot" now point to OpenClaw.

### Architecture

OpenClaw runs a local **WebSocket Gateway** (`ws://127.0.0.1:18789`) as a single control plane for sessions, channels, tools, and events. The agent runtime communicates via RPC with tool/block streaming. Supported channels include WhatsApp, Telegram, Slack, Discord, Google Chat, Signal, iMessage (BlueBubbles/legacy), IRC, Matrix, Nostr, Microsoft Teams, LINE, Mattermost, and 6+ more. Backend LLMs are pluggable (Claude, DeepSeek, GPT models). Install path: `npm install -g openclaw@latest`.

**Key architectural parallels with LegionForge:**
- Local-first gateway pattern (LegionForge: port 8080; OpenClaw: ws://127.0.0.1:18789)
- Multi-channel inbox with connector abstraction (LegionForge: Discord, WhatsApp, Telegram, Slack, Webhook)
- Pluggable LLM backend (LegionForge: LLMFactory; OpenClaw: configurable model per workspace)
- Skills/tools as the extensibility primitive

### OpenClaw Skills System

Skills are the extensibility mechanism. Each skill is a directory containing a `SKILL.md` file with YAML frontmatter:

```yaml
name: skill-name
description: What it does
homepage: https://...         # optional
user-invocable: true          # optional
disable-model-invocation: false
command-dispatch: ...         # optional
```

**Load precedence (highest to lowest):**
1. Workspace skills (`<workspace>/skills/`)
2. Managed/local skills (`~/.openclaw/skills/`)
3. Bundled skills (shipped with installation)

**Load-time gating via `requires` metadata:**
- `requires.bins` — executables that must exist on PATH
- `requires.env` — environment variables or config values
- `requires.config` — specific OpenClaw config paths
- `os` — platform restriction (darwin, linux, win32)

**Three categories of skills:** bundled (default), managed (team-curated), workspace (user-defined).

**ClawHub (the marketplace):** The public registry at `clawhub.com` (now `clawhub.ai` after the collapse). Users install via `clawhub install <skill-slug>`. As of early 2026, ClawHub had 800+ skills growing toward 5,000. It collapsed in February 2026 (see Security Risks section below).

### Related OpenClaw Projects

| Project | URL | Purpose |
|---------|-----|---------|
| nanobot | `github.com/HKUDS/nanobot` | Ultra-lightweight OpenClaw implementation |
| openclaw-agents | `github.com/shenhao-stu/openclaw-agents` | 9-agent multi-agent setup, group routing |
| awesome-openclaw-agents | `github.com/mergisi/awesome-openclaw-agents` | Curated SOUL.md configs for productivity/dev/marketing agents |
| mission-control | `github.com/abhi1693/openclaw-mission-control` | Agent orchestration dashboard |
| OpenClaw-RL | `github.com/Gen-Verse/OpenClaw-RL` | Train agents by talking (RL from conversation) |

### Relation to LegionForge

LegionForge's connector architecture (Discord, WhatsApp, Telegram, Slack, Webhook) mirrors OpenClaw's multi-channel inbox model. LegionForge diverges significantly on security: Guardian sidecar, Ed25519 tool signing, LangGraph state machine with three-layer loop protection, and PostgreSQL-backed audit log chains are not present in OpenClaw. LegionForge should treat OpenClaw as a **design reference for UX/connector patterns**, not as a security model to emulate.

---

## Agent Marketplace Landscape (2025–2026)

The ecosystem has exploded. In December 2025, Anthropic released the **Agent Skills specification** as an open standard; OpenAI adopted the same SKILL.md format for Codex CLI and ChatGPT. This created an inter-operable skill format and ignited a marketplace race.

### Primary Skill Marketplaces

| Platform | Type | Scale | Security Model | Relevance to LegionForge |
|----------|------|-------|---------------|--------------------------|
| **SkillsMP** (`skillsmp.com`) | Community-indexed; crawls GitHub for SKILL.md files | 351,349 skills; 89K tools, 70K dev, 60K business | Minimal — AI-powered semantic search, no mandatory vetting | High — shows demand; shows what categories exist |
| **Skills.sh** | Vercel's entry; cross-agent compatibility focus | 83,627 skills; 8M+ installs; 18 agents supported | Install count tracking; no cryptographic vetting | High — shows install velocity as trust signal |
| **ClawHub** (now defunct/rebuilt) | OpenClaw native registry | 800+ skills (pre-collapse); ~1,184 malicious confirmed | Initially zero. Post-collapse: VirusTotal Code Insight scan, instant block on malicious flag | Critical negative example — what not to do |
| **Smithery.ai** | MCP server registry | 7,300+ MCP tools | Ephemeral config handling, enterprise security features; no mandatory signing | Medium — MCP gateway pattern is relevant |
| **LobeHub Skills** | Skill discovery + MCP servers | 565+ ClawHub-adjacent | Community; no explicit vetting described | Low |
| **LangChain Hub** (LangSmith) | Prompt/chain/agent artifact repo | Large; integrated into LangSmith | Read-only without LangSmith; vulnerability disclosed 2024 (malicious proxy agent) | Medium — lessons from the proxy agent CVE |
| **Composio** | Managed tool registry + auth broker | 500+ integrations | SOC 2 compliant; OAuth 2.1 + PKCE; credential broker (LLM never sees token) | High — auth brokering pattern is worth adopting |
| **tech-leads-club/agent-skills** | Curated, security-focused registry | Small; professionally curated | Snyk Agent Scan pre-publication; 100% open source (no binaries); static analysis in CI; content hashing; human curation | Very High — closest to what LegionForge needs |

### MCP Server Ecosystem (Anthropic Standard)

MCP (Model Context Protocol) is now the dominant wire format for connecting LLMs to external tools. Directories include:

- **PulseMCP** (`pulsemcp.com`): 10,400+ servers, updated daily
- **MCP.so**: 18,503 servers collected
- **mcpservers.org / awesome-mcp-servers**: Curated list by category (Developer Tools, API Development, Database Management, Security & Testing, Browser Automation, Cloud Infrastructure, etc.)
- **AWS Labs MCP**: AWS-maintained MCP servers

**Architectural relevance:** LegionForge already has MCP endpoints in `src/gateway/app.py`. The MCP ecosystem is a direct integration surface. Any marketplace integration that LegionForge exposes should be MCP-compatible.

### Broader AI Agent Directories

| Platform | Purpose | Notes |
|----------|---------|-------|
| `aiagentstore.ai` | Directory of 1,300+ AI agents/frameworks | Discovery, not execution |
| `aiagentsdirectory.com` | Categorized agent marketplace | Industry/function/pricing categorization |
| **ServiceNow AI Agent Marketplace** | Enterprise agent store | Governed, approval-gated; targets enterprise IT |
| **Oracle Fusion AI Agent Marketplace** | Enterprise agents for ERP/HCM workflows | Tight integration with Oracle Cloud |
| **Hugging Face Spaces + OpenEnv** | Model deployment + agent environment standard | Meta+HF launched OpenEnv (Nov 2025); standardized sandbox spec for environments |

### Enterprise Marketplace Pattern (ServiceNow / Oracle)

Enterprise platforms (ServiceNow, Oracle) implement approval-gated agent marketplaces with RBAC on who can install what. ServiceNow's AI Agent Studio provides a declarative model with governance controls. This is the right pattern for LegionForge's operator-facing integration — frame marketplace access as a governed workflow, not a self-service free-for-all.

---

## Security Risks of External Agent/Skill Integration

This is the most critical section for LegionForge planning. The threat model below is grounded in real 2025–2026 incidents.

### OWASP Top 10 for Agentic Applications (2026)

OWASP released the first dedicated Agentic AI Top 10 in December 2025, developed by 100+ experts. The risks most relevant to marketplace integration:

| ID | Name | Threat | Marketplace Relevance |
|----|------|--------|----------------------|
| **ASI01** | Agent Goal Hijack | Malicious text in external data (emails, PDFs, web content) alters agent objectives | Skill SKILL.md instructions can embed hidden goal overrides |
| **ASI02** | Tool Misuse & Exploitation | Agents misuse legitimate tools via poisoned tool descriptors or ambiguous prompts | External skills can describe tools in ways that trick the agent into destructive actions |
| **ASI03** | Identity & Privilege Abuse | Agents inherit high-privilege credentials reused across systems; caching SSH keys in agent memory | Marketplace skill gets access to all credentials the agent holds |
| **ASI04** | Agentic Supply Chain Vulnerabilities | Dynamically fetched tools, plugins, MCP servers, prompt templates are compromised | Core threat for any marketplace integration |
| **ASI05** | Unexpected Code Execution | Agent-generated or skill-generated code executed unsafely | Skills that emit shell commands, Python snippets, or tool invocations treated as trusted |
| **ASI06** | Memory & Context Poisoning | RAG databases, embeddings, agent memory poisoned to influence future decisions | Malicious skill could inject persistent false beliefs into LegionForge's memory layer |
| **ASI07** | Insecure Inter-Agent Communication | Multi-agent message exchanges lack auth/encryption; injection via MCP/RPC/shared memory | External skill acting as sub-agent could inject instructions into parent agent |
| **ASI08** | Cascading Failures | Small errors compound across planning, execution, and downstream agents | Buggy external skill causing loop or budget exhaustion; hitting all three safeguard layers |
| **ASI09** | Human-Agent Trust Exploitation | Agents exploit user over-trust to extract data or influence decisions | Skill that impersonates a legitimate LegionForge tool in HITL approval dialogs |
| **ASI10** | Rogue Agents | Compromised agents act harmfully while appearing legitimate; persist across sessions | External skill registers as a persistent agent with long-lived credentials |

### Real-World Incidents (2025–2026)

**ClawHub Collapse (February 2026)**
The most directly instructive case for LegionForge. ClawHub, OpenClaw's public skill registry, had:
- No automated security scanning
- No mechanism to flag malicious content
- No author verification
- No code signing

Result: 341+ malicious skills discovered by researchers; five of the top seven most-downloaded skills were malware. Attack patterns included:
- Prompt injection embedded in SKILL.md instructions (91% of malicious skills)
- Base64-obfuscated commands exfiltrating AWS keys and API tokens
- Fake authentication skills capturing credentials
- Reverse shells and backdoors installed via `setupCommand`
- Auto-updater trojans that persisted after initial installation

One attacker (`@hightower6eu`) published nine malicious skills targeting crypto developers. The platform had no way to report skills as malicious. An AI-based moderation system rejected a pull request deleting 400 malicious packages, claiming the repo "wasn't being used."

**Key lesson:** Skills operate within an agent that already has broad permissions (file access, shell execution, env vars). This makes a compromised skill more dangerous than a compromised npm package — the blast radius is the entire agent's permission scope.

**Cline/Clinejection Supply Chain Attack (February 17, 2026)**
Attack on the Cline AI coding tool (5M+ users) via npm. Three vulnerabilities chained:
1. GitHub Issue title with hidden prompt-injection instructions — injected into AI agent prompt without sanitization
2. GitHub Actions cache poisoning — shared cache between low-privilege triage workflow and high-privilege release workflow
3. Credential scope failure — single npm token covered both nightly and production releases

Result: Unauthorized `cline@2.3.0` published to npm, globally installing OpenClaw via postinstall scripts.

**LangChain Hub Proxy Agent CVE (disclosed October 2024, patched November 2024)**
A malicious agent uploaded to LangChain's Prompt Hub contained a pre-configured proxy server. Users who cloned the agent unknowingly routed all their API calls (including API keys and prompts) through the attacker's proxy. LangChain responded with a warning prompt before cloning agents with custom proxy configs.

**MCP Supply Chain — mcp-remote RCE (2025)**
The `mcp-remote` library (558,000+ downloads) contained a critical RCE vulnerability. MCP's trust model assumes tool descriptions are safe to inject into LLM context — they are not. Tool description injection is now OWASP ASI02.

**Supabase MCP Lethal Trifecta**
Combining privileged DB access + untrusted input via MCP tool + missing capability boundaries allowed cross-tenant data leakage.

### Threat Categories Specific to LegionForge

Given LegionForge's architecture, external marketplace skills present these specific risks:

1. **Guardian bypass via skill description:** A skill's SKILL.md could contain instructions that tell the agent to format tool calls in ways that bypass Guardian's 7-check pipeline. Guardian checks happen pre-invocation; if the skill manipulates the agent's reasoning *before* tool call formation, the attack lands upstream of the check.

2. **Ed25519 signing not applied to skill content:** LegionForge signs individual tools at registration time. A marketplace skill that dynamically generates tool definitions at runtime could produce unsigned tool descriptors that pass initial hash validation but have been altered.

3. **Loop protection triggering on legitimate skill:** A complex skill that legitimately requires many steps could hit LegionForge's 5-window / 3-repeat loop detector. This is acceptable (safe failure) but needs documentation for skill authors.

4. **Memory poisoning via skill output:** If a skill's output is stored in LegionForge's RAG layer (`documents` table, 768-dim HNSW), a malicious skill could inject false embeddings that persist and influence future agent decisions after the skill is removed.

5. **Token budget exhaustion (Denial of Wallet):** A skill that triggers expensive LLM calls in a loop could exhaust LegionForge's daily rate limits (`src/rate_limiter.py`). The 80%/100% thresholds provide protection, but a skill operating at 79% repeatedly would evade the hard cap.

6. **PostgreSQL privilege escalation via skill:** If a skill's tool call constructs SQL fragments injected into queries, even the restricted `legionforge_worker` role (SELECT-only) could be leveraged for read-based data exfiltration.

---

## Recommended Integration Architecture for LegionForge

Based on the research above, this section proposes a concrete integration architecture that fits LegionForge's existing Guardian/registry/HITL model. The design follows a **zero-trust, defense-in-depth** approach where marketplace skills are always lower-trust than built-in tools.

### Guiding Principles

1. **Skills are hostile until cleared.** Treat every marketplace skill like untrusted network input. Never give it the trust level of a built-in tool.
2. **Immutable manifests.** The skill manifest (SKILL.md + tool definitions) must be hash-locked at import time. Runtime mutation of tool descriptors is rejected.
3. **Operator gate before any execution.** No marketplace skill executes until an operator approves it through the existing HITL gate. Auto-approval is not a configuration option.
4. **Sandboxed trial run.** Before promotion to production, the skill runs in a sandboxed environment with network egress blocked and filesystem limited to a temp directory.
5. **Separate trust tier.** Marketplace skills run under a `marketplace` trust tier that Guardian enforces as a lower capability boundary than `internal` tools.

### Proposed Component Architecture

```
                    ┌─────────────────────────────────────┐
                    │         Skill Marketplace            │
                    │  (SKILL.md + tool defs + signature)  │
                    └────────────────┬────────────────────┘
                                     │ 1. Import request
                                     ▼
                    ┌─────────────────────────────────────┐
                    │       Skill Import Service           │
                    │  - Fetch manifest + compute SHA-256  │
                    │  - Verify Ed25519 signature (if any) │
                    │  - Static analysis (injection scan)  │
                    │  - Record to skill_registry table    │
                    │  - Status: PENDING_APPROVAL          │
                    └────────────────┬────────────────────┘
                                     │ 2. Approval request
                                     ▼
                    ┌─────────────────────────────────────┐
                    │     HITL Approval Gate               │
                    │  (existing src/gateway/app.py HITL)  │
                    │  - Operator sees diff of tool defs   │
                    │  - Operator sees static scan results │
                    │  - Approve → SANDBOX_TRIAL           │
                    │  - Reject → REJECTED (permanent)     │
                    └────────────────┬────────────────────┘
                                     │ 3. Trial run
                                     ▼
                    ┌─────────────────────────────────────┐
                    │     Sandbox Trial Executor           │
                    │  - gVisor or Firecracker microVM     │
                    │  - Network egress: blocked           │
                    │  - FS: /tmp/<skill-id>/ only         │
                    │  - Token budget: 5% of daily limit   │
                    │  - Guardian: marketplace tier        │
                    │  - Run canonical test task           │
                    │  - Capture all tool calls + outputs  │
                    └────────────────┬────────────────────┘
                                     │ 4. Operator reviews trial
                                     ▼
                    ┌─────────────────────────────────────┐
                    │     Second HITL Gate                 │
                    │  - Show trial run transcript         │
                    │  - Approve → ACTIVE (marketplace     │
                    │    trust tier, rate-limited)         │
                    │  - Reject → REJECTED                 │
                    └────────────────┬────────────────────┘
                                     │ 5. Production execution
                                     ▼
                    ┌─────────────────────────────────────┐
                    │     Guardian (existing, :9766)       │
                    │  - marketplace tier: reduced caps    │
                    │  - hash validation on every call     │
                    │  - tool revocation check             │
                    │  - no destructive patterns allowed   │
                    │  - sequence contracts enforced       │
                    └─────────────────────────────────────┘
```

### Database Schema Additions

Add a `skill_registry` table to the existing 16-table schema:

```sql
CREATE TABLE skill_registry (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            TEXT NOT NULL UNIQUE,           -- e.g. "weather-reporter"
    version         TEXT NOT NULL,                   -- semver
    source_url      TEXT NOT NULL,                   -- canonical fetch URL
    manifest_hash   TEXT NOT NULL,                   -- SHA-256 of SKILL.md + tool defs
    publisher_key   TEXT,                            -- Ed25519 public key (nullable)
    signature       TEXT,                            -- Ed25519 signature (nullable)
    trust_tier      TEXT NOT NULL DEFAULT 'marketplace',
    status          TEXT NOT NULL DEFAULT 'PENDING_APPROVAL',
    -- status values: PENDING_APPROVAL, SANDBOX_TRIAL, ACTIVE, REJECTED, REVOKED
    approved_by     TEXT,                            -- operator user_id
    approved_at     TIMESTAMPTZ,
    trial_run_id    UUID REFERENCES tasks(id),      -- link to trial run task
    static_scan_result JSONB,                       -- scan findings
    installed_at    TIMESTAMPTZ DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    revocation_reason TEXT
);

CREATE INDEX skill_registry_status ON skill_registry(status);
CREATE INDEX skill_registry_slug ON skill_registry(slug);
```

### Guardian Trust Tier: `marketplace`

Extend Guardian's capability boundary system to add a `marketplace` tier below the existing tiers:

| Tier | Max tools | Destructive ops | Network | File write | DB write |
|------|-----------|----------------|---------|------------|----------|
| `internal` | Unlimited | Operator-gated | Yes | Yes | Yes |
| `gateway` | Per-user quota | Operator-gated | Yes | No | Restricted |
| `marketplace` | 10 per turn | Never | Allowlist only | /tmp only | None |
| `sandbox_trial` | 5 per turn | Never | Blocked | /tmp/<id>/ | None |

Guardian enforces this at the hot-path check (check #3: capability boundary). The tier is stored in the `skill_registry` table and passed via the tool invocation context.

### Rate Limiting for Marketplace Skills

Extend `src/rate_limiter.py` to add per-skill rate limits:

- **Daily token budget:** 1% of the global daily limit per marketplace skill (prevents Denial of Wallet from a single bad skill)
- **Per-turn token budget:** 5,000 tokens maximum per skill invocation
- **Cooldown:** 60 seconds between skill invocations of the same slug
- **Global marketplace cap:** 10% of daily global limit shared across all marketplace skills

### Credential Isolation (Composio Pattern)

Marketplace skills must never receive raw credentials. Apply the **credential broker pattern**:

1. The agent decides what action to take
2. The broker (a new `src/skill_broker.py` module) intercepts the tool call
3. The broker looks up the required credential from Keychain/Keyring
4. The broker makes the external call and returns only the result
5. The marketplace skill never sees the credential value

This neutralizes prompt-injection attacks that attempt to exfiltrate credentials via skill outputs.

---

## Fingerprinting & Vetting Protocol

A step-by-step proposed process for vetting a new skill before production use. This draws on the `skill-signer` project, tech-leads-club/agent-skills, and the ClawHub post-mortem.

### Step 1: Manifest Ingestion & Hash Lock

```
INPUT: SKILL.md + tool definition files (from URL or file upload)

1a. Fetch all skill files; verify no symlinks (symlink guard)
1b. Canonicalize paths (normalize separators, strip trailing slashes)
1c. Compute SHA-256 over sorted concatenation of all file contents
    hash = SHA256(sorted(file_path + ":" + file_content for each file))
1d. Store hash as manifest_hash in skill_registry
1e. Any future load that produces a different hash → immediate REVOKED
```

### Step 2: Ed25519 Signature Verification (if provided)

```
INPUT: manifest_hash + publisher's .sig file + publisher's public key

2a. Publisher provides: skill.sig (Ed25519 signature over manifest_hash)
2b. Publisher registers public key (one-time, out-of-band) → trusted_publishers table
2c. Verify: ssh-keygen -Y verify (same mechanism as skill-signer project)
2d. If signature present and valid: publisher_verified = true (shown in HITL UI)
2e. If signature present and invalid: REJECT immediately
2f. If signature absent: accepted with warning; shown as "unverified publisher" in HITL UI
```

### Step 3: Static Analysis Scan

```
INPUT: all skill files

3a. Prompt injection pattern scan (reuse src/security/core.py's 29-pattern scanner)
    - Check SKILL.md instructions for injection patterns
    - Flag any "ignore previous instructions", "system:", "SYSTEM:", etc.

3b. Credential exfiltration pattern scan
    - Regex for base64-encoded strings in shell commands
    - URLs in tool definitions pointing to non-allowlisted domains
    - Environment variable access patterns ($HOME, $AWS_*, $ANTHROPIC_*, etc.)

3c. Destructive pattern scan (reuse Guardian's destructive_pattern_detection check)
    - rm -rf, DROP TABLE, DELETE FROM without WHERE, etc.

3d. Binary file detection (100% open source rule — no binaries)
    - Any non-text file → REJECT

3e. setupCommand inspection
    - Any setupCommand that downloads from the internet → flag as HIGH RISK
    - Operator must explicitly acknowledge before HITL approval

3f. Store scan results as static_scan_result JSONB in skill_registry
3g. Critical findings → status = REJECTED (no HITL needed)
3h. High-risk findings → shown prominently in HITL UI with require-acknowledge checkbox
```

### Step 4: HITL Approval — First Gate

```
INPUT: static scan results + manifest diff + publisher verification status

4a. Send HITL approval request to operator via existing gateway HITL mechanism
4b. Operator sees:
    - Rendered diff of what the skill adds (tools, instructions, scripts)
    - Publisher verified badge (or "unverified publisher" warning)
    - Static scan summary with severity breakdown
    - Any HIGH RISK findings with acknowledge checkboxes
    - Full manifest_hash for operator's records

4c. Operator decision:
    - APPROVE → status = SANDBOX_TRIAL
    - REJECT → status = REJECTED (final; logged to audit_log with hash chain)
    - DEFER → status stays PENDING_APPROVAL (no expiry)
```

### Step 5: Sandboxed Trial Run

```
INPUT: approved skill + canonical test task

5a. Provision isolated execution environment:
    - gVisor container OR Firecracker microVM (production: Firecracker)
    - Network egress: blocked (no outbound connections)
    - Filesystem: /tmp/<skill-id>/ read/write; all other paths read-only
    - No access to Keychain or environment credentials
    - Guardian: sandbox_trial tier (most restrictive caps)
    - Token budget: 5% of daily limit

5b. Run canonical test task:
    - A standardized "hello world" task that exercises the skill's declared capabilities
    - Capture: all tool calls, all outputs, all Guardian events, timing

5c. Runtime monitoring:
    - Any attempt to access paths outside /tmp/<skill-id>/ → FAIL
    - Any network connection attempt → FAIL
    - Any attempt to read environment variables → FAIL (and REVOKE)
    - Loop detection (same as src/safeguards.py) → FAIL

5d. Trial run transcript saved to tasks table (trial_run_id FK)
5e. Status:
    - Clean run → SANDBOX_TRIAL_PASSED → proceed to Step 6
    - Any FAIL → status = REJECTED; reason logged to audit_log
```

### Step 6: HITL Approval — Second Gate (Trial Review)

```
INPUT: trial run transcript

6a. Send second HITL approval request to operator
6b. Operator sees full trial run transcript:
    - Every tool call the skill made
    - Every output returned
    - Guardian events (if any)
    - Resource usage (tokens, time)

6c. Operator decision:
    - APPROVE → status = ACTIVE (marketplace tier)
    - REJECT → status = REJECTED (final)
```

### Step 7: Production Monitoring & Revocation

```
ONGOING after ACTIVE status:

7a. Every skill invocation: recompute manifest_hash and compare to stored value
    - Mismatch → immediate REVOKE + log TOOL_HASH_MISMATCH threat event

7b. Per-invocation Guardian check: all 7 existing checks apply + marketplace tier caps

7c. Anomaly detection (new):
    - Per-skill daily token spend tracked in rate_limiter
    - Any single skill consuming >5% of daily global budget → alert operator
    - Repeated pattern detection across skill invocations (action history loop)

7d. Revocation mechanism:
    - Operator can REVOKE at any time via gateway UI
    - Publisher can revoke by revoking their Ed25519 key (propagated via trusted_publishers)
    - Guardian's hot-reload (every 10s from threat_rules) propagates revocations in near-real-time
    - Revoked skills cannot be re-enabled; must go through full vetting again

7e. Audit trail:
    - All vetting decisions logged to audit_log (SHA-256 hash chain, existing)
    - All skill invocations logged with skill_slug + manifest_hash
    - threat_events table captures any Guardian violations during marketplace skill execution
```

---

## Immediate Next Steps (post-v0.8.0)

Ordered by priority, given LegionForge's current architecture and the UAT testing phase:

1. **Add `skill_registry` table** — database migration adding the table described above. Low risk, no behavioral change, enables tracking even before the full marketplace integration exists.

2. **Extend Guardian with `marketplace` and `sandbox_trial` trust tiers** — add two new capability boundary entries to Guardian's check #3. Required before any external skill can safely execute.

3. **Build `src/skill_broker.py` — credential isolation layer** — the broker pattern that ensures marketplace skills never receive raw credentials. High security value, moderate implementation effort.

4. **Extend `src/security/core.py` static analysis** — add the credential exfiltration and binary file detection scans described in Steps 3b and 3d. Most of the injection pattern infrastructure already exists.

5. **Wire marketplace approval into existing HITL gate** — extend the HITL mechanism in `src/gateway/app.py` to handle the two-gate skill approval workflow. The HITL gate already exists; this extends it with a new request type.

6. **Sandbox trial executor** — this is the highest-effort item. Options:
   - **Short term:** Docker with `--security-opt=no-new-privileges --cap-drop=ALL --network=none` and a restricted tmpfs mount. Not microVM-level isolation but viable for initial UAT.
   - **Medium term:** gVisor (`runsc`) container runtime for syscall-level isolation.
   - **Long term:** Firecracker microVM via Kata Containers for hardware-level isolation.

7. **Ed25519 skill signing tooling** — build a `make sign-skill` target that uses the existing `legionforge_tool_signer` Ed25519 key infrastructure to sign first-party skills. This enables LegionForge to publish signed skills to its own marketplace, demonstrating the trust model.

8. **`trusted_publishers` table and key registry** — enables publisher-signed skills to be verified. Prerequisite for a federated trust model where external publishers can be vetted once and their skills trusted transitively.

9. **Rate limit extensions** — per-skill daily token budget and marketplace global cap in `src/rate_limiter.py`. Prevents Denial of Wallet from a single compromised skill.

10. **LegionForge marketplace read API** — after all the above are in place, expose a `GET /skills` endpoint listing ACTIVE marketplace skills with their hashes, trust tiers, and approval metadata. This is the public-facing integration surface.

---

## References

All sources consulted during this research pass:

### OpenClaw / ClawdBot / Moltbot
- [OpenClaw GitHub](https://github.com/openclaw/openclaw) — primary repo, 247K stars
- [OpenClaw official site](https://openclaw.ai/)
- [OpenClaw Skills documentation](https://docs.openclaw.ai/tools/skills)
- [ClawdBot GitHub](https://github.com/clawdbot/clawdbot) — historical repo
- [Moltbot GitHub](https://github.com/moltbot/moltbot) — intermediate name repo
- [nanobot: Ultra-Lightweight OpenClaw](https://github.com/HKUDS/nanobot)
- [openclaw-agents](https://github.com/shenhao-stu/openclaw-agents)
- [awesome-openclaw-agents](https://github.com/mergisi/awesome-openclaw-agents)
- [OpenClaw mission-control dashboard](https://github.com/abhi1693/openclaw-mission-control)
- [OpenClaw-RL](https://github.com/Gen-Verse/OpenClaw-RL)
- [OpenClaw + Coolify deployment](https://github.com/essamamdani/openclaw-coolify)
- [ClawdBot self-hosted AI review — VelvetShark](https://velvetshark.com/clawdbot-the-self-hosted-ai-that-siri-should-have-been)
- [Setup Clawdbot Discord for Mac — DEV Community](https://dev.to/0xkoji/setup-clawdbot-discord-for-mac-2llh)
- [Why Verified Skill Matters — ClawHub Collapse](https://spec-weave.com/docs/guides/why-verified-skill-matters/)
- [Microsoft Security Blog: Running OpenClaw safely](https://www.microsoft.com/en-us/security/blog/2026/02/19/running-openclaw-safely-identity-isolation-runtime-risk/)
- [OpenClaw partners with VirusTotal](https://openclaw.ai/blog/virustotal-partnership)
- [OpenClaw ClawHub 2026 Security Guide](https://advenboost.com/en/openclaw-clawhub/)
- [DigitalOcean: What are OpenClaw Skills?](https://www.digitalocean.com/resources/articles/what-are-openclaw-skills)

### Marketplace Landscape
- [SkillsMP — Agent Skills Marketplace](https://skillsmp.com)
- [Skills.sh — Vercel's cross-agent marketplace](https://skills.sh)
- [aiagentstore.ai](https://aiagentstore.ai/)
- [aiagentsdirectory.com](https://aiagentsdirectory.com/)
- [LobeHub Skills Marketplace](https://lobehub.com/skills)
- [Smithery.ai — MCP Registry](https://smithery.ai/)
- [PulseMCP — 10,400+ MCP Servers](https://www.pulsemcp.com/servers)
- [MCP.so marketplace](https://mcp.so/)
- [mcpservers.org / Awesome MCP Servers](https://mcpservers.org/en)
- [AWS Labs MCP Servers](https://awslabs.github.io/mcp/)
- [MCP Market categories](https://mcpmarket.com/)
- [17+ Top MCP Registries (Medium)](https://medium.com/demohub-tutorials/17-top-mcp-registries-and-directories-explore-the-best-sources-for-server-discovery-integration-0f748c72c34a)
- [LangChain Hub announcement](https://blog.langchain.com/langchain-prompt-hub/)
- [LangSmith marketplace](https://smith.langchain.com/hub)
- [LangSmith Bug / malicious proxy agent — The Hacker News](https://thehackernews.com/2025/06/langchain-langsmith-bug-let-hackers.html)
- [Agent Skills Are the New npm (2026)](https://www.buildmvpfast.com/blog/agent-skills-npm-ai-package-manager-2026)
- [AI Agent Skills Boom 2026](https://www.solobusinesshub.com/trend-watch/ai-agent-skills-boom-2026/)
- [ServiceNow AI Agent Marketplace](https://store.servicenow.com/store/ai-marketplace)
- [Oracle AI Agents Software Provider Report 2025](https://research.isg-one.com/buyers-guide/business-technologies/digital-business-and-workplace/ai-agents-software-provider-report/2025/oracle)
- [Hugging Face Hub Security](https://huggingface.co/docs/hub/en/security)
- [Meta + Hugging Face OpenEnv](https://www.infoq.com/news/2025/11/hugging-face-openenv/)
- [SkillsMP Review 2026 — SmartScope](https://smartscope.blog/en/blog/skillsmp-marketplace-guide/)

### Security Architecture
- [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)
- [OWASP Top 10 for Agentic Applications (Dec 2025)](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
- [OWASP Top 10 for Agentic Applications 2026 — Aikido](https://www.aikido.dev/blog/owasp-top-10-agentic-applications)
- [OWASP Top 10 for Agentic Applications 2026 resource](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Top 10 for LLMs 2025 PDF](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf)
- [OWASP Agentic Top 10 — Lares Labs](https://labs.lares.com/owasp-agentic-top-10/)
- [skill-signer: Ed25519 signing for AI agent skills](https://github.com/rdevaul/skill-signer)
- [tech-leads-club/agent-skills: secure skill registry](https://github.com/tech-leads-club/agent-skills)
- [Skills Directory — security-tested skills](https://www.skillsdirectory.com/)
- [agentshield-benchmark](https://github.com/doronp/agentshield-benchmark)
- [Clinejection supply chain attack — Snyk](https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/)
- [Prompt Injection via GitHub Actions — Aikido](https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents)
- [MCP Vulnerabilities — Composio](https://composio.dev/content/mcp-vulnerabilities-every-developer-should-know)
- [Microsoft: Protecting against indirect injection in MCP](https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp)
- [Microsoft MCP security and governance — Inside Track](https://www.microsoft.com/insidetrack/blog/protecting-ai-conversations-at-microsoft-with-model-context-protocol-security-and-governance/)
- [Composio secure AI agent infrastructure guide](https://composio.dev/blog/secure-ai-agent-infrastructure-guide)
- [Composio MCP Gateways guide 2026](https://composio.dev/content/mcp-gateways-guide)
- [Composio AI agent authentication platforms](https://composio.dev/blog/ai-agent-authentication-platforms)
- [AI Agent Sandboxing 2026 — Northflank](https://northflank.com/blog/how-to-sandbox-ai-agents)
- [AI Agent Sandboxing guide — Manveer substack](https://manveerc.substack.com/p/ai-agent-sandboxing-guide)
- [4 ways to sandbox untrusted code 2026 — DEV Community](https://dev.to/mohameddiallo/4-ways-to-sandbox-untrusted-code-in-2026-1ffb)
- [awesome-sandbox for AI](https://github.com/restyler/awesome-sandbox)
- [Sandboxes for AI — Luis Cardoso](https://www.luiscardoso.dev/blog/sandboxes-for-ai)
- [Code Sandboxes for LLMs — Amir Malik](https://amirmalik.net/2025/03/07/code-sandboxes-for-llm-ai-agents)
- [How AI agents upend software supply chain — ReversingLabs](https://www.reversinglabs.com/blog/how-ai-agents-upend-sscs)
- [2026 Software Supply Chain Security Report — ReversingLabs](https://www.reversinglabs.com/sscs-report)
- [Fingerprinting AI Coding Agents on GitHub — arxiv](https://arxiv.org/html/2601.17406v1)
- [Who Signed This? Provenance for AI Agents — Medium](https://medium.com/@alexzanfir/who-signed-this-provenance-for-ai-agents-78208f9574f1)
- [Verifiable AI Provenance (VAP) Framework — IETF draft](https://datatracker.ietf.org/doc/draft-ailex-vap-legal-ai-provenance/)
- [AI Agents with DIDs and VCs — arxiv](https://arxiv.org/html/2511.02841v1)
- [Enterprises securing agentic AI — Help Net Security](https://www.helpnetsecurity.com/2026/02/23/ai-agent-security-risks-enterprise/)
- [Top Agentic AI Security Threats — Stellar Cyber](https://stellarcyber.ai/learn/agentic-ai-securiry-threats/)
- [Custom GPT security vulnerabilities analysis — arxiv](https://arxiv.org/html/2505.08148v1)
- [OpenAI agent builder safety](https://platform.openai.com/docs/guides/agent-builder-safety)
- [Hugging Face model scanning: 4M scanned — Protect AI](https://huggingface.co/blog/pai-6-month)
- [Cisco State of AI Security 2026](https://blogs.cisco.com/ai/cisco-state-of-ai-security-2026-report)
- [Mastra: Why we're all-in on MCP](https://mastra.ai/blog/mastra-mcp)
- [Smithery alternatives — Composio](https://composio.dev/blog/smithery-alternative)
