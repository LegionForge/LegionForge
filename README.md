# LegionForge

**Version:** 1.1.0
**Last updated:** 2026-02-22 21:45 CST

---

A **local-first, security-native AI agent framework** built on LangGraph, running on Apple Silicon.
Agents use local LLMs (Ollama) or cloud APIs. Security is built into the foundation — not bolted on later.

> **New to this project? Start with [`TLDR.md`](./TLDR.md)** — a plain-language summary of what we're building and why.

---

> **Design priorities:** Security · Reliability · Observability · Modularity
> **Non-negotiables:** Human gates on mutations · Loop safeguards · Keychain-only credential storage · Deterministic security hot paths

---

## Project Status

| Phase | Status | What It Is |
|---|---|---|
| 0 — Infrastructure | ✅ Complete | PostgreSQL, pgvector, LLM factory, health server, 23/23 smoke tests |
| 1 — First Agent + Security Foundations | 🔄 Active | Researcher agent, tool hash validation, cost estimation, threat logging |
| 2 — Containerization + Guardian | ⬜ Next | Docker stack, Guardian security sidecar, immutable audit log |
| 3 — ACLs + Sub-Agents | ⬜ Planned | Task tokens, role definitions, orchestrator pattern |
| 4 — Adaptive Threat Intelligence | ⬜ Planned | Threat Analyst agent, adaptive Guardian rules, AI-BOM |
| 5 — Crystallization Pipeline | ⬜ Planned | Observer + Crystallizer agents, pre-HITL analyzer, signed deterministic tools |
| 6 — PentestAgent | ⬜ Planned | Air-gapped red-team bot, continuous security regression |

**→ Full roadmap:** [`PHASE_PLAN.md`](./PHASE_PLAN.md)

---

## Hardware Support

| Profile | Chip | RAM | Status |
|---|---|---|---|
| `mac_m4_mini_16gb` | M4 | 16GB | ✅ Active |
| `mac_m5_mini_32gb` | M5 | 32GB | 📋 Template (update on purchase) |

All hardware-specific values (memory limits, model sizes, path locations, concurrency limits, safeguard thresholds) are read from a YAML profile. **Nothing is hardcoded.** Switch hardware by setting one environment variable.

---

## Quick Start

### 1. Prerequisites

- macOS (Apple Silicon M4/M5)
- Python 3.11+
- [Homebrew](https://brew.sh)
- [Ollama](https://ollama.ai)
- A [LangSmith](https://smith.langchain.com) account (free tier works)

### 2. Clone and Install

```bash
git clone https://github.com/LegionForge/LegionForge.git
cd LegionForge

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Configure Your External Drive

Edit `config/hardware_profiles/mac_m4_mini_16gb.yaml` and update the mount path:

```yaml
storage:
  external:
    mount_path: "/Volumes/MAC_MINI_1TB"   # ← update this
```

### 4. Store API Keys in macOS Keychain

API keys are **never** stored in files. They live in macOS Keychain:

```bash
python -m keyring set openai api_key
python -m keyring set anthropic api_key
python -m keyring set langsmith api_key
```

Verify:
```bash
python -c "import keyring; print(keyring.get_password('openai', 'api_key')[:8] + '...')"
```

### 5. Pull Local Models

```bash
export OLLAMA_MODELS=/Volumes/MAC_MINI_1TB/LegionForge/models/ollama

ollama pull llama3.1:8b        # Primary reasoning (~4.9GB)
ollama pull qwen2.5:3b         # Router/supervisor (~1.9GB)
ollama pull nomic-embed-text   # Embeddings (~274MB)
```

### 6. Verify Setup

```bash
python -c "from config.settings import settings; print('✅ Config loaded')"
make test-smoke    # 23/23 should pass
make health-server # then curl http://localhost:8765/status
```

For full first-time setup instructions, see [`VERIFICATION.md`](./VERIFICATION.md).

---

## Project Structure

```
LegionForge/
├── TLDR.md                        # Start here — plain-language project summary
├── PROJECT_STATUS.md              # Current build state, infra details, todos
├── PHASE_PLAN.md                  # Full phased roadmap with exit criteria
├── RESEARCH.md                    # Threat taxonomy, design theory, open questions
├── CONTRIBUTING.md                # Branch strategy, commit conventions, test requirements
├── VERIFICATION.md                # Step-by-step setup verification guide
│
├── config/
│   ├── settings.py                # Pydantic config loader
│   └── hardware_profiles/
│       ├── mac_m4_mini_16gb.yaml  # Active profile
│       └── mac_m5_mini_32gb.yaml  # Template for future hardware
│
├── src/
│   ├── base_graph.py              # LangGraph agent template — copy for every new agent
│   ├── database.py                # PostgreSQL pool, pgvector, LangGraph checkpointer
│   ├── security.py                # Keychain loader, PII redaction, injection detection
│   ├── safeguards.py              # Three-layer loop protection + token budgets
│   ├── rate_limiter.py            # Per-provider rate limiting + cost alerts
│   ├── llm_factory.py             # Unified Ollama/OpenAI/Anthropic factory
│   ├── observability.py           # Structured logging + LangSmith upload
│   ├── health.py                  # FastAPI health/metrics server (localhost:8765)
│   └── agents/                    # Agents built on base_graph.py (Phase 1+)
│       └── researcher.py          # 🔄 In progress
│
├── tests/
│   ├── test_smoke.py              # 23 tests, no services required, ~0.2s
│   └── conftest.py
│
└── scripts/
    ├── check_mount.sh             # Verify external drive mounted before agent start
    ├── setup_postgres.sh          # One-time PostgreSQL setup (already run)
    └── com.jpc.check-agent-drive.plist  # macOS LaunchAgent for mount guard
```

---

## Security Model

Security is layered and builds across phases. What exists today, and what is coming:

| Layer | Component | Status | Notes |
|---|---|---|---|
| Credential storage | macOS Keychain | ✅ Phase 0 | No `.env` files with secrets ever |
| PII redaction | `security.py` | ✅ Phase 0 | Email, phone, SSN, card numbers |
| Prompt injection detection | `security.py` | ✅ Phase 0 | Pattern-based, hot path |
| Loop protection | `safeguards.py` | ✅ Phase 0 | Three independent layers |
| Rate limiting + cost alerts | `rate_limiter.py` | ✅ Phase 0 | Hard cutoffs per provider |
| Tool metadata hash validation | `security.py` | 🔄 Phase 1 | Blocks tool poisoning / rug-pull |
| Pre-execution cost estimation | `rate_limiter.py` | 🔄 Phase 1 | Rejects resource bombs before execution |
| Threat event logging | `database.py` | 🔄 Phase 1 | Feeds future Threat Analyst |
| Guardian security sidecar | `src/security/guardian.py` | ⬜ Phase 2 | HTTP oracle; any framework can use it |
| Immutable audit log | `database.py` | ⬜ Phase 2 | Hash-chain append-only event log |
| RAG document provenance | `security.py` | ⬜ Phase 2 | Trust scoring per ingested document |
| Task-scoped ACL tokens | `src/security/acl.py` | ⬜ Phase 3 | Ephemeral per-run privilege tokens |
| Adaptive threat rules | `src/agents/threat_analyst.py` | ⬜ Phase 4 | Human-approved rule updates |
| Crystallized tool signing | `src/tools/registry.py` | ⬜ Phase 5 | Ed25519; tampering breaks signature |
| Automated red-teaming | `src/agents/pentest_agent.py` | ⬜ Phase 6 | Air-gapped; manual trigger only |

**→ Full threat research and design theory:** [`RESEARCH.md`](./RESEARCH.md)

---

## Loop Safeguards (Three Independent Layers)

1. **LangGraph recursion limit** — framework-level hard stop, set per invocation
2. **Step counter in state** — explicit counter in every graph's state schema
3. **Action history tracker** — detects repeated identical actions (stuck loops)

All three limits are read from the active hardware profile. Nothing hardcoded.

---

## Switching Hardware Profiles

```bash
export AGENT_HARDWARE_PROFILE=mac_m5_mini_32gb
python your_agent.py
```

To add a new profile:
1. `cp config/hardware_profiles/mac_m4_mini_16gb.yaml config/hardware_profiles/YOUR_PROFILE.yaml`
2. Update all values
3. Validate: `python -c "from config.settings import load_settings; load_settings('YOUR_PROFILE')"`

---

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the branch strategy, commit message format, and smoke test requirements.

The short version: branch from `dev`, never commit directly to `main`, write a smoke test alongside every new component.

---

## License

GNU Affero General Public License v3.0 (AGPL-3.0)

See [`LICENSE`](./LICENSE) for full terms.
