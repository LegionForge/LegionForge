# LangGraph Agent Framework

A hardware-parameterized, production-ready multi-agent framework built on LangGraph.  
Designed for local Apple Silicon hardware with optional cloud LLM fallback.

> **Design priorities:** Reliability · Observability · Dynamic agents · Performance  
> **Non-negotiables:** Loop safeguards · Security · API key management

---

## Hardware Support

| Profile | Chip | RAM | Status |
|---------|------|-----|--------|
| `mac_m4_mini_16gb` | M4 | 16GB | ✅ Active |
| `mac_m5_mini_32gb` | M5 | 32GB | 📋 Template (update on purchase) |

The framework reads all hardware-specific values (memory limits, model sizes, path locations, concurrency limits, safeguard thresholds) from a YAML profile. **No values are hardcoded.** Switch hardware by setting one environment variable.

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
git clone https://github.com/jp/jpc-mac-agent-framework.git
cd jpc-mac-agent-framework

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Configure Your External Drive

Edit `config/hardware_profiles/mac_m4_mini_16gb.yaml` and update the external drive mount path:

```yaml
storage:
  external:
    mount_path: "/Volumes/MAC_MINI_1TB"   # ← update this
```

### 4. Store API Keys in macOS Keychain

API keys are **never** stored in files. They live in macOS Keychain:

```bash
# Run each of these once — you'll be prompted to enter the key securely
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
# Set model storage to external drive first
export OLLAMA_MODELS=/Volumes/MAC_MINI_1TB/jpc-mac-agent-framework/models/ollama

ollama pull llama3.1:8b        # Primary reasoning model (~4.7GB)
ollama pull qwen2.5:3b         # Router/supervisor model (~2GB)
ollama pull nomic-embed-text   # Embeddings (~274MB)
```

### 6. Verify Setup

```bash
python -c "from config.settings import settings; print('✅ Config loaded')"
```

---

## Switching Hardware Profiles

```bash
# Use the M5 profile
export AGENT_HARDWARE_PROFILE=mac_m5_mini_32gb
python your_agent.py

# Or pass it explicitly in code
from config.settings import load_settings
settings = load_settings(profile="mac_m5_mini_32gb")
```

---

## Project Structure

```
jpc-mac-agent-framework/
├── config/
│   ├── settings.py                    # Pydantic config loader
│   └── hardware_profiles/
│       ├── mac_m4_mini_16gb.yaml      # M4 16GB profile (active)
│       └── mac_m5_mini_32gb.yaml      # M5 32GB profile (template)
├── src/
│   ├── base_graph.py                  # Base graph template with safeguards
│   ├── security.py                    # Key management + injection guards
│   ├── safeguards.py                  # Loop detection + token budgets
│   ├── llm_factory.py                 # Unified LLM provider factory
│   ├── observability.py               # LangSmith + local logging
│   └── agents/
│       ├── supervisor.py              # Orchestrator/router agent
│       ├── researcher.py              # Research agent
│       └── writer.py                  # Writing agent
├── tests/
│   ├── test_loop_guards.py
│   ├── test_security.py
│   └── test_config.py
├── docs/
│   └── setup_plan.md                  # Full setup documentation
├── .env                               # Non-sensitive config (safe to commit)
├── .env.secrets.example               # Template — copy, never commit actual secrets
├── .gitignore
├── langgraph.json                     # LangGraph Studio config
└── requirements.txt
```

---

## Security Model

| Secret Type | Storage | Never In |
|-------------|---------|----------|
| API keys (OpenAI, Anthropic, LangSmith) | macOS Keychain | Files, env vars, git |
| Non-sensitive config (URLs, model names) | `.env` file | Keychain |
| Hardware config | YAML profile | Hardcoded in Python |

---

## Loop Safeguards (Three Independent Layers)

1. **LangGraph recursion limit** — framework-level hard stop, set per invocation
2. **Step counter in state** — explicit counter baked into every graph's state schema
3. **Action history tracker** — detects repeated identical actions (stuck loops)

All three limits are read from the active hardware profile's `safeguards` section — never hardcoded.

---

## Adding a New Hardware Profile

1. Copy an existing profile: `cp config/hardware_profiles/mac_m4_mini_16gb.yaml config/hardware_profiles/YOUR_PROFILE.yaml`
2. Update all values to match your hardware
3. Validate it: `python -c "from config.settings import load_settings; load_settings('YOUR_PROFILE')"`
4. Set `AGENT_HARDWARE_PROFILE=YOUR_PROFILE` when running

---

## License

MIT
