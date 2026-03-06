# LegionForge — Quick Start Guide

**Version:** 0.7.0-alpha
**Last updated:** 2026-03-06

This guide takes you from zero to a running LegionForge instance and your first agent task.
It assumes a Mac Mini M4 running macOS 14+.

---

## Prerequisites

| Component | Version | Install |
|---|---|---|
| Python | 3.11+ | `brew install pyenv && pyenv install 3.11.9` |
| PostgreSQL | 17 | `brew install postgresql@17` |
| pgvector | latest | `brew install pgvector` |
| Ollama | latest | [ollama.com](https://ollama.com) |
| Docker Desktop | 24+ | [docker.com](https://www.docker.com/products/docker-desktop) |
| macOS Keychain | built-in | Used for all secrets — no `.env` files |

---

## Step 1 — Clone and Install

```bash
git clone https://github.com/jp-cruz/LegionForge.git
cd LegionForge
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Set your hardware profile (required before any `make` command):

```bash
export AGENT_HARDWARE_PROFILE=mac_m4_mini_16gb
# Add to your ~/.zshrc so it persists:
echo 'export AGENT_HARDWARE_PROFILE=mac_m4_mini_16gb' >> ~/.zshrc
```

Verify the environment:

```bash
make check
```

---

## Step 2 — First-Time Setup (one-time only)

### 2a. Store your PostgreSQL admin password

LegionForge reads credentials from `~/.pgpass` (PostgreSQL standard, chmod 0600):

```bash
# Replace 'yourpassword' with your actual PostgreSQL admin password
echo "localhost:5432:*:$(whoami):yourpassword" >> ~/.pgpass
chmod 0600 ~/.pgpass
```

**New install with default Homebrew trust auth (no password set)?** Set this env var instead:
```bash
export POSTGRES_TRUST_AUTH=true   # dev/trust-auth only — do not use in production
```

Optionally also store in macOS Keychain (best-effort — Keychain access from subprocesses
requires an interactive session grant, so `~/.pgpass` is the reliable path):
```bash
security add-generic-password -s postgres -a api_key -w yourpassword
```

### 2b. Pull Ollama models

```bash
ollama pull llama3.1:8b       # ~4.7 GB — primary agent model
ollama pull qwen2.5:3b        # ~2.0 GB — fast router model
ollama pull nomic-embed-text  # ~0.3 GB — RAG embeddings
```

### 2c. Initialize the database

```bash
make db-init        # Create tables, roles, pgvector extension
make setup-db-roles # Create legionforge_app restricted role
```

### 2d. Generate security secrets (one-time)

```bash
make setup-task-token-secret   # JWT signing secret for task tokens
make setup-signing-key         # Ed25519 keypair for tool signing
```

Store the operator health token (used to access /status and /metrics):

```bash
# Generate a random token and store it
TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
security add-generic-password -s legionforge_health -a api_key -w "$TOKEN"
echo "Your operator token: $TOKEN"  # save this somewhere
```

### 2e. Register tools with Guardian

```bash
make register-researcher-tools  # web_search, web_fetch, document_store
make register-http-tools        # http_get, http_post
make register-file-tools        # file_read, file_write
make register-code-tool         # code_execute (sandboxed Docker)
make register-threat-analyst-tools
make register-observer-tools
make register-crystallizer-tools
make register-agent-sequences   # declare agent tool sequences
```

### 2f. Run smoke tests (verify the install)

```bash
make test-smoke
# Expected: 1995 passed in ~22s (no services required)
```

---

## Step 3 — Start Services

Open separate terminal tabs/windows for each service, or use a process manager.

```bash
# Tab 1 — Ollama (if not already running)
ollama serve

# Tab 2 — PostgreSQL (if not already running)
make db-start

# Tab 3 — Operator / Health server
make health-server
# Verify: curl http://localhost:8765/health

# Tab 4 — Gateway (user-facing API + web UI)
make gateway-start
# Verify: curl http://localhost:8080/metrics

# Tab 5 — Guardian sidecar (optional but recommended for full security)
make guardian-start
# Requires: Docker Desktop running
# Verify: curl http://localhost:9766/health
```

Or use the full startup shortcut:

```bash
make start          # Starts Ollama + PostgreSQL + model warmup
make health-server  # Start health server (separate terminal)
make gateway-start  # Start gateway (separate terminal)
```

---

## Step 4 — Create Your First User

The gateway requires API key authentication. Create a user account:

```bash
make create-user USERNAME=myname
# Prints: API key for myname: lf_...
```

Save the printed API key — you'll use it to authenticate all requests.

To set a custom daily token budget (default: 100,000 tokens):

```bash
make create-user USERNAME=myname DAILY_LIMIT=500000
```

---

## Step 5 — Submit Your First Task

### Option A — Web UI (easiest)

Open your browser to: `http://localhost:8080/ui`

1. Paste your API key into the key field (it saves to localStorage)
2. Select agent type: `orchestrator` (default) or `researcher`
3. Type a task and press **Submit** (or `Cmd+Enter`)
4. Watch the live SSE stream — tool calls appear as styled blocks, tokens stream in real time

### Option B — curl

```bash
API_KEY="lf_your_api_key_here"

# Submit a task
RESPONSE=$(curl -s -X POST http://localhost:8080/tasks \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"input": "Research the latest news on LLM security vulnerabilities", "agent_type": "orchestrator"}')

TASK_ID=$(echo $RESPONSE | python -c "import sys,json; print(json.load(sys.stdin)['task_id'])")
echo "Task ID: $TASK_ID"

# Stream the output live (Ctrl+C to stop early)
curl -N "http://localhost:8080/tasks/$TASK_ID/stream" \
  -H "Authorization: Bearer $API_KEY"

# Fetch the final result
curl -s "http://localhost:8080/tasks/$TASK_ID" \
  -H "Authorization: Bearer $API_KEY" | python -m json.tool
```

### Option C — Python

```python
import httpx, json

API_KEY = "lf_your_api_key_here"
BASE = "http://localhost:8080"

# Submit
resp = httpx.post(f"{BASE}/tasks",
    headers={"Authorization": f"Bearer {API_KEY}"},
    json={"input": "Summarize the top 3 AI papers from this week", "agent_type": "orchestrator"})
task_id = resp.json()["task_id"]

# Stream
with httpx.stream("GET", f"{BASE}/tasks/{task_id}/stream",
        headers={"Authorization": f"Bearer {API_KEY}"}) as r:
    for line in r.iter_lines():
        if line.startswith("data: "):
            print(json.loads(line[6:]).get("content", ""), end="", flush=True)
```

---

## Step 6 — Connect a Messaging Channel

### Discord Bot

1. Create a bot at [discord.com/developers/applications](https://discord.com/developers/applications)
2. Copy the bot token
3. Store secrets in Keychain:
   ```bash
   security add-generic-password -s legionforge_discord_token -a api_key -w "your-discord-bot-token"
   make create-user USERNAME=discord-bot
   # Copy the printed API key, then:
   security add-generic-password -s legionforge_discord_api_key -a api_key -w "lf_printed_api_key"
   ```
4. Invite the bot to your server (Bot scope, Send Messages + Read Message History permissions)
5. Start the connector:
   ```bash
   make discord-start
   ```
6. In any channel the bot can see:
   ```
   !Research quantum computing breakthroughs from 2026
   ```
   The bot replies and updates the message live as the agent streams output.

---

### Telegram Bot

1. Message [@BotFather](https://t.me/botfather) → `/newbot` → copy the token
2. Store secrets:
   ```bash
   security add-generic-password -s legionforge_telegram_token -a api_key -w "your-telegram-token"
   make create-user USERNAME=telegram-bot
   security add-generic-password -s legionforge_telegram_api_key -a api_key -w "lf_printed_api_key"
   ```
3. Start:
   ```bash
   make telegram-start
   ```
4. Message your bot:
   ```
   /Research the current state of AI agent frameworks
   ```

---

### Slack Bot (Socket Mode — no public URL needed)

1. Create a Slack app at [api.slack.com/apps](https://api.slack.com/apps)
2. Enable **Socket Mode** → generate an App-Level Token (`xapp-...`)
3. Under **OAuth & Permissions** → install to workspace → copy Bot Token (`xoxb-...`)
4. Add scopes: `app_mentions:read`, `chat:write`, `channels:history`
5. Store secrets:
   ```bash
   security add-generic-password -s legionforge_slack_bot_token -a api_key -w "xoxb-..."
   security add-generic-password -s legionforge_slack_app_token -a api_key -w "xapp-..."
   make create-user USERNAME=slack-bot
   security add-generic-password -s legionforge_slack_api_key -a api_key -w "lf_printed_api_key"
   ```
6. Start:
   ```bash
   make slack-start
   ```
7. In any channel where the bot is present:
   ```
   !Research what happened in AI security this week
   ```

---

### Generic Webhook

The webhook connector accepts inbound HTTP POSTs, verifies them with HMAC-SHA256, and
forwards them to the gateway as tasks. Use for n8n, Zapier, or any custom integration.

```bash
# Create a webhook user and HMAC secret
make create-user USERNAME=webhook-bot
security add-generic-password -s legionforge_webhook_api_key -a api_key -w "lf_printed_api_key"

# Optional: set an HMAC secret for inbound verification
# If empty, verification is skipped (acceptable on private networks)
security add-generic-password -s legionforge_webhook_inbound_secret -a api_key -w "your-hmac-secret"

# Start (listens on :8081)
make webhook-start

# Verify it's running
curl http://localhost:8081/health
```

Send a task:

```bash
# Compute HMAC-SHA256 signature
BODY='{"input": "Summarize today'\''s AI news", "agent_type": "orchestrator"}'
SECRET="your-hmac-secret"
SIG=$(echo -n "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')

curl -X POST http://localhost:8081/inbound \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=$SIG" \
  -d "$BODY"
```

---

## Step 7 — Check System Health

```bash
# Quick liveness check
curl http://localhost:8765/health

# Full system status (requires operator token)
OPERATOR_TOKEN=$(security find-generic-password -s legionforge_health -a api_key -w)
curl -H "Authorization: Bearer $OPERATOR_TOKEN" http://localhost:8765/status | python -m json.tool

# Prometheus metrics from gateway
curl http://localhost:8080/metrics

# Your token usage
curl -H "Authorization: Bearer $API_KEY" http://localhost:8080/usage/me
```

---

## Step 8 — Run the Security Audit

Before any significant use, run the built-in audit:

```bash
make security-audit
# Runs: smoke tests + bandit static analysis + URI secret scan
# Expected: 0 high / 0 medium bandit findings, no secret URIs
```

To run the red-team pentest suite against a synthetic environment:

```bash
make pentest          # stop-at-proof mode (safe to run)
make pentest-report   # view the findings
```

---

## Makefile Reference (All Commands)

```bash
# Environment
make check             # Verify drive, venv, models, config
make start             # Full startup (Ollama + PostgreSQL + model warmup)
make stop              # Graceful shutdown
make install           # Install/update pip dependencies

# Testing
make test-smoke        # 1995 smoke tests, ~22s, no services required
make test-integration  # 38 integration tests (requires PostgreSQL)
make test-kerberos     # 5 Kerberos live-KDC tests (requires KDC)
make test-ui           # 40 UI tests (Playwright)
make test-fast         # All tests except slow ones
make test              # Full test suite

# Code quality
make lint              # Black formatter check
make format            # Auto-format
make security-audit    # Smoke + bandit + URI secret scan

# Database
make db-init           # Initialize PostgreSQL + tables (one-time)
make db-start          # Start PostgreSQL service
make db-stop           # Stop PostgreSQL service
make db-shell          # Open psql shell

# Gateway
make gateway-start     # Start gateway API at :8080
make create-user USERNAME=<name>              # Create API user
make create-user USERNAME=<name> DAILY_LIMIT=<n>  # With custom budget

# Health / Operator
make health-server     # Start operator health API at :8765
make health            # Quick liveness check
make status            # Full system status

# Guardian (requires Docker Desktop)
make guardian-start    # Build + start Guardian sidecar at :9766
make guardian-stop     # Stop Guardian
make guardian-logs     # Tail Guardian logs

# Channel connectors
make discord-start     # Discord bot (requires Keychain secrets)
make telegram-start    # Telegram bot (requires Keychain secrets)
make slack-start       # Slack Socket Mode (requires Keychain secrets)
make webhook-start     # Webhook connector at :8081

# Agents
make run-researcher TASK="your task here"
make run-observer
make run-threat-analyst
make pentest           # Air-gapped red-team suite
make pentest-report    # View pentest findings

# Crystallization (HITL tool promotion)
make run-observer      # Nominate candidates
make run-crystallizer CANDIDATE_ID=<id>   # Generate function
make pending-packages  # List packages awaiting review
make approve-package PACKAGE_ID=<id>      # Approve + sign + register
```

---

## Troubleshooting

### "PostgreSQL not available" in tests or startup

```bash
# Check if PostgreSQL is running
pg_ctl status -D /opt/homebrew/var/postgresql@17
# Start it
make db-start
# Verify credentials
security find-generic-password -s postgres -a api_key -w
```

### "Ollama model not found"

```bash
ollama list          # See what's available
ollama pull llama3.1:8b
```

### "Guardian connection refused" at :9766

Guardian is optional but recommended. Start it with:

```bash
make guardian-start  # Requires Docker Desktop to be running
```

Without Guardian, agents run with local hash + registry checks only (Checks 0–1 in `SecureToolNode`). Checks 2–6 (capability boundary, destructive patterns, sequence contracts, Ed25519, adaptive rules) are bypassed. Suitable for development; not for production.

### "Keychain access denied" or "PostgreSQL password not found"

macOS Keychain requires user interaction to grant access on first use per application.
The recommended approach is `~/.pgpass` (see Step 2a) — it works reliably in all contexts.

For new Homebrew installs with trust auth (no password required):
```bash
export POSTGRES_TRUST_AUTH=true   # then re-run make db-init
```

For CI/CD environments, use environment variables:
```bash
export POSTGRES_PASSWORD=yourpassword
export TASK_TOKEN_SECRET=yoursecret
```

### Connector bot not responding

1. Confirm the gateway is running: `curl http://localhost:8080/metrics`
2. Confirm the connector started without error: check terminal output for the connector
3. Verify the API key stored in Keychain matches an active gateway user:
   ```bash
   make list-users
   ```
4. Check the connector is authorized: send a task via curl first to confirm the API key works

---

## Next Steps

- **Architecture deep-dive:** [`docs/architecture.md`](./architecture.md)
- **Horizontal scaling (multi-user, Redis, Nginx):** [`docs/SCALING.md`](./SCALING.md)
- **Threat model and security policy:** [`SECURITY.md`](../SECURITY.md)
- **Full phase history and component inventory:** [`TLDR.md`](../TLDR.md)
- **Product vision and roadmap:** [`docs/VISION.md`](./VISION.md)
