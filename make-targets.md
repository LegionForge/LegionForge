# LegionForge — Make Targets Reference

All commands assume the venv is active: `source venv/bin/activate`

---

## Help

| Target | Description | Arguments |
|--------|-------------|-----------|
| `help` | Display help text for all common commands | — |

---

## Startup / Shutdown

| Target | Description | Arguments |
|--------|-------------|-----------|
| `check` | Verify drive, venv, models, config, and Guardian before starting | — |
| `start` | Full startup: check → ollama-start → db-start → ollama-warm → guardian-start → servers-start | — |
| `stop` | Full shutdown — stops app servers, Guardian, PostgreSQL, and Ollama. **Prompts for confirmation.** Data is safe (clean shutdown). To resume without a full restart: `make db-start && make servers-start` | — |
| `restart` | Full stop + start — stops all services then runs `make start`. **Prompts for confirmation.** In-flight requests lost; data safe. | — |

---

## Server Management

| Target | Description | Arguments |
|--------|-------------|-----------|
| `servers-start` | Start health (:8765), gateway (:8080), and testlab (:8090) in background | — |
| `servers-stop` | Kill health, gateway, and testlab servers | — |
| `servers-restart` | Stop then restart all three servers | — |

---

## Health Server

| Target | Description | Arguments |
|--------|-------------|-----------|
| `health` | Quick liveness check (`/health`, no auth required) | — |
| `status` | Full system status (requires Bearer token from Keychain) | — |
| `health-server` | Start health server in foreground at http://localhost:8765 | — |
| `health-server-stop` | Kill the health server process on :8765 | — |
| `health-server-restart` | Stop then restart the health server | — |
| `health-token` | Print the stored health server Bearer token from Keychain | — |
| `usage` | Show API usage for last 24h (requires health server token) | — |

---

## Gateway

| Target | Description | Arguments |
|--------|-------------|-----------|
| `gateway-start` | Start LegionForge gateway in foreground at http://localhost:8080 | — |
| `create-user` | Create a gateway user | `USERNAME=<name>` `[DAILY_LIMIT=100000]` |
| `create-admin-user` | Create a gateway admin user | `USERNAME=<name>` `[DAILY_LIMIT=100000]` |
| `rotate-key` | Reset a user's API key (prints new key once) | `USERNAME=<name>` |
| `promote-admin` | Promote an existing user to admin | `USERNAME=<name>` |

---

## Database

| Target | Description | Arguments |
|--------|-------------|-----------|
| `db-start` | Start PostgreSQL 17 service | — |
| `db-stop` | Stop PostgreSQL 17 service | — |
| `db-init` | Initialize PostgreSQL database and all tables (one-time) | — |
| `db-shell` | Open interactive psql shell | — |
| `setup-db-roles` | Create `legionforge_app` PostgreSQL role + grants (idempotent) | — |

---

## Ollama (Native Homebrew)

| Target | Description | Arguments |
|--------|-------------|-----------|
| `ollama-start` | Start native Ollama service (Homebrew, Metal GPU) | — |
| `ollama-warm` | Warm up local models — loads llama3.1:8b + qwen2.5:3b (~30s) | — |
| `models` | List loaded Ollama models | — |

---

## Ollama (Docker — CPU-only)

| Target | Description | Arguments |
|--------|-------------|-----------|
| `ollama-docker-start` | Start Dockerised Ollama on internal network (CPU-only, 3–5x slower) | — |
| `ollama-docker-stop` | Stop Dockerised Ollama | — |
| `ollama-docker-logs` | Tail Dockerised Ollama logs | — |
| `ollama-docker-pull` | Pull required models into Dockerised Ollama | — |
| `ollama-docker-status` | Check Dockerised Ollama health and loaded models | — |

---

## Channel Connectors

| Target | Description | Arguments |
|--------|-------------|-----------|
| `discord-start` | Start Discord connector bot | `[DISCORD_GATEWAY_URL=http://localhost:8080]` |
| `telegram-start` | Start Telegram connector | `[TELEGRAM_GATEWAY_URL=http://localhost:8080]` |
| `slack-start` | Start Slack Socket Mode connector | `[SLACK_GATEWAY_URL=http://localhost:8080]` |
| `webhook-start` | Start Webhook connector | `[WEBHOOK_PORT=8081]` `[WEBHOOK_GATEWAY_URL=http://localhost:8080]` |

---

## Testing

| Target | Description | Arguments |
|--------|-------------|-----------|
| `test` | Run all test suites (smoke → testlab → ui in separate sessions) | — |
| `test-fast` | Smoke + TestLab + UI, excluding slow/LLM tests | — |
| `test-smoke` | 2133 smoke tests, ~21s, no external services required | — |
| `test-integration` | 38 integration tests (requires PostgreSQL — `make db-start` first) | — |
| `test-kerberos` | 5 live-KDC Kerberos tests | `[KERBEROS_TEST_KDC=1]` `[KERBEROS_REALM=TEST.LOCAL]` `[KERBEROS_KEYTAB=/tmp/test.keytab]` `[KERBEROS_TEST_USER=testuser]` `[KERBEROS_TEST_PASS=testpass]` |
| `test-all` | Single-session run of all tests (for CI/quick checks) | — |
| `test-ui` | 40 Playwright UI tests headless (separate pytest session) | — |
| `test-testlab-all` | All 110+ testlab_suite tests (excludes LLM/CVE tests, separate session) | — |
| `test-agent` | Live agent quality suite — submit real queries, assert structure, save transcripts. **Requires gateway + Ollama + `GATEWAY_API_KEY`.** Opt-in only; not part of `make test` or `make ci`. | `GATEWAY_API_KEY=<key>` `[GATEWAY_URL=http://localhost:8080]` `[AGENT_TRANSCRIPT_DIR=...]` |

---

## UI Tests (Playwright)

| Target | Description | Arguments |
|--------|-------------|-----------|
| `install-browsers` | Install Playwright Chromium browser (one-time) | — |
| `test-ui` | Run 40 Playwright UI tests headless | — |
| `test-ui-headed` | Run Playwright UI tests with visible browser (debug) | — |
| `test-ui-smoke` | Run quick page-load UI smoke subset | — |

---

## TestLab

| Target | Description | Arguments |
|--------|-------------|-----------|
| `build-testlab` | Build `legionforge-testlab:latest` Docker image | — |
| `testlab-start` | Start TestLab in Docker on :8090 (mounts live tests/ and src/) | `[TESTLAB_ADMIN_KEY=...]` |
| `testlab-stop` | Stop TestLab container | — |
| `testlab-dev` | Run TestLab locally without Docker (development mode) | `[TESTLAB_ADMIN_KEY=...]` |

---

## TestLab Attack Suite

| Target | Description | Arguments |
|--------|-------------|-----------|
| `test-functional` | 25 functional tests — mock gateway, no services | — |
| `test-security-attacks` | 35 security attack tests — injection, session, protocol | — |
| `test-dos` | 15 DoS resilience tests — flood, oversized body, protocol attacks | — |
| `test-auth-attacks` | 20 authentication attack tests — token replay, timing, multi-auth | — |
| `test-data-attacks` | 15 data/PII attack tests — exfiltration, cross-user isolation | — |
| `test-novel` | LLM-generated tests (requires Ollama) | — |
| `test-cve` | CVE-based tests from NVD API (requires network + Ollama) | — |
| `test-testlab-all` | All 110+ testlab_suite tests (excludes LLM/CVE tests) | — |

---

## Tool Accuracy Tests

| Target | Description | Arguments |
|--------|-------------|-----------|
| `test-tool-accuracy` | Tool unit tests — web_fetch/web_search accuracy, no LLM | — |
| `test-researcher-accuracy` | Researcher anti-hallucination tests (requires Ollama + PostgreSQL, ~90s) | — |
| `test-tool-all` | All tool accuracy tests (fast + LLM) | — |

---

## Gateway Docker

| Target | Description | Arguments |
|--------|-------------|-----------|
| `build-gateway` | Build `legionforge-gateway:latest` Docker image | — |
| `gateway-start-docker` | Run gateway in Docker | `POSTGRES_PASSWORD=...` `TASK_TOKEN_SECRET=...` |

---

## Gateway Test Client

| Target | Description | Arguments |
|--------|-------------|-----------|
| `build-testclient` | Build `legionforge-testclient:latest` Docker image | — |
| `test-gateway-basic` | Suite 1 — functional correctness (14 tests) | `[GATEWAY_URL=http://host.docker.internal:8080]` `GATEWAY_API_KEY=...` `[GATEWAY_API_KEY_2=...]` |
| `test-gateway-load` | Suite 2 — load and DoS resilience (8 tests) | `[GATEWAY_URL=...]` `GATEWAY_API_KEY=...` `[LOAD_CONCURRENCY=20]` `[LOAD_ITERATIONS=50]` `[HEALTH_SLA_MS=2000]` |
| `test-gateway-security` | Suite 3 — authorized security verification (12 tests) | `[GATEWAY_URL=...]` `GATEWAY_API_KEY=...` `[GATEWAY_API_KEY_2=...]` |
| `test-gateway-injection` | Suite 4 — injection and malicious input tests (35+ tests) | `[GATEWAY_URL=...]` `GATEWAY_API_KEY=...` |
| `test-gateway-all` | All four gateway test suites | `[GATEWAY_URL=...]` `GATEWAY_API_KEY=...` `[GATEWAY_API_KEY_2=...]` `[LOAD_CONCURRENCY=20]` `[LOAD_ITERATIONS=50]` `[HEALTH_SLA_MS=2000]` |
| `test-gateway-all-json` | All suites with JSON report output (for CI) | same as above |

---

## Code Quality

| Target | Description | Arguments |
|--------|-------------|-----------|
| `lint` | Black formatter check on src/, tests/, config/ | — |
| `format` | Auto-format code with Black | — |
| `js-check` | Syntax-check JS extracted from index.html via `node --check` | — |
| `security-audit` | Smoke tests + JS check + bandit static analysis + secret scan | — |
| `review-prep` | All PR gates: formatting + smoke + bandit + secret scan + dependency check + scope check | — |

---

## Tool Registry

| Target | Description | Arguments |
|--------|-------------|-----------|
| `register-http-tools` | Register http_get and http_post tools (one-time) | — |
| `register-file-tools` | Register file_read and file_write tools (one-time) | — |
| `register-code-tool` | Register code_execute tool (one-time) | — |
| `register-researcher-tools` | Register Researcher agent tools (one-time) | — |
| `register-orchestrator-tools` | Register Orchestrator agent tools (one-time) | — |
| `register-observer-tools` | Register Observer agent tools (one-time) | — |
| `register-observer-sequences` | Register Observer agent expected sequences (one-time) | — |
| `register-crystallizer-tools` | Register Crystallizer agent tools (one-time) | — |
| `register-crystallizer-sequences` | Register Crystallizer agent expected sequences (one-time) | — |
| `register-threat-analyst-tools` | Register Threat Analyst agent tools (one-time) | — |
| `register-agent-sequences` | Register all agent expected sequences (one-time) | — |
| `verify-tool-registry` | Verify all registered tools are APPROVED | — |
| `verify-model-integrity` | SHA256 hash-check Ollama model manifests (~30–120s) | — |
| `revoke-tool` | Revoke a registered tool immediately via health server | `TOOL_ID=<id>` `[REASON="..."]` |

---

## Guardian

| Target | Description | Arguments |
|--------|-------------|-----------|
| `guardian-start` | Start Guardian sidecar container on :9766 | `[TASK_TOKEN_SECRET=...]` |
| `guardian-stop` | Stop Guardian container | — |
| `guardian-logs` | Tail Guardian container logs | — |

---

## Docker

| Target | Description | Arguments |
|--------|-------------|-----------|
| `sandbox-build` | Build `legionforge-sandbox` Docker image | — |
| `build-analyzer` | Build `legionforge-analyzer:latest` Docker image | — |
| `build-pentest` | Build `legionforge-pentest:latest` Docker image (air-gapped) | — |
| `docker-build` | Build all Docker images | — |
| `docker-up` | Start all Docker services | — |

---

## Run Agents

| Target | Description | Arguments |
|--------|-------------|-----------|
| `run-researcher` | Run Researcher agent | `[TASK="..."]` |
| `run-threat-analyst` | Run Threat Analyst agent (7-day threat window) | — |
| `run-observer` | Run Observer agent | `[OBSERVER_HOURS=168]` `[OBSERVER_MIN_OCC=3]` |
| `run-crystallizer` | Run Crystallizer agent for a candidate package | `CANDIDATE_ID=<id>` |
| `pentest` | Run PentestAgent in verify mode (stop at proof-of-concept) | `[POSTGRES_HOST=host.docker.internal]` `[AGENT_HARDWARE_PROFILE=mac_m4_mini_16gb]` |
| `pentest-resilience` | Run PentestAgent in resilience mode (measures blast radius) | same as above |
| `pentest-report` | Print latest pentest report (Markdown) | `[RUN_ID=<uuid>]` (default: latest) |

---

## Documents & Memory

| Target | Description | Arguments |
|--------|-------------|-----------|
| `docs-ingest` | Ingest a file into the RAG namespace | `FILE=path/to/file.txt` `[NS=global]` |
| `docs-list` | List documents in a namespace | `[NS=global]` `[LIMIT=20]` |
| `memory-stats` | Show agent memory stats for all namespaces | — |
| `memory-search` | Semantic search agent memory | `Q="your query"` `[NS=namespace]` |
| `memory-ingest` | Ingest a text file into agent memory | `FILE=path/to/file.txt` `[NS=namespace]` |

---

## Scheduled Tasks

| Target | Description | Arguments |
|--------|-------------|-----------|
| `schedule-list` | List all scheduled tasks | `[USER=user_id]` |
| `schedule-create` | Create a scheduled task | `USER=<uid>` `NAME="label"` `CRON="@daily"` `TASK="..."` `[AGENT=orchestrator]` |

---

## Crystallization Review

| Target | Description | Arguments |
|--------|-------------|-----------|
| `pending-packages` | Show candidates awaiting crystallization approval | — |
| `approve-package` | Approve a crystallization package | `PACKAGE_ID=<id>` |
| `reject-package` | Reject a crystallization package | `PACKAGE_ID=<id>` `[REASON="..."]` |

---

## Threat Rules

| Target | Description | Arguments |
|--------|-------------|-----------|
| `bom` | Show AI Bill of Materials (requires health server) | — |
| `pending-rules` | Show threat rules awaiting approval | — |

---

## Audit

| Target | Description | Arguments |
|--------|-------------|-----------|
| `audit-log-verify` | Verify audit log SHA-256 hash chain integrity | — |
| `db-maintenance` | Run DB maintenance — prune stale rows per retention config | — |

---

## One-Time Setup

| Target | Description | Arguments |
|--------|-------------|-----------|
| `setup-task-token-secret` | Generate and store JWT task token signing secret in Keychain | — |
| `setup-signing-key` | Generate Ed25519 signing keypair and store in Keychain | — |
| `init-credentials-file` | Create credentials file template at `~/.config/legionforge/credentials.yaml` (chmod 0600) | — |
| `credential-store-status` | Show CredentialStore status — which services are loaded | — |
| `install-launch-agent` | Install `com.legionforge.check-agent-drive` LaunchAgent | — |
| `install` | Install/update Python packages from requirements.txt | — |

---

## Git & Logs

| Target | Description | Arguments |
|--------|-------------|-----------|
| `git-status` | Show git status | — |
| `dev-branch` | Create and switch to dev branch (or switch if exists) | — |
| `logs` | Tail the agent log (live JSON streaming) | — |
| `clean-logs` | Remove logs older than 30 days | — |
| `cluster-status` | Show Ollama cluster health across all configured nodes | — |
