# ============================================================
# Makefile — LegionForge
# Usage: make <target>
# ============================================================

BASE    := $(shell git rev-parse --show-toplevel 2>/dev/null || pwd)
VENV    := $(BASE)/venv
PYTHON  := $(VENV)/bin/python
PIP     := $(VENV)/bin/pip
PYTEST  := $(VENV)/bin/pytest

# ── Inline Python scripts ──────────────────────────────────────
# Used by targets that need async code with nested blocks.
# Python's -c flag can't express nested compound statements (async def + async with)
# when lines are joined by Make's \ continuation. These define blocks pass the
# script to Python via stdin instead: echo "$$_SCRIPT_VAR" | $(PYTHON)

define _SETUP_DB_ROLES_PY
import asyncio, os, psycopg
from src.database import _get_postgres_password, _setup_db_roles

async def run():
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    db   = os.environ.get("POSTGRES_DB", "legionforge")
    user = os.environ.get("POSTGRES_USER", os.environ.get("USER", "postgres"))
    pw   = _get_postgres_password()
    dsn  = f"host={host} port={port} dbname={db} user={user} password={pw}"
    conn = await psycopg.AsyncConnection.connect(dsn, autocommit=True)
    await _setup_db_roles(conn)
    await conn.close()
    print("✅ legionforge_app role + grants configured")

asyncio.run(run())
endef
export _SETUP_DB_ROLES_PY

define _VERIFY_MODELS_PY
import asyncio
from src.tools.model_integrity import compute_model_hashes
from config.settings import settings

async def run():
    hashes = await compute_model_hashes(settings)
    print()
    print("Pin these values in config/hardware_profiles/mac_m4_mini_16gb.yaml:")
    for model_id, h in hashes.items():
        if h:
            print(f"  {model_id}: {h}")
        else:
            print(f"  {model_id}: NOT FOUND")

asyncio.run(run())
endef
export _VERIFY_MODELS_PY

define _REGISTER_SEQUENCES_PY
import asyncio
from src.database import init_db, register_agent_sequences
from src.agents.researcher import RESEARCHER_EXPECTED_SEQUENCES
from src.agents.observer import OBSERVER_EXPECTED_SEQUENCES
from src.agents.crystallizer import CRYSTALLIZER_EXPECTED_SEQUENCES

async def run():
    await init_db()
    await register_agent_sequences("researcher", RESEARCHER_EXPECTED_SEQUENCES)
    print(f"  ✅ researcher: {len(RESEARCHER_EXPECTED_SEQUENCES)} sequences")
    await register_agent_sequences("observer", OBSERVER_EXPECTED_SEQUENCES)
    print(f"  ✅ observer:   {len(OBSERVER_EXPECTED_SEQUENCES)} sequences")
    await register_agent_sequences("crystallizer", CRYSTALLIZER_EXPECTED_SEQUENCES)
    print(f"  ✅ crystallizer: {len(CRYSTALLIZER_EXPECTED_SEQUENCES)} sequences")

asyncio.run(run())
endef
export _REGISTER_SEQUENCES_PY

.DEFAULT_GOAL := help

# ── Help ──────────────────────────────────────────────────────
.PHONY: help
help:
	@echo ""
	@echo "  LegionForge"
	@echo "  ─────────────────────────────────────────────────"
	@echo "  make check        — verify drive, venv, models, config, Guardian"
	@echo "  make start        — full startup sequence (includes Guardian)"
	@echo "  make stop         — full shutdown: servers + Guardian + PostgreSQL + Ollama (prompts)"
	@echo "  make restart      — full stop then start (prompts — stops and restarts DB + Ollama)"
	@echo "  make status       — print system status (curl /status, needs token)"
	@echo "  make health       — quick liveness check (curl /health)"
	@echo "  make health-server — start health server in foreground"
	@echo "  make health-token — print stored health server Bearer token"
	@echo "  make db-init      — initialize PostgreSQL and tables"
	@echo "  make db-start     — start PostgreSQL service"
	@echo "  make db-stop      — stop PostgreSQL service"
	@echo "  make ollama-start — start native Ollama service (Homebrew, Metal GPU)"
	@echo "  make ollama-warm  — warm up local models"
	@echo "  make ollama-docker-start — start Dockerised Ollama (CPU-only, internal network)"
	@echo "  make ollama-docker-stop  — stop Dockerised Ollama"
	@echo "  make ollama-docker-pull  — pull models into Dockerised Ollama"
	@echo "  make ollama-docker-status — check Dockerised Ollama health"
	@echo "  make models       — list loaded Ollama models"
	@echo "  make install      — install/update Python packages"
	@echo "  make test         — run all tests"
	@echo "  make test-fast    — run tests excluding slow ones"
	@echo "  make test-integration — run integration tests (requires PostgreSQL)"
	@echo "  make test-all     — run smoke + integration tests"
	@echo "  make test-ui      — run 40 Playwright UI tests (headless Chromium)"
	@echo "  make test-ui-headed — run UI tests with browser visible (debug)"
	@echo "  make install-browsers — install Playwright Chromium (one-time)"
	@echo "  make build-testlab  — build legionforge-testlab Docker image (Phase 18)"
	@echo "  make testlab-start  — start TestLab admin UI on :8090 (Docker)"
	@echo "  make testlab-stop   — stop TestLab container"
	@echo "  make testlab-dev    — run TestLab locally without Docker"
	@echo "  make test-functional     — 25 functional gateway tests (mock, no services)"
	@echo "  make test-security-attacks — 35 security attack tests (mock)"
	@echo "  make test-dos        — 15 DOS resilience tests (mock)"
	@echo "  make test-auth-attacks — 20 auth attack tests (mock)"
	@echo "  make test-data-attacks — 15 data/PII attack tests (mock)"
	@echo "  make test-novel      — LLM-generated tests (requires Ollama)"
	@echo "  make test-cve        — CVE-based tests (requires network + Ollama)"
	@echo "  make test-testlab-all — all 110+ testlab_suite tests"
	@echo "  make build-gateway    — build legionforge-gateway Docker image (Phase 11)"
	@echo "  make gateway-start-docker — run gateway in Docker (Phase 11)"
	@echo "  make lint         — run black formatter check"
	@echo "  make format       — auto-format with black"
	@echo "  make security-audit — smoke tests + bandit static analysis"
	@echo "  make review-prep  — all automated gates for PR review (run before manual review)"
	@echo "  make setup-task-token-secret — generate and store JWT signing secret (one-time)"
	@echo "  make register-threat-analyst-tools — register Phase 4 tools (one-time)"
	@echo "  make run-threat-analyst — run Threat Analyst agent (7-day window)"
	@echo "  make run-researcher     — run Researcher agent (set TASK=\"...\" to customise)"
	@echo "  make bom             — show AI Bill of Materials"
	@echo "  make pending-rules   — show threat rules awaiting approval"
	@echo "  make register-researcher-tools — register Phase 1 tools (one-time)"
	@echo "  make register-orchestrator-tools — register Phase 3 orchestrator tools (one-time)"
	@echo "  make register-agent-sequences — register Researcher expected sequences"
	@echo "  make verify-tool-registry — verify all registered tools are APPROVED"
	@echo "  make verify-model-integrity — hash-check Ollama model manifests"
	@echo "  make audit-log-verify — verify audit log hash chain integrity"
	@echo "  make setup-db-roles  — create legionforge_app PostgreSQL role + grants (Phase 6)"
	@echo "  make verify-models   — compute SHA256 of GGUF files for hash pinning (Phase 6)"
	@echo "  make build-analyzer  — build legionforge-analyzer:latest Docker image (Phase 6)"
	@echo "  make revoke-tool     — revoke a tool: make revoke-tool TOOL_ID=<id> (Phase 6)"
	@echo "  make build-pentest   — build legionforge-pentest:latest Docker image (Phase 6)"
	@echo "  make pentest         — run pentest in verify mode (stop-at-proof) (Phase 6)"
	@echo "  make pentest-resilience — run pentest in resilience mode, explicit opt-in (Phase 6)"
	@echo "  make pentest-report  — print latest pentest report (Phase 6)"
	@echo "  make guardian-start — start Guardian container"
	@echo "  make guardian-stop  — stop Guardian container"
	@echo "  make guardian-logs  — tail Guardian container logs"
	@echo "  make docker-build   — build all Docker images"
	@echo "  make docker-up      — start all Docker services"
	@echo "  make git-status   — show git status"
	@echo "  make dev-branch   — create and switch to dev branch"
	@echo "  make logs         — tail the agent log"
	@echo "  make clean-logs   — remove logs older than 30 days"
	@echo "  make usage        — show API usage for last 24h"
	@echo ""

# ── Startup / Shutdown ────────────────────────────────────────
.PHONY: check
check:
	@echo "🔍 Running system check..."
	@$(BASE)/scripts/check_mount.sh --create-dirs
	@$(PYTHON) -c "from config.settings import settings" 2>/dev/null && \
		echo "✅ Config loaded" || echo "❌ Config failed"
	@$(PYTHON) -c "from src.security import get_api_key_optional; \
		k = get_api_key_optional('langsmith'); \
		print('✅ LangSmith key found' if k else '⚠️  LangSmith key not found')"
	@if [ -n "$$POSTGRES_PASSWORD" ]; then \
		echo "✅ Keychain: postgres password loaded"; \
	else \
		echo "⚠️  Keychain: postgres password NOT loaded — source ~/.zshrc or run: python3 -m keyring set postgres api_key"; \
	fi
	@curl -s --max-time 2 http://localhost:9766/health >/dev/null 2>&1 && \
		echo "✅ Guardian sidecar healthy" || \
		echo "⚠️  Guardian not running (warning only) — run: make guardian-start"

.PHONY: start
start: check ollama-start db-start ollama-warm docker-start guardian-start servers-start
	@echo ""
	@echo "✅ Framework ready."
	@echo "   Health  → http://localhost:8765/health"
	@echo "   Gateway → http://localhost:8080"
	@echo "   TestLab → http://localhost:8090"
	@echo "   Run 'make test' to verify everything is working."

.PHONY: stop
stop:
	@printf "\n⚠️  FULL SHUTDOWN\n"
	@printf "   Stops: app servers, Guardian, PostgreSQL 17, Ollama\n"
	@printf "   In-flight requests will be lost. Data is safe (clean shutdown).\n"
	@printf "   To resume without a full restart: make db-start && make servers-start\n\n"
	@printf "Proceed? [y/N] "; \
	  read _ans; \
	  [ "$$_ans" = "y" ] || [ "$$_ans" = "Y" ] || { echo "Aborted."; exit 1; }
	@echo ""
	@$(MAKE) --no-print-directory servers-stop
	@echo "Stopping infrastructure services..."
	@docker-compose stop guardian 2>/dev/null || true
	@echo "   Guardian stopped."
	@brew services stop postgresql@17 2>/dev/null || true
	@echo "   PostgreSQL stopped."
	@brew services stop ollama 2>/dev/null || true
	@echo "   Ollama stopped."
	@echo ""
	@echo "✅ All services stopped."
	@echo "   → Full restart:               make start"
	@echo "   → App servers only:           make db-start && make servers-start"

.PHONY: restart
restart:  ## Full stop + start with confirmation prompt (stops and restarts DB + Ollama)
	@printf "\n⚠️  FULL RESTART\n"
	@printf "   All services (PostgreSQL 17, Ollama, Guardian, app servers) will be\n"
	@printf "   stopped then started fresh. In-flight requests will be lost.\n"
	@printf "   Data is safe — PostgreSQL shuts down cleanly before restart.\n\n"
	@printf "Proceed? [y/N] "; \
	  read _ans; \
	  [ "$$_ans" = "y" ] || [ "$$_ans" = "Y" ] || { echo "Aborted."; exit 1; }
	@echo ""
	@echo "── Stopping all services ──────────────────────────────────────────"
	@$(MAKE) --no-print-directory servers-stop
	@docker-compose stop guardian 2>/dev/null || true
	@echo "   Guardian stopped."
	@brew services stop postgresql@17 2>/dev/null || true
	@echo "   PostgreSQL stopped."
	@brew services stop ollama 2>/dev/null || true
	@echo "   Ollama stopped."
	@echo ""
	@echo "── Starting all services ──────────────────────────────────────────"
	@$(MAKE) --no-print-directory start

## ── Server management (health + gateway + testlab) ────────────
.PHONY: servers-start
servers-start:  ## Start health-server (:8765), gateway (:8080), and testlab (:8090) in background
	@echo "Starting health server on :8765..."
	@cd $(BASE) && $(PYTHON) -m src.health &
	@sleep 1
	@echo "Starting gateway on :8080..."
	@cd $(BASE) && \
	  POSTGRES_PASSWORD=$${POSTGRES_PASSWORD:-$$(security find-generic-password -s postgres -a api_key -w 2>/dev/null || echo "")} \
	  TOOL_SIGNING_PRIVATE_KEY=$$(security find-generic-password -s legionforge_tool_signer -a api_key -w 2>/dev/null || echo "") \
	  $(PYTHON) -m src.gateway.app &
	@sleep 1
	@echo "Starting TestLab on :8090..."
	@cd $(BASE) && \
	  TESTLAB_ADMIN_KEY=$${TESTLAB_ADMIN_KEY:-$$(security find-generic-password -s legionforge_health -a api_key -w 2>/dev/null)} \
	  $(PYTHON) -m uvicorn src.testlab.app:app --host 0.0.0.0 --port 8090 &
	@sleep 1
	@echo ""
	@echo "✅ Servers started:"
	@echo "   Health  → http://localhost:8765/health"
	@echo "   Gateway → http://localhost:8080"
	@echo "   TestLab → http://localhost:8090"

.PHONY: servers-stop
servers-stop:  ## Kill health-server (:8765), gateway (:8080), and testlab (:8090)
	@echo "Stopping servers..."
	@lsof -ti :8765 | xargs kill 2>/dev/null || true
	@lsof -ti :8080 | xargs kill 2>/dev/null || true
	@lsof -ti :8090 | xargs kill 2>/dev/null || true
	@echo "✅ Servers stopped (8765, 8080, 8090)"

.PHONY: servers-restart
servers-restart: servers-stop servers-start  ## Restart all three servers

# ── Health & Status ───────────────────────────────────────────
.PHONY: health
health:
	@curl -s http://localhost:8765/health | python3 -m json.tool 2>/dev/null \
		|| echo "⚠️  Health server not running. Start with: make health-server"

.PHONY: status
status:
	@TOKEN=$$(security find-generic-password -s legionforge_health -a api_key -w 2>/dev/null) && \
	curl -s -H "Authorization: Bearer $$TOKEN" http://localhost:8765/status | python3 -m json.tool 2>/dev/null \
		|| echo "⚠️  Health server not running or token missing. Start with: make health-server"

.PHONY: health-server
health-server:
	@echo "Starting health server at http://localhost:8765 ..."
	@cd $(BASE) && $(PYTHON) -m src.health

# ── Gateway (Phase 8) ──────────────────────────────────────────
.PHONY: gateway-start
gateway-start:
	@echo "Starting LegionForge gateway at http://localhost:8080 ..."
	@cd $(BASE) && $(PYTHON) -m src.gateway.app

.PHONY: create-user
create-user:
	@if [ -z "$(USERNAME)" ]; then echo "Usage: make create-user USERNAME=<name> [DAILY_LIMIT=100000]"; exit 1; fi
	@cd $(BASE) && $(PYTHON) -m src.cli.manage_users create-user \
		--username "$(USERNAME)" \
		$(if $(DAILY_LIMIT),--daily-limit $(DAILY_LIMIT),)

.PHONY: create-admin-user
create-admin-user:  ## Create a gateway admin user: make create-admin-user USERNAME=<name> (Phase 24)
	@if [ -z "$(USERNAME)" ]; then echo "Usage: make create-admin-user USERNAME=<name> [DAILY_LIMIT=100000]"; exit 1; fi
	@cd $(BASE) && $(PYTHON) -m src.cli.manage_users create-user \
		--username "$(USERNAME)" \
		--admin \
		$(if $(DAILY_LIMIT),--daily-limit $(DAILY_LIMIT),)

.PHONY: rotate-key
rotate-key:  ## Reset a user's API key: make rotate-key USERNAME=<name>
	@if [ -z "$(USERNAME)" ]; then echo "Usage: make rotate-key USERNAME=<name>"; exit 1; fi
	@cd $(BASE) && $(PYTHON) -m src.cli.manage_users rotate-key --username "$(USERNAME)"

.PHONY: promote-admin
promote-admin:  ## Promote an existing user to admin: make promote-admin USERNAME=<name> (Phase 24)
	@if [ -z "$(USERNAME)" ]; then echo "Usage: make promote-admin USERNAME=<name>"; exit 1; fi
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.database import init_db, close_db, promote_gateway_user_to_admin; \
async def run(): \
    await init_db(); \
    ok = await promote_gateway_user_to_admin('$(USERNAME)', True); \
    await close_db(); \
    print('✅ $(USERNAME) promoted to admin' if ok else '❌ user not found'); \
asyncio.run(run())"

# ── Phase 9: Tool Library ──────────────────────────────────────
.PHONY: register-http-tools
register-http-tools:
	@echo "Registering Phase 9 HTTP tools..."
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.tools.http_tools import register_http_tools; \
asyncio.run(register_http_tools()); \
print('✅ http_get + http_post registered')"

.PHONY: register-file-tools
register-file-tools:
	@echo "Registering Phase 9 file tools..."
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.tools.file_tools import register_file_tools; \
asyncio.run(register_file_tools()); \
print('✅ file_read + file_write registered')"

.PHONY: register-code-tool
register-code-tool:
	@echo "Registering Phase 9 code_execute tool..."
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.tools.code_tools import register_code_tool; \
asyncio.run(register_code_tool()); \
print('✅ code_execute registered')"

.PHONY: sandbox-build
sandbox-build:
	@echo "Building legionforge-sandbox Docker image..."
	docker build -f Dockerfile.sandbox -t legionforge-sandbox:latest .
	@echo "✅ legionforge-sandbox:latest built"

# ── Channel Connectors (Phase 8 / Phase 16) ────────────────────
.PHONY: discord-start
discord-start:
	@echo "Starting Discord connector (gateway=$(DISCORD_GATEWAY_URL:-http://localhost:8080)) ..."
	@cd $(BASE) && $(PYTHON) -m src.connectors.discord

.PHONY: telegram-start
telegram-start:
	@echo "Starting Telegram connector (gateway=$(TELEGRAM_GATEWAY_URL:-http://localhost:8080)) ..."
	@cd $(BASE) && $(PYTHON) -m src.connectors.telegram

.PHONY: slack-start
slack-start:
	@echo "Starting Slack Socket Mode connector (gateway=$(SLACK_GATEWAY_URL:-http://localhost:8080)) ..."
	@cd $(BASE) && $(PYTHON) -m src.connectors.slack

.PHONY: webhook-start
webhook-start:
	@echo "Starting Webhook connector (port=$(WEBHOOK_PORT:-8081) gateway=$(WEBHOOK_GATEWAY_URL:-http://localhost:8080)) ..."
	@cd $(BASE) && $(PYTHON) -m src.connectors.webhook

.PHONY: health-token
health-token:
	@TOKEN=$$(security find-generic-password -s legionforge_health -a api_key -w 2>/dev/null) && \
	echo "Health server Bearer token:" && echo "  $$TOKEN" \
		|| echo "⚠️  Token not found in Keychain. Start health server once to generate it: make health-server"

.PHONY: usage
usage:
	@TOKEN=$$(security find-generic-password -s legionforge_health -a api_key -w 2>/dev/null) && \
	curl -s -H "Authorization: Bearer $$TOKEN" http://localhost:8765/usage | python3 -m json.tool 2>/dev/null \
		|| echo "⚠️  Health server not running or token missing. Start with: make health-server"

# ── Database ──────────────────────────────────────────────────
.PHONY: db-start
db-start:
	@brew services start postgresql@17 2>/dev/null || true
	@printf "   Waiting for PostgreSQL to accept connections"; \
	for i in $$(seq 1 20); do \
		if pg_isready -U "$${POSTGRES_USER:-jp}" -d legionforge -q 2>/dev/null; then \
			printf " ✅\n"; break; \
		fi; \
		printf "."; sleep 1; \
		if [ "$$i" = "20" ]; then printf " ❌ timed out (20s)\n"; exit 1; fi; \
	done
	@echo "✅ PostgreSQL started"

.PHONY: db-stop
db-stop:
	@brew services stop postgresql@17
	@echo "✅ PostgreSQL stopped"

.PHONY: db-init
db-init:
	@echo "Initializing PostgreSQL database and tables..."
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.database import init_db; \
asyncio.run(init_db()); \
print('✅ Database initialized')"

.PHONY: db-shell
db-shell:
	@psql -U "$${POSTGRES_USER:-jpc}" -d legionforge

# ── Ollama (native Homebrew) ───────────────────────────────────
.PHONY: ollama-start
ollama-start:
	@brew services start ollama 2>/dev/null || true
	@sleep 2
	@echo "✅ Ollama started"

## ── Dockerised Ollama (internal network, CPU-only on Apple Silicon) ─────────
# ⚠ On Apple Silicon, containerised Ollama runs CPU-only (no Metal GPU).
#   Inference is 3–5x slower than native Homebrew Ollama.
#   Use for Linux/cloud deployments or when GPU access isn't required.
#   Gateway/agents must set OLLAMA_BASE_URL=http://ollama:11434 (container)
#   or http://localhost:11436 (host, only if port is exposed).
.PHONY: ollama-docker-start
ollama-docker-start:  ## Start Dockerised Ollama on internal network (CPU-only on Apple Silicon)
	@echo "⚠️  Starting Dockerised Ollama (CPU-only on Apple Silicon — 3–5x slower than native)"
	@docker-compose --profile ollama-docker up -d ollama
	@echo "Waiting for Ollama to be ready..."
	@for i in $$(seq 1 30); do \
	  docker exec legionforge-ollama curl -sf http://localhost:11434/api/tags > /dev/null 2>&1 && break; \
	  sleep 2; \
	done
	@echo "✅ Dockerised Ollama running (internal network only — not exposed to host)"
	@echo "   Containers reach it at: http://ollama:11434"
	@echo "   Pull models: make ollama-docker-pull"

.PHONY: ollama-docker-stop
ollama-docker-stop:  ## Stop Dockerised Ollama
	@docker-compose --profile ollama-docker stop ollama
	@echo "✅ Dockerised Ollama stopped"

.PHONY: ollama-docker-logs
ollama-docker-logs:  ## Tail Dockerised Ollama logs
	@docker logs -f legionforge-ollama

.PHONY: ollama-docker-pull
ollama-docker-pull:  ## Pull required models into Dockerised Ollama
	@echo "Pulling models into Dockerised Ollama..."
	@echo "  ⏳ llama3.1:8b (primary agent — ~4.7GB)"
	@docker exec legionforge-ollama ollama pull llama3.1:8b
	@echo "  ⏳ qwen2.5:3b (router — ~1.9GB)"
	@docker exec legionforge-ollama ollama pull qwen2.5:3b
	@echo "  ⏳ nomic-embed-text (embeddings — ~274MB)"
	@docker exec legionforge-ollama ollama pull nomic-embed-text
	@echo "✅ Models pulled into Dockerised Ollama"

.PHONY: ollama-docker-status
ollama-docker-status:  ## Check Dockerised Ollama health and loaded models
	@docker exec legionforge-ollama ollama list 2>/dev/null \
	  && echo "✅ Dockerised Ollama healthy" \
	  || echo "❌ Dockerised Ollama not running — run: make ollama-docker-start"

.PHONY: docs-ingest
docs-ingest:  ## Ingest a file into the global RAG namespace: make docs-ingest FILE=path [NS=global] (Phase 22)
	@[ -n "$(FILE)" ] || (echo "Usage: make docs-ingest FILE=path/to/file.txt [NS=global]" && exit 1)
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.database import init_db, close_db; \
from src.ingestor import DocumentIngestor; \
async def run(): \
    await init_db(); \
    ns = '$(NS)' if '$(NS)' else 'global'; \
    ingestor = DocumentIngestor(); \
    ids = await ingestor.ingest_file('$(FILE)', namespace=ns); \
    await close_db(); \
    print(f'  Ingested {len(ids)} chunk(s) from $(FILE) → namespace \"{ns}\"'); \
asyncio.run(run())"

.PHONY: docs-list
docs-list:  ## List documents in a namespace: make docs-list [NS=global] [LIMIT=20] (Phase 22)
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.database import init_db, close_db; \
from src.ingestor import DocumentIngestor; \
async def run(): \
    await init_db(); \
    ns = '$(NS)' if '$(NS)' else 'global'; \
    limit = int('$(LIMIT)') if '$(LIMIT)' else 20; \
    docs = await DocumentIngestor().list_documents(ns, limit=limit); \
    await close_db(); \
    if not docs: print(f'  (no documents in namespace \"{ns}\")'); return; \
    [print(f'  [{d[\"id\"]:6d}] {d[\"created_at\"][:19]}  {d[\"content_preview\"][:80]}') for d in docs]; \
asyncio.run(run())"

# ── Phase 23: Scheduled tasks ─────────────────────────────────────────────────

.PHONY: schedule-list
schedule-list:  ## List all scheduled tasks for USER (default: admin): make schedule-list [USER=user_id] (Phase 23)
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.database import init_db, close_db, list_scheduled_tasks; \
async def run(): \
    await init_db(); \
    uid = '$(USER)' if '$(USER)' else 'admin'; \
    schedules = await list_scheduled_tasks(uid); \
    await close_db(); \
    if not schedules: print(f'  (no schedules for user \"{uid}\")'); return; \
    [print(f'  [{s[\"id\"]:4d}] {\"✓\" if s[\"enabled\"] else \"✗\"}  {s[\"cron_expr\"]:20s}  next={s[\"next_run_at\"][:19]}  {s[\"name\"]}') for s in schedules]; \
asyncio.run(run())"

.PHONY: schedule-create
schedule-create:  ## Create a scheduled task: make schedule-create USER=uid NAME="label" CRON="@daily" TASK="..." [AGENT=orchestrator] (Phase 23)
	@[ -n "$(USER)" ] || (echo "Usage: make schedule-create USER=uid NAME='label' CRON='@daily' TASK='...' [AGENT=orchestrator]" && exit 1)
	@[ -n "$(NAME)" ] || (echo "NAME is required" && exit 1)
	@[ -n "$(CRON)" ] || (echo "CRON is required" && exit 1)
	@[ -n "$(TASK)" ] || (echo "TASK is required" && exit 1)
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.database import init_db, close_db, create_scheduled_task; \
async def run(): \
    await init_db(); \
    s = await create_scheduled_task('$(USER)', '$(NAME)', '$(TASK)', '$(CRON)', '$(AGENT)' or 'orchestrator'); \
    await close_db(); \
    print(f'Created schedule {s[\"id\"]}: {s[\"name\"]} ({s[\"cron_expr\"]}) next={s[\"next_run_at\"][:19]}'); \
asyncio.run(run())"

.PHONY: memory-stats
memory-stats:  ## Show agent memory stats for all namespaces (Phase 21 — requires PostgreSQL)
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.database import init_db, close_db, get_pool; \
async def run(): \
    await init_db(); \
    pool = get_pool(); \
    async with pool.connection() as conn: \
        rows = await conn.fetch('SELECT namespace, COUNT(*) as n, MIN(created_at) as oldest, MAX(created_at) as newest FROM documents GROUP BY namespace ORDER BY n DESC'); \
    await close_db(); \
    if not rows: print('  (no documents stored yet)'); return; \
    [print(f'  {r[\"namespace\"]:40s} {r[\"n\"]:6d} docs  oldest={str(r[\"oldest\"])[:19]}  newest={str(r[\"newest\"])[:19]}') for r in rows]; \
asyncio.run(run())"

.PHONY: memory-search
memory-search:  ## Semantic search agent memory: make memory-search Q="your query" NS="namespace" (Phase 21)
	@[ -n "$(Q)" ] || (echo "Usage: make memory-search Q='your query' [NS=namespace]" && exit 1)
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.database import init_db, close_db; \
from src.memory import get_memory_store; \
async def run(): \
    await init_db(); \
    store = get_memory_store(); \
    ns = '$(NS)' if '$(NS)' else 'global'; \
    results = await store.search('$(Q)', namespace=ns, limit=10, min_similarity=0.5); \
    await close_db(); \
    if not results: print('  No results found in namespace: ' + ns); return; \
    print(f'  Results in namespace \"{ns}\":'); \
    [print(f'  [{i+1}] sim={r[\"similarity\"]:.3f}  {r[\"content\"][:120]}') for i,r in enumerate(results)]; \
asyncio.run(run())"

.PHONY: memory-ingest
memory-ingest:  ## Ingest a text file into agent memory: make memory-ingest FILE=path [NS=namespace] (Phase 21)
	@[ -n "$(FILE)" ] || (echo "Usage: make memory-ingest FILE=path/to/file.txt [NS=namespace]" && exit 1)
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.database import init_db, close_db; \
from src.memory import get_memory_store; \
async def run(): \
    await init_db(); \
    content = open('$(FILE)').read(); \
    store = get_memory_store(); \
    ns = '$(NS)' if '$(NS)' else 'global'; \
    doc_id = await store.store(content, namespace=ns, metadata={'source': '$(FILE)'}); \
    await close_db(); \
    print(f'  Stored doc #{doc_id} in namespace \"{ns}\" ({len(content)} chars)'); \
asyncio.run(run())"

.PHONY: cluster-status
cluster-status:  ## Show Ollama cluster health — checks all configured nodes (Phase 20)
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.ollama_cluster import get_cluster_manager; \
mgr = get_cluster_manager(); \
if not mgr._nodes: \
    print('No cluster nodes configured (single-node mode).'); \
    from config.settings import settings; \
    print(f'  Primary Ollama: {settings.local_services.ollama.resolved_url()}'); \
else: \
    statuses = asyncio.run(mgr.check_all()); \
    [print(f'  {s.label:20s} {s.url:35s} {\"✅\" if s.healthy else \"❌\"} {s.latency_ms:.0f}ms  {chr(34) + \", \".join(s.models[:3]) + chr(34) if s.healthy else s.error[:60]}') for s in statuses]"

.PHONY: ollama-warm
ollama-warm:
	@echo "Warming up local models (this takes ~30s)..."
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.llm_factory import warmup_local_models; \
results = asyncio.run(warmup_local_models()); \
[print(f'  {k}: {\"✅\" if v else \"❌\"}') for k, v in results.items()]"

.PHONY: models
models:
	@OLLAMA_MODELS=$(BASE)/models/ollama ollama list

# ── Python Environment ────────────────────────────────────────
.PHONY: install
install:
	@$(PIP) install --upgrade pip -q
	@$(PIP) install -r $(BASE)/requirements.txt -q
	@echo "✅ Packages installed"

.PHONY: lock
lock:  ## Pin all transitive deps → requirements.lock (run after any requirements.txt change)
	@$(PIP) install pip-tools --quiet
	@cd $(BASE) && pip-compile requirements.txt \
		--output-file requirements.lock \
		--no-strip-extras \
		--annotation-style line \
		--quiet
	@echo "✅ requirements.lock updated"

.PHONY: install-locked
install-locked:  ## Install exact pinned versions from requirements.lock (use for reproducible envs)
	@$(PIP) install --upgrade pip -q
	@$(PIP) install -r $(BASE)/requirements.lock -q
	@echo "✅ Packages installed from lock file"

# ── Testing ───────────────────────────────────────────────────
.PHONY: test
test:
	@echo "▶ Smoke tests…"
	@cd $(BASE) && $(PYTEST) tests/test_smoke.py -v
	@echo "▶ TestLab suite…"
	@cd $(BASE) && $(PYTEST) tests/testlab_suite/ -v --tb=short
	@echo "▶ UI tests…"
	@cd $(BASE) && $(PYTEST) tests/ui/ -v -m ui
	@echo "✅ All test suites passed"

.PHONY: test-fast
test-fast:
	@echo "▶ Smoke tests (not slow)…"
	@cd $(BASE) && $(PYTEST) tests/test_smoke.py -v -m "not slow"
	@echo "▶ TestLab suite (not slow)…"
	@cd $(BASE) && $(PYTEST) tests/testlab_suite/ -v -m "not slow" --tb=short
	@echo "▶ UI tests…"
	@cd $(BASE) && $(PYTEST) tests/ui/ -v -m ui
	@echo "✅ Fast test suites passed"

.PHONY: test-critical
test-critical:  ## Fast iteration gate (~35s): smoke + security_attacks + UI page-load
	@echo "▶ Smoke tests…"
	@cd $(BASE) && $(PYTEST) tests/test_smoke.py -q
	@echo "▶ Security attack tests…"
	@cd $(BASE) && $(PYTEST) tests/testlab_suite/test_security_attacks.py -q --tb=short
	@echo "▶ UI page-load tests…"
	@cd $(BASE) && $(PYTEST) tests/ui/test_page_load.py -q -m ui
	@echo "✅ Critical tests passed"

.PHONY: ci
ci:  ## Full CI gate: make test + security-audit — required before every commit/PR
	@echo "════════════════════════════════════════════════════"
	@echo "  LegionForge CI Gate"
	@echo "════════════════════════════════════════════════════"
	@$(MAKE) --no-print-directory test
	@echo ""
	@$(MAKE) --no-print-directory security-audit
	@echo ""
	@echo "════════════════════════════════════════════════════"
	@echo "  ✅ CI gate passed — safe to commit"
	@echo "════════════════════════════════════════════════════"

.PHONY: test-smoke
test-smoke:
	@cd $(BASE) && $(PYTEST) tests/test_smoke.py -v

.PHONY: test-integration
test-integration:  ## Run integration tests (requires PostgreSQL — make db-start first)
	@cd $(BASE) && $(PYTEST) tests/test_integration.py -v -m "integration"

.PHONY: test-kerberos
test-kerberos:  ## Run Kerberos live-KDC tests (requires KERBEROS_TEST_KDC=1 + KDC setup — see docs/SCALING.md)
	@cd $(BASE) && \
	  POSTGRES_PASSWORD=$${POSTGRES_PASSWORD:-$$($(PYTHON) -c "import keyring; print(keyring.get_password('postgres','api_key') or '')" 2>/dev/null)} \
	  KRB5_CONFIG=$$HOME/.krb5.conf \
	  KRB5_KDC_PROFILE=$$HOME/.krb5kdc/kdc.conf \
	  KERBEROS_TEST_KDC=1 \
	  KERBEROS_REALM=$${KERBEROS_REALM:-TEST.LOCAL} \
	  KERBEROS_KEYTAB=$${KERBEROS_KEYTAB:-/tmp/test.keytab} \
	  KERBEROS_TEST_USER=$${KERBEROS_TEST_USER:-testuser} \
	  KERBEROS_TEST_PASS=$${KERBEROS_TEST_PASS:-testpass} \
	  $(PYTEST) tests/test_kerberos_integration.py -v

.PHONY: test-all
test-all:  ## Run all tests (smoke + integration)
	@cd $(BASE) && $(PYTEST) tests/ -v

## ── UI Tests — Playwright browser automation (Phase 18) ───────
.PHONY: install-browsers
install-browsers:  ## Install Playwright Chromium browser (one-time setup)
	@cd $(BASE) && $(PYTHON) -m playwright install chromium
	@echo "✅ Chromium installed for Playwright UI tests"

.PHONY: test-ui
test-ui:  ## Run Playwright UI tests (headless Chromium, requires no running services)
	@cd $(BASE) && $(PYTEST) tests/ui/ -v -m ui
	@echo "✅ UI tests complete"

.PHONY: test-ui-headed
test-ui-headed:  ## Run Playwright UI tests with browser window visible (debug mode)
	@cd $(BASE) && $(PYTEST) tests/ui/ -v -m ui --headed --slowmo=300
	@echo "✅ UI tests complete (headed)"

.PHONY: test-ui-smoke
test-ui-smoke:  ## Run quick subset of UI tests (page-load only)
	@cd $(BASE) && $(PYTEST) tests/ui/test_page_load.py -v -m ui

## ── Agent Quality Tests — live query runner (Phase Q1) ────────
.PHONY: test-agent
test-agent:  ## Run live agent query suite (requires gateway + Ollama — set GATEWAY_API_KEY first)
	@if [ -z "$$GATEWAY_API_KEY" ]; then \
	  echo "❌ GATEWAY_API_KEY is not set."; \
	  echo "   Create a test user first:  make create-user USERNAME=testclient"; \
	  echo "   Then:  export GATEWAY_API_KEY=<key from above>"; \
	  exit 1; \
	fi
	@echo "Running live agent quality suite against $(GATEWAY_URL)..."
	@echo "Transcripts will be saved to tests/agent_quality_transcripts/"
	@cd $(BASE) && $(PYTHON) -m tests.gateway_client --suite agent

## ── TestLab — admin test management UI (Phase 18) ─────────────
.PHONY: build-testlab
build-testlab:  ## Build legionforge-testlab:latest Docker image
	docker build -f $(BASE)/Dockerfile.testlab -t legionforge-testlab:latest $(BASE)
	@echo "✅ legionforge-testlab:latest built"

.PHONY: testlab-start
testlab-start:  ## Start TestLab in Docker on :8090 (mounts live tests/ and src/)
	@echo "🔑 Resolving admin key from TESTLAB_ADMIN_KEY or Keychain legionforge_health…"
	@TESTLAB_ADMIN_KEY=$${TESTLAB_ADMIN_KEY:-$$($(PYTHON) -c "import keyring; print(keyring.get_password('legionforge_health','api_key') or '')" 2>/dev/null)} ; \
	if [ -z "$$TESTLAB_ADMIN_KEY" ]; then echo "❌ Set TESTLAB_ADMIN_KEY or populate legionforge_health Keychain item"; exit 1; fi ; \
	docker run --rm -d --name legionforge-testlab -p 8090:8090 \
	  -e TESTLAB_ADMIN_KEY="$$TESTLAB_ADMIN_KEY" \
	  -e POSTGRES_PASSWORD="$${POSTGRES_PASSWORD:-}" \
	  -e TASK_TOKEN_SECRET="$${TASK_TOKEN_SECRET:-}" \
	  -v $(BASE)/tests:/app/tests \
	  -v $(BASE)/src:/app/src:ro \
	  -v $(BASE)/config:/app/config:ro \
	  --add-host host.docker.internal:host-gateway \
	  legionforge-testlab:latest && \
	echo "✅ TestLab running — open http://localhost:8090"

.PHONY: testlab-stop
testlab-stop:  ## Stop TestLab container
	docker stop legionforge-testlab 2>/dev/null || true
	@echo "✅ TestLab stopped"

.PHONY: testlab-dev
testlab-dev:  ## Run TestLab locally (no Docker) — development mode
	@cd $(BASE) && \
	  TESTLAB_ADMIN_KEY=$${TESTLAB_ADMIN_KEY:-$$($(PYTHON) -c "import keyring; print(keyring.get_password('legionforge_health','api_key') or '')" 2>/dev/null)} \
	  $(PYTHON) -m uvicorn src.testlab.app:app --host 0.0.0.0 --port 8090 --reload
	@echo "✅ TestLab dev server started on http://0.0.0.0:8090"

## ── TestLab Attack Suite — Phase 19 ───────────────────────────
.PHONY: test-functional
test-functional:  ## 25 functional tests — mock gateway, no services
	@cd $(BASE) && $(PYTEST) tests/testlab_suite/test_functional.py -v -m functional --tb=short
	@echo "✅ Functional tests complete"

.PHONY: test-security-attacks
test-security-attacks:  ## 35 security attack tests — injection, session, protocol
	@cd $(BASE) && $(PYTEST) tests/testlab_suite/test_security_attacks.py -v -m security --tb=short
	@echo "✅ Security attack tests complete"

.PHONY: test-dos
test-dos:  ## 15 DOS resilience tests — flood, oversized body, protocol attacks
	@cd $(BASE) && $(PYTEST) tests/testlab_suite/test_dos.py -v -m dos --tb=short
	@echo "✅ DOS resilience tests complete"

.PHONY: test-auth-attacks
test-auth-attacks:  ## 20 authentication attack tests — token replay, timing, multi-auth
	@cd $(BASE) && $(PYTEST) tests/testlab_suite/test_auth_attacks.py -v -m auth_attack --tb=short
	@echo "✅ Auth attack tests complete"

.PHONY: test-data-attacks
test-data-attacks:  ## 15 data attack tests — PII, exfiltration, cross-user isolation
	@cd $(BASE) && $(PYTEST) tests/testlab_suite/test_data_attacks.py -v -m data_attack --tb=short
	@echo "✅ Data attack tests complete"

.PHONY: test-novel
test-novel:  ## LLM-generated tests (requires Ollama at OLLAMA_BASE_URL)
	@cd $(BASE) && $(PYTEST) tests/testlab_suite/test_novel_llm.py tests/testlab_suite/test_novel_security.py -v --tb=short
	@echo "✅ Novel LLM tests complete"

.PHONY: test-cve
test-cve:  ## CVE-based tests from NVD API (requires network + Ollama)
	@cd $(BASE) && $(PYTEST) tests/testlab_suite/test_cve.py -v --tb=short
	@echo "✅ CVE tests complete"

.PHONY: test-crystallization
test-crystallization:  ## Run crystallization pipeline tests (no services required)
	@cd $(BASE) && $(PYTEST) tests/crystallization/ -v --tb=short
	@echo "✅ Crystallization pipeline tests complete"

.PHONY: test-testlab-all
test-testlab-all:  ## All 110+ testlab_suite tests (excludes LLM/CVE tests)
	@cd $(BASE) && $(PYTEST) tests/testlab_suite/ -v --tb=short \
	  --ignore=tests/testlab_suite/test_novel_llm.py \
	  --ignore=tests/testlab_suite/test_novel_security.py \
	  --ignore=tests/testlab_suite/test_cve.py
	@echo "✅ All TestLab attack suite tests complete"

.PHONY: test-tool-accuracy
test-tool-accuracy:  ## Tool unit tests — web_fetch/web_search accuracy (no LLM, fast)
	@cd $(BASE) && $(PYTEST) tests/tool_accuracy/ -m tool_accuracy -v --tb=short
	@echo "✅ Tool accuracy tests complete"

.PHONY: test-researcher-accuracy
test-researcher-accuracy:  ## Researcher anti-hallucination tests (require Ollama + PostgreSQL, 90s timeout)
	@cd $(BASE) && $(PYTEST) tests/tool_accuracy/ -m tool_accuracy_llm -v --tb=short --timeout=90
	@echo "✅ Researcher accuracy tests complete"

.PHONY: test-tool-all
test-tool-all:  ## All tool accuracy tests (fast + LLM)
	@cd $(BASE) && $(PYTEST) tests/tool_accuracy/ -v --tb=short --timeout=90
	@echo "✅ All tool accuracy tests complete"

.PHONY: test-hallucination
test-hallucination:  ## Live hallucination detection tests (require Ollama + PostgreSQL + internet, ~120s/test)
	@cd $(BASE) && $(PYTEST) tests/hallucination/ -v --tb=short --timeout=180 -s
	@echo "✅ Live hallucination tests complete"

.PHONY: test-tool-integrity
test-tool-integrity:  ## All tool runtime integrity tests (schema, result injection, Guardian, sandbox, memory)
	@cd $(BASE) && $(PYTEST) tests/tool_integrity/ -v --tb=short --timeout=120 -s
	@echo "✅ Tool integrity tests complete"

.PHONY: test-tool-integrity-schema
test-tool-integrity-schema:  ## Schema conformance tests — fast, no external services required
	@cd $(BASE) && $(PYTEST) tests/tool_integrity/test_schema_conformance.py -v --tb=short
	@echo "✅ Schema conformance tests complete"

.PHONY: test-tool-integrity-injection
test-tool-integrity-injection:  ## Result injection + PII scrubbing tests (require Ollama + PostgreSQL)
	@cd $(BASE) && $(PYTEST) tests/tool_integrity/test_result_injection.py -v --tb=short --timeout=120 -s
	@echo "✅ Result injection tests complete"

.PHONY: test-tool-integrity-guardian
test-tool-integrity-guardian:  ## Guardian sidecar end-to-end tests (require make guardian-start)
	@cd $(BASE) && $(PYTEST) tests/tool_integrity/test_guardian_e2e.py -v --tb=short --timeout=30 -s
	@echo "✅ Guardian e2e tests complete"

.PHONY: test-tool-integrity-sandbox
test-tool-integrity-sandbox:  ## code_execute Docker sandbox containment tests (require make sandbox-build)
	@cd $(BASE) && $(PYTEST) tests/tool_integrity/test_code_execute_sandbox.py -v --tb=short --timeout=120 -s
	@echo "✅ Sandbox containment tests complete"

.PHONY: test-tool-integrity-memory
test-tool-integrity-memory:  ## memory_write/memory_recall isolation tests (require PostgreSQL)
	@cd $(BASE) && $(PYTEST) tests/tool_integrity/test_memory_isolation.py -v --tb=short --timeout=60 -s
	@echo "✅ Memory isolation tests complete"

## ── Gateway Docker (Phase 11) ─────────────────────────────────
.PHONY: build-gateway
build-gateway:  ## Build legionforge-gateway:latest Docker image
	docker build -f Dockerfile.gateway -t legionforge-gateway:latest .
	@echo "✅ legionforge-gateway:latest built"

.PHONY: gateway-start-docker
gateway-start-docker:  ## Run gateway in Docker (requires POSTGRES_PASSWORD + TASK_TOKEN_SECRET)
	docker run --rm -d --name legionforge-gateway -p 8080:8080 \
		--env POSTGRES_PASSWORD="$(POSTGRES_PASSWORD)" \
		--env TASK_TOKEN_SECRET="$(TASK_TOKEN_SECRET)" \
		--add-host host.docker.internal:host-gateway \
		legionforge-gateway:latest
	@echo "✅ legionforge-gateway container started on :8080"

## ── Gateway test client (Phase 12) ────────────────────────────
# Requires: GATEWAY_URL, GATEWAY_API_KEY (and optionally GATEWAY_API_KEY_2)
# Example:
#   export GATEWAY_URL=http://localhost:8080
#   export GATEWAY_API_KEY=lf_your_key_here
#   make test-gateway-all

.PHONY: build-testclient
build-testclient:  ## Build legionforge-testclient:latest Docker image
	docker build -f Dockerfile.testclient -t legionforge-testclient:latest .
	@echo "✅ legionforge-testclient:latest built"

.PHONY: test-gateway-basic
test-gateway-basic:  ## Run Suite 1 — functional correctness (14 tests)
	docker run --rm \
		-e GATEWAY_URL=$${GATEWAY_URL:-http://host.docker.internal:8080} \
		-e GATEWAY_API_KEY="$${GATEWAY_API_KEY}" \
		-e GATEWAY_API_KEY_2="$${GATEWAY_API_KEY_2:-}" \
		--add-host host.docker.internal:host-gateway \
		legionforge-testclient:latest --suite basic

.PHONY: test-gateway-load
test-gateway-load:  ## Run Suite 2 — load and DOS resilience (8 tests)
	docker run --rm \
		-e GATEWAY_URL=$${GATEWAY_URL:-http://host.docker.internal:8080} \
		-e GATEWAY_API_KEY="$${GATEWAY_API_KEY}" \
		-e LOAD_CONCURRENCY=$${LOAD_CONCURRENCY:-20} \
		-e LOAD_ITERATIONS=$${LOAD_ITERATIONS:-50} \
		-e HEALTH_SLA_MS=$${HEALTH_SLA_MS:-2000} \
		--add-host host.docker.internal:host-gateway \
		legionforge-testclient:latest --suite load

.PHONY: test-gateway-security
test-gateway-security:  ## Run Suite 3 — authorized security verification (12 tests)
	docker run --rm \
		-e GATEWAY_URL=$${GATEWAY_URL:-http://host.docker.internal:8080} \
		-e GATEWAY_API_KEY="$${GATEWAY_API_KEY}" \
		-e GATEWAY_API_KEY_2="$${GATEWAY_API_KEY_2:-}" \
		--add-host host.docker.internal:host-gateway \
		legionforge-testclient:latest --suite pentest

.PHONY: test-gateway-injection
test-gateway-injection:  ## Run Suite 4 — injection and malicious input tests (35+ tests)
	docker run --rm \
		-e GATEWAY_URL=$${GATEWAY_URL:-http://host.docker.internal:8080} \
		-e GATEWAY_API_KEY="$${GATEWAY_API_KEY}" \
		--add-host host.docker.internal:host-gateway \
		legionforge-testclient:latest --suite injection

.PHONY: test-gateway-all
test-gateway-all:  ## Run all four gateway test suites
	docker run --rm \
		-e GATEWAY_URL=$${GATEWAY_URL:-http://host.docker.internal:8080} \
		-e GATEWAY_API_KEY="$${GATEWAY_API_KEY}" \
		-e GATEWAY_API_KEY_2="$${GATEWAY_API_KEY_2:-}" \
		-e LOAD_CONCURRENCY=$${LOAD_CONCURRENCY:-20} \
		-e LOAD_ITERATIONS=$${LOAD_ITERATIONS:-50} \
		-e HEALTH_SLA_MS=$${HEALTH_SLA_MS:-2000} \
		--add-host host.docker.internal:host-gateway \
		legionforge-testclient:latest

.PHONY: test-gateway-all-json
test-gateway-all-json:  ## Run all suites; emit JSON report (for CI)
	docker run --rm \
		-e GATEWAY_URL=$${GATEWAY_URL:-http://host.docker.internal:8080} \
		-e GATEWAY_API_KEY="$${GATEWAY_API_KEY}" \
		-e GATEWAY_API_KEY_2="$${GATEWAY_API_KEY_2:-}" \
		--add-host host.docker.internal:host-gateway \
		legionforge-testclient:latest --json

# ── Code Quality ──────────────────────────────────────────────
.PHONY: lint
lint:
	@$(VENV)/bin/black --check $(BASE)/src $(BASE)/tests $(BASE)/config \
		&& echo "✅ Code style OK" || echo "❌ Style issues found. Run: make format"

.PHONY: format
format:
	@$(VENV)/bin/black $(BASE)/src $(BASE)/tests $(BASE)/config
	@echo "✅ Code formatted"

# ── Security Audit ───────────────────────────────────────────
# Run at every milestone: phase start/end, new library added, new agent added,
# before any PR merge. Proactive checks prevent downstream compounding errors.
.PHONY: js-check
js-check:  ## Syntax-check JS extracted from index.html (node --check on a temp file)
	@JS_SRC="$(BASE)/src/gateway/static/index.html"; \
	TMP=$$(mktemp /tmp/lf_js_check_XXXXXX.js); \
	awk '/<script[^>]*>/{flag=1;next} /<\/script>/{flag=0} flag' "$$JS_SRC" > "$$TMP"; \
	node --check "$$TMP" && echo "✅ JS syntax OK" || (echo "❌ JS syntax errors in index.html — fix before merging" && rm -f "$$TMP" && exit 1); \
	rm -f "$$TMP"

.PHONY: dep-audit
dep-audit:  ## Scan dependencies for known CVEs via pip-audit (OSV/PyPI Advisory DB)
	@echo "--- pip-audit: dependency CVE scan ---"
	@if [ -x "$(VENV)/bin/pip-audit" ]; then \
		$(VENV)/bin/pip-audit --requirement $(BASE)/requirements.txt --skip-editable \
		&& echo "✅ pip-audit: no known vulnerabilities" \
		|| (echo "❌ pip-audit: vulnerabilities above — update affected packages" && exit 1); \
	else \
		echo "⚠️  pip-audit not installed. Run: make install"; \
	fi

.PHONY: security-audit
security-audit:
	@echo "🔐 Running security audit..."
	@echo ""
	@echo "--- Full test suite (smoke → testlab → ui) ---"
	@$(MAKE) --no-print-directory test
	@echo ""
	@echo "--- JS syntax check (index.html) ---"
	@$(MAKE) --no-print-directory js-check
	@echo ""
	@echo "--- bandit static analysis (medium+ severity) ---"
	@if [ -x "$(VENV)/bin/bandit" ]; then \
		$(VENV)/bin/bandit -r $(BASE)/src/ -ll && echo "✅ bandit: no medium/high issues found" \
		|| (echo "❌ bandit found medium/high severity issues above — fix before merging" && exit 1); \
	else \
		echo "⚠️  bandit not installed. Run: make install"; \
	fi
	@echo ""
	@$(MAKE) --no-print-directory dep-audit
	@echo ""
	@echo "--- Checking for password/secret in URI patterns ---"
	@! grep -rn "postgresql://.*:.*@" $(BASE)/src/ --include="*.py" \
		&& echo "✅ No embedded passwords in connection URIs" \
		|| (echo "❌ Found password in URI above — use keyword args instead" && exit 1)
	@echo ""
	@echo "✅ Security audit complete. Review any warnings above."

# ── Code Review Prep ─────────────────────────────────────────
# Run before every manual PR review. Automated gates must all pass
# before starting the human checklist in docs/code-review-protocol.md.
.PHONY: review-prep
review-prep:
	@echo ""
	@echo "════════════════════════════════════════════════════"
	@echo "  LegionForge — PR Review: Automated Gates"
	@echo "════════════════════════════════════════════════════"
	@echo ""
	@echo "─── [1/7] Formatting ────────────────────────────────"
	@cd $(BASE) && $(VENV)/bin/black --check src/ tests/ config/ \
		&& echo "✅ Black: all files formatted" \
		|| (echo "❌ Black: unformatted files above — run: make format" && exit 1)
	@echo ""
	@echo "─── [2/7] Full test suite (smoke → testlab → ui) ───"
	@$(MAKE) --no-print-directory test
	@echo ""
	@echo "─── [3/7] Bandit static analysis ────────────────────"
	@if [ -x "$(VENV)/bin/bandit" ]; then \
		$(VENV)/bin/bandit -r $(BASE)/src/ -ll \
		&& echo "✅ Bandit: no medium/high issues" \
		|| (echo "❌ Bandit: medium/high issues above — fix before merging" && exit 1); \
	else \
		echo "⚠️  bandit not installed — run: make install"; \
	fi
	@echo ""
	@echo "─── [4/6] Dependency CVE scan ───────────────────────"
	@$(MAKE) --no-print-directory dep-audit
	@echo ""
	@echo "─── [5/7] Secret scan ───────────────────────────────"
	@! grep -rn "postgresql://.*:.*@" $(BASE)/src/ --include="*.py" \
		&& echo "✅ No embedded passwords in connection URIs" \
		|| (echo "❌ Embedded password in URI — use keyword args" && exit 1)
	@! grep -rn "sk-[A-Za-z0-9]\{20,\}" $(BASE)/src/ --include="*.py" \
		&& echo "✅ No OpenAI-style API keys in source" \
		|| (echo "❌ Possible API key in source above" && exit 1)
	@echo ""
	@echo "─── [6/7] New external dependencies ────────────────"
	@DEPS=$$(git diff origin/main -- requirements.txt 2>/dev/null | grep "^+" | grep -v "^+++" | grep -v "^+#"); \
	if [ -n "$$DEPS" ]; then \
		echo "⚠️  New dependencies detected — review required (Phase C3):"; \
		echo "$$DEPS"; \
	else \
		echo "✅ No new external dependencies"; \
	fi
	@echo ""
	@echo "─── [7/7] Scope check — changed files ──────────────"
	@git diff --stat origin/main 2>/dev/null || git diff --stat HEAD~1
	@echo ""
	@echo "════════════════════════════════════════════════════"
	@echo "  Automated gates complete."
	@echo "  If all green, proceed to manual review:"
	@echo "  docs/code-review-protocol.md  (Phase B onward)"
	@echo "════════════════════════════════════════════════════"
	@echo ""

# ── Tool Registry ────────────────────────────────────────────
.PHONY: register-researcher-tools
register-researcher-tools:
	@echo "Registering researcher agent tools..."
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.agents.researcher import register_researcher_tools; \
asyncio.run(register_researcher_tools()); \
print('✅ Researcher tools registered')"

.PHONY: verify-tool-registry
verify-tool-registry:
	@echo "Verifying tool registry (all loaded tools must be APPROVED)..."
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio, sys; \
from src.agents.researcher import register_researcher_tools, RESEARCHER_TOOL_MANIFESTS; \
from src.security import verify_tool_before_invocation; \
async def check(): \
    await register_researcher_tools(); \
    failed = []; \
    for m in RESEARCHER_TOOL_MANIFESTS: \
        ok = await verify_tool_before_invocation(m.tool_id); \
        (print(f'  ✅ {m.tool_id}') if ok else (failed.append(m.tool_id), print(f'  ❌ {m.tool_id}'))); \
    if failed: print(f'FAIL: {failed}', file=sys.stderr); sys.exit(1); \
    else: print('✅ All tools verified'); \
asyncio.run(check())"

.PHONY: verify-model-integrity
verify-model-integrity:
	@echo "Verifying Ollama model manifests..."
	@$(PYTHON) -c "\
import hashlib, json, os, pathlib, sys; \
ollama_dir = pathlib.Path(os.environ.get('OLLAMA_MODELS', pathlib.Path.home() / '.ollama' / 'models')) / 'manifests'; \
if not ollama_dir.exists(): print('⚠️  Ollama model dir not found — skipping'); sys.exit(0); \
manifests = list(ollama_dir.rglob('*')); \
print(f'Found {len(manifests)} manifest entries in {ollama_dir}'); \
print('✅ Model manifest check complete (hash diffing added in Phase 2)')"

# ── Docker Desktop ────────────────────────────────────────────
.PHONY: docker-start
docker-start:  ## Ensure Docker Desktop is running; start it if not and wait until ready
	@if docker info >/dev/null 2>&1; then \
		echo "✅ Docker Desktop already running"; \
	else \
		echo "   Docker Desktop not running — starting..."; \
		open -a Docker; \
		printf "   Waiting for Docker Desktop to be ready"; \
		for i in $$(seq 1 45); do \
			if docker info >/dev/null 2>&1; then \
				printf " ✅\n"; break; \
			fi; \
			printf "."; sleep 2; \
			if [ "$$i" = "45" ]; then printf " ❌ timed out (90s)\n"; exit 1; fi; \
		done; \
		echo "✅ Docker Desktop ready"; \
	fi

# ── Guardian (Phase 2) ────────────────────────────────────────
.PHONY: guardian-start
guardian-start: docker-start
	@echo "Starting Guardian sidecar..."
	@# Load secrets from Keychain into the shell so docker-compose substitutes them
	@# into docker-compose.yml before creating the container.
	@# If the container exists but was started outside docker-compose (e.g. via
	@# `docker run`), compose cannot --force-recreate it.  Remove it first so
	@# compose always creates a fresh container with the current env vars.
	@docker rm -f legionforge-guardian 2>/dev/null || true
	@export TASK_TOKEN_SECRET=$$(security find-generic-password \
		-s legionforge_task_tokens -a api_key -w 2>/dev/null || echo "") && \
	export POSTGRES_PASSWORD=$$(security find-generic-password \
		-s legionforge_guardian -a api_key -w 2>/dev/null || echo "") && \
	docker-compose up -d guardian && \
	sleep 2 && \
	curl -s --max-time 5 http://localhost:9766/health >/dev/null && \
	echo "✅ Guardian healthy at http://localhost:9766" || \
	echo "⚠️  Guardian may still be starting — check: make guardian-logs"

.PHONY: guardian-stop
guardian-stop:
	@docker-compose stop guardian 2>/dev/null && echo "✅ Guardian stopped" || true

.PHONY: guardian-logs
guardian-logs:
	@docker-compose logs -f guardian

.PHONY: docker-build
docker-build:
	@echo "Building Docker images..."
	@docker-compose build && echo "✅ All images built"

.PHONY: docker-up
docker-up:
	@echo "Starting all Docker services..."
	@docker-compose up -d && echo "✅ Services started"

# ── Audit log & DB maintenance ────────────────────────────────
.PHONY: audit-log-verify
audit-log-verify:
	@echo "Verifying audit log hash chain integrity..."
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio, sys; \
from src.database import init_db, verify_audit_log_chain; \
async def run(): \
    await init_db(); \
    ok, rows, err = await verify_audit_log_chain(); \
    if ok: print(f'✅ Audit log chain valid ({rows} rows verified)'); \
    else: print(f'❌ Chain INVALID at row {rows}: {err}'); sys.exit(1); \
asyncio.run(run())"

.PHONY: db-maintenance
db-maintenance:
	@echo "Running DB maintenance (pruning stale rows per retention config)..."
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio, sys; \
from src.database import init_db, run_db_maintenance; \
from config.settings import settings; \
async def run(): \
    await init_db(); \
    m = settings.db_maintenance; \
    if not m.enabled: print('⚠️  DB maintenance disabled in config'); sys.exit(0); \
    results = await run_db_maintenance( \
        tasks_days=m.tasks_days, api_usage_days=m.api_usage_days, \
        health_metrics_days=m.health_metrics_days, \
        threat_events_days=m.threat_events_days, audit_log_days=m.audit_log_days); \
    print('✅ DB maintenance complete:'); \
    [print(f'   {tbl}: {n} rows deleted') for tbl, n in results.items()]; \
asyncio.run(run())"

# ── Phase 3: JWT task token secret setup ──────────────────────
.PHONY: setup-task-token-secret
setup-task-token-secret:
	@echo "Setting up JWT task token signing secret..."
	@echo "Generating a 32-byte hex secret and storing via Python keyring (correct ACL)..."
	@$(PYTHON) -c "\
import secrets, keyring; \
secret = secrets.token_hex(32); \
keyring.set_password('legionforge_task_tokens', 'api_key', secret); \
print('Secret stored. Fingerprint (first 8 chars):', secret[:8] + '...'); \
" && \
	echo "✅ Task token secret stored in Keychain (service=legionforge_task_tokens)" && \
	echo "   Verify: python -c \"import keyring; print(keyring.get_password('legionforge_task_tokens', 'api_key')[:8], '...')\"" && \
	echo "" && \
	echo "   To start Guardian with the token secret:" && \
	echo "   export TASK_TOKEN_SECRET=\$$(security find-generic-password -s legionforge_task_tokens -a api_key -w)" && \
	echo "   TASK_TOKEN_SECRET=\$$TASK_TOKEN_SECRET docker-compose up -d guardian" \
	|| echo "❌ Could not store secret — run manually:" && \
	echo "   python -c \"import secrets, keyring; keyring.set_password('legionforge_task_tokens', 'api_key', secrets.token_hex(32))\""

# ── Phase 3: Orchestrator tool registration ───────────────────
.PHONY: register-orchestrator-tools
register-orchestrator-tools:
	@echo "Registering orchestrator agent tools..."
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.agents.orchestrator import register_orchestrator_tools; \
asyncio.run(register_orchestrator_tools()); \
print('✅ Orchestrator tools registered')"

# ── Run agents ───────────────────────────────────────────────
# Usage: make run-researcher TASK="summarise what LangGraph is"
#        make run-researcher          (uses default task)
# TASK= is the public interface; RESEARCHER_TASK is the internal variable.
# If TASK is set on the command line it takes priority over RESEARCHER_TASK.
RESEARCHER_TASK ?= What is LangGraph and how does it relate to LangChain? Give a brief summary.
ifdef TASK
RESEARCHER_TASK := $(TASK)
endif

.PHONY: run-researcher
run-researcher:
	@echo "Running Researcher agent..."
	@echo "  Task: $(RESEARCHER_TASK)"
	@cd $(BASE) && $(PYTHON) scripts/run_researcher.py "$(RESEARCHER_TASK)"

# ── Phase 4: Threat Analyst + BOM ────────────────────────────
.PHONY: register-threat-analyst-tools
register-threat-analyst-tools:
	@echo "Registering threat analyst agent tools..."
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.agents.threat_analyst import register_threat_analyst_tools; \
asyncio.run(register_threat_analyst_tools()); \
print('✅ Threat analyst tools registered')"

.PHONY: run-threat-analyst
run-threat-analyst:
	@echo "Running Threat Analyst (7-day window)..."
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.agents.threat_analyst import run_threat_analyst; \
result = asyncio.run(run_threat_analyst()); \
print('✅ Threat analysis complete'); \
print(f'  Proposed rules: {len(result[\"proposed_rules\"])}'); \
print(f'  Steps: {result[\"steps\"]}'); \
print(f'  Errors: {result[\"errors\"]}')"

.PHONY: bom
bom:
	@TOKEN=$$(security find-generic-password -s legionforge_health -a api_key -w 2>/dev/null) && \
	curl -s -H "Authorization: Bearer $$TOKEN" http://localhost:8765/bom | python3 -m json.tool 2>/dev/null \
		|| echo "⚠️  Health server not running or token missing. Start with: make health-server"

.PHONY: pending-rules
pending-rules:
	@TOKEN=$$(security find-generic-password -s legionforge_health -a api_key -w 2>/dev/null) && \
	curl -s -H "Authorization: Bearer $$TOKEN" http://localhost:8765/rules | python3 -m json.tool 2>/dev/null \
		|| echo "⚠️  Health server not running or token missing."

# ── Phase 5: Ed25519 signing key setup ───────────────────────
.PHONY: setup-signing-key
setup-signing-key:
	@echo "Generating Ed25519 signing keypair..."
	@cd $(BASE) && $(PYTHON) -c "\
from src.tools.signing import generate_signing_keypair; \
import hashlib, subprocess; \
priv, pub = generate_signing_keypair(); \
subprocess.run(['security', 'delete-generic-password', '-s', 'legionforge_tool_signer', '-a', 'api_key'], capture_output=True); \
r = subprocess.run(['security', 'add-generic-password', '-s', 'legionforge_tool_signer', '-a', 'api_key', '-w', priv, '-A'], capture_output=True, text=True); \
r.returncode != 0 and (print('❌ Could not store key:', r.stderr.decode()), __import__('sys').exit(1)); \
fp = hashlib.sha256(bytes.fromhex(pub)).hexdigest()[:16]; \
print('✅ Signing key stored in Keychain (service=legionforge_tool_signer)'); \
print(f'   Public key fingerprint: {fp}'); \
print(f'   Public key (full hex):  {pub}')"

# ── Phase 5: Observer agent ───────────────────────────────────
.PHONY: register-observer-tools
register-observer-tools:
	@echo "Registering observer agent tools..."
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.agents.observer import register_observer_tools; \
asyncio.run(register_observer_tools()); \
print('✅ Observer tools registered')"

.PHONY: register-observer-sequences
register-observer-sequences:
	@echo "Registering observer agent expected sequences..."
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.database import init_db, register_agent_sequences; \
from src.agents.observer import OBSERVER_EXPECTED_SEQUENCES; \
async def run(): \
    await init_db(); \
    await register_agent_sequences('observer', OBSERVER_EXPECTED_SEQUENCES); \
    print(f'✅ Registered {len(OBSERVER_EXPECTED_SEQUENCES)} sequences for observer agent'); \
asyncio.run(run())"

# Usage: make run-observer
#        make run-observer OBSERVER_HOURS=72 OBSERVER_MIN_OCC=3
OBSERVER_HOURS ?= 168
OBSERVER_MIN_OCC ?= 3
.PHONY: run-observer
run-observer:
	@echo "Running Observer agent (window=$(OBSERVER_HOURS)h, min_occ=$(OBSERVER_MIN_OCC))..."
	@cd $(BASE) && OBSERVER_HOURS=$(OBSERVER_HOURS) OBSERVER_MIN_OCC=$(OBSERVER_MIN_OCC) \
		$(PYTHON) scripts/run_observer.py

# ── Phase 5: Crystallizer agent ──────────────────────────────
.PHONY: register-crystallizer-tools
register-crystallizer-tools:
	@echo "Registering crystallizer agent tools..."
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.agents.crystallizer import register_crystallizer_tools; \
asyncio.run(register_crystallizer_tools()); \
print('✅ Crystallizer tools registered')"

.PHONY: register-crystallizer-sequences
register-crystallizer-sequences:
	@echo "Registering crystallizer agent expected sequences..."
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.database import init_db, register_agent_sequences; \
from src.agents.crystallizer import CRYSTALLIZER_EXPECTED_SEQUENCES; \
async def run(): \
    await init_db(); \
    await register_agent_sequences('crystallizer', CRYSTALLIZER_EXPECTED_SEQUENCES); \
    print(f'✅ Registered {len(CRYSTALLIZER_EXPECTED_SEQUENCES)} sequences for crystallizer agent'); \
asyncio.run(run())"

# Usage: make run-crystallizer CANDIDATE_ID=cand_abc123def456
CANDIDATE_ID ?=
.PHONY: run-crystallizer
run-crystallizer:
	@if [ -z "$(CANDIDATE_ID)" ]; then \
		echo "❌ CANDIDATE_ID is required: make run-crystallizer CANDIDATE_ID=<id>"; \
		exit 1; \
	fi
	@echo "Running Crystallizer agent for candidate $(CANDIDATE_ID)..."
	@cd $(BASE) && CANDIDATE_ID=$(CANDIDATE_ID) $(PYTHON) scripts/run_crystallizer.py

# ── Phase 5: Crystallization review ──────────────────────────
.PHONY: pending-packages
pending-packages:
	@TOKEN=$$(security find-generic-password -s legionforge_health -a api_key -w 2>/dev/null) && \
	curl -s -H "Authorization: Bearer $$TOKEN" \
		http://localhost:8765/crystallization/candidates | python3 -m json.tool 2>/dev/null \
		|| echo "⚠️  Health server not running or token missing. Start with: make health-server"

# Usage: make approve-package PACKAGE_ID=pkg_abc123
PACKAGE_ID ?=
.PHONY: approve-package
approve-package:
	@if [ -z "$(PACKAGE_ID)" ]; then \
		echo "❌ PACKAGE_ID is required: make approve-package PACKAGE_ID=<id>"; \
		exit 1; \
	fi
	@TOKEN=$$(security find-generic-password -s legionforge_health -a api_key -w 2>/dev/null) && \
	curl -s -X POST -H "Authorization: Bearer $$TOKEN" \
		http://localhost:8765/crystallization/candidates/$(PACKAGE_ID)/approve \
		| python3 -m json.tool 2>/dev/null \
		|| echo "⚠️  Health server not running or token missing."

# Usage: make reject-package PACKAGE_ID=pkg_abc123
.PHONY: reject-package
reject-package:
	@if [ -z "$(PACKAGE_ID)" ]; then \
		echo "❌ PACKAGE_ID is required: make reject-package PACKAGE_ID=<id>"; \
		exit 1; \
	fi
	@TOKEN=$$(security find-generic-password -s legionforge_health -a api_key -w 2>/dev/null) && \
	curl -s -X POST -H "Authorization: Bearer $$TOKEN" \
		-H "Content-Type: application/json" \
		-d '{"reason": "Rejected via make reject-package"}' \
		http://localhost:8765/crystallization/candidates/$(PACKAGE_ID)/reject \
		| python3 -m json.tool 2>/dev/null \
		|| echo "⚠️  Health server not running or token missing."

# ── Phase 5.5: Security hardening ────────────────────────────
# Create a credentials file template at ~/.config/legionforge/credentials.yaml
# The file is chmod 0600 immediately. Fill in the values with real secrets.
.PHONY: init-credentials-file
init-credentials-file:
	@mkdir -p ~/.config/legionforge
	@if [ -f ~/.config/legionforge/credentials.yaml ]; then \
		echo "⚠️  Credentials file already exists — not overwriting."; \
		echo "    Location: ~/.config/legionforge/credentials.yaml"; \
	else \
		printf '# LegionForge credentials file\n# chmod 0600 required — world-readable files are rejected\n#\nopenai: ""\nanthropic: ""\nlangsmith: ""\npostgres: ""\nlegionforge_health: ""\nlegionforge_task_tokens: ""\nlegionforge_tool_signer: ""\n' \
			> ~/.config/legionforge/credentials.yaml; \
		chmod 0600 ~/.config/legionforge/credentials.yaml; \
		echo "✅ Created ~/.config/legionforge/credentials.yaml (chmod 0600)"; \
		echo "   Edit the file and fill in your credentials."; \
	fi

# Show CredentialStore status (which services are loaded)
.PHONY: credential-store-status
credential-store-status:
	@cd $(BASE) && $(PYTHON) -c "\
from config.settings import settings; \
from src.credentials import creds; \
creds.initialize(settings.security); \
import json; \
print(json.dumps(creds.status(), indent=2))"

# ── macOS LaunchAgent ─────────────────────────────────────────
# Installs the mount-check LaunchAgent, substituting the actual project path.
# Safe to re-run (unloads existing agent first if present).
.PHONY: install-launch-agent
install-launch-agent:
	@echo "🔌 Installing com.legionforge.check-agent-drive LaunchAgent..."
	@DEST=$$HOME/Library/LaunchAgents/com.legionforge.check-agent-drive.plist; \
	launchctl unload "$$DEST" 2>/dev/null || true; \
	sed "s|LEGIONFORGE_HOME_PLACEHOLDER|$(BASE)|g" \
	    "$(BASE)/scripts/com.legionforge.check-agent-drive.plist" > "$$DEST"; \
	launchctl load "$$DEST" && \
	echo "✅ LaunchAgent installed: $$DEST" || \
	echo "❌ launchctl load failed — check: launchctl list | grep legionforge"

# ── Phase 6: Security hardening ───────────────────────────────
# Two-phase DB init must already have run (make db-init).
# This target is idempotent — safe to re-run; roles/grants are CREATE IF NOT EXISTS.
.PHONY: setup-db-roles
setup-db-roles:
	@echo "🔐 Setting up legionforge_app PostgreSQL role + grants..."
	@cd $(BASE) && echo "$$_SETUP_DB_ROLES_PY" | $(PYTHON)

# Compute SHA256 hashes for all configured GGUF model files.
# Run this after downloading models to get the hash values for pinning in
# config/hardware_profiles/mac_m4_mini_16gb.yaml under each model's gguf_sha256 field.
.PHONY: verify-models
verify-models:
	@echo "🔒 Computing SHA256 hashes for installed GGUF models..."
	@echo "   (This may take 30-120 seconds for large GGUF files)"
	@cd $(BASE) && echo "$$_VERIFY_MODELS_PY" | $(PYTHON)

# Build the deny-default analyzer container image.
# Must be run before the Docker-backed analyzer sandbox is available.
# Requires Docker Desktop to be running.
.PHONY: build-analyzer
build-analyzer:
	@echo "🐳 Building legionforge-analyzer:latest container..."
	@cd $(BASE) && docker build -f Dockerfile.analyzer -t legionforge-analyzer:latest .
	@echo "✅ legionforge-analyzer:latest built"
	@echo "   The crystallization analyzer will now prefer the Docker sandbox over sandbox-exec."

# Revoke a registered tool immediately via the health server API.
# Usage: make revoke-tool TOOL_ID=<tool_id> [REASON="optional reason"]
# The Guardian cache refreshes within 10 seconds of revocation.
.PHONY: revoke-tool
revoke-tool:
	@test -n "$(TOOL_ID)" || (echo "❌ Usage: make revoke-tool TOOL_ID=<tool_id>"; exit 1)
	@TOKEN=$$(security find-generic-password -s legionforge_health -a api_key -w 2>/dev/null) && \
	REASON=$${REASON:-"Revoked via make revoke-tool"}; \
	curl -s -X POST -H "Authorization: Bearer $$TOKEN" \
		-H "Content-Type: application/json" \
		-d "{\"reason\": \"$$REASON\"}" \
		http://localhost:8765/tools/$(TOOL_ID)/revoke \
		| python3 -m json.tool 2>/dev/null \
		|| echo "⚠️  Health server not running or token missing."

# ── Phase 6: PentestAgent ─────────────────────────────────────────────────────

# Build the air-gapped pentest container image.
# Must be run before make pentest or make pentest-resilience.
.PHONY: build-pentest
build-pentest:
	@echo "🐳 Building legionforge-pentest:latest container..."
	@cd $(BASE) && docker build -f Dockerfile.pentest -t legionforge-pentest:latest .
	@echo "✅ legionforge-pentest:latest built"
	@echo "   Container is air-gapped (--network none). No production keys in scope."

# Run pentest in verify mode (stop-at-proof-of-concept, default).
# Each of the 8 attack classes is tested independently — a bypass in one
# class does NOT feed into the next attack (no cross-test chaining).
#
# Prerequisites: make build-pentest
.PHONY: pentest
pentest:
	@echo "🔍 Starting LegionForge PentestAgent — verify mode (stop-at-proof)"
	@docker run --rm \
		--network none \
		--read-only \
		--tmpfs /tmp:size=10m \
		--memory 512m \
		--cpus 1.0 \
		--security-opt no-new-privileges \
		--pids-limit 50 \
		-e POSTGRES_HOST=host.docker.internal \
		-e POSTGRES_PORT=5432 \
		-e POSTGRES_USER=$${POSTGRES_USER:-$(shell whoami)} \
		-e POSTGRES_PASSWORD=$${POSTGRES_PASSWORD:-} \
		-e TASK_TOKEN_SECRET=$${TASK_TOKEN_SECRET:-pentest-stub-secret} \
		-e AGENT_HARDWARE_PROFILE=$${AGENT_HARDWARE_PROFILE:-mac_m4_mini_16gb} \
		-e PYTHONPATH=/pentest \
		--add-host host.docker.internal:host-gateway \
		legionforge-pentest:latest \
		python -m src.agents.pentest_agent --mode=verify
	@echo ""
	@echo "📊 Run 'make pentest-report' to view the latest report."

# Run pentest in resilience mode — explicit opt-in only.
# Continues past proof-of-concept to measure blast radius.
# Prompts for confirmation before starting.
# ⚠️  This mode is intentionally harder to trigger than verify mode.
.PHONY: pentest-resilience
pentest-resilience:
	@echo "⚠️  Resilience mode: the agent will continue past confirmed bypasses"
	@echo "   to measure blast radius. ONLY synthetic environment is used."
	@echo "   No production data, credentials, or services are touched."
	@echo ""
	@read -p "Continue with resilience mode? [y/N] " confirm && [ "$$confirm" = "y" ] || exit 1
	@echo ""
	@echo "🔴 Starting LegionForge PentestAgent — resilience mode"
	@docker run --rm \
		--network none \
		--read-only \
		--tmpfs /tmp:size=10m \
		--memory 512m \
		--cpus 1.0 \
		--security-opt no-new-privileges \
		--pids-limit 50 \
		-e POSTGRES_HOST=host.docker.internal \
		-e POSTGRES_PORT=5432 \
		-e POSTGRES_USER=$${POSTGRES_USER:-$(shell whoami)} \
		-e POSTGRES_PASSWORD=$${POSTGRES_PASSWORD:-} \
		-e TASK_TOKEN_SECRET=$${TASK_TOKEN_SECRET:-pentest-stub-secret} \
		-e AGENT_HARDWARE_PROFILE=$${AGENT_HARDWARE_PROFILE:-mac_m4_mini_16gb} \
		-e PYTHONPATH=/pentest \
		--add-host host.docker.internal:host-gateway \
		legionforge-pentest:latest \
		python -m src.agents.pentest_agent --mode=resilience

# Print the most recent pentest report.
# Optional: make pentest-report RUN_ID=<uuid> (default: latest)
.PHONY: pentest-report
pentest-report:
	@cd $(BASE) && source venv/bin/activate && \
	python -m src.agents.pentest_report $(if $(RUN_ID),--run-id $(RUN_ID),--latest) --format markdown

# ── Agent sequence registration ───────────────────────────────
.PHONY: register-agent-sequences
register-agent-sequences:
	@echo "Registering all agent expected sequences..."
	@cd $(BASE) && echo "$$_REGISTER_SEQUENCES_PY" | $(PYTHON)
	@echo "✅ All agent sequences registered"

# ── Git ───────────────────────────────────────────────────────
.PHONY: git-status
git-status:
	@cd $(BASE) && git status

.PHONY: dev-branch
dev-branch:
	@cd $(BASE) && git checkout -b dev 2>/dev/null || git checkout dev
	@cd $(BASE) && git push -u origin dev 2>/dev/null || true
	@echo "✅ On dev branch"

# ── Logs ─────────────────────────────────────────────────────
.PHONY: logs
logs:
	@tail -f $(BASE)/logs/agents.log | python3 -m json.tool 2>/dev/null \
		|| tail -f $(BASE)/logs/agents.log

.PHONY: clean-logs
clean-logs:
	@find $(BASE)/logs -name "*.log*" -mtime +30 -delete
	@echo "✅ Old logs cleaned"
