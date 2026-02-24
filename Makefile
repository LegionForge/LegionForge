# ============================================================
# Makefile — LegionForge
# Usage: make <target>
# ============================================================

BASE    := /Volumes/MAC_MINI_1TB/LegionForge
VENV    := $(BASE)/venv
PYTHON  := $(VENV)/bin/python
PIP     := $(VENV)/bin/pip
PYTEST  := $(VENV)/bin/pytest

.DEFAULT_GOAL := help

# ── Help ──────────────────────────────────────────────────────
.PHONY: help
help:
	@echo ""
	@echo "  LegionForge"
	@echo "  ─────────────────────────────────────────────────"
	@echo "  make check        — verify drive, venv, models, config"
	@echo "  make start        — full startup sequence"
	@echo "  make stop         — graceful shutdown"
	@echo "  make status       — print system status (curl /status)"
	@echo "  make health       — quick liveness check (curl /health)"
	@echo "  make health-server — start health server in foreground"
	@echo "  make db-init      — initialize PostgreSQL and tables"
	@echo "  make db-start     — start PostgreSQL service"
	@echo "  make db-stop      — stop PostgreSQL service"
	@echo "  make ollama-start — start Ollama service"
	@echo "  make ollama-warm  — warm up local models"
	@echo "  make models       — list loaded Ollama models"
	@echo "  make install      — install/update Python packages"
	@echo "  make test         — run all tests"
	@echo "  make test-fast    — run tests excluding slow ones"
	@echo "  make lint         — run black formatter check"
	@echo "  make format       — auto-format with black"
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

.PHONY: start
start: check ollama-start db-start ollama-warm
	@echo ""
	@echo "✅ Framework ready."
	@echo "   Run 'make health-server' in a separate terminal to start the status endpoint."
	@echo "   Run 'make test' to verify everything is working."

.PHONY: stop
stop:
	@echo "Stopping services..."
	@brew services stop postgresql@17 2>/dev/null || true
	@brew services stop ollama 2>/dev/null || true
	@echo "✅ Services stopped"

# ── Health & Status ───────────────────────────────────────────
.PHONY: health
health:
	@curl -s http://localhost:8765/health | python3 -m json.tool 2>/dev/null \
		|| echo "⚠️  Health server not running. Start with: make health-server"

.PHONY: status
status:
	@curl -s http://localhost:8765/status | python3 -m json.tool 2>/dev/null \
		|| echo "⚠️  Health server not running. Start with: make health-server"

.PHONY: health-server
health-server:
	@echo "Starting health server at http://localhost:8765 ..."
	@cd $(BASE) && $(PYTHON) -m src.health

.PHONY: usage
usage:
	@curl -s http://localhost:8765/usage | python3 -m json.tool 2>/dev/null \
		|| echo "⚠️  Health server not running. Start with: make health-server"

# ── Database ──────────────────────────────────────────────────
.PHONY: db-start
db-start:
	@brew services start postgresql@17 2>/dev/null || true
	@sleep 2
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
	@psql -U jpc -d jpc_agents

# ── Ollama ────────────────────────────────────────────────────
.PHONY: ollama-start
ollama-start:
	@brew services start ollama 2>/dev/null || true
	@sleep 2
	@echo "✅ Ollama started"

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

# ── Testing ───────────────────────────────────────────────────
.PHONY: test
test:
	@cd $(BASE) && $(PYTEST) tests/ -v

.PHONY: test-fast
test-fast:
	@cd $(BASE) && $(PYTEST) tests/ -v -m "not slow"

.PHONY: test-smoke
test-smoke:
	@cd $(BASE) && $(PYTEST) tests/test_smoke.py -v

# ── Code Quality ──────────────────────────────────────────────
.PHONY: lint
lint:
	@$(VENV)/bin/black --check $(BASE)/src $(BASE)/tests $(BASE)/config \
		&& echo "✅ Code style OK" || echo "❌ Style issues found. Run: make format"

.PHONY: format
format:
	@$(VENV)/bin/black $(BASE)/src $(BASE)/tests $(BASE)/config
	@echo "✅ Code formatted"

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
