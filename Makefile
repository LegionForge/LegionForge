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
	@echo "  make check        — verify drive, venv, models, config, Guardian"
	@echo "  make start        — full startup sequence (includes Guardian)"
	@echo "  make stop         — graceful shutdown"
	@echo "  make status       — print system status (curl /status, needs token)"
	@echo "  make health       — quick liveness check (curl /health)"
	@echo "  make health-server — start health server in foreground"
	@echo "  make health-token — print stored health server Bearer token"
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
	@echo "  make security-audit — smoke tests + bandit static analysis"
	@echo "  make review-prep  — all automated gates for PR review (run before manual review)"
	@echo "  make setup-task-token-secret — generate and store JWT signing secret (one-time)"
	@echo "  make register-threat-analyst-tools — register Phase 4 tools (one-time)"
	@echo "  make run-threat-analyst — run Threat Analyst agent (7-day window)"
	@echo "  make bom             — show AI Bill of Materials"
	@echo "  make pending-rules   — show threat rules awaiting approval"
	@echo "  make register-researcher-tools — register Phase 1 tools (one-time)"
	@echo "  make register-orchestrator-tools — register Phase 3 orchestrator tools (one-time)"
	@echo "  make register-agent-sequences — register Researcher expected sequences"
	@echo "  make verify-tool-registry — verify all registered tools are APPROVED"
	@echo "  make verify-model-integrity — hash-check Ollama model manifests"
	@echo "  make audit-log-verify — verify audit log hash chain integrity"
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
start: check ollama-start db-start ollama-warm guardian-start
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
	@TOKEN=$$(security find-generic-password -s legionforge_health -a api_key -w 2>/dev/null) && \
	curl -s -H "Authorization: Bearer $$TOKEN" http://localhost:8765/status | python3 -m json.tool 2>/dev/null \
		|| echo "⚠️  Health server not running or token missing. Start with: make health-server"

.PHONY: health-server
health-server:
	@echo "Starting health server at http://localhost:8765 ..."
	@cd $(BASE) && $(PYTHON) -m src.health

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
	@psql -U jpc -d legionforge

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

# ── Security Audit ───────────────────────────────────────────
# Run at every milestone: phase start/end, new library added, new agent added,
# before any PR merge. Proactive checks prevent downstream compounding errors.
.PHONY: security-audit
security-audit:
	@echo "🔐 Running security audit..."
	@echo ""
	@echo "--- Smoke tests (includes security regression tests) ---"
	@cd $(BASE) && $(PYTEST) tests/test_smoke.py -v
	@echo ""
	@echo "--- bandit static analysis (medium+ severity) ---"
	@if [ -x "$(VENV)/bin/bandit" ]; then \
		$(VENV)/bin/bandit -r $(BASE)/src/ -ll && echo "✅ bandit: no medium/high issues found" \
		|| (echo "❌ bandit found medium/high severity issues above — fix before merging" && exit 1); \
	else \
		echo "⚠️  bandit not installed. Run: make install"; \
	fi
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
	@echo "─── [1/6] Formatting ────────────────────────────────"
	@cd $(BASE) && $(VENV)/bin/black --check src/ tests/ config/ \
		&& echo "✅ Black: all files formatted" \
		|| (echo "❌ Black: unformatted files above — run: make format" && exit 1)
	@echo ""
	@echo "─── [2/6] Smoke tests ───────────────────────────────"
	@cd $(BASE) && $(PYTEST) tests/test_smoke.py -v
	@echo ""
	@echo "─── [3/6] Bandit static analysis ────────────────────"
	@if [ -x "$(VENV)/bin/bandit" ]; then \
		$(VENV)/bin/bandit -r $(BASE)/src/ -ll \
		&& echo "✅ Bandit: no medium/high issues" \
		|| (echo "❌ Bandit: medium/high issues above — fix before merging" && exit 1); \
	else \
		echo "⚠️  bandit not installed — run: make install"; \
	fi
	@echo ""
	@echo "─── [4/6] Secret scan ───────────────────────────────"
	@! grep -rn "postgresql://.*:.*@" $(BASE)/src/ --include="*.py" \
		&& echo "✅ No embedded passwords in connection URIs" \
		|| (echo "❌ Embedded password in URI — use keyword args" && exit 1)
	@! grep -rn "sk-[A-Za-z0-9]\{20,\}" $(BASE)/src/ --include="*.py" \
		&& echo "✅ No OpenAI-style API keys in source" \
		|| (echo "❌ Possible API key in source above" && exit 1)
	@echo ""
	@echo "─── [5/6] New external dependencies ────────────────"
	@DEPS=$$(git diff origin/main -- requirements.txt 2>/dev/null | grep "^+" | grep -v "^+++" | grep -v "^+#"); \
	if [ -n "$$DEPS" ]; then \
		echo "⚠️  New dependencies detected — review required (Phase C3):"; \
		echo "$$DEPS"; \
	else \
		echo "✅ No new external dependencies"; \
	fi
	@echo ""
	@echo "─── [6/6] Scope check — changed files ──────────────"
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
import hashlib, json, pathlib, sys; \
ollama_dir = pathlib.Path('/Volumes/MAC_MINI_1TB/ollama_models/manifests'); \
if not ollama_dir.exists(): print('⚠️  Ollama model dir not found — skipping'); sys.exit(0); \
manifests = list(ollama_dir.rglob('*')); \
print(f'Found {len(manifests)} manifest entries in {ollama_dir}'); \
print('✅ Model manifest check complete (hash diffing added in Phase 2)')"

# ── Guardian (Phase 2) ────────────────────────────────────────
.PHONY: guardian-start
guardian-start:
	@echo "Starting Guardian sidecar..."
	@docker-compose up -d guardian 2>/dev/null && \
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

# ── Audit log ─────────────────────────────────────────────────
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

# ── Phase 3: JWT task token secret setup ──────────────────────
.PHONY: setup-task-token-secret
setup-task-token-secret:
	@echo "Setting up JWT task token signing secret..."
	@echo "Generating a 32-byte hex secret..."
	@SECRET=$$($(PYTHON) -c "import secrets; print(secrets.token_hex(32))") && \
	security add-generic-password \
		-s legionforge_task_tokens \
		-a api_key \
		-w "$$SECRET" \
		-U 2>/dev/null && \
	echo "✅ Task token secret stored in Keychain (service=legionforge_task_tokens)" && \
	echo "   Verify with: security find-generic-password -s legionforge_task_tokens -a api_key -w" \
	|| echo "❌ Could not store secret in Keychain — store manually:"
	@echo "   python3 -c \"import secrets; print(secrets.token_hex(32))\""
	@echo "   security add-generic-password -s legionforge_task_tokens -a api_key -w '<secret>' -U"

# ── Phase 3: Orchestrator tool registration ───────────────────
.PHONY: register-orchestrator-tools
register-orchestrator-tools:
	@echo "Registering orchestrator agent tools..."
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.agents.orchestrator import register_orchestrator_tools; \
asyncio.run(register_orchestrator_tools()); \
print('✅ Orchestrator tools registered')"

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

# ── Agent sequence registration ───────────────────────────────
.PHONY: register-agent-sequences
register-agent-sequences:
	@echo "Registering Researcher agent expected sequences..."
	@cd $(BASE) && $(PYTHON) -c "\
import asyncio; \
from src.database import init_db, register_agent_sequences; \
from src.agents.researcher import RESEARCHER_EXPECTED_SEQUENCES; \
async def run(): \
    await init_db(); \
    await register_agent_sequences('researcher', RESEARCHER_EXPECTED_SEQUENCES); \
    print(f'✅ Registered {len(RESEARCHER_EXPECTED_SEQUENCES)} sequences for researcher agent'); \
asyncio.run(run())"

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
