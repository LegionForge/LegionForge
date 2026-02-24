#!/usr/bin/env bash
# =============================================================================
# startup.sh — LegionForge
# =============================================================================
# Verifies the environment, loads secrets, and starts the health server.
# Run from the project root: ./startup.sh
#
# Behavior:
#   - Aborts immediately on any failure
#   - Logs all output to logs/startup.log (relative to project root)
#   - Prints clear fix instructions for every failure to stdio
#
# Optional: comment out the HEALTH SERVER section at the bottom if you
# prefer to start the health server manually (make health-server).
# =============================================================================

set -euo pipefail

# ── Resolve project root (portable — works from any mount point) ──────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
VENV_DIR="$PROJECT_ROOT/venv"
LOG_DIR="$PROJECT_ROOT/logs"
LOG_FILE="$LOG_DIR/startup.log"
PID_FILE="$PROJECT_ROOT/.health_server.pid"
PYTHON="$VENV_DIR/bin/python3"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Logging ───────────────────────────────────────────────────────────────────
mkdir -p "$LOG_DIR"

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "${timestamp} [${level}] ${message}" >> "$LOG_FILE"
}

print_header() {
    echo ""
    echo -e "${BOLD}════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}  LegionForge — startup${RESET}"
    echo -e "${BOLD}  $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
    echo -e "${BOLD}════════════════════════════════════════════════════════${RESET}"
    echo ""
}

pass() {
    local message="$*"
    echo -e "  ${GREEN}✅${RESET}  ${message}"
    log "INFO" "PASS: ${message}"
}

fail() {
    local message="$1"
    local fix="$2"
    echo ""
    echo -e "  ${RED}❌  STARTUP FAILED${RESET}"
    echo -e "  ${RED}    ${message}${RESET}"
    echo ""
    echo -e "  ${YELLOW}→ Fix:${RESET} ${fix}"
    echo ""
    echo -e "  Log: ${LOG_FILE}"
    echo ""
    log "ERROR" "FAIL: ${message} | Fix: ${fix}"
    exit 1
}

warn() {
    local message="$*"
    echo -e "  ${YELLOW}⚠️  ${message}${RESET}"
    log "WARN" "${message}"
}

section() {
    echo ""
    echo -e "  ${BLUE}${BOLD}$*${RESET}"
}

# =============================================================================
print_header
log "INFO" "Starting startup.sh from PROJECT_ROOT=${PROJECT_ROOT}"

# ── CHECK 1: External drive / project root is accessible ─────────────────────
section "Checking project root..."

if [[ ! -d "$PROJECT_ROOT" ]]; then
    fail \
        "Project root not found: ${PROJECT_ROOT}" \
        "Ensure the drive is mounted and re-run from the project root directory."
fi
pass "Project root: ${PROJECT_ROOT}"

# ── CHECK 2: Virtualenv exists ────────────────────────────────────────────────
section "Checking virtualenv..."

if [[ ! -f "$PYTHON" ]]; then
    fail \
        "Virtualenv not found at: ${VENV_DIR}" \
        "Create it with: cd ${PROJECT_ROOT} && python3 -m venv venv && pip install -r requirements.txt"
fi
pass "Virtualenv: ${VENV_DIR}"

# Activate venv for this script's subshells
source "$VENV_DIR/bin/activate"
pass "Virtualenv activated"

# ── CHECK 3: Load secrets ─────────────────────────────────────────────────────
section "Loading secrets..."

OS="$(uname -s)"

if [[ "$OS" == "Darwin" ]]; then
    # macOS — load from Keychain via Python keyring
    POSTGRES_PASSWORD="$("$PYTHON" -c "
import keyring, sys
pw = keyring.get_password('postgres', 'api_key')
if not pw:
    sys.exit(1)
print(pw)
" 2>/dev/null)" || fail \
        "POSTGRES_PASSWORD not found in macOS Keychain." \
        "Store it with: python -m keyring set postgres api_key"

    export POSTGRES_PASSWORD
    pass "POSTGRES_PASSWORD loaded from Keychain"

    # LangSmith (optional — warn but don't abort)
    LANGSMITH_KEY="$("$PYTHON" -c "
import keyring
k = keyring.get_password('langsmith', 'api_key')
print(k or '')
" 2>/dev/null)"
    if [[ -n "$LANGSMITH_KEY" ]]; then
        export LANGSMITH_API_KEY="$LANGSMITH_KEY"
        pass "LANGSMITH_API_KEY loaded from Keychain"
    else
        warn "LANGSMITH_API_KEY not in Keychain — tracing will be disabled"
        log "WARN" "LangSmith key not found; tracing disabled for this session"
    fi

else
    # Non-macOS (Linux, CI, Docker) — fall back to environment variables
    warn "Non-macOS system detected (${OS}). Skipping Keychain. Using environment variables."
    log "WARN" "Non-macOS: Keychain unavailable, expecting env vars"

    if [[ -z "${POSTGRES_PASSWORD:-}" ]]; then
        fail \
            "POSTGRES_PASSWORD environment variable is not set." \
            "Export it before running: export POSTGRES_PASSWORD=your_password"
    fi
    pass "POSTGRES_PASSWORD loaded from environment"
fi

# ── CHECK 4: PostgreSQL reachable ─────────────────────────────────────────────
section "Checking PostgreSQL..."

PG_CHECK="$("$PYTHON" -c "
import asyncio, os, sys
import psycopg

async def check():
    host = os.environ.get('POSTGRES_HOST', 'localhost')
    port = os.environ.get('POSTGRES_PORT', '5432')
    db   = os.environ.get('POSTGRES_DB', 'legionforge')
    user = os.environ.get('POSTGRES_USER', 'jpc')
    pw   = os.environ.get('POSTGRES_PASSWORD', '')
    conn_str = f'postgresql://{user}:{pw}@{host}:{port}/{db}'
    try:
        async with await psycopg.AsyncConnection.connect(conn_str) as conn:
            await conn.execute('SELECT 1')
        print('ok')
    except Exception as e:
        print(f'error: {e}', file=sys.stderr)
        sys.exit(1)

asyncio.run(check())
" 2>&1)" || fail \
    "PostgreSQL is not reachable: ${PG_CHECK}" \
    "Start it with: brew services start postgresql@17"

pass "PostgreSQL: reachable"

# ── CHECK 5: Ollama reachable ─────────────────────────────────────────────────
section "Checking Ollama..."

OLLAMA_URL="${OLLAMA_HOST:-http://localhost:11434}"

OLLAMA_CHECK="$(curl -sf --max-time 5 "${OLLAMA_URL}/api/tags" 2>&1)" || fail \
    "Ollama is not reachable at ${OLLAMA_URL}" \
    "Start it with: ollama serve   (or open the Ollama app)"

# List loaded models
MODELS="$("$PYTHON" -c "
import json, sys
try:
    data = json.loads('''${OLLAMA_CHECK}''')
    models = [m['name'] for m in data.get('models', [])]
    print(', '.join(models) if models else 'none loaded')
except Exception:
    print('unknown')
" 2>/dev/null)"
pass "Ollama: reachable — models: ${MODELS}"

# Warn on missing required models
for model in "llama3.1:8b" "nomic-embed-text:latest"; do
    if [[ "$OLLAMA_CHECK" != *"$model"* ]]; then
        warn "Required model not loaded: ${model} — pull with: ollama pull ${model}"
    fi
done

# ── CHECK 6: Smoke tests ──────────────────────────────────────────────────────
section "Running smoke tests..."

SMOKE_OUTPUT="$(cd "$PROJECT_ROOT" && "$VENV_DIR/bin/pytest" tests/test_smoke.py -q 2>&1)"
SMOKE_EXIT=$?

if [[ $SMOKE_EXIT -ne 0 ]]; then
    echo "$SMOKE_OUTPUT"
    log "ERROR" "Smoke tests failed:\n${SMOKE_OUTPUT}"
    fail \
        "Smoke tests failed. See output above." \
        "Fix the failing tests before starting the framework."
fi

# Extract pass count for display
SMOKE_SUMMARY="$(echo "$SMOKE_OUTPUT" | tail -1)"
pass "Smoke tests: ${SMOKE_SUMMARY}"

# ── STATUS SUMMARY ────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}${GREEN}All checks passed. Framework is ready.${RESET}"
echo ""
log "INFO" "All startup checks passed."

# =============================================================================
# HEALTH SERVER (optional — comment out this section to skip)
# =============================================================================
section "Starting health server..."

# Kill any existing health server from a previous session
if [[ -f "$PID_FILE" ]]; then
    OLD_PID="$(cat "$PID_FILE")"
    if kill -0 "$OLD_PID" 2>/dev/null; then
        warn "Stopping existing health server (PID ${OLD_PID})..."
        kill "$OLD_PID" 2>/dev/null || true
        sleep 1
    fi
    rm -f "$PID_FILE"
fi

# Start health server in background
cd "$PROJECT_ROOT"
nohup "$PYTHON" -m src.health >> "$LOG_DIR/health_server.log" 2>&1 &
HEALTH_PID=$!
echo "$HEALTH_PID" > "$PID_FILE"

# Give it a moment to start, then verify it's up
sleep 2

if ! kill -0 "$HEALTH_PID" 2>/dev/null; then
    fail \
        "Health server failed to start (PID ${HEALTH_PID})." \
        "Check logs: tail -50 ${LOG_DIR}/health_server.log"
fi

# Quick HTTP check
HTTP_CHECK="$(curl -sf --max-time 5 http://localhost:8765/health 2>&1)" || fail \
    "Health server started but /health endpoint is not responding." \
    "Check logs: tail -50 ${LOG_DIR}/health_server.log"

pass "Health server: running (PID ${HEALTH_PID}) → http://localhost:8765"
log "INFO" "Health server started with PID ${HEALTH_PID}"

# END OF OPTIONAL HEALTH SERVER SECTION
# =============================================================================

echo ""
echo -e "  ${BOLD}Useful commands:${RESET}"
echo -e "    curl -s http://localhost:8765/status | python3 -m json.tool"
echo -e "    tail -f ${LOG_DIR}/health_server.log"
echo -e "    kill \$(cat ${PID_FILE})   # stop health server"
echo ""
echo -e "  ${BOLD}Startup log:${RESET} ${LOG_FILE}"
echo ""
log "INFO" "startup.sh complete."
