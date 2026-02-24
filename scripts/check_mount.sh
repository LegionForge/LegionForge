#!/bin/bash
# ============================================================
# scripts/check_mount.sh
#
# Run this BEFORE starting any agent processes.
# Verifies the external drive is mounted and all required
# directories exist. Exits with error if not ready.
#
# Why this matters:
#   On a headless rack machine, macOS sometimes finishes
#   booting before external drives are fully mounted.
#   If agent processes start before the drive is ready,
#   macOS creates paths on the INTERNAL drive instead —
#   exactly what we're trying to avoid.
#
# Usage:
#   ./scripts/check_mount.sh                  # check only
#   ./scripts/check_mount.sh --wait           # wait up to 60s for mount
#   ./scripts/check_mount.sh --create-dirs    # create missing dirs
# ============================================================

set -e

VOLUME="/Volumes/MAC_MINI_1TB"
PROJECT="$VOLUME/LegionForge"
WAIT_MODE=false
CREATE_DIRS=false
MAX_WAIT=60   # seconds

# Parse args
for arg in "$@"; do
  case $arg in
    --wait)       WAIT_MODE=true ;;
    --create-dirs) CREATE_DIRS=true ;;
  esac
done

# ── Check drive is mounted ────────────────────────────────────

echo "🔍  Checking external drive: $VOLUME"

if [ "$WAIT_MODE" = true ]; then
    ELAPSED=0
    while [ ! -d "$VOLUME" ]; do
        if [ $ELAPSED -ge $MAX_WAIT ]; then
            echo "❌  Drive not mounted after ${MAX_WAIT}s. Aborting."
            echo "    Check USB/Thunderbolt connection and drive health."
            exit 1
        fi
        echo "⏳  Waiting for $VOLUME ... (${ELAPSED}s)"
        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done
else
    if [ ! -d "$VOLUME" ]; then
        echo "❌  External drive not mounted at: $VOLUME"
        echo ""
        echo "    Possible causes:"
        echo "      - Drive not connected or powered"
        echo "      - Drive needs to be manually mounted (Finder or diskutil)"
        echo "      - macOS still booting (try: ./check_mount.sh --wait)"
        echo ""
        echo "    Check with: diskutil list"
        exit 1
    fi
fi

echo "✅  Drive mounted: $VOLUME"

# ── Verify project directory ──────────────────────────────────

if [ ! -d "$PROJECT" ]; then
    echo "❌  Project directory not found: $PROJECT"
    exit 1
fi

echo "✅  Project directory: $PROJECT"

# ── Check required subdirectories ────────────────────────────

REQUIRED_DIRS=(
    "$PROJECT/venv"
    "$PROJECT/models/ollama"
    "$PROJECT/models/lmstudio"
    "$PROJECT/models/hf"
    "$PROJECT/checkpoints"
    "$PROJECT/logs"
    "$PROJECT/vector_store"
    "$PROJECT/data"
)

MISSING=()
for DIR in "${REQUIRED_DIRS[@]}"; do
    if [ ! -d "$DIR" ]; then
        MISSING+=("$DIR")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    if [ "$CREATE_DIRS" = true ]; then
        echo "📁  Creating missing directories..."
        for DIR in "${MISSING[@]}"; do
            mkdir -p "$DIR"
            echo "   + $DIR"
        done
    else
        echo "⚠️   Missing directories (run with --create-dirs to fix):"
        for DIR in "${MISSING[@]}"; do
            echo "      $DIR"
        done
        exit 1
    fi
fi

echo "✅  All required directories present"

# ── Check venv exists ─────────────────────────────────────────

if [ ! -f "$PROJECT/venv/bin/activate" ]; then
    echo ""
    echo "⚠️   Python venv not found. Create it with:"
    echo "      python3.12 -m venv $PROJECT/venv"
    echo "      source $PROJECT/venv/bin/activate"
    echo "      pip install -r $PROJECT/requirements.txt"
    exit 1
fi

echo "✅  Python venv ready"

# ── Check Ollama is running ───────────────────────────────────

if command -v ollama &> /dev/null; then
    if ollama list &> /dev/null 2>&1; then
        echo "✅  Ollama service running"
    else
        echo "⚠️   Ollama installed but not responding."
        echo "    Start with: brew services start ollama"
    fi
else
    echo "⚠️   Ollama not installed. Install with: brew install ollama"
fi

# ── All good ──────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅  System ready. Safe to start agent processes."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
