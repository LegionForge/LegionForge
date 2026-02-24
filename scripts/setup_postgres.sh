#!/bin/bash
# ============================================================
# scripts/setup_postgres.sh
#
# One-time PostgreSQL setup for LegionForge.
# Run this ONCE after installing PostgreSQL.
#
# What it does:
#   1. Installs PostgreSQL 16 + pgvector via Homebrew
#   2. Configures data directory on external drive
#   3. Creates the jpc database and user
#   4. Stores the password in macOS Keychain
#   5. Starts PostgreSQL as a background service
#
# Usage:
#   chmod +x scripts/setup_postgres.sh
#   ./scripts/setup_postgres.sh
# ============================================================

set -e

BASE="/Volumes/MAC_MINI_1TB/LegionForge"
PG_DATA="$BASE/postgres/data"
PG_VERSION="16"
DB_NAME="legionforge"
DB_USER="jpc"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║         PostgreSQL Setup for jpc-agent-framework     ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Check drive is mounted ────────────────────────────────────
if [ ! -d "/Volumes/MAC_MINI_1TB" ]; then
    echo "❌ External drive not mounted at /Volumes/MAC_MINI_1TB"
    exit 1
fi
echo "✅ External drive mounted"

# ── Install PostgreSQL and pgvector ──────────────────────────
echo "📦 Installing PostgreSQL $PG_VERSION and pgvector..."
brew install postgresql@$PG_VERSION pgvector 2>/dev/null || true
echo "✅ Packages ready"

# ── Create data directory on external drive ───────────────────
mkdir -p "$PG_DATA"
echo "✅ PostgreSQL data directory: $PG_DATA"

# ── Check if already initialized ─────────────────────────────
if [ -f "$PG_DATA/PG_VERSION" ]; then
    echo "ℹ️  PostgreSQL data directory already initialized. Skipping initdb."
else
    echo "🔧 Initializing PostgreSQL database cluster..."
    /opt/homebrew/opt/postgresql@$PG_VERSION/bin/initdb \
        -D "$PG_DATA" \
        --encoding=UTF8 \
        --locale=en_US.UTF-8 \
        --auth=trust
    echo "✅ Database cluster initialized"
fi

# ── Configure PostgreSQL to use external data dir ─────────────
BREW_PG_CONF="$(brew --prefix)/var/postgresql@$PG_VERSION"

# Create a launchd plist override to use external data dir
PLIST="$HOME/Library/LaunchAgents/homebrew.mxcl.postgresql@$PG_VERSION.plist"

if [ -f "$PLIST" ]; then
    echo "⚠️  PostgreSQL LaunchAgent already exists. Checking data dir..."
    if grep -q "$PG_DATA" "$PLIST"; then
        echo "✅ LaunchAgent already points to external drive"
    else
        echo "⚠️  LaunchAgent points to a different data dir."
        echo "    To change it, edit: $PLIST"
        echo "    Change -D value to: $PG_DATA"
    fi
else
    # Copy the homebrew plist and modify data dir
    HOMEBREW_PLIST="/opt/homebrew/opt/postgresql@$PG_VERSION/homebrew.mxcl.postgresql@$PG_VERSION.plist"
    if [ -f "$HOMEBREW_PLIST" ]; then
        cp "$HOMEBREW_PLIST" "$PLIST"
        # Replace the data directory argument
        sed -i '' "s|-D [^ ]*|-D $PG_DATA|g" "$PLIST"
        echo "✅ LaunchAgent configured to use external drive"
    fi
fi

# ── Start PostgreSQL ──────────────────────────────────────────
echo "🚀 Starting PostgreSQL..."
brew services start postgresql@$PG_VERSION
sleep 3

# Add to PATH for this session
export PATH="/opt/homebrew/opt/postgresql@$PG_VERSION/bin:$PATH"

# ── Create database user and database ────────────────────────
echo "🔧 Setting up database and user..."

# Generate a secure random password
DB_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")

# Create user (ignore error if already exists)
createuser --superuser $DB_USER 2>/dev/null || true

# Set password — use psql variable substitution to avoid shell injection
# if the password ever contains single quotes or special characters.
psql postgres -v pass="$DB_PASSWORD" -c "ALTER USER $DB_USER WITH PASSWORD :'pass';" 2>/dev/null || \
    psql -U "$DB_USER" postgres -v pass="$DB_PASSWORD" -c "ALTER USER $DB_USER WITH PASSWORD :'pass';" 2>/dev/null || true

# Create database (ignore error if already exists)
createdb -U $DB_USER $DB_NAME 2>/dev/null || true

echo "✅ Database '$DB_NAME' ready for user '$DB_USER'"

# ── Enable pgvector extension ─────────────────────────────────
psql -U $DB_USER -d $DB_NAME -c "CREATE EXTENSION IF NOT EXISTS vector;" 2>/dev/null || true
psql -U $DB_USER -d $DB_NAME -c "CREATE EXTENSION IF NOT EXISTS pg_trgm;" 2>/dev/null || true
echo "✅ PostgreSQL extensions enabled (vector, pg_trgm)"

# ── Store password in macOS Keychain ─────────────────────────
# Pass password via temp env var + heredoc — never interpolate secrets
# directly into python3 -c "..." strings (shell injection risk).
echo "🔐 Storing database password in macOS Keychain..."
_LF_TMP_PWD="$DB_PASSWORD" python3 - << 'PYTHON_EOF'
import os, keyring
keyring.set_password('postgres', 'api_key', os.environ['_LF_TMP_PWD'])
PYTHON_EOF
unset _LF_TMP_PWD
echo "✅ Password stored in Keychain (service: 'postgres', username: 'api_key')"

# ── Update .env with connection details ───────────────────────
ENV_FILE="$BASE/.env"
# Add postgres config if not already present
if ! grep -q "POSTGRES_HOST" "$ENV_FILE"; then
    cat >> "$ENV_FILE" << EOF

# ── PostgreSQL ────────────────────────────────────────────────
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=$DB_NAME
POSTGRES_USER=$DB_USER
# POSTGRES_PASSWORD is loaded from macOS Keychain at runtime
EOF
    echo "✅ PostgreSQL config added to .env"
else
    echo "ℹ️  PostgreSQL config already in .env"
fi

# ── Add PostgreSQL to PATH in .zshrc ─────────────────────────
if ! grep -q "postgresql@$PG_VERSION" ~/.zshrc 2>/dev/null; then
    echo "export PATH=\"/opt/homebrew/opt/postgresql@$PG_VERSION/bin:\$PATH\"" >> ~/.zshrc
    echo "✅ PostgreSQL added to PATH in ~/.zshrc"
fi

# ── Verify connection ─────────────────────────────────────────
echo ""
echo "🔍 Verifying connection..."
if psql -U $DB_USER -d $DB_NAME -c "SELECT 'connection_ok' AS status;" 2>/dev/null | grep -q "connection_ok"; then
    echo "✅ Database connection verified"
else
    echo "⚠️  Could not verify connection. Try: psql -U $DB_USER -d $DB_NAME"
fi

# ── Done ──────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅  PostgreSQL setup complete!"
echo ""
echo "  Database: $DB_NAME"
echo "  User:     $DB_USER"
echo "  Data dir: $PG_DATA"
echo "  Password: stored in macOS Keychain"
echo ""
echo "  Next steps:"
echo "    source ~/.zshrc"
echo "    make db-init    ← creates LangGraph + app tables"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
