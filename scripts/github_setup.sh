#!/bin/bash
# ============================================================
# github_setup.sh
# One-time script to initialize git, create the GitHub repo
# jpc-mac-agent-framework, and push the first commit.
#
# Requirements: GitHub CLI (gh) already authenticated
# Run from the project root:
#   chmod +x scripts/github_setup.sh
#   ./scripts/github_setup.sh
# ============================================================

set -e

REPO_NAME="jpc-mac-agent-framework"
REPO_DESCRIPTION="Hardware-parameterized LangGraph multi-agent framework for Apple Silicon"
GITHUB_VISIBILITY="private"   # Change to "public" if preferred

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║      jpc-mac-agent-framework — GitHub Setup          ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Preflight checks ─────────────────────────────────────────

if [ ! -f "README.md" ] || [ ! -d "config" ]; then
    echo "❌  Run this from the project root (where README.md lives)."
    exit 1
fi

if ! command -v gh &> /dev/null; then
    echo "❌  GitHub CLI (gh) not found. Install: brew install gh"
    exit 1
fi

if ! gh auth status &> /dev/null; then
    echo "🔑  Not authenticated with gh. Running: gh auth login"
    gh auth login
fi

GITHUB_USER=$(gh api user --jq .login)
echo "✅  Authenticated as: $GITHUB_USER"

# ── Git init ─────────────────────────────────────────────────

echo ""
echo "📁  Initializing local git repository..."
git init
git branch -M main

GIT_NAME=$(git config user.name 2>/dev/null || echo "")
GIT_EMAIL=$(git config user.email 2>/dev/null || echo "")

if [ -z "$GIT_NAME" ] || [ -z "$GIT_EMAIL" ]; then
    echo ""
    echo "⚠️   Git user not configured. Setting for this repo:"
    read -p "  Your name: " GIT_NAME
    read -p "  Your GitHub email: " GIT_EMAIL
    git config user.name "$GIT_NAME"
    git config user.email "$GIT_EMAIL"
fi

echo "✅  Git user: $GIT_NAME <$GIT_EMAIL>"

# ── Stage files ───────────────────────────────────────────────

echo ""
echo "📦  Staging all files..."
git add .

# Security pre-check
echo "🔐  Checking for accidentally staged secrets..."
for DANGER in ".env.secrets" "*.pem" "*.key"; do
    if git diff --cached --name-only | grep -q "$DANGER" 2>/dev/null; then
        echo "🚨  SECURITY: '$DANGER' staged — removing it."
        git reset HEAD "$DANGER" 2>/dev/null || true
    fi
done

echo "✅  Security check passed. Staging:"
git diff --cached --name-only | sed 's/^/   + /'

# ── First commit ──────────────────────────────────────────────

echo ""
echo "💾  Creating initial commit..."
git commit -m "feat: initial framework scaffold

- Hardware-parameterized config (YAML + Pydantic)
- Mac M4 16GB and M5 32GB hardware profiles  
- Loop safeguards: recursion limit, step counter, action history
- macOS Keychain secret management (never in files)
- LangSmith + local JSON logging observability
- Base graph template with safeguards wired in
- Pre-commit hooks for secret scanning (gitleaks)"

echo "✅  Initial commit created."

# ── Create GitHub repo and push ───────────────────────────────

echo ""
echo "🐙  Creating repo: github.com/$GITHUB_USER/$REPO_NAME ..."

gh repo create "$REPO_NAME" \
    --description "$REPO_DESCRIPTION" \
    --"$GITHUB_VISIBILITY" \
    --source=. \
    --remote=origin \
    --push

REPO_URL="https://github.com/$GITHUB_USER/$REPO_NAME"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅  SUCCESS — Repo live at:"
echo "      $REPO_URL"
echo ""
echo "  IMMEDIATE NEXT STEPS:"
echo ""
echo "  1. Update your external drive name:"
echo "       config/hardware_profiles/mac_m4_mini_16gb.yaml"
echo "       → storage.external.mount_path"
echo "       (check Finder > Locations for the exact name)"
echo ""
echo "  2. Store API keys in macOS Keychain:"
echo "       python -m keyring set openai api_key"
echo "       python -m keyring set anthropic api_key"
echo "       python -m keyring set langsmith api_key"
echo ""
echo "  3. Install pre-commit secret scanning:"
echo "       pip install pre-commit"
echo "       pre-commit install"
echo ""
echo "  4. Verify config loads:"
echo "       python -c \"from config.settings import settings\""
echo ""
echo "  5. Pull local models:"
echo "       ollama pull llama3.1:8b"
echo "       ollama pull qwen2.5:3b"
echo "       ollama pull nomic-embed-text"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
