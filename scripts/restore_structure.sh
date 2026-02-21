#!/bin/bash
# ============================================================
# restore_structure.sh
# Fixes the flattened download by creating all missing files
# and the correct directory structure in one shot.
#
# Run from anywhere:
#   chmod +x restore_structure.sh
#   ./restore_structure.sh
# ============================================================
set -e

BASE="/Volumes/MAC_MINI_1TB/jpc-mac-agent-framework"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║         Restoring jpc-mac-agent-framework            ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Create directory structure ────────────────────────────────
echo "📁 Creating directory structure..."
mkdir -p "$BASE/config/hardware_profiles"
mkdir -p "$BASE/src/agents"
mkdir -p "$BASE/src/tools"
mkdir -p "$BASE/src/memory"
mkdir -p "$BASE/docs"
mkdir -p "$BASE/tests"
echo "✅ Directories ready"

# ── Move misplaced yaml to correct location ───────────────────
if [ -f "$BASE/mac_m4_mini_16gb.yaml" ]; then
    mv "$BASE/mac_m4_mini_16gb.yaml" \
       "$BASE/config/hardware_profiles/mac_m4_mini_16gb.yaml"
    echo "✅ Moved mac_m4_mini_16gb.yaml → config/hardware_profiles/"
fi

# ── requirements.txt ─────────────────────────────────────────
cat > "$BASE/requirements.txt" << 'EOF'
# ============================================================
# Core LangGraph Framework Requirements
# Pin major versions; allow patch updates (~=)
# Last verified: February 2026 / Python 3.11
# ============================================================

# ── Framework Core ───────────────────────────────────────────
langgraph~=0.2
langchain~=0.3
langchain-core~=0.3
langchain-community~=0.3

# ── LLM Provider Clients ─────────────────────────────────────
langchain-openai~=0.2
langchain-anthropic~=0.3
langchain-ollama~=0.1

# ── Observability ────────────────────────────────────────────
langsmith~=0.1

# ── Persistence / Checkpointing ──────────────────────────────
langgraph-checkpoint-sqlite~=1.0

# ── Config & Validation ──────────────────────────────────────
pydantic~=2.0
pydantic-settings~=2.0
pyyaml~=6.0

# ── Secret Management ────────────────────────────────────────
keyring~=25.0
python-dotenv~=1.0

# ── Token Counting ───────────────────────────────────────────
tiktoken~=0.7

# ── HTTP / Async ─────────────────────────────────────────────
httpx~=0.27
aiohttp~=3.9
tenacity~=8.0

# ── Dev / Testing ────────────────────────────────────────────
pytest~=8.0
pytest-asyncio~=0.23
EOF
echo "✅ requirements.txt"

# ── .env ─────────────────────────────────────────────────────
cat > "$BASE/.env" << 'EOF'
# .env — NON-SENSITIVE config only. Safe to commit.
# API keys are stored in macOS Keychain, never here.

AGENT_HARDWARE_PROFILE=mac_m4_mini_16gb
LANGSMITH_PROJECT=local-agents-m4
OLLAMA_BASE_URL=http://localhost:11434
LMSTUDIO_BASE_URL=http://localhost:1234/v1
LOG_LEVEL=INFO
EOF
echo "✅ .env"

# ── .env.secrets.example ─────────────────────────────────────
cat > "$BASE/.env.secrets.example" << 'EOF'
# TEMPLATE ONLY — safe to commit. Never commit the real .env.secrets.
# Preferred method: macOS Keychain
#   python -m keyring set openai api_key
#   python -m keyring set anthropic api_key
#   python -m keyring set langsmith api_key

OPENAI_API_KEY=sk-...your-key-here...
ANTHROPIC_API_KEY=sk-ant-...your-key-here...
LANGSMITH_API_KEY=ls__...your-key-here...
EOF
echo "✅ .env.secrets.example"

# ── .gitignore ───────────────────────────────────────────────
cat > "$BASE/.gitignore" << 'EOF'
# ── SECRETS — NEVER COMMIT ───────────────────────────────────
.env.secrets
.env.local
.env.production
*.key
*.pem
secrets/

# ── Python ───────────────────────────────────────────────────
__pycache__/
*.py[cod]
*.so
build/
dist/
*.egg-info/

# ── Virtual Environments ─────────────────────────────────────
venv/
.venv/

# ── LangGraph Runtime ────────────────────────────────────────
.langgraph/
.langchain/

# ── Model Files ──────────────────────────────────────────────
*.gguf
*.safetensors
*.bin
*.pt
*.onnx

# ── Logs & Runtime Data ──────────────────────────────────────
logs/
*.log
checkpoints/
*.db
*.sqlite
vector_store/

# ── macOS ────────────────────────────────────────────────────
.DS_Store
.Spotlight-V100
.Trashes

# ── IDEs ─────────────────────────────────────────────────────
.vscode/
.idea/
.cursor/
EOF
echo "✅ .gitignore"

# ── langgraph.json ───────────────────────────────────────────
cat > "$BASE/langgraph.json" << 'EOF'
{
  "dependencies": ["."],
  "graphs": {
    "agent": "./src/base_graph.py:graph"
  },
  "env": ".env"
}
EOF
echo "✅ langgraph.json"

# ── .pre-commit-config.yaml ──────────────────────────────────
cat > "$BASE/.pre-commit-config.yaml" << 'EOF'
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks
        name: "🔐 Scan for secrets (gitleaks)"

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-json
      - id: check-added-large-files
        args: ['--maxkb=1024']
      - id: check-merge-conflict
      - id: no-commit-to-branch
        args: ['--branch', 'main']

  - repo: https://github.com/psf/black
    rev: 24.3.0
    hooks:
      - id: black
        language_version: python3.11
EOF
echo "✅ .pre-commit-config.yaml"

# ── src/__init__.py ──────────────────────────────────────────
cat > "$BASE/src/__init__.py" << 'EOF'
# LangGraph Agent Framework — source package
EOF

cat > "$BASE/src/agents/__init__.py" << 'EOF'
# agents subpackage
EOF

echo "✅ src/ package files"

# ── docs/README.md ───────────────────────────────────────────
cat > "$BASE/docs/README.md" << 'EOF'
# Documentation

## Setup Plan
See [setup_plan.md](setup_plan.md) for the complete setup guide including:
- Hardware reality check and memory budgeting
- Phase-by-phase installation steps
- Loop safeguard implementation details
- Security and key management
- Observability configuration
- Base graph template
EOF
echo "✅ docs/README.md"

# ── config/__init__.py ───────────────────────────────────────
touch "$BASE/config/__init__.py"
echo "✅ config/__init__.py"

# ── config/hardware_profiles/mac_m5_mini_32gb.yaml ───────────
cat > "$BASE/config/hardware_profiles/mac_m5_mini_32gb.yaml" << 'EOF'
# ============================================================
# Hardware Profile: Mac Mini M5 — Template (update on purchase)
# ============================================================

profile:
  name: "mac_m5_mini_32gb"
  description: "Mac Mini M5, 32GB unified memory (placeholder)"
  platform: "macos"
  chip_family: "apple_silicon"
  chip_model: "m5"
  python_min_version: "3.11"

memory:
  total_gb: 32
  os_reserved_gb: 4
  framework_reserved_gb: 2
  available_for_models_gb: 26
  max_concurrent_models: 3
  max_primary_model_size_gb: 14
  max_secondary_model_size_gb: 7

storage:
  internal:
    total_gb: 512
    mount_path: "/"
    enabled: true
    uses: [python_envs, source_code, config_files]
  external:
    total_gb: 1000
    mount_path: "/Volumes/MAC_MINI_1TB"
    enabled: true
    uses: [llm_models, checkpoints, logs, datasets, vector_stores]

paths:
  workspace_root: "/Volumes/MAC_MINI_1TB/jpc-mac-agent-framework"
  models:
    ollama:      "/Volumes/MAC_MINI_1TB/jpc-mac-agent-framework/models/ollama"
    lmstudio:    "/Volumes/MAC_MINI_1TB/jpc-mac-agent-framework/models/lmstudio"
    huggingface: "/Volumes/MAC_MINI_1TB/jpc-mac-agent-framework/models/hf"
  runtime:
    checkpoints:  "/Volumes/MAC_MINI_1TB/jpc-mac-agent-framework/checkpoints"
    logs:         "/Volumes/MAC_MINI_1TB/jpc-mac-agent-framework/logs"
    vector_store: "/Volumes/MAC_MINI_1TB/jpc-mac-agent-framework/vector_store"
    datasets:     "/Volumes/MAC_MINI_1TB/jpc-mac-agent-framework/data"
  internal:
    venv:   "/Volumes/MAC_MINI_1TB/jpc-mac-agent-framework/venv"
    source: "/Volumes/MAC_MINI_1TB/jpc-mac-agent-framework"

local_services:
  ollama:
    enabled: true
    base_url: "http://localhost:11434"
    env_var_override: "OLLAMA_BASE_URL"
  lmstudio:
    enabled: false
    base_url: "http://localhost:1234/v1"
    env_var_override: "LMSTUDIO_BASE_URL"

models:
  primary:
    provider: "ollama"
    model_id: "llama3.3:70b-instruct-q2_K"
    estimated_size_gb: 26.0
    use_cases: [general_reasoning, writing, analysis, complex_tasks]
    quantization: "q2_K"
  router:
    provider: "ollama"
    model_id: "qwen2.5:7b"
    estimated_size_gb: 4.7
    use_cases: [routing, classification, supervisor]
    quantization: "q4_K_M"
  embeddings:
    provider: "ollama"
    model_id: "nomic-embed-text"
    estimated_size_gb: 0.3
    use_cases: [embeddings, rag, semantic_search]
    quantization: null
  cloud_fallback:
    openai:
      model_id: "gpt-4o"
      use_cases: [frontier_reasoning]
    anthropic:
      model_id: "claude-opus-4-6"
      use_cases: [frontier_reasoning, complex_code]

safeguards:
  default_recursion_limit: 20
  max_recursion_limit: 40
  default_token_budget: 100000
  max_token_budget: 300000
  loop_detection_window: 5
  loop_detection_threshold: 3
  max_errors_per_run: 3
  step_counter_enabled: true
  human_interrupt_on_irreversible: true

observability:
  langsmith:
    enabled: true
    project_name: "local-agents-m5"
    env_var: "LANGSMITH_API_KEY"
  local_logging:
    enabled: true
    format: "json"
    log_dir: "/Volumes/MAC_MINI_1TB/jpc-mac-agent-framework/logs"
    rotation: "daily"
    retention_days: 30

security:
  secret_backend: "keychain"
  keychain_service_names:
    openai: "openai"
    anthropic: "anthropic"
    langsmith: "langsmith"
  prompt_injection_guard: true
  tool_permission_enforcement: true
  git_secret_scanning: true
EOF
echo "✅ config/hardware_profiles/mac_m5_mini_32gb.yaml"

# ── config/settings.py ───────────────────────────────────────
cat > "$BASE/config/settings.py" << 'PYEOF'
"""
config/settings.py
──────────────────
Loads and validates the hardware profile YAML using Pydantic.
Single source of truth for all framework configuration.

Usage:
    from config.settings import settings
    print(settings.memory.available_for_models_gb)
    print(settings.paths.runtime.checkpoints)

Switch hardware profiles:
    export AGENT_HARDWARE_PROFILE=mac_m5_mini_32gb
"""

from __future__ import annotations

import os
import yaml
from pathlib import Path
from typing import Optional, Literal
from pydantic import BaseModel, field_validator, model_validator
from functools import lru_cache


class ProfileMeta(BaseModel):
    name: str
    description: str
    platform: Literal["macos", "linux", "windows"]
    chip_family: Literal["apple_silicon", "intel", "amd", "nvidia"]
    chip_model: str
    python_min_version: str


class MemoryConfig(BaseModel):
    total_gb: int
    os_reserved_gb: int
    framework_reserved_gb: int
    available_for_models_gb: int
    max_concurrent_models: int
    max_primary_model_size_gb: float
    max_secondary_model_size_gb: float

    @model_validator(mode="after")
    def validate_memory_budget(self) -> MemoryConfig:
        allocated = (
            self.os_reserved_gb
            + self.framework_reserved_gb
            + self.available_for_models_gb
        )
        if allocated > self.total_gb:
            raise ValueError(
                f"Memory over-allocated: {allocated}GB assigned but only "
                f"{self.total_gb}GB total."
            )
        return self

    @model_validator(mode="after")
    def validate_model_sizes(self) -> MemoryConfig:
        max_combined = (
            self.max_primary_model_size_gb + self.max_secondary_model_size_gb
        )
        if max_combined > self.available_for_models_gb:
            raise ValueError(
                f"Primary + secondary model sizes exceed available memory."
            )
        return self


class StorageDevice(BaseModel):
    total_gb: int
    mount_path: str
    uses: list[str]
    enabled: bool = True

    @field_validator("mount_path")
    @classmethod
    def expand_path(cls, v: str) -> str:
        return str(Path(v).expanduser())


class StorageConfig(BaseModel):
    internal: StorageDevice
    external: StorageDevice


class ModelPaths(BaseModel):
    ollama: str
    lmstudio: str
    huggingface: str


class RuntimePaths(BaseModel):
    checkpoints: str
    logs: str
    vector_store: str
    datasets: str


class InternalPaths(BaseModel):
    venv: str
    source: str


class PathsConfig(BaseModel):
    workspace_root: str
    models: ModelPaths
    runtime: RuntimePaths
    internal: InternalPaths

    def ensure_directories(self) -> None:
        dirs = [
            self.workspace_root,
            self.models.ollama,
            self.models.lmstudio,
            self.models.huggingface,
            self.runtime.checkpoints,
            self.runtime.logs,
            self.runtime.vector_store,
            self.runtime.datasets,
        ]
        for d in dirs:
            os.makedirs(str(Path(d).expanduser()), exist_ok=True)


class LocalService(BaseModel):
    enabled: bool
    base_url: str
    env_var_override: Optional[str] = None

    def resolved_url(self) -> str:
        if self.env_var_override:
            return os.environ.get(self.env_var_override, self.base_url)
        return self.base_url


class LocalServicesConfig(BaseModel):
    ollama: LocalService
    lmstudio: LocalService


class ModelEntry(BaseModel):
    provider: str
    model_id: str
    estimated_size_gb: float
    use_cases: list[str]
    quantization: Optional[str] = None


class CloudModel(BaseModel):
    model_id: str
    use_cases: list[str]


class CloudFallback(BaseModel):
    openai: CloudModel
    anthropic: CloudModel


class ModelsConfig(BaseModel):
    primary: ModelEntry
    router: ModelEntry
    embeddings: ModelEntry
    cloud_fallback: CloudFallback


class SafeguardsConfig(BaseModel):
    default_recursion_limit: int
    max_recursion_limit: int
    default_token_budget: int
    max_token_budget: int
    loop_detection_window: int
    loop_detection_threshold: int
    max_errors_per_run: int
    step_counter_enabled: bool
    human_interrupt_on_irreversible: bool

    @model_validator(mode="after")
    def default_must_not_exceed_max(self) -> SafeguardsConfig:
        if self.default_recursion_limit > self.max_recursion_limit:
            raise ValueError(
                f"default_recursion_limit cannot exceed max_recursion_limit"
            )
        return self


class LangSmithConfig(BaseModel):
    enabled: bool
    project_name: str
    env_var: str


class LocalLoggingConfig(BaseModel):
    enabled: bool
    format: Literal["json", "text"]
    log_dir: str
    rotation: str
    retention_days: int


class ObservabilityConfig(BaseModel):
    langsmith: LangSmithConfig
    local_logging: LocalLoggingConfig


class KeychainNames(BaseModel):
    openai: str
    anthropic: str
    langsmith: str


class SecurityConfig(BaseModel):
    secret_backend: Literal["keychain", "env_var", "vault"]
    keychain_service_names: KeychainNames
    prompt_injection_guard: bool
    tool_permission_enforcement: bool
    git_secret_scanning: bool


class HardwareSettings(BaseModel):
    profile: ProfileMeta
    memory: MemoryConfig
    storage: StorageConfig
    paths: PathsConfig
    local_services: LocalServicesConfig
    models: ModelsConfig
    safeguards: SafeguardsConfig
    observability: ObservabilityConfig
    security: SecurityConfig

    def apply_to_environment(self) -> None:
        os.environ.setdefault("OLLAMA_MODELS", self.paths.models.ollama)
        if self.observability.langsmith.enabled:
            os.environ.setdefault("LANGCHAIN_TRACING_V2", "true")
            os.environ.setdefault(
                "LANGCHAIN_PROJECT",
                self.observability.langsmith.project_name
            )
        os.environ.setdefault(
            "AGENT_MAX_RECURSION",
            str(self.safeguards.max_recursion_limit)
        )
        os.environ.setdefault(
            "AGENT_MAX_TOKENS",
            str(self.safeguards.max_token_budget)
        )

    def summarize(self) -> str:
        return (
            f"\n{'='*55}\n"
            f"  Hardware Profile : {self.profile.name}\n"
            f"  {self.profile.description}\n"
            f"{'─'*55}\n"
            f"  Memory           : {self.memory.total_gb}GB total, "
            f"{self.memory.available_for_models_gb}GB for models\n"
            f"  Primary Model    : {self.models.primary.model_id} "
            f"({self.models.primary.estimated_size_gb}GB)\n"
            f"  Router Model     : {self.models.router.model_id} "
            f"({self.models.router.estimated_size_gb}GB)\n"
            f"  Recursion Limit  : {self.safeguards.default_recursion_limit} "
            f"(max {self.safeguards.max_recursion_limit})\n"
            f"  Token Budget     : {self.safeguards.default_token_budget:,}\n"
            f"  Secret Backend   : {self.security.secret_backend}\n"
            f"  Checkpoints      : {self.paths.runtime.checkpoints}\n"
            f"{'='*55}\n"
        )


PROFILES_DIR = Path(__file__).parent / "hardware_profiles"
DEFAULT_PROFILE = "mac_m4_mini_16gb"


def load_settings(profile: Optional[str] = None) -> HardwareSettings:
    profile_name = (
        profile
        or os.environ.get("AGENT_HARDWARE_PROFILE")
        or DEFAULT_PROFILE
    )
    profile_path = PROFILES_DIR / f"{profile_name}.yaml"
    if not profile_path.exists():
        available = [p.stem for p in PROFILES_DIR.glob("*.yaml")]
        raise FileNotFoundError(
            f"Profile '{profile_name}' not found. Available: {available}"
        )
    with open(profile_path, "r") as f:
        raw = yaml.safe_load(f)
    return HardwareSettings(**raw)


@lru_cache(maxsize=1)
def get_settings() -> HardwareSettings:
    s = load_settings()
    s.apply_to_environment()
    s.paths.ensure_directories()
    print(s.summarize())
    return s


settings: HardwareSettings = get_settings()
PYEOF
echo "✅ config/settings.py"

# ── Final verification ────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Final structure:"
find "$BASE" -not -path "*/venv/*" -not -path "*/.DS_Store" \
             -not -path "*/__pycache__/*" | sort
echo ""
echo "  ✅  Structure restored. Ready for pip install."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
