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
        max_combined = self.max_primary_model_size_gb + self.max_secondary_model_size_gb
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
    # Phase 6: SHA256 of the GGUF file for integrity verification. Empty = skip.
    gguf_sha256: str = ""


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
    secret_backend: Literal["keychain", "env_var", "vault", "file"]
    keychain_service_names: KeychainNames
    prompt_injection_guard: bool
    tool_permission_enforcement: bool
    git_secret_scanning: bool
    # Phase 2: Guardian sidecar enforcement
    guardian_enabled: bool = True
    guardian_url: str = "http://localhost:9766"
    guardian_timeout_seconds: float = 2.0
    # Phase 2: Health server auth
    health_token_service: str = "legionforge_health"
    # Phase 3: Task-scoped JWT tokens
    task_token_secret_service: str = "legionforge_task_tokens"
    task_token_issuer: str = "legionforge"
    task_token_ttl_seconds: int = 3600
    # Phase 5: Ed25519 tool manifest signing
    tool_signing_enabled: bool = True
    signing_key_service: str = "legionforge_tool_signer"
    # Phase 5.5: Credential store hardening
    # Whether to purge API keys from os.environ after loading into CredentialStore.
    # WARNING: Setting true breaks LangChain/LangSmith (they require env vars).
    # Only enable if using a fully store-aware LLM client.
    purge_env_after_load: bool = False
    # Set false to disable all macOS Keychain access (Docker/CI environments).
    keychain_access_allowed: bool = True
    # Enable sandbox-exec OS-level sandboxing for analyzer subprocess (macOS only).
    sandbox_exec_enabled: bool = True
    # Require Bearer auth on Guardian /check and /rules endpoints.
    # Set to true in production; leave false for local dev / smoke tests.
    guardian_require_auth: bool = False
    # Path to file-backend credentials YAML (empty = use default ~/.config/legionforge/credentials.yaml).
    credentials_file_path: str = ""
    # Phase 6: Database RBAC — restricted runtime user (no DDL, no DELETE on audit tables).
    db_app_user: str = "legionforge_app"
    db_app_password_service: str = "legionforge_db_app"
    # Phase 6: Tool result injection — emit threat event and optionally halt the run.
    halt_on_tool_result_injection: bool = False
    # Phase 6: Analyzer Docker container (deny-default sandbox). Falls back to sandbox-exec.
    analyzer_container_enabled: bool = True
    # Phase 6: Model integrity — verify SHA256 of GGUF files at startup.
    model_integrity_strict: bool = False


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
                "LANGCHAIN_PROJECT", self.observability.langsmith.project_name
            )
        os.environ.setdefault(
            "AGENT_MAX_RECURSION", str(self.safeguards.max_recursion_limit)
        )
        os.environ.setdefault("AGENT_MAX_TOKENS", str(self.safeguards.max_token_budget))

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

# Project root is always the directory containing this file's parent (config/).
# This makes workspace_root portable across any machine or CI environment.
# Override with WORKSPACE_ROOT env var if you need a non-standard location.
PROJECT_ROOT = Path(__file__).parent.parent


def _resolve_paths(raw: dict, project_root: Path) -> None:
    """Resolve relative subpaths in the YAML dict against project_root.

    Hardware profile YAMLs store subdirectory paths as relative fragments
    (e.g. "models/ollama"). This function resolves them to absolute paths
    at load time so the rest of the framework always works with absolute paths.
    """
    paths = raw.setdefault("paths", {})
    paths["workspace_root"] = str(project_root)

    for category in ("models", "runtime", "internal"):
        section = paths.get(category, {})
        for key, val in section.items():
            if val is not None and not os.path.isabs(str(val)):
                section[key] = str(project_root / val)

    # Resolve observability log_dir if it's a relative path
    log_dir = raw.get("observability", {}).get("local_logging", {}).get("log_dir", "")
    if log_dir and not os.path.isabs(log_dir):
        raw["observability"]["local_logging"]["log_dir"] = str(project_root / log_dir)


def load_settings(profile: Optional[str] = None) -> HardwareSettings:
    profile_name = (
        profile or os.environ.get("AGENT_HARDWARE_PROFILE") or DEFAULT_PROFILE
    )
    profile_path = PROFILES_DIR / f"{profile_name}.yaml"
    if not profile_path.exists():
        available = [p.stem for p in PROFILES_DIR.glob("*.yaml")]
        raise FileNotFoundError(
            f"Profile '{profile_name}' not found. Available: {available}"
        )
    with open(profile_path, "r") as f:
        raw = yaml.safe_load(f)

    workspace_override = os.environ.get("WORKSPACE_ROOT")
    project_root = Path(workspace_override) if workspace_override else PROJECT_ROOT
    _resolve_paths(raw, project_root)

    return HardwareSettings(**raw)


@lru_cache(maxsize=1)
def get_settings() -> HardwareSettings:
    s = load_settings()
    s.apply_to_environment()
    s.paths.ensure_directories()
    print(s.summarize())
    return s


settings: HardwareSettings = get_settings()
