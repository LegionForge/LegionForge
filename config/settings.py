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


class OllamaNodeConfig(BaseModel):
    """
    A single Ollama node in a multi-machine cluster (Phase 20).

    Fields:
        url    — Base URL of the Ollama instance, e.g. http://192.168.1.100:11434
        label  — Human-readable name used in the TestLab Cluster admin UI.
        weight — Relative request weight (round-robin; reserved for future use).
        enabled — Set false to temporarily remove a node without deleting config.
        timeout — Health-check connect+read timeout in seconds.
    """

    url: str
    label: str
    weight: int = 1
    enabled: bool = True
    timeout: float = 10.0


class OllamaClusterConfig(BaseModel):
    """
    Multi-machine Ollama cluster configuration (Phase 20).

    When ``nodes`` is empty (the default), the framework uses the single
    ``local_services.ollama.base_url`` — no behavioural change.

    Routing strategies:
        round_robin   — distribute requests across healthy nodes in order.
        primary_first — always prefer the first configured healthy node.
        least_busy    — route to the node with the lowest recent latency.
    """

    nodes: list[OllamaNodeConfig] = []
    routing: Literal["round_robin", "primary_first", "least_busy"] = "round_robin"
    health_check_interval: int = 30  # seconds between background health polls
    fallback_to_primary: bool = True  # use local ollama URL when all cluster nodes fail


class LocalServicesConfig(BaseModel):
    ollama: LocalService
    lmstudio: LocalService
    ollama_cluster: OllamaClusterConfig = OllamaClusterConfig()


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


class OIDCConfig(BaseModel):
    """
    Configuration for the Phase 12 OIDCBackend.

    Covers any OIDC-compliant IdP: Google, Okta, Auth0, Keycloak, Azure AD,
    Ping, Cognito, etc.  All fields default to empty (OIDC disabled) so the
    profile YAML can omit this section entirely when using api_key auth.

    Fields:
        issuer_url          — Base URL of the IdP, e.g. https://accounts.google.com
                              Used to build the discovery doc URL:
                              <issuer_url>/.well-known/openid-configuration
        client_id           — OAuth2 client ID registered with the IdP.
        audience            — Expected ``aud`` claim in the access token.
                              Defaults to ``client_id`` if left empty.
        userinfo_endpoint   — Override the userinfo URL from the discovery doc.
                              Empty = use the URL advertised by the discovery doc.
        jwks_cache_ttl      — Seconds to cache JWKS public keys (default 300).
    """

    issuer_url: str = ""
    client_id: str = ""
    audience: str = ""
    userinfo_endpoint: str = ""
    jwks_cache_ttl: int = 300


class LDAPConfig(BaseModel):
    """
    Configuration for the Phase 12 LDAPBackend.

    Supports OpenLDAP (uid={username}) and Active Directory
    (sAMAccountName={username}) via a configurable search filter.
    All fields default to empty (LDAP disabled) so hardware profiles that
    use api_key auth can omit this section.

    Fields:
        url                — LDAP server URL, e.g. ldap://ldap.example.com:389
                             or ldaps://ldap.example.com:636 (StartTLS / LDAPS).
        bind_dn            — Service-account DN used to search the directory,
                             e.g. cn=svc-legionforge,ou=services,dc=example,dc=com
        user_search_base   — Base DN for user searches,
                             e.g. ou=users,dc=example,dc=com
        user_search_filter — LDAP filter template; ``{username}`` is substituted.
                             OpenLDAP:  (uid={username})
                             AD:        (sAMAccountName={username})
        daily_token_limit  — Default token budget for LDAP-authenticated users.

    Keychain: legionforge_ldap_bind_password (service account password).
    """

    url: str = ""
    bind_dn: str = ""
    user_search_base: str = ""
    user_search_filter: str = "(uid={username})"
    daily_token_limit: int = 100000


class KerberosConfig(BaseModel):
    """
    Configuration for the Phase 13 KerberosBackend (GSSAPI / Negotiate).

    Requires:
      - A working KDC with ``/etc/krb5.conf`` on every host.
      - A service principal registered in the KDC:
            HTTP/legionforge.example.com@EXAMPLE.COM
      - A keytab file (default: /etc/legionforge/http.keytab).
      - The ``gssapi`` Python package (``pip install gssapi``).

    When ``gssapi`` is not installed, KerberosBackend logs a WARNING and
    returns None instead of raising — the caller receives a 401.

    Fields:
        keytab_path   — Path to the HTTP service keytab file.
        service_name  — GSSAPI service name (default: "HTTP").
        realm         — Kerberos realm (e.g. EXAMPLE.COM). Empty = KDC default.
        daily_token_limit — Default token budget for Kerberos-authenticated users.

    Keychain: legionforge_kerberos_keytab_path (override keytab location at runtime).
    """

    keytab_path: str = "/etc/legionforge/http.keytab"
    service_name: str = "HTTP"
    realm: str = ""
    daily_token_limit: int = 100000


class GatewayConfig(BaseModel):
    """
    Configuration for Phase 10+ gateway multi-user and auth features.
    All fields have safe defaults — add a ``gateway:`` section to your hardware
    profile YAML to override individual fields.
    """

    # Default daily token budget for new gateway users.
    # Override per-user via CLI: python -m src.cli.manage_users set-quota --username ...
    default_daily_token_limit: int = 100000

    # Auth backend to use for incoming requests.
    # "api_key"   — default; bcrypt-hashed keys in gateway_users table.
    # "oidc"      — OIDC/JWKS for Google, Okta, Auth0, Keycloak, Azure AD…
    # "github"    — GitHub OAuth opaque token → /user API.
    # "ldap"      — LDAP / Active Directory bind+search+rebind (Basic auth).
    # "kerberos"  — Kerberos/GSSAPI (Phase 13; graceful fallback when gssapi absent).
    auth_provider: str = "api_key"

    # Phase 12: OIDC provider configuration (required when auth_provider="oidc").
    oidc: OIDCConfig = OIDCConfig()

    # Phase 12: LDAP / Active Directory configuration (required when auth_provider="ldap").
    ldap: LDAPConfig = LDAPConfig()

    # Phase 13: Kerberos/GSSAPI configuration (required when auth_provider="kerberos").
    kerberos: KerberosConfig = KerberosConfig()

    # Phase 13: Optional Redis URL for cross-instance stream token sharing.
    # Empty string = DB-backed tokens (single-instance mode, current default).
    # Set to "redis://localhost:6379/0" (or REDIS_URL env var) to enable Redis mode.
    redis_url: str = ""


class TelegramConfig(BaseModel):
    """
    Configuration for the Phase 16 Telegram connector.
    See src/connectors/telegram.py for setup instructions.
    """

    gateway_url: str = "http://localhost:8080"
    agent_type: str = "orchestrator"
    prefix: str = "/"
    max_edit_interval: float = 2.0


class SlackConfig(BaseModel):
    """
    Configuration for the Phase 16 Slack Socket Mode connector.
    See src/connectors/slack.py for setup instructions.
    """

    gateway_url: str = "http://localhost:8080"
    agent_type: str = "orchestrator"
    prefix: str = "!"
    max_edit_interval: float = 2.0


class WebhookConfig(BaseModel):
    """
    Configuration for the Phase 16 generic inbound/outbound webhook connector.
    See src/connectors/webhook.py for setup instructions.
    """

    gateway_url: str = "http://localhost:8080"
    agent_type: str = "orchestrator"
    port: int = 8081


class ConnectorsConfig(BaseModel):
    """
    Aggregated connector configuration for Phase 16 channel connectors.
    All fields have safe defaults; configure via hardware profile YAML.
    """

    telegram: TelegramConfig = TelegramConfig()
    slack: SlackConfig = SlackConfig()
    webhook: WebhookConfig = WebhookConfig()


class AgentMemoryConfig(BaseModel):
    """
    Configuration for Phase 21 persistent agent memory (pgvector RAG).

    Disabled by default — set ``enabled: true`` in your hardware profile to
    activate.  Requires PostgreSQL with the pgvector extension and a running
    Ollama embeddings model (``nomic-embed-text`` by default).

    Fields:
        enabled              — Master switch.  No DB calls are made when False.
        recall_on_task       — Inject relevant past memory before each LLM call.
        store_results        — Persist task+result pairs for future recall.
        bootstrap_user_prefs — Inject the submitting user's preferences as context
                               before every LLM call (the USER.md equivalent).
        max_docs_per_namespace — Prune oldest docs when this limit is exceeded.
                                 0 = unlimited (not recommended in production).
        search_limit         — Top-K documents returned by similarity search.
        min_similarity       — Cosine similarity threshold (0–1; higher = stricter).
    """

    enabled: bool = False
    recall_on_task: bool = True
    store_results: bool = True
    bootstrap_user_prefs: bool = (
        True  # Gap 5: inject user preferences before every LLM call
    )
    episodic_memory: bool = True  # Gap 2: store daily summary after each task
    flush_on_compaction: bool = True  # Gap 4: extract key facts when context fills
    persona_bootstrap: bool = (
        True  # Gap 1: load persona: namespace before every LLM call
    )
    max_docs_per_namespace: int = 1000
    search_limit: int = 5
    min_similarity: float = 0.7


class PentestConfig(BaseModel):
    """
    Configuration for the Phase 6 PentestAgent (air-gapped red-team bot).

    All fields have safe defaults so this block is optional in hardware YAML profiles.
    Add a `pentest:` section to a profile to override individual fields.
    """

    enabled: bool = True
    # "verify"     — stop-at-proof-of-concept (default, safe)
    # "resilience" — continue past PoC to measure blast radius (explicit opt-in only)
    default_mode: str = "verify"
    # Maximum size (bytes) for attack payload strings stored in the DB.
    max_payload_size_bytes: int = 4096
    # Halt the entire run if a CRITICAL-severity bypass is confirmed.
    stop_on_critical: bool = True
    # Separate PostgreSQL database for synthetic pentest environment.
    synthetic_db_name: str = "legionforge_pentest"
    # Output format for the final report written to disk.
    report_format: str = "json"  # "json" | "markdown" | "html"
    # HTTP port for the deterministic stub Ollama responder.
    # Must not overlap with the real Ollama port (default 11434).
    stub_ollama_port: int = 11435


class ToolsConfig(BaseModel):
    """
    Configuration for Phase 9 tool library (file I/O, HTTP, code execution).
    All fields have safe defaults; configure via hardware profile YAML.
    """

    # ── file_read / file_write ──────────────────────────────────
    # Empty list = tool refuses every path until operator configures an allowlist.
    allowed_read_paths: list[str] = []
    allowed_write_paths: list[str] = []
    max_file_read_bytes: int = 51200  # 50 KB
    max_file_write_bytes: int = 51200  # 50 KB

    # ── http_get / http_post ────────────────────────────────────
    http_timeout_seconds: float = 30.0
    max_response_bytes: int = 51200  # 50 KB
    max_post_body_bytes: int = 10240  # 10 KB

    # ── code_execute ────────────────────────────────────────────
    sandbox_image: str = "legionforge-sandbox:latest"
    sandbox_timeout_seconds: int = 30
    sandbox_memory_mb: int = 256
    sandbox_cpus: float = 0.5
    sandbox_max_output_bytes: int = 10240  # 10 KB


# ── Search Provider Config (Phase 56) ─────────────────────────────────────────


class DDGSearchConfig(BaseModel):
    """DuckDuckGo provider config — no API key required."""

    region: str = "wt-wt"
    safe_search: str = "off"


class TavilySearchConfig(BaseModel):
    """Tavily AI search config. Keychain: legionforge_tavily_api_key."""

    search_depth: str = "basic"  # "basic" | "advanced"
    max_tokens: int = 4096


class BraveSearchConfig(BaseModel):
    """Brave Search API config. Keychain: legionforge_brave_api_key."""

    country: str = "us"
    search_lang: str = "en"


class ExaSearchConfig(BaseModel):
    """Exa (Metaphor) neural search config. Keychain: legionforge_exa_api_key."""

    use_autoprompt: bool = True
    type: str = "auto"  # "auto" | "neural" | "keyword"


class PerplexitySearchConfig(BaseModel):
    """Perplexity Sonar API config. Keychain: legionforge_perplexity_api_key."""

    model: str = "sonar"  # "sonar" | "sonar-pro" | "sonar-reasoning"


class SearXNGSearchConfig(BaseModel):
    """SearXNG self-hosted meta-search config — no API key required."""

    url: str = "http://localhost:8888"
    engines: list[str] = []  # empty = SearXNG default engines


class SearchSettings(BaseModel):
    """
    Phase 56 — Configurable Search Providers.

    ``provider`` names the primary search backend.  ``fallback_chain`` is an
    ordered list of providers to try if the primary fails — tried in order,
    first success wins.  Each value must be one of:
    ddg | tavily | brave | exa | perplexity | searxng.

    ``fallback`` (legacy single-fallback field) is still honoured when
    ``fallback_chain`` is empty, for backwards compatibility.

    Per-provider sub-configs below carry defaults that work out of the box;
    override individual fields in your hardware YAML profile under ``search:``.
    """

    provider: str = "ddg"
    fallback: str = "ddg"  # legacy — ignored when fallback_chain is set
    fallback_chain: list[str] = []  # ordered fallback list; overrides fallback
    max_results: int = 5
    timeout: float = 10.0

    ddg: DDGSearchConfig = DDGSearchConfig()
    tavily: TavilySearchConfig = TavilySearchConfig()
    brave: BraveSearchConfig = BraveSearchConfig()
    exa: ExaSearchConfig = ExaSearchConfig()
    perplexity: PerplexitySearchConfig = PerplexitySearchConfig()
    searxng: SearXNGSearchConfig = SearXNGSearchConfig()


class ModelPreferencesConfig(BaseModel):
    """
    Phase 58 — Named model speed presets for per-task model selection.

    Maps preference names (fast / balanced / powerful) to specific model IDs.
    Referenced by ``set_task_model_preference()`` in ``src/llm_factory.py``.
    Override in your hardware YAML profile under ``model_preferences:``.
    """

    fast: str = "qwen2.5:3b"
    balanced: str = "llama3.1:8b"
    powerful: str = "llama3.1:8b"

    def get(self, pref: str) -> str | None:
        """Return the model_id for a named preference, or None if unknown."""
        return getattr(self, pref, None)


class DbMaintenanceSettings(BaseModel):
    """
    Per-table retention schedule for nightly DB maintenance.

    All *_days values are in days.  Set to 0 to skip pruning for that table.
    audit_log uses anchor-based pruning (see prune_audit_log() in database.py)
    so verify_audit_log_chain() remains valid after rows are deleted.
    """

    enabled: bool = True
    tasks_days: int = 30
    api_usage_days: int = 90
    health_metrics_days: int = 30
    threat_events_days: int = 90
    audit_log_days: int = 90


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
    pentest: PentestConfig = PentestConfig()
    tools: ToolsConfig = ToolsConfig()
    gateway: GatewayConfig = GatewayConfig()
    connectors: ConnectorsConfig = ConnectorsConfig()
    agent_memory: AgentMemoryConfig = AgentMemoryConfig()
    search: SearchSettings = SearchSettings()
    model_preferences: ModelPreferencesConfig = ModelPreferencesConfig()
    db_maintenance: DbMaintenanceSettings = DbMaintenanceSettings()

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
