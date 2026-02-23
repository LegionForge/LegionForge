"""
src/llm_factory.py
──────────────────
Unified factory for creating LLM instances from any provider.
Async-first. Rate limiting built in for paid providers.
Reads all configuration from hardware profile — no hardcoded values.

Usage:
    from src.llm_factory import get_llm, get_primary_llm, get_router_llm

    llm = get_primary_llm()           # Uses profile's primary model
    llm = get_router_llm()            # Uses profile's router model
    llm = get_llm("ollama", "llama3.1:8b", temperature=0.1)
"""

from __future__ import annotations

import logging
from functools import lru_cache

from langchain_core.language_models import BaseChatModel
from langchain_ollama import ChatOllama

from config.settings import settings
from src.rate_limiter import get_limiter

logger = logging.getLogger(__name__)


def get_llm(
    provider: str,
    model: str | None = None,
    temperature: float = 0.1,
    max_tokens: int | None = None,
    streaming: bool = False,
    **kwargs,
) -> BaseChatModel:
    """
    Create an LLM instance for the given provider and model.

    Args:
        provider:    "ollama", "openai", or "anthropic"
        model:       Model ID. If None, uses the profile's primary model.
        temperature: Sampling temperature (0.0 = deterministic)
        max_tokens:  Max output tokens. If None, uses profile safeguard limit.
        streaming:   Enable token streaming.
        **kwargs:    Additional provider-specific arguments.

    Returns:
        A LangChain BaseChatModel instance.
    """
    max_tokens = max_tokens or settings.safeguards.default_token_budget

    if provider == "ollama":
        return _get_ollama(model, temperature, streaming, **kwargs)
    elif provider == "openai":
        return _get_openai(model, temperature, max_tokens, streaming, **kwargs)
    elif provider == "anthropic":
        return _get_anthropic(model, temperature, max_tokens, streaming, **kwargs)
    else:
        raise ValueError(
            f"Unknown provider '{provider}'. "
            f"Supported: 'ollama', 'openai', 'anthropic'"
        )


def get_primary_llm(**kwargs) -> BaseChatModel:
    """Get the primary reasoning LLM from the hardware profile."""
    m = settings.models.primary
    logger.info(f"Loading primary model: {m.provider}/{m.model_id}")
    return get_llm(m.provider, m.model_id, **kwargs)


def get_router_llm(**kwargs) -> BaseChatModel:
    """Get the router/supervisor LLM from the hardware profile."""
    m = settings.models.router
    logger.info(f"Loading router model: {m.provider}/{m.model_id}")
    return get_llm(m.provider, m.model_id, temperature=0.0, **kwargs)


def get_embedding_model():
    """Get the embeddings model from the hardware profile."""
    from langchain_ollama import OllamaEmbeddings

    m = settings.models.embeddings
    logger.info(f"Loading embeddings model: {m.model_id}")
    return OllamaEmbeddings(
        model=m.model_id,
        base_url=settings.local_services.ollama.resolved_url(),
    )


def get_cloud_fallback_llm(prefer: str = "anthropic", **kwargs) -> BaseChatModel:
    """
    Get a cloud LLM as fallback for complex tasks.
    Only use when local models are insufficient.
    Checks for API key availability before attempting.
    """
    from src.security import get_api_key_optional

    if prefer == "anthropic" and get_api_key_optional("anthropic"):
        m = settings.models.cloud_fallback.anthropic
        return get_llm("anthropic", m.model_id, **kwargs)
    elif get_api_key_optional("openai"):
        m = settings.models.cloud_fallback.openai
        return get_llm("openai", m.model_id, **kwargs)
    else:
        logger.warning(
            "No cloud API keys available. Falling back to primary local model."
        )
        return get_primary_llm(**kwargs)


# ── Provider implementations ──────────────────────────────────────────────────


def _get_ollama(
    model: str | None,
    temperature: float,
    streaming: bool,
    **kwargs,
) -> ChatOllama:
    model = model or settings.models.primary.model_id
    base_url = settings.local_services.ollama.resolved_url()

    return ChatOllama(
        model=model,
        base_url=base_url,
        temperature=temperature,
        streaming=streaming,
        # Keep-alive: hold model in memory for 10 minutes after last call
        keep_alive="10m",
        **kwargs,
    )


def _get_openai(
    model: str | None,
    temperature: float,
    max_tokens: int,
    streaming: bool,
    **kwargs,
) -> BaseChatModel:
    from langchain_openai import ChatOpenAI
    from src.security import get_api_key

    model = model or settings.models.cloud_fallback.openai.model_id
    _ = get_limiter("openai")  # ensure limiter is registered

    return ChatOpenAI(
        model=model,
        api_key=get_api_key("openai"),
        temperature=temperature,
        max_tokens=max_tokens,
        streaming=streaming,
        **kwargs,
    )


def _get_anthropic(
    model: str | None,
    temperature: float,
    max_tokens: int,
    streaming: bool,
    **kwargs,
) -> BaseChatModel:
    from langchain_anthropic import ChatAnthropic
    from src.security import get_api_key

    model = model or settings.models.cloud_fallback.anthropic.model_id
    _ = get_limiter("anthropic")  # ensure limiter is registered

    return ChatAnthropic(
        model=model,
        api_key=get_api_key("anthropic"),
        temperature=temperature,
        max_tokens=max_tokens,
        streaming=streaming,
        **kwargs,
    )


# ── Warmup ────────────────────────────────────────────────────────────────────


async def warmup_local_models() -> dict[str, bool]:
    """
    Ping local Ollama models to load them into memory before agent runs.
    Eliminates cold-start latency on the first real request.
    Returns dict of {model_id: success}.
    """
    import httpx

    results = {}
    base_url = settings.local_services.ollama.resolved_url()

    models_to_warm = [
        settings.models.primary.model_id,
        settings.models.router.model_id,
    ]

    for model_id in models_to_warm:
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    f"{base_url}/api/generate",
                    json={"model": model_id, "prompt": "hi", "stream": False},
                )
                resp.raise_for_status()
                results[model_id] = True
                logger.info(f"✅ Warmed up model: {model_id}")
        except Exception as e:
            results[model_id] = False
            logger.warning(f"⚠️  Failed to warm up {model_id}: {e}")

    return results
