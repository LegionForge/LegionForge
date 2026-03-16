"""
src/gateway/routes/models.py
─────────────────────────────
GET /models — list selectable models for the web UI.

Returns named presets (fast/balanced/powerful) from the hardware profile
PLUS any locally installed Ollama chat models.  Named presets let users
route to cloud providers (OpenRouter, Anthropic, OpenAI) without knowing
the underlying model ID.  Auth required (Bearer token).
"""

from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, Depends

from config.settings import settings
from src.gateway.auth import require_user

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/models")
async def list_models(user: dict = Depends(require_user)) -> dict:
    """
    Return selectable models for the UI dropdown.

    Response::

        {
            "models": ["balanced", "fast", "powerful", "llama3.1:8b", ...],
            "default": "balanced",
            "presets": {"balanced": "mistralai/mistral-small-3.1-24b-instruct:free", ...}
        }

    Named presets come first (from ``settings.model_preferences``), followed
    by locally installed Ollama chat models.  The ``default`` field is the
    preset name whose model_id matches the hardware profile's primary model,
    or the primary model_id itself when no preset matches.
    """
    # ── Named presets from hardware profile ──────────────────────────────────
    presets: dict[str, str] = dict(settings.model_preferences or {})

    # Determine the default selection: prefer a preset name over raw model ID
    primary_id = settings.models.primary.model_id
    default_key = primary_id
    for preset_name, preset_model_id in presets.items():
        if preset_model_id == primary_id:
            default_key = preset_name
            break

    # ── Local Ollama models (best-effort — skip if Ollama is down) ───────────
    ollama_names: list[str] = []
    ollama_url = settings.local_services.ollama.resolved_url()
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{ollama_url}/api/tags")
            resp.raise_for_status()
            data = resp.json()

        _EMBED_FAMILIES = {"bert", "nomic-bert"}

        def _is_chat_model(m: dict) -> bool:
            family = (m.get("details") or {}).get("family", "").lower()
            if family in _EMBED_FAMILIES:
                return False
            return "embed" not in m.get("name", "").lower()

        ollama_names = sorted(
            m["name"] for m in data.get("models", []) if _is_chat_model(m)
        )
    except httpx.HTTPError as exc:
        logger.warning("[models] Ollama unreachable (local models omitted): %s", exc)

    # Presets first, then local models (exclude any local model already in presets)
    preset_values = set(presets.values())
    local_only = [n for n in ollama_names if n not in preset_values]
    all_models = list(presets.keys()) + local_only

    return {
        "models": all_models,
        "default": default_key,
        "presets": presets,
    }
