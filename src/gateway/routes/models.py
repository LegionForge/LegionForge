"""
src/gateway/routes/models.py
─────────────────────────────
GET /models — list selectable models for the web UI.

Returns named cloud presets from the hardware profile's ``model_preferences``
PLUS any locally installed Ollama chat models.  Cloud presets use
"provider/model" values (e.g. "inceptionlabs/mercury-2") so the factory
can route them without knowing the provider up front.  Auth required.
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
            "models": ["mercury-2", "llama3.1:8b", ...],
            "default": "llama3.1:8b",
            "presets": {"mercury-2": "inceptionlabs/mercury-2"}
        }

    Cloud presets come first (from ``settings.model_preferences``), followed
    by locally installed Ollama chat models.  The ``default`` field is the
    primary model ID (or a preset name if one matches the primary).
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
