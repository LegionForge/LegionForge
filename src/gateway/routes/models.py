"""
src/gateway/routes/models.py
─────────────────────────────
GET /models — list models currently installed in the local Ollama instance.

Used by the web UI to populate the model selector dropdown so users can
pick any installed model rather than choosing between fixed fast/balanced/
powerful presets.  Auth required (Bearer token).
"""

from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException, status

from config.settings import settings
from src.gateway.auth import require_user

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/models")
async def list_models(user: dict = Depends(require_user)) -> dict:
    """
    Return the list of models installed in the local Ollama instance.

    Response::

        {
            "models": ["qwen2.5:7b", "qwen2.5:3b", "llama3.1:8b", ...],
            "default": "qwen2.5:7b"
        }

    The ``default`` field reflects the hardware profile's primary model so
    the UI can pre-select it on load.
    """
    ollama_url = settings.local_services.ollama.resolved_url()
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{ollama_url}/api/tags")
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        logger.warning("[models] Ollama unreachable: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Ollama is not reachable — is it running?",
        )

    # Exclude embedding models — they can't do chat/instruction following.
    # Ollama reports family as "bert" or "nomic-bert" for embedding models;
    # fall back to name-pattern matching for any family not yet recognised.
    _EMBED_FAMILIES = {"bert", "nomic-bert"}

    def _is_chat_model(m: dict) -> bool:
        family = (m.get("details") or {}).get("family", "").lower()
        if family in _EMBED_FAMILIES:
            return False
        name = m.get("name", "").lower()
        return "embed" not in name

    names = sorted(m["name"] for m in data.get("models", []) if _is_chat_model(m))
    return {
        "models": names,
        "default": settings.models.primary.model_id,
    }
