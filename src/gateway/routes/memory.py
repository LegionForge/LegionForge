"""
src/gateway/routes/memory.py
────────────────────────────
Gateway endpoints for persistent agent memory (Phase 21).

All endpoints are user-scoped: documents are stored in the
``user:<user_id>`` namespace and are private to the authenticated user.

Endpoints:
    POST   /memory/ingest  — embed and store a document
    POST   /memory/search  — semantic similarity search
    DELETE /memory         — clear your memory namespace
    GET    /memory/stats   — document count + timestamps

Requires:
    - PostgreSQL with the pgvector extension (make db-init)
    - A running Ollama embeddings model (nomic-embed-text)
    - settings.agent_memory.enabled = true   OR   the endpoints return 503
      (guards are explicit so callers get a clear error, not a silent no-op)
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.gateway.auth import require_user

logger = logging.getLogger(__name__)

router = APIRouter()


def _require_memory_enabled() -> None:
    """Raise 503 if agent memory is not enabled in settings."""
    from config.settings import settings

    if not settings.agent_memory.enabled:
        raise HTTPException(
            status_code=503,
            detail=(
                "Agent memory is disabled. "
                "Set agent_memory.enabled: true in your hardware profile to activate."
            ),
        )


# ── Request / Response models ─────────────────────────────────────────────────


class IngestRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=32768)
    namespace: str = Field(
        default="",
        description="Override namespace. Leave empty to use your user-scoped namespace.",
    )
    metadata: dict = Field(default_factory=dict)


class SearchRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=4096)
    namespace: str = Field(
        default="",
        description="Override namespace. Leave empty to search your user-scoped namespace.",
    )
    limit: int = Field(default=5, ge=1, le=50)
    min_similarity: float = Field(default=0.7, ge=0.0, le=1.0)


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("/ingest")
async def ingest_document(
    req: IngestRequest,
    user: dict = Depends(require_user),
):
    """
    Embed and store a document in the user's memory namespace.

    The document is embedded via Ollama (nomic-embed-text) and stored in the
    pgvector documents table.  Returns the new document ID and the namespace
    it was stored in.

    Example:
        POST /memory/ingest
        {"content": "User prefers concise, bullet-point answers."}
    """
    _require_memory_enabled()

    from src.memory import get_memory_store, MemoryStore

    namespace = req.namespace.strip() or MemoryStore.user_namespace(user["user_id"])

    try:
        store = get_memory_store()
        doc_id = await store.store(req.content, namespace, req.metadata)
    except Exception as e:
        logger.error("Memory ingest failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Ingest failed: {e}")

    return {"id": doc_id, "namespace": namespace, "status": "stored"}


@router.post("/search")
async def search_memory(
    req: SearchRequest,
    user: dict = Depends(require_user),
):
    """
    Semantic search over the user's memory namespace.

    Returns up to ``limit`` documents ranked by cosine similarity.
    Documents below ``min_similarity`` are excluded.

    Example:
        POST /memory/search
        {"query": "preferred response style", "limit": 3}
    """
    _require_memory_enabled()

    from src.memory import get_memory_store, MemoryStore

    namespace = req.namespace.strip() or MemoryStore.user_namespace(user["user_id"])

    try:
        store = get_memory_store()
        results = await store.search(
            req.query,
            namespace,
            limit=req.limit,
            min_similarity=req.min_similarity,
        )
    except Exception as e:
        logger.error("Memory search failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Search failed: {e}")

    return {"namespace": namespace, "count": len(results), "results": results}


@router.delete("")
async def clear_memory(user: dict = Depends(require_user)):
    """
    Delete ALL documents in the user's memory namespace.

    This is irreversible.  Use ``GET /memory/stats`` first to see how many
    documents will be deleted.
    """
    _require_memory_enabled()

    from src.memory import get_memory_store, MemoryStore

    namespace = MemoryStore.user_namespace(user["user_id"])

    try:
        store = get_memory_store()
        deleted = await store.clear_namespace(namespace)
    except Exception as e:
        logger.error("Memory clear failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Clear failed: {e}")

    return {"namespace": namespace, "deleted": deleted, "status": "cleared"}


@router.get("/stats")
async def memory_stats(user: dict = Depends(require_user)):
    """
    Return document count and oldest/newest timestamps for the user's namespace.
    Works even when ``agent_memory.enabled = False`` (returns 0 docs).
    """
    from src.memory import get_memory_store, MemoryStore

    namespace = MemoryStore.user_namespace(user["user_id"])

    try:
        store = get_memory_store()
        stats = await store.stats(namespace)
    except Exception as e:
        logger.error("Memory stats failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Stats failed: {e}")

    return stats
