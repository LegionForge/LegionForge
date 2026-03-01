"""
src/gateway/routes/documents.py
────────────────────────────────
Gateway endpoints for document management in the pgvector memory store (Phase 22).

Complements the /memory/* endpoints (Phase 21) with chunked ingestion and
document-level list/delete operations.

Endpoints:
    GET    /documents            — list documents in user namespace
    POST   /documents/ingest     — chunk and ingest text or a file path (admin)
    DELETE /documents/{id}       — delete a specific document

All endpoints are user-scoped (namespace = ``user:<user_id>``).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.gateway.auth import require_user

logger = logging.getLogger(__name__)

router = APIRouter()


def _require_memory_enabled() -> None:
    from config.settings import settings

    if not settings.agent_memory.enabled:
        raise HTTPException(
            status_code=503,
            detail=(
                "Agent memory is disabled. "
                "Set agent_memory.enabled: true in your hardware profile."
            ),
        )


# ── Models ────────────────────────────────────────────────────────────────────


class IngestTextRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=1_048_576)  # 1 MB limit
    namespace: str = Field(default="", description="Leave empty for user namespace.")
    metadata: dict = Field(default_factory=dict)
    chunk_size: int = Field(
        default=512, ge=64, le=2048, description="Target chunk size in tokens."
    )
    overlap: int = Field(
        default=64, ge=0, le=512, description="Overlap between chunks in tokens."
    )
    source: str = Field(
        default="", description="Human-readable source label (URL, filename, etc.)."
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("")
async def list_documents(
    limit: int = 50,
    offset: int = 0,
    user: dict = Depends(require_user),
):
    """
    List documents stored in the user's namespace (newest first).

    Returns id, content_preview (first 200 chars), metadata, created_at.
    """
    _require_memory_enabled()

    from src.ingestor import get_ingestor
    from src.memory import MemoryStore

    namespace = MemoryStore.user_namespace(user["user_id"])

    try:
        docs = await get_ingestor().list_documents(
            namespace, limit=limit, offset=offset
        )
    except Exception as e:
        logger.error("list_documents failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

    return {"namespace": namespace, "count": len(docs), "documents": docs}


@router.post("/ingest")
async def ingest_document(
    req: IngestTextRequest,
    user: dict = Depends(require_user),
):
    """
    Chunk text and store all chunks in the user's memory namespace.

    Large documents are split into overlapping chunks of approximately
    ``chunk_size`` tokens with ``overlap`` token overlap.  Each chunk is
    embedded via Ollama and stored in pgvector.

    Example:
        POST /documents/ingest
        {
            "content": "...<long document>...",
            "source": "company_handbook.md",
            "chunk_size": 512,
            "overlap": 64
        }
    """
    _require_memory_enabled()

    from src.ingestor import DocumentIngestor
    from src.memory import MemoryStore

    namespace = req.namespace.strip() or MemoryStore.user_namespace(user["user_id"])

    ingestor = DocumentIngestor(chunk_size=req.chunk_size, overlap=req.overlap)
    try:
        doc_ids = await ingestor.ingest_text(
            req.content, namespace, req.metadata, source=req.source
        )
    except Exception as e:
        logger.error("ingest_document failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "namespace": namespace,
        "chunks_stored": len(doc_ids),
        "doc_ids": doc_ids,
        "status": "ingested",
    }


@router.delete("/{doc_id}")
async def delete_document(
    doc_id: int,
    user: dict = Depends(require_user),
):
    """
    Delete a specific document by ID from the user's namespace.

    Only deletes documents owned by the authenticated user's namespace.
    Returns 404 if the document is not found.
    """
    _require_memory_enabled()

    from src.ingestor import get_ingestor
    from src.memory import MemoryStore

    namespace = MemoryStore.user_namespace(user["user_id"])

    try:
        deleted = await get_ingestor().delete_document(doc_id, namespace)
    except Exception as e:
        logger.error("delete_document failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail=f"Document {doc_id} not found in namespace '{namespace}'",
        )

    return {"id": doc_id, "namespace": namespace, "status": "deleted"}
