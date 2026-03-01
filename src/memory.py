"""
src/memory.py
─────────────
Persistent agent memory backed by pgvector.

Provides a thin, async-friendly wrapper around the existing
``store_document()`` / ``similarity_search()`` helpers in ``src/database.py``.
Embedding is handled via the configured Ollama model (``nomic-embed-text`` by
default) so there are no new dependencies.

Namespace convention:
    ``user:<user_id>``                — gateway user scoped
    ``agent:<agent_id>``              — agent-type scoped (shared across users)
    ``agent:<agent_id>/user:<uid>``   — per-agent per-user (most isolated)
    ``global``                        — shared knowledge base

Feature flags (``settings.agent_memory``):
    enabled          — master switch; when False no DB calls are made
    recall_on_task   — inject relevant memory before each LLM call
    store_results    — persist task+result pairs for future recall
    max_docs_per_ns  — prune oldest docs when namespace exceeds this limit
    search_limit     — top-K docs returned by similarity_search
    min_similarity   — cosine similarity threshold (0–1; 1 = identical)

Usage:
    from src.memory import get_memory_store

    store = get_memory_store()
    doc_id = await store.store(
        "User prefers concise answers",
        namespace="user:alice",
        metadata={"type": "preference"},
    )
    hits = await store.search("preferred response style", namespace="user:alice")
    for h in hits:
        print(h["content"], h["similarity"])
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)


# ── MemoryStore ───────────────────────────────────────────────────────────────


class MemoryStore:
    """
    Async agent memory backed by pgvector.

    All public methods are async.  The class holds no DB connection — it
    acquires a connection from the pool on each call.

    Instantiate via ``get_memory_store()`` (singleton); do NOT create directly
    in hot-path code.
    """

    # ── Embedding ─────────────────────────────────────────────────────────────

    async def embed(self, text: str) -> list[float]:
        """
        Return a 768-dim embedding for ``text`` using the configured Ollama
        embeddings model (``nomic-embed-text`` by default).

        Raises:
            RuntimeError: if the Ollama server is unreachable or returns an error.
        """
        import httpx

        from config.settings import settings
        from src.llm_factory import _get_ollama_url

        model = settings.models.embeddings.model_id
        base_url = _get_ollama_url()

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{base_url.rstrip('/')}/api/embeddings",
                json={"model": model, "prompt": text},
            )
            resp.raise_for_status()
            data = resp.json()

        embedding = data.get("embedding")
        if not embedding:
            raise RuntimeError(
                f"Ollama /api/embeddings returned no embedding for model '{model}'"
            )
        return embedding

    # ── Store ─────────────────────────────────────────────────────────────────

    async def store(
        self,
        content: str,
        namespace: str = "default",
        metadata: dict | None = None,
    ) -> int:
        """
        Embed ``content`` and store it in the pgvector documents table.

        Args:
            content:   Text to store and embed.
            namespace: Logical partition for the document (see module docstring).
            metadata:  Arbitrary JSON metadata (role, agent_id, run_id, etc.).

        Returns:
            The new document's primary-key ID.
        """
        from src.database import store_document
        from config.settings import settings

        embedding = await self.embed(content)
        doc_id = await store_document(content, embedding, namespace, metadata or {})

        # Prune oldest docs if namespace has grown too large
        cfg = settings.agent_memory
        if cfg.max_docs_per_namespace > 0:
            await self._prune_if_needed(namespace, cfg.max_docs_per_namespace)

        logger.debug("Memory stored doc %d in namespace '%s'", doc_id, namespace)
        return doc_id

    # ── Search ────────────────────────────────────────────────────────────────

    async def search(
        self,
        query: str,
        namespace: str = "default",
        limit: int | None = None,
        min_similarity: float | None = None,
    ) -> list[dict]:
        """
        Semantic search: return the top-K documents most similar to ``query``.

        Args:
            query:          Natural-language search string.
            namespace:      Namespace to search within.
            limit:          Max results (defaults to ``settings.agent_memory.search_limit``).
            min_similarity: Cosine threshold (defaults to ``settings.agent_memory.min_similarity``).

        Returns:
            List of ``{id, content, metadata, similarity}`` dicts, sorted by
            similarity descending (most relevant first).
        """
        from src.database import similarity_search
        from config.settings import settings

        cfg = settings.agent_memory
        _limit = limit if limit is not None else cfg.search_limit
        _min_sim = min_similarity if min_similarity is not None else cfg.min_similarity

        embedding = await self.embed(query)
        results = await similarity_search(embedding, namespace, _limit, _min_sim)
        return results

    # ── Stats ─────────────────────────────────────────────────────────────────

    async def stats(self, namespace: str) -> dict:
        """
        Return document count and oldest/newest timestamps for a namespace.
        """
        from src.database import get_pool

        pool = get_pool()
        async with pool.connection() as conn:
            row = await conn.fetchrow(
                """
                SELECT
                    COUNT(*)            AS total,
                    MIN(created_at)     AS oldest,
                    MAX(created_at)     AS newest
                FROM documents
                WHERE namespace = $1
                """,
                namespace,
            )
        if row is None:
            return {"namespace": namespace, "total": 0, "oldest": None, "newest": None}
        return {
            "namespace": namespace,
            "total": row["total"],
            "oldest": row["oldest"].isoformat() if row["oldest"] else None,
            "newest": row["newest"].isoformat() if row["newest"] else None,
        }

    # ── Clear ─────────────────────────────────────────────────────────────────

    async def clear_namespace(self, namespace: str) -> int:
        """
        Delete ALL documents in ``namespace``.

        Returns:
            Number of rows deleted.
        """
        from src.database import get_pool

        pool = get_pool()
        async with pool.connection() as conn:
            result = await conn.execute(
                "DELETE FROM documents WHERE namespace = $1", namespace
            )
        # asyncpg returns "DELETE N" as the status string
        deleted = int(result.split()[-1]) if result else 0
        logger.info("Memory: cleared %d doc(s) from namespace '%s'", deleted, namespace)
        return deleted

    # ── Prune ─────────────────────────────────────────────────────────────────

    async def prune(self, namespace: str, keep_last_n: int) -> int:
        """
        Delete the oldest documents beyond ``keep_last_n`` in ``namespace``.

        Returns:
            Number of rows deleted.
        """
        from src.database import get_pool

        pool = get_pool()
        async with pool.connection() as conn:
            result = await conn.execute(
                """
                DELETE FROM documents
                WHERE namespace = $1
                  AND id NOT IN (
                      SELECT id FROM documents
                      WHERE namespace = $1
                      ORDER BY created_at DESC
                      LIMIT $2
                  )
                """,
                namespace,
                keep_last_n,
            )
        deleted = int(result.split()[-1]) if result else 0
        if deleted:
            logger.debug(
                "Memory: pruned %d old doc(s) from namespace '%s' (kept %d)",
                deleted,
                namespace,
                keep_last_n,
            )
        return deleted

    async def _prune_if_needed(self, namespace: str, max_docs: int) -> None:
        """Prune oldest docs if namespace size exceeds max_docs. Best-effort."""
        try:
            s = await self.stats(namespace)
            if s["total"] > max_docs:
                await self.prune(namespace, max_docs)
        except Exception as e:
            logger.debug("Memory prune failed for '%s': %s", namespace, e)

    # ── Convenience helpers ───────────────────────────────────────────────────

    @staticmethod
    def user_namespace(user_id: str) -> str:
        """Standard namespace for a gateway user."""
        return f"user:{user_id}"

    @staticmethod
    def agent_namespace(agent_id: str) -> str:
        """Standard namespace for an agent type (shared across users)."""
        return f"agent:{agent_id}"

    @staticmethod
    def agent_user_namespace(agent_id: str, user_id: str) -> str:
        """Most-isolated namespace: per-agent, per-user."""
        return f"agent:{agent_id}/user:{user_id}"


# ── Module-level singleton ────────────────────────────────────────────────────

_store: Optional[MemoryStore] = None
_store_lock = threading.Lock()


def get_memory_store() -> MemoryStore:
    """
    Return the module-level MemoryStore singleton.

    Instantiates on first call; thread-safe.
    Calling this when ``settings.agent_memory.enabled = False`` is harmless —
    the store object exists but callers should gate on the flag before
    calling async methods.
    """
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = MemoryStore()
    return _store


def reset_memory_store() -> None:
    """Reset the singleton (for testing only)."""
    global _store
    with _store_lock:
        _store = None


# ── Recall helper for agents ──────────────────────────────────────────────────


async def recall_for_task(task: str, namespace: str) -> str:
    """
    Retrieve relevant memory for a task and return formatted context string.

    Returns an empty string when:
    - ``settings.agent_memory.enabled`` is False
    - No relevant documents are found
    - Any error occurs (gracefully degraded)
    """
    from config.settings import settings

    if not settings.agent_memory.enabled or not settings.agent_memory.recall_on_task:
        return ""

    try:
        store = get_memory_store()
        results = await store.search(task, namespace)
        if not results:
            return ""
        lines = []
        for r in results:
            rtype = r.get("metadata", {}).get("type", "memory")
            snippet = r["content"][:600].replace("\n", " ")
            lines.append(f"[{rtype}] {snippet}")
        return "\n".join(lines)
    except Exception as e:
        logger.debug("Memory recall failed for namespace '%s': %s", namespace, e)
        return ""


async def store_task_result(
    task: str,
    result: str,
    namespace: str,
    run_id: str = "",
) -> None:
    """
    Persist a completed task + result pair for future recall.

    Called by the agent finalizer when ``settings.agent_memory.store_results``
    is True.  Silently swallows exceptions so it never breaks an agent run.
    """
    from config.settings import settings

    if not settings.agent_memory.enabled or not settings.agent_memory.store_results:
        return

    content = f"Task: {task}\nResult: {result}"
    metadata = {"type": "task_result", "run_id": run_id}
    try:
        store = get_memory_store()
        await store.store(content, namespace, metadata)
    except Exception as e:
        logger.debug("Memory store_task_result failed: %s", e)
