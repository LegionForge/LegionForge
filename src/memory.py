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
        temporal_decay: bool = True,
    ) -> list[dict]:
        """
        Semantic search: return the top-K documents most similar to ``query``.

        Args:
            query:          Natural-language search string.
            namespace:      Namespace to search within.
            limit:          Max results (defaults to ``settings.agent_memory.search_limit``).
            min_similarity: Cosine threshold (defaults to ``settings.agent_memory.min_similarity``).
            temporal_decay: If True (default), blends cosine similarity with a
                recency factor (half-life 30 days) so recent memories rank higher
                than equally similar but older ones.  Set False to get pure cosine
                ordering (e.g. for document search where recency is irrelevant).

        Returns:
            List of ``{id, content, metadata, similarity, created_at}`` dicts,
            ordered by decayed_score desc (temporal_decay=True) or cosine
            similarity desc (temporal_decay=False).
        """
        from src.database import similarity_search
        from config.settings import settings

        cfg = settings.agent_memory
        _limit = limit if limit is not None else cfg.search_limit
        _min_sim = min_similarity if min_similarity is not None else cfg.min_similarity

        embedding = await self.embed(query)
        results = await similarity_search(
            embedding, namespace, _limit, _min_sim, temporal_decay=temporal_decay
        )
        return results

    # ── Get all ───────────────────────────────────────────────────────────────

    async def get_all(self, namespace: str, limit: int = 20) -> list[dict]:
        """
        Return all documents in ``namespace`` ordered by creation time (oldest first).

        Used for always-relevant content (persona, standing instructions) where
        similarity search is not appropriate — every document should always be loaded.

        Returns:
            List of ``{id, content, metadata}`` dicts.
        """
        from src.database import get_worker_pool

        pool = get_worker_pool()
        async with pool.connection() as conn:
            rows = await conn.fetch(
                """
                SELECT id, content, metadata
                FROM documents
                WHERE namespace = $1
                ORDER BY created_at ASC
                LIMIT $2
                """,
                namespace,
                limit,
            )
        return [
            {"id": row["id"], "content": row["content"], "metadata": row["metadata"]}
            for row in rows
        ]

    # ── Stats ─────────────────────────────────────────────────────────────────

    async def stats(self, namespace: str) -> dict:
        """
        Return document count and oldest/newest timestamps for a namespace.
        """
        from src.database import get_worker_pool

        pool = get_worker_pool()
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
        from src.database import get_worker_pool

        pool = get_worker_pool()
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
        from src.database import get_worker_pool

        pool = get_worker_pool()
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


async def user_context_bootstrap(user_id: str | None) -> str:
    """
    Return a formatted context string from the user's stored preferences.

    Injected as a SystemMessage before every LLM call when both
    ``settings.agent_memory.enabled`` and
    ``settings.agent_memory.bootstrap_user_prefs`` are True.

    This is the USER.md equivalent from file-based agent systems: the agent
    always knows who it's talking to, how to address them, and what their
    standing preferences are — without the user re-explaining every session.

    Returns an empty string when:
    - ``settings.agent_memory.enabled`` is False
    - ``settings.agent_memory.bootstrap_user_prefs`` is False
    - ``user_id`` is None or empty
    - No preferences have been stored for this user yet
    - Any error occurs (gracefully degraded — never breaks an agent run)
    """
    from config.settings import settings

    if (
        not settings.agent_memory.enabled
        or not settings.agent_memory.bootstrap_user_prefs
    ):
        return ""
    if not user_id:
        return ""

    try:
        from src.database import get_user_preferences

        result = await get_user_preferences(user_id)
        prefs = result.get("prefs", {})
        if not prefs:
            return ""

        lines = [f"{k}: {v}" for k, v in sorted(prefs.items()) if v is not None]
        if not lines:
            return ""

        return "[User context — injected from stored preferences]\n" + "\n".join(lines)
    except Exception as e:
        logger.debug("User context bootstrap failed for user '%s': %s", user_id, e)
        return ""


async def persona_bootstrap(agent_id: str, user_id: str | None) -> str:
    """
    Gap 1 — Persona namespace bootstrap (SOUL.md equivalent).

    Loads freeform persona text stored in the ``persona:`` namespaces and
    returns it as a single formatted context string.  Injected as the
    outermost ``SystemMessage`` before every LLM call — before user
    preferences (Gap 5) and semantic recall (Phase 21).

    Two namespace tiers are combined:
        ``persona:agent:<agent_id>``    — operator-defined agent character,
                                          tone, and operating boundaries
                                          (SOUL.md equivalent, shared across users)
        ``persona:user:<user_id>``      — per-user persona overrides and
                                          standing instructions (USER.md equivalent)

    Personas are stored as ordinary documents in the ``documents`` table via
    ``POST /memory/ingest`` with the appropriate namespace.  All documents in
    each namespace are always loaded (not similarity-searched) because persona
    content is always relevant, not query-dependent.

    Returns an empty string when:
    - ``settings.agent_memory.enabled`` is False
    - ``settings.agent_memory.persona_bootstrap`` is False
    - No documents exist in either namespace
    - Any error occurs (gracefully degraded — never breaks an agent run)
    """
    from config.settings import settings

    if not settings.agent_memory.enabled or not settings.agent_memory.persona_bootstrap:
        return ""

    try:
        store = get_memory_store()
        sections: list[str] = []

        # Agent-level persona (operator-defined — loaded for all users)
        agent_ns = f"persona:agent:{agent_id}"
        agent_docs = await store.get_all(agent_ns)
        if agent_docs:
            body = "\n\n".join(d["content"] for d in agent_docs)
            sections.append(f"[Agent persona]\n{body}")

        # Per-user persona (user-specific overrides and standing instructions)
        if user_id:
            user_ns = f"persona:user:{user_id}"
            user_docs = await store.get_all(user_ns)
            if user_docs:
                body = "\n\n".join(d["content"] for d in user_docs)
                sections.append(f"[User persona]\n{body}")

        if not sections:
            return ""

        return "\n\n".join(sections)
    except Exception as e:
        logger.debug(
            "Persona bootstrap failed for agent='%s' user='%s': %s",
            agent_id,
            user_id,
            e,
        )
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


async def summarize_and_store_episodic(
    task: str,
    result: str,
    user_id: str,
    run_id: str = "",
) -> None:
    """
    Gap 2 — Daily episodic memory.

    Summarize a completed task+result with the router LLM (qwen2.5:3b) and
    store it under ``user:<uid>/daily:<YYYY-MM-DD>`` for cross-session
    continuity.  Analogous to OpenClaw's daily log that agents read at
    the start of each session.

    Called as fire-and-forget (asyncio.create_task) from the gateway worker
    after task completion.  Silently swallows all exceptions so it never
    blocks a task response.
    """
    from config.settings import settings

    if not settings.agent_memory.enabled or not settings.agent_memory.episodic_memory:
        return
    if not user_id:
        return

    try:
        from datetime import date

        from langchain_core.messages import HumanMessage

        from src.llm_factory import get_router_llm

        llm = get_router_llm(temperature=0.1)
        prompt = (
            "Summarize this completed AI agent task in 2-3 sentences for future memory recall.\n"
            "Be specific — include key facts, findings, or decisions made.\n\n"
            f"Task: {task[:500]}\n"
            f"Result: {result[:500]}\n\n"
            "Summary:"
        )
        response = await llm.ainvoke([HumanMessage(content=prompt)])
        summary = (
            response.content.strip()
            if hasattr(response, "content")
            else str(response).strip()
        )
        if not summary:
            return

        store = get_memory_store()
        today = date.today().isoformat()
        namespace = f"user:{user_id}/daily:{today}"
        await store.store(
            summary,
            namespace=namespace,
            metadata={"type": "episodic_summary", "run_id": run_id, "date": today},
        )
        logger.debug(
            "Episodic memory: stored summary for user '%s' on %s", user_id, today
        )
    except Exception as e:
        logger.debug("Episodic memory store failed for user '%s': %s", user_id, e)


async def flush_key_facts(
    messages: list,
    namespace: str,
    run_id: str = "",
) -> None:
    """
    Gap 4 — Pre-compaction flush.

    When an agent run ends due to token budget exhaustion or loop detection
    (force_end=True), extract 3-5 key facts from the recent message history
    using the router LLM (qwen2.5:3b) and store them in the agent namespace
    before the context is discarded.

    Called as fire-and-forget from finalizer_node in base_graph.py.
    Silently swallows all exceptions so it never blocks an agent run.
    """
    from config.settings import settings

    if (
        not settings.agent_memory.enabled
        or not settings.agent_memory.flush_on_compaction
    ):
        return
    if not messages:
        return

    try:
        from langchain_core.messages import HumanMessage

        from src.llm_factory import get_router_llm

        # Use the last 10 messages to keep the prompt cheap
        MAX_MSGS = 10
        recent = messages[-MAX_MSGS:]
        msg_text = "\n".join(
            f"{type(m).__name__}: {str(m.content)[:300]}"
            for m in recent
            if hasattr(m, "content")
        )
        if not msg_text.strip():
            return

        llm = get_router_llm(temperature=0.1)
        prompt = (
            "Extract 3-5 key facts from this agent conversation worth remembering.\n"
            "Format: one fact per line, starting with '- '.\n\n"
            f"{msg_text}\n\nKey facts:"
        )
        response = await llm.ainvoke([HumanMessage(content=prompt)])
        facts_text = response.content.strip() if hasattr(response, "content") else ""
        if not facts_text:
            return

        store = get_memory_store()
        await store.store(
            facts_text,
            namespace=namespace,
            metadata={"type": "compaction_flush", "run_id": run_id},
        )
        logger.debug(
            "Pre-compaction flush: stored %d chars in namespace '%s'",
            len(facts_text),
            namespace,
        )
    except Exception as e:
        logger.debug("Pre-compaction flush failed in namespace '%s': %s", namespace, e)
