"""
src/ingestor.py
───────────────
Document ingestion pipeline for the Phase 21 pgvector memory store.

Handles chunking, format detection, and batch embedding for large documents.
Designed to complement MemoryStore (src/memory.py), which handles single-item
storage.  Use the ingestor when you have a file or a long string to split into
retrievable chunks.

Supported formats (auto-detected by file extension):
    .txt  .md  .rst  .csv         — plain text
    .py   .js  .ts  .go  .rs      — source code (kept verbatim)
    .json .yaml .toml .ini .conf  — config files
    .html .htm                    — HTML (tags stripped)
    .pdf                          — PDF (requires pdfplumber; skipped if missing)

Chunking strategy:
    - Split on paragraph breaks first (double newlines)
    - If a paragraph exceeds chunk_size tokens, split on sentence boundaries
    - Each chunk overlaps the previous by ``overlap`` tokens
    - Token count is approximated as len(text) // 4 (cheap, good enough for
      retrieval; exact tokenization is not needed here)

Usage:
    from src.ingestor import DocumentIngestor

    ingestor = DocumentIngestor()

    # Ingest a file
    doc_ids = await ingestor.ingest_file(
        "/path/to/CONTRIBUTING.md",
        namespace="global",
        metadata={"source": "CONTRIBUTING.md"},
    )

    # Ingest a string
    doc_ids = await ingestor.ingest_text(
        long_string,
        namespace="user:alice",
        metadata={"type": "pasted_context"},
    )

    # List documents in a namespace
    docs = await ingestor.list_documents("global", limit=50)

    # Delete a specific document
    deleted = await ingestor.delete_document(doc_id=42, namespace="global")
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Token-approximate constants ───────────────────────────────────────────────
# 4 chars ≈ 1 token (GPT-family heuristic, good enough for chunking)
_CHARS_PER_TOKEN = 4
_DEFAULT_CHUNK_TOKENS = 512
_DEFAULT_OVERLAP_TOKENS = 64
_MIN_CHUNK_CHARS = 8  # discard only near-empty fragments

# ── Text extensions treated as plain text ─────────────────────────────────────
_TEXT_EXTENSIONS = {
    ".txt",
    ".md",
    ".rst",
    ".csv",
    ".tsv",
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".go",
    ".rs",
    ".rb",
    ".java",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
    ".swift",
    ".kt",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".conf",
    ".cfg",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".html",
    ".htm",
    ".xml",
    ".sql",
}


# ── Chunking ──────────────────────────────────────────────────────────────────


def chunk_text(
    text: str,
    chunk_size: int = _DEFAULT_CHUNK_TOKENS,
    overlap: int = _DEFAULT_OVERLAP_TOKENS,
) -> list[str]:
    """
    Split ``text`` into overlapping chunks of approximately ``chunk_size`` tokens.

    Strategy:
    1. Split on double newlines (paragraph / block boundaries)
    2. If a paragraph exceeds ``chunk_size``, split further on sentence ends
    3. Greedily pack paragraphs into a chunk until it would overflow
    4. Start the next chunk ``overlap`` tokens back into the previous chunk

    Args:
        text:       Input text to chunk.
        chunk_size: Target chunk size in approximate tokens (default 512).
        overlap:    Overlap in approximate tokens between consecutive chunks (default 64).

    Returns:
        List of non-empty chunk strings.
    """
    if not text or not text.strip():
        return []

    chunk_chars = chunk_size * _CHARS_PER_TOKEN
    overlap_chars = overlap * _CHARS_PER_TOKEN

    # Step 1: Split into paragraphs
    paragraphs = [p.strip() for p in re.split(r"\n{2,}", text) if p.strip()]

    # Step 2: Further split oversized paragraphs on sentence boundaries
    units: list[str] = []
    for para in paragraphs:
        if len(para) <= chunk_chars:
            units.append(para)
        else:
            # Split on ". ", "! ", "? ", keeping delimiter at end of sentence
            sentences = re.split(r"(?<=[.!?])\s+", para)
            current = ""
            for sent in sentences:
                if len(current) + len(sent) + 1 <= chunk_chars:
                    current = (current + " " + sent).strip() if current else sent
                else:
                    if current:
                        units.append(current)
                    current = sent
            if current:
                units.append(current)

    if not units:
        return []

    # Step 3: Greedily pack units into chunks with overlap
    chunks: list[str] = []
    current_chars: list[str] = []
    current_len = 0

    for unit in units:
        unit_len = len(unit)
        if current_len + unit_len + 1 > chunk_chars and current_chars:
            chunk = "\n\n".join(current_chars)
            if len(chunk) >= _MIN_CHUNK_CHARS:
                chunks.append(chunk)
            # Start next chunk with overlap from tail of current
            overlap_text = chunk[-overlap_chars:] if overlap_chars else ""
            current_chars = [overlap_text] if overlap_text.strip() else []
            current_len = len(overlap_text)
        current_chars.append(unit)
        current_len += unit_len + 2  # +2 for "\n\n"

    # Flush remaining
    if current_chars:
        chunk = "\n\n".join(current_chars)
        if len(chunk) >= _MIN_CHUNK_CHARS:
            chunks.append(chunk)

    return chunks


# ── Format readers ────────────────────────────────────────────────────────────


def _read_html(raw: str) -> str:
    """Strip HTML tags from raw HTML string."""
    # Remove script/style blocks first
    raw = re.sub(
        r"<(script|style)[^>]*>.*?</(script|style)>", "", raw, flags=re.S | re.I
    )
    # Strip remaining tags
    raw = re.sub(r"<[^>]+>", " ", raw)
    # Collapse whitespace
    return re.sub(r"\s{3,}", "\n\n", raw).strip()


def _read_pdf(path: Path) -> str:
    """Extract text from PDF using pdfplumber (optional dep)."""
    try:
        import pdfplumber  # type: ignore[import]
    except ImportError:
        logger.warning(
            "pdfplumber not installed — cannot read %s. "
            "Install with: pip install pdfplumber",
            path,
        )
        return ""

    pages = []
    try:
        with pdfplumber.open(str(path)) as pdf:
            for page in pdf.pages:
                text = page.extract_text()
                if text:
                    pages.append(text)
    except Exception as e:
        logger.error("PDF read failed for %s: %s", path, e)
        return ""
    return "\n\n".join(pages)


def read_file(path: Path) -> str:
    """
    Read a file and return its text content, handling format detection.

    Returns an empty string for unsupported or unreadable files.
    """
    ext = path.suffix.lower()

    if ext == ".pdf":
        return _read_pdf(path)

    if ext in _TEXT_EXTENSIONS or ext == "":
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
            if ext in (".html", ".htm"):
                return _read_html(raw)
            return raw
        except Exception as e:
            logger.error("Failed to read %s: %s", path, e)
            return ""

    logger.debug("Unsupported file extension '%s' — skipping %s", ext, path)
    return ""


# ── DocumentIngestor ──────────────────────────────────────────────────────────


class DocumentIngestor:
    """
    Chunked document ingestion pipeline backed by MemoryStore / pgvector.

    All public methods are async; they delegate embedding to MemoryStore.embed()
    and storage to MemoryStore.store().
    """

    def __init__(
        self,
        chunk_size: int = _DEFAULT_CHUNK_TOKENS,
        overlap: int = _DEFAULT_OVERLAP_TOKENS,
    ) -> None:
        self.chunk_size = chunk_size
        self.overlap = overlap

    async def ingest_text(
        self,
        content: str,
        namespace: str = "default",
        metadata: dict | None = None,
        source: str = "",
    ) -> list[int]:
        """
        Chunk ``content`` and store all chunks in the memory store.

        Args:
            content:   Text to ingest.
            namespace: Memory namespace to store chunks in.
            metadata:  Extra metadata merged into every chunk's metadata.
            source:    Human-readable source identifier (file path, URL, etc.).

        Returns:
            List of document IDs for the stored chunks.
        """
        from src.memory import get_memory_store

        chunks = chunk_text(content, self.chunk_size, self.overlap)
        if not chunks:
            logger.debug(
                "Ingestor: no chunks produced from content (empty or too short)"
            )
            return []

        store = get_memory_store()
        base_meta = dict(metadata or {})
        if source:
            base_meta["source"] = source

        doc_ids: list[int] = []
        for i, chunk in enumerate(chunks):
            chunk_meta = {**base_meta, "chunk_index": i, "chunk_count": len(chunks)}
            try:
                doc_id = await store.store(chunk, namespace, chunk_meta)
                doc_ids.append(doc_id)
            except Exception as e:
                logger.error(
                    "Ingestor: failed to store chunk %d/%d: %s", i + 1, len(chunks), e
                )

        logger.info(
            "Ingestor: stored %d/%d chunks in namespace '%s' (source: %s)",
            len(doc_ids),
            len(chunks),
            namespace,
            source or "—",
        )
        return doc_ids

    async def ingest_file(
        self,
        path: str | Path,
        namespace: str = "default",
        metadata: dict | None = None,
    ) -> list[int]:
        """
        Read a file, auto-detect format, chunk, and store in memory.

        Args:
            path:      Absolute or relative path to the file.
            namespace: Memory namespace.
            metadata:  Extra metadata merged into every chunk.

        Returns:
            List of document IDs for stored chunks (empty if file unreadable).
        """
        p = Path(path)
        if not p.exists():
            logger.error("Ingestor: file not found: %s", p)
            return []

        content = read_file(p)
        if not content.strip():
            logger.warning("Ingestor: no text extracted from %s", p)
            return []

        base_meta = dict(metadata or {})
        base_meta.setdefault("filename", p.name)
        base_meta.setdefault("extension", p.suffix.lower())

        return await self.ingest_text(content, namespace, base_meta, source=str(p))

    # ── Document management ───────────────────────────────────────────────────

    async def list_documents(
        self,
        namespace: str,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        """
        List documents in ``namespace``, ordered by recency (newest first).

        Returns dicts with: id, namespace, content_preview (first 200 chars),
        metadata, created_at.
        """
        from src.database import get_worker_pool

        pool = get_worker_pool()
        async with pool.connection() as conn:
            rows = await conn.fetch(
                """
                SELECT id, namespace, LEFT(content, 200) AS content_preview,
                       metadata, created_at
                FROM documents
                WHERE namespace = $1
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3
                """,
                namespace,
                limit,
                offset,
            )
        return [
            {
                "id": r["id"],
                "namespace": r["namespace"],
                "content_preview": r["content_preview"],
                "metadata": r["metadata"],
                "created_at": r["created_at"].isoformat(),
            }
            for r in rows
        ]

    async def delete_document(self, doc_id: int, namespace: str) -> bool:
        """
        Delete a specific document by ID, scoped to ``namespace``.

        Returns True if a row was deleted, False if not found.
        """
        from src.database import get_worker_pool

        pool = get_worker_pool()
        async with pool.connection() as conn:
            result = await conn.execute(
                "DELETE FROM documents WHERE id = $1 AND namespace = $2",
                doc_id,
                namespace,
            )
        deleted = int(result.split()[-1]) if result else 0
        if deleted:
            logger.info(
                "Ingestor: deleted doc %d from namespace '%s'", doc_id, namespace
            )
        return bool(deleted)


# ── Module-level default ingestor ─────────────────────────────────────────────

_ingestor: Optional[DocumentIngestor] = None


def get_ingestor() -> DocumentIngestor:
    """Return the module-level DocumentIngestor singleton (default chunk sizes)."""
    global _ingestor
    if _ingestor is None:
        _ingestor = DocumentIngestor()
    return _ingestor
