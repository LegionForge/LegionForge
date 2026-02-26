"""
src/tools/model_integrity.py
────────────────────────────
Phase 6: Ollama model integrity verification.

Verifies SHA256 checksums of GGUF model files against pinned hashes stored
in the hardware profile. This detects model tampering, supply-chain attacks,
or accidental model swaps.

Verification results:
  "ok"         — SHA256 matches the pinned hash
  "mismatch"   — SHA256 does not match (CRITICAL: model may be tampered)
  "not_found"  — GGUF file could not be located in OLLAMA_MODELS directory
  "skipped"    — gguf_sha256 is empty in the profile (pin not yet set)

Usage:
    from src.tools.model_integrity import verify_model_integrity
    results = await verify_model_integrity(settings)
    # {'llama3.1:8b': 'ok', 'qwen2.5:3b': 'skipped', ...}

To pin hashes for the first time:
    make verify-models   # prints current SHA256 for each GGUF file

After pinning, update mac_m4_mini_16gb.yaml:
    models:
      primary:
        gguf_sha256: "abc123..."

Set model_integrity_strict: true to raise on mismatch (default: log only).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Chunk size for streaming SHA256 computation (1 MB — avoids loading full GGUF into RAM)
_SHA256_CHUNK_SIZE = 1024 * 1024


def _sha256_file(path: Path) -> str:
    """Compute SHA256 of a file in streaming fashion. Returns hex digest."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_SHA256_CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def _find_gguf(model_id: str, ollama_models_dir: Path) -> Path | None:
    """
    Find the GGUF file for a given model_id in the Ollama models directory.

    Ollama stores models as:
      <OLLAMA_MODELS>/blobs/sha256-<hash>

    The manifest is at:
      <OLLAMA_MODELS>/manifests/registry.ollama.ai/library/<name>/<tag>

    We locate the manifest, parse the layer digest, and find the blob file.
    Falls back to a recursive glob for .gguf files matching the model name.

    Returns the Path to the GGUF file, or None if not found.
    """
    # Normalise model_id: "llama3.1:8b" → name="llama3.1", tag="8b"
    if ":" in model_id:
        name, tag = model_id.rsplit(":", 1)
    else:
        name, tag = model_id, "latest"

    # Try Ollama manifest path
    manifest_path = (
        ollama_models_dir / "manifests" / "registry.ollama.ai" / "library" / name / tag
    )
    if manifest_path.exists():
        try:
            import json

            manifest = json.loads(manifest_path.read_text())
            for layer in manifest.get("layers", []):
                media_type = layer.get("mediaType", "")
                if "model" in media_type or "gguf" in media_type.lower():
                    digest = layer.get("digest", "")
                    if digest.startswith("sha256:"):
                        blob_name = "sha256-" + digest[7:]
                        blob_path = ollama_models_dir / "blobs" / blob_name
                        if blob_path.exists():
                            return blob_path
        except Exception as e:
            logger.debug(f"[integrity] Could not parse manifest for {model_id!r}: {e}")

    # Fallback: glob for .gguf files containing the model name
    safe_name = name.replace(".", "*").replace("/", "-")
    for pattern in [f"**/{safe_name}*.gguf", f"**/*{safe_name}*.gguf"]:
        matches = list(ollama_models_dir.glob(pattern))
        if matches:
            return matches[0]  # Return first match

    return None


async def verify_model_integrity(settings: Any) -> dict[str, str]:
    """
    Verify SHA256 checksums of installed GGUF model files.

    For each model entry in the hardware profile that has a non-empty gguf_sha256:
      1. Locate the GGUF file in OLLAMA_MODELS directory
      2. Compute its SHA256 in a thread executor (non-blocking for large files)
      3. Compare against the pinned hash

    On mismatch:
      - Always: logs CRITICAL warning + emits TOOL_RESULT_INJECTION threat event
      - If model_integrity_strict=True: raises RuntimeError (halts startup)

    Args:
        settings: HardwareSettings instance from config.settings

    Returns:
        dict mapping model_id → status string
        Status values: "ok" | "mismatch" | "not_found" | "skipped"

    Usage:
        from config.settings import settings
        from src.tools.model_integrity import verify_model_integrity
        results = await verify_model_integrity(settings)
    """
    # Resolve Ollama models directory
    ollama_models_env = os.environ.get("OLLAMA_MODELS", "")
    if ollama_models_env:
        ollama_dir = Path(ollama_models_env)
    else:
        # Default Ollama location
        ollama_dir = Path(settings.paths.models.ollama)

    strict = getattr(settings.security, "model_integrity_strict", False)
    results: dict[str, str] = {}

    for attr in ("primary", "router", "embeddings"):
        model_entry = getattr(settings.models, attr, None)
        if model_entry is None:
            continue

        model_id: str = model_entry.model_id
        pinned_hash: str = getattr(model_entry, "gguf_sha256", "")

        if not pinned_hash:
            logger.debug(
                f"[integrity] {model_id!r}: gguf_sha256 not set — skipping verification. "
                "Run 'make verify-models' to compute and pin the hash."
            )
            results[model_id] = "skipped"
            continue

        # Locate the GGUF file (run in thread executor — file system walk can be slow)
        loop = asyncio.get_event_loop()
        gguf_path = await loop.run_in_executor(None, _find_gguf, model_id, ollama_dir)

        if gguf_path is None:
            logger.warning(
                f"[integrity] {model_id!r}: GGUF file not found in {ollama_dir} — "
                "is the model downloaded? (result: not_found)"
            )
            results[model_id] = "not_found"
            continue

        # Compute SHA256 in thread executor (GGUF files can be 4–8 GB)
        logger.info(f"[integrity] Computing SHA256 for {model_id!r} ({gguf_path})...")
        try:
            actual_hash = await loop.run_in_executor(None, _sha256_file, gguf_path)
        except Exception as e:
            logger.error(f"[integrity] SHA256 computation failed for {model_id!r}: {e}")
            results[model_id] = "not_found"
            continue

        if actual_hash == pinned_hash:
            logger.info(f"[integrity] {model_id!r}: SHA256 OK ({actual_hash[:16]}...)")
            results[model_id] = "ok"
        else:
            logger.critical(
                f"[integrity] {model_id!r}: SHA256 MISMATCH!\n"
                f"  Expected: {pinned_hash}\n"
                f"  Actual:   {actual_hash}\n"
                f"  File:     {gguf_path}\n"
                "  ⚠️  Model file may be tampered. Revoke and re-download."
            )
            results[model_id] = "mismatch"

            # Log threat event (non-fatal — DB may not be initialized yet at startup)
            try:
                from src.database import log_threat_event

                await log_threat_event(
                    agent_id="model_integrity",
                    run_id="startup",
                    threat_type="MODEL_INTEGRITY_MISMATCH",
                    confidence=1.0,
                    raw_input=f"model={model_id} expected={pinned_hash[:16]}... actual={actual_hash[:16]}...",
                    action_taken="LOGGED",
                    metadata={
                        "model_id": model_id,
                        "gguf_path": str(gguf_path),
                        "expected_hash": pinned_hash,
                        "actual_hash": actual_hash,
                    },
                )
            except Exception as db_err:
                logger.debug(f"[integrity] Could not log threat event: {db_err}")

            if strict:
                raise RuntimeError(
                    f"Model integrity check FAILED for {model_id!r}.\n"
                    f"  Expected SHA256: {pinned_hash}\n"
                    f"  Actual SHA256:   {actual_hash}\n"
                    f"  File: {gguf_path}\n"
                    "Set model_integrity_strict: false to run anyway (not recommended)."
                )

    return results


async def compute_model_hashes(settings: Any) -> dict[str, str | None]:
    """
    Compute and return the current SHA256 hashes for all configured models.

    Used by 'make verify-models' to display hashes for pinning.
    Does NOT compare against stored hashes — just computes current values.

    Returns:
        dict mapping model_id → hex SHA256 string (or None if file not found)
    """
    ollama_models_env = os.environ.get("OLLAMA_MODELS", "")
    ollama_dir = (
        Path(ollama_models_env)
        if ollama_models_env
        else Path(settings.paths.models.ollama)
    )

    hashes: dict[str, str | None] = {}
    loop = asyncio.get_event_loop()

    for attr in ("primary", "router", "embeddings"):
        model_entry = getattr(settings.models, attr, None)
        if model_entry is None:
            continue

        model_id = model_entry.model_id
        gguf_path = await loop.run_in_executor(None, _find_gguf, model_id, ollama_dir)

        if gguf_path is None:
            logger.warning(f"[integrity] {model_id!r}: GGUF not found in {ollama_dir}")
            hashes[model_id] = None
            continue

        logger.info(f"[integrity] Computing SHA256 for {model_id!r}...")
        try:
            h = await loop.run_in_executor(None, _sha256_file, gguf_path)
            hashes[model_id] = h
            print(f"  {model_id}: {h}")
        except Exception as e:
            logger.error(f"[integrity] Error hashing {model_id!r}: {e}")
            hashes[model_id] = None

    return hashes
