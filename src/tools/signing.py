"""
src/tools/signing.py
────────────────────
Ed25519 tool manifest signing for the Phase 5 Crystallization Pipeline.

Every crystallized tool is signed at approval time and the signature is
stored alongside the tool_registry entry. Guardian check 5 verifies the
signature before any crystallized tool call executes.

Key management:
  - Private key lives in macOS Keychain (service: 'legionforge_tool_signer')
  - Falls back to TOOL_SIGNING_PRIVATE_KEY env var (Docker / CI path)
  - Public key fingerprint (SHA256[:16] of raw public key bytes) is stored
    in tool_registry alongside the hex signature

Setup (one-time):
    make setup-signing-key
    # or:
    python -c "from src.tools.signing import generate_signing_keypair; \\
               priv, pub = generate_signing_keypair(); print('public:', pub[:16], '...')"

Verification:
    from src.tools.signing import verify_tool_signature
    ok = verify_tool_signature(manifest, signature_hex, fingerprint)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess

logger = logging.getLogger(__name__)


# ── Ed25519 via cryptography package ──────────────────────────────────────────

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        PrivateFormat,
        NoEncryption,
    )

    _CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover
    _CRYPTO_AVAILABLE = False
    logger.warning(
        "[signing] cryptography package not installed — tool signing disabled. "
        "Run: pip install 'cryptography~=42.0'"
    )


# ── Keychain service name ─────────────────────────────────────────────────────

_SIGNING_KEY_SERVICE = "legionforge_tool_signer"


# ── Key generation ────────────────────────────────────────────────────────────


def generate_signing_keypair() -> tuple[str, str]:
    """
    Generate a new Ed25519 key pair.

    Returns:
        (private_key_hex, public_key_hex) — both as lowercase hex strings.

    The private key should be stored in Keychain immediately after generation:
        security add-generic-password -s legionforge_tool_signer -a api_key \\
            -w '<private_key_hex>' -U
    Or use:  make setup-signing-key
    """
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError(
            "cryptography package not installed. "
            "Run: pip install 'cryptography~=42.0'"
        )

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

    return priv_bytes.hex(), pub_bytes.hex()


# ── Key loading ───────────────────────────────────────────────────────────────


def _load_private_key_hex() -> str | None:
    """
    Load the Ed25519 private key (hex) from env var or Keychain.
    Load order:
      1. TOOL_SIGNING_PRIVATE_KEY env var (Docker / CI / test path)
      2. macOS Keychain (service: legionforge_tool_signer)
    Returns None if neither source has a value.
    """
    # 1. Env var (Docker / CI)
    key_hex = os.environ.get("TOOL_SIGNING_PRIVATE_KEY", "")
    if key_hex:
        return key_hex

    # 2. macOS Keychain via security CLI (timeout-guarded)
    try:
        result = subprocess.run(
            [
                "security",
                "find-generic-password",
                "-s",
                _SIGNING_KEY_SERVICE,
                "-a",
                "api_key",
                "-w",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return None


def _get_signing_private_key() -> "Ed25519PrivateKey":
    """
    Load and return the Ed25519 private key object.
    Raises RuntimeError if the key is not available.
    """
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography package not installed")

    key_hex = _load_private_key_hex()
    if not key_hex:
        raise RuntimeError(
            "Tool signing key not found.\n"
            "Run: make setup-signing-key\n"
            "Or store manually: security add-generic-password "
            f"-s {_SIGNING_KEY_SERVICE} -a api_key -w '<hex_private_key>' -U"
        )

    try:
        key_bytes = bytes.fromhex(key_hex.strip())
        return Ed25519PrivateKey.from_private_bytes(key_bytes)
    except (ValueError, Exception) as e:
        raise RuntimeError(f"Invalid signing key format: {e}") from e


def get_public_key_bytes() -> bytes:
    """Return raw public key bytes (32 bytes for Ed25519)."""
    private_key = _get_signing_private_key()
    pub = private_key.public_key()
    return pub.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)


def get_public_key_fingerprint() -> str:
    """
    Return the public key fingerprint: first 16 hex chars of SHA256(public_key_bytes).
    Stored in tool_registry.public_key_fingerprint for signature verification.
    """
    pub_bytes = get_public_key_bytes()
    return hashlib.sha256(pub_bytes).hexdigest()[:16]


# ── Canonical manifest serialization ─────────────────────────────────────────


def _canonical_manifest(
    tool_id: str,
    description: str,
    input_schema: dict,
    declared_side_effects: list,
    version: str,
) -> bytes:
    """
    Canonical, deterministic JSON representation of a tool manifest.
    This is the exact byte sequence that is signed and verified.
    All fields are sorted so the representation is stable across Python versions.
    """
    payload = {
        "declared_side_effects": sorted(declared_side_effects),
        "description": description,
        "input_schema": input_schema,
        "tool_id": tool_id,
        "version": version,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ── Public API ────────────────────────────────────────────────────────────────


def sign_tool_manifest(
    tool_id: str,
    description: str,
    input_schema: dict,
    declared_side_effects: list,
    version: str = "0.7.0-alpha",
) -> str:
    """
    Ed25519-sign a tool manifest.

    Returns:
        Lowercase hex string of the 64-byte Ed25519 signature.

    Raises:
        RuntimeError: if the signing key is unavailable or crypto is not installed.
    """
    private_key = _get_signing_private_key()
    message = _canonical_manifest(
        tool_id, description, input_schema, declared_side_effects, version
    )
    signature_bytes = private_key.sign(message)
    return signature_bytes.hex()


def verify_tool_signature(
    tool_id: str,
    description: str,
    input_schema: dict,
    declared_side_effects: list,
    version: str,
    signature_hex: str,
    public_key_hex: str | None = None,
) -> bool:
    """
    Verify an Ed25519 tool manifest signature.

    Args:
        tool_id, description, input_schema, declared_side_effects, version:
            The manifest fields — must match exactly what was signed.
        signature_hex:
            The signature to verify (hex string).
        public_key_hex:
            Optional 64-char hex of raw public key bytes. If not supplied,
            the public key is derived from the currently-loaded private key
            (works for local verification; for air-gapped verification pass
            the public key explicitly).

    Returns:
        True if the signature is valid, False on any failure.
    """
    if not _CRYPTO_AVAILABLE:
        logger.warning("[signing] cryptography unavailable — cannot verify signature")
        return False

    try:
        if public_key_hex:
            pub_bytes = bytes.fromhex(public_key_hex)
            public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        else:
            # Derive public key from locally-loaded private key
            public_key = _get_signing_private_key().public_key()

        message = _canonical_manifest(
            tool_id, description, input_schema, declared_side_effects, version
        )
        sig_bytes = bytes.fromhex(signature_hex)
        public_key.verify(sig_bytes, message)  # raises InvalidSignature on failure
        return True

    except Exception as e:
        logger.warning(f"[signing] Signature verification failed for {tool_id!r}: {e}")
        return False


def signing_available() -> bool:
    """Return True if the signing key is loaded and crypto is available."""
    if not _CRYPTO_AVAILABLE:
        return False
    try:
        _get_signing_private_key()
        return True
    except RuntimeError:
        return False
