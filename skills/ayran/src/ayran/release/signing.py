"""RFC 8785 canonical JSON → SHA-256 content-addressed signatures."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ayran.graph.canonical import canonical_bytes, canonical_hash, sha256_bytes
from ayran.release.errors import SIGNATURE_MISMATCH, ReleaseError


def sign_payload(value: dict[str, Any]) -> dict[str, str]:
    digest = canonical_hash(value)
    return {
        "algorithm": "sha256",
        "canonicalization": "rfc8785",
        "content_hash": digest,
        "signature": digest,
        "note": "content-addressed signing placeholder; GPG code signing is deferred",
    }


def write_signature(path: Path, value: dict[str, Any]) -> dict[str, str]:
    signature = sign_payload(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        canonical_bytes(signature).decode("utf-8") + "\n",
        encoding="utf-8",
    )
    return signature


def verify_signature(path: Path, value: dict[str, Any]) -> bool:
    expected = sign_payload(value)
    if not path.is_file():
        raise ReleaseError(SIGNATURE_MISMATCH, f"signature file missing: {path}")
    import json

    actual = json.loads(path.read_text(encoding="utf-8"))
    if actual.get("content_hash") != expected["content_hash"]:
        raise ReleaseError(SIGNATURE_MISMATCH, "release signature does not match payload")
    return True


def file_sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())
