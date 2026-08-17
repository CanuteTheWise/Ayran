"""Canonical content-addressed artifact store.

Artifacts are immutable, byte-identical copies of tool output or evidence files.
Naming only uses the canonical digest; identical content always resolves to the
same path.  Newly stored bytes are written through a temp file + fsync +
rename + directory fsync, so a crash can never leave a partial artifact
visible under the canonical name.  Existing artifacts are returned with their
hash verified again (never rewritten in place).
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
from typing import Any, BinaryIO

from ayran.graph.canonical import canonical_line, file_hash, fsync_directory, utc_now
from ayran.graph.errors import CONTRACT_INVALID, GraphError
from ayran.graph.ids import new_id
from ayran.graph.namespaces import require_ext4

ARTIFACT_MISSING = "ARTIFACT_MISSING"

# Deterministic scan profile used both at store time and in diagnostics export.
# Any match inside a stored byte stream is a hard failure because blueprint §15
# secrets never persist.
FORBIDDEN_MARKERS: tuple[bytes, ...] = (
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"x-api-key:",
    b"Authorization: Bearer ",
)


class ArtifactError(GraphError):
    pass


def _digest_parts(digest: str) -> tuple[str, str, str]:
    if not digest.startswith("sha256:") or len(digest) != 64 + 7:
        raise ArtifactError(
            CONTRACT_INVALID,
            "canonical artifact digests must be sha256:<64-hex>",
            details={"digest": digest},
        )
    hexpart = digest[7:]
    return hexpart[:2], hexpart[2:4], hexpart


class ArtifactStore:
    """Store, verify and retrieve immutable content-addressed artifacts on ext4."""

    def __init__(self, root: Path, *, allow_unsafe_filesystem: bool = False) -> None:
        require_ext4(root, allow_unsafe_filesystem=allow_unsafe_filesystem)
        self.root = root
        self.cas = root / "cas"
        self.index_path = root / "index.jsonl"
        self.cas.mkdir(parents=True, exist_ok=True)
        self.root.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self.root.chmod(0o700)
            self.cas.chmod(0o700)

    def _object_path(self, digest: str) -> Path:
        bucket1, bucket2, leaf = _digest_parts(digest)
        return self.cas / bucket1 / bucket2 / leaf

    def _scan(self, payload: bytes) -> None:
        for marker in FORBIDDEN_MARKERS:
            if marker.lower() in payload.lower():
                raise ArtifactError(
                    ARTIFACT_MISSING,
                    "artifact contains a forbidden secret-shaped byte sequence; refused to persist",
                    details={"marker_prefix": marker[:24].decode("latin-1", errors="replace")},
                )

    def store(
        self,
        payload: bytes,
        *,
        media_type: str = "application/octet-stream",
        source: str | None = None,
    ) -> dict[str, Any]:
        """Persist bytes once under their canonical digest; return a verified record."""

        if not payload:
            raise ArtifactError(CONTRACT_INVALID, "refusing to store an empty artifact")
        self._scan(payload)
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        target = self._object_path(digest)
        record = {
            "schema_version": "1.0.0",
            "artifact_id": new_id("art"),
            "content_hash": digest,
            "size_bytes": len(payload),
            "media_type": media_type,
            "created_at": utc_now(),
            "source": source,
        }
        if target.is_file():
            # Idempotent return: verify the existing bytes match the digest path.
            have = file_hash(target)
            if have != digest:
                raise ArtifactError(
                    ARTIFACT_MISSING,
                    "existing artifact bytes disagree with their canonical path digest",
                    details={"expected": digest, "found": have},
                )
            record["deduplicated"] = True
            return record
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
        temporary_path = Path(temporary)
        written = 0
        try:
            while written < len(payload):
                chunk = payload[written : written + 1024 * 1024]
                os.write(fd, chunk)
                written += len(chunk)
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, target)
            fsync_directory(target.parent)
        finally:
            if fd >= 0:
                os.close(fd)
            temporary_path.unlink(missing_ok=True)
        line = canonical_line(record)
        ifd = os.open(
            self.index_path,
            os.O_CREAT | os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            os.write(ifd, line)
            os.fsync(ifd)
        finally:
            os.close(ifd)
        fsync_directory(target.parent)
        record["deduplicated"] = False
        return record

    def open(self, digest: str) -> BinaryIO:
        path = self._object_path(digest)
        if not path.is_file():
            raise ArtifactError(ARTIFACT_MISSING, f"artifact {digest} is not in this store")
        return path.open("rb")

    def verify(self, digest: str) -> dict[str, Any]:
        path = self._object_path(digest)
        if not path.is_file():
            raise ArtifactError(ARTIFACT_MISSING, f"artifact {digest} is not in this store")
        have = file_hash(path)
        return {
            "content_hash": digest,
            "path": str(path),
            "bytes": path.stat().st_size,
            "valid": have == digest,
        }
