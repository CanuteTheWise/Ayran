"""RFC 8785 canonical bytes, strict JSON framing, hashes, and durable file helpers."""

from __future__ import annotations

import copy
import errno
import hashlib
import json
import os
import re
import tempfile
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import rfc8785

from .errors import CONTRACT_INVALID, RESOURCE_EXHAUSTED, GraphError

Hash = str
CANONICAL_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")


def utc_now() -> str:
    """Return one canonical, microsecond-precision UTC spelling."""

    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def require_canonical_timestamps(value: Any, path: str = "$") -> None:
    """Reject non-UTC or alternate timestamp spellings before durable hashing."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            child = f"{path}.{key}"
            if (
                (key.endswith("_at") or key in {"deadline"})
                and isinstance(item, str)
                and not CANONICAL_UTC.fullmatch(item)
            ):
                raise GraphError(
                    CONTRACT_INVALID,
                    "Durable timestamps must use canonical RFC 3339 UTC spelling.",
                    details={"field": child},
                )
            require_canonical_timestamps(item, child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            require_canonical_timestamps(item, f"{path}[{index}]")


def _remove_path(value: Any, dotted: str) -> None:
    current = value
    parts = dotted.split(".")
    for part in parts[:-1]:
        if not isinstance(current, dict):
            return
        current = current.get(part)
    if isinstance(current, dict):
        current.pop(parts[-1], None)


def canonical_bytes(value: Any, *, exclude: Iterable[str] = ()) -> bytes:
    """Serialize with the one project-wide RFC 8785 implementation."""

    clone = copy.deepcopy(value)
    for path in exclude:
        _remove_path(clone, path)
    try:
        return rfc8785.dumps(clone)
    except (TypeError, ValueError) as error:
        raise GraphError(
            CONTRACT_INVALID,
            "Value is outside the RFC 8785 canonical JSON domain.",
            details={"reason": str(error)},
        ) from error


def sha256_bytes(value: bytes) -> Hash:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical_hash(value: Any, *, exclude: Iterable[str] = ()) -> Hash:
    return sha256_bytes(canonical_bytes(value, exclude=exclude))


def object_hash(value: Any) -> Hash:
    return canonical_hash(value, exclude=("integrity.content_hash", "event_hash"))


def commit_hash(value: Mapping[str, Any]) -> Hash:
    return canonical_hash(value, exclude=("commit_hash",))


def canonical_line(value: Any) -> bytes:
    return canonical_bytes(value) + b"\n"


def strict_json_loads(raw: bytes) -> Any:
    """Parse UTF-8 JSON while rejecting duplicate keys and BOMs."""

    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("UTF-8 BOM is not allowed")
    if b"\r" in raw:
        raise ValueError("CR bytes are not allowed in journal frames")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = item
        return result

    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)


def strict_canonical_load(raw: bytes) -> Any:
    value = strict_json_loads(raw)
    if canonical_bytes(value) != raw:
        raise ValueError("journal frame is not RFC 8785 canonical JSON")
    return value


def write_all(fd: int, payload: bytes) -> None:
    """Complete an append despite short writes or EINTR."""

    view = memoryview(payload)
    offset = 0
    while offset < len(view):
        try:
            written = os.write(fd, view[offset:])
        except InterruptedError:
            continue
        except OSError as error:
            if error.errno == errno.ENOSPC or getattr(error, "winerror", None) == 112:
                raise GraphError(
                    RESOURCE_EXHAUSTED,
                    "journal append failed: disk full",
                    retryable=True,
                    details={"errno": int(error.errno or 0)},
                ) from error
            raise
        if written <= 0:
            raise OSError("short journal write made no progress")
        offset += written


def fsync_directory(path: Path) -> None:
    """Persist directory entries on Linux/WSL; Windows is not an authority filesystem."""

    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(
    path: Path,
    payload: bytes,
    *,
    mode: int = 0o600,
    fault_hook: Callable[[str], None] | None = None,
    fault_prefix: str | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        os.chmod(temporary_path, mode)
        write_all(fd, payload)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        if fault_hook is not None and fault_prefix is not None:
            fault_hook(f"after_{fault_prefix}_temp_fsync")
        os.replace(temporary_path, path)
        if fault_hook is not None and fault_prefix is not None:
            fault_hook(f"after_{fault_prefix}_rename")
        fsync_directory(path.parent)
        if fault_hook is not None and fault_prefix is not None:
            fault_hook(f"after_{fault_prefix}_directory_fsync")
    finally:
        if fd >= 0:
            os.close(fd)
        temporary_path.unlink(missing_ok=True)


def file_hash(path: Path) -> Hash:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def members_hash(event_hashes: list[Hash]) -> Hash:
    return canonical_hash(
        {"domain": "ayran.journal.members.v1", "event_hashes": event_hashes}
    )


def merkle_root(event_hashes: list[Hash]) -> Hash:
    if not event_hashes:
        return canonical_hash({"domain": "ayran.journal.merkle.v1", "empty": True})
    level = [
        canonical_hash(
            {"domain": "ayran.journal.merkle.v1", "index": index, "event_hash": value}
        )
        for index, value in enumerate(event_hashes)
    ]
    while len(level) > 1:
        next_level: list[Hash] = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            next_level.append(
                canonical_hash(
                    {"domain": "ayran.journal.merkle.v1", "left": left, "right": right}
                )
            )
        level = next_level
    return level[0]
