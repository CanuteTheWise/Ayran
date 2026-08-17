"""Durable checkpoint manifests for graph resume and rebuild validation."""

from __future__ import annotations

import copy
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from ayran.api.validators import validate_contract

from .canonical import atomic_write, canonical_line, object_hash, utc_now
from .ids import new_id


def create_checkpoint(
    root: Path,
    stream: dict[str, Any],
    *,
    journal_cursor: int,
    journal_event_hash: str | None,
    journal_commit_hash: str | None,
    projection_schema_version: str,
    migration_version: int,
    projection_digest: str,
    outbox_digest: str,
    target_hash: str | None = None,
    config_hash: str | None = None,
    source_hash: str | None = None,
    tool_hash: str | None = None,
    artifact_manifest_hash: str | None = None,
    fault_hook: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": "1.0.0",
        "checkpoint_id": new_id("chk"),
        "created_at": utc_now(),
        "stream": copy.deepcopy(stream),
        "journal_cursor": journal_cursor,
        "journal_event_hash": journal_event_hash,
        "journal_commit_hash": journal_commit_hash,
        "projection_schema_version": projection_schema_version,
        "migration_version": migration_version,
        "target_hash": target_hash,
        "config_hash": config_hash,
        "source_hash": source_hash,
        "tool_hash": tool_hash,
        "artifact_manifest_hash": artifact_manifest_hash,
        "outbox_digest": outbox_digest,
        "projection_digest": projection_digest,
        "integrity": {
            "algorithm": "sha256",
            "canonicalization": "rfc8785",
            "content_hash": "sha256:" + "0" * 64,
            "excluded_fields": ["integrity.content_hash"],
        },
    }
    value["integrity"]["content_hash"] = object_hash(value)
    validate_contract("graph-checkpoint", value)
    path = root / "checkpoints" / f"{value['checkpoint_id']}.json"
    atomic_write(
        path,
        canonical_line(value),
        fault_hook=fault_hook,
        fault_prefix="checkpoint",
    )
    return value


def read_checkpoint(path: Path, stream: dict[str, Any]) -> dict[str, Any]:
    import json

    value = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    validate_contract("graph-checkpoint", value)
    if value["stream"] != stream:
        raise ValueError("checkpoint stream identity mismatch")
    return value
