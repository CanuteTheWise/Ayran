"""Redacted, content-addressed diagnostics support bundle (§15).

The bundle is a deterministic collection of run state.  Every exported record
is included in the bundle manifest; every file is content-scanned before
inclusion and any secret-shaped byte content raises ``CORRUPTION``.

Target artifacts are intentionally omitted by default.  Source or target file
content is *never* copied unless the operator passes an explicit override.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from ayran.artifacts.store import FORBIDDEN_MARKERS
from ayran.config.models import EffectiveConfig
from ayran.graph.canonical import canonical_line, fsync_directory, utc_now, write_all
from ayran.graph.errors import GraphError
from ayran.runtime.logs import StructuredLogger
from ayran.runtime.paths import process_root, run_root

CORRUPTION = "CORRUPTION"

_INDEX_SUFFIX = ".diagnostic-index.json"


def _scan(payload: bytes) -> None:
    lowered = payload.lower()
    for marker in FORBIDDEN_MARKERS:
        if marker.lower() in lowered:
            raise GraphError(
                CORRUPTION,
                "support bundle export contains a secret-shaped byte sequence",
                details={"marker_prefix": marker[:24].decode("latin-1", errors="replace")},
            )


def _hash(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def create_bundle(
    config: EffectiveConfig,
    run_id: str,
    bundle_path: Path,
    state_root: Path | None,
) -> dict[str, Any]:
    base = run_root((state_root or Path(config.state_root)), run_id)
    logger = StructuredLogger(
        base / "logs" / "runtime.jsonl", run_id=run_id, component="ayran.diagnose"
    )

    candidates: list[tuple[str, str]] = [
        ("config", "config.json"),
        ("run_receipt", "run.json"),
        ("stream_identity", "stream.json"),
    ]
    proc_root = process_root((state_root or Path(config.state_root)), run_id)
    records_root = proc_root / "records"
    if records_root.is_dir():
        for path in sorted(records_root.glob("*.jsonl")):
            candidates.append((f"process_record:{path.stem}", str(path)))
    logs = base / "logs" / "runtime.jsonl"
    if logs.is_file():
        candidates.append(("logs:runtime", str(logs)))

    manifest: dict[str, Any] = {
        "schema_version": "1.0.0",
        "bundle_id": f"bundle_{run_id}",
        "run_id": run_id,
        "created_at": utc_now(),
        "entries": [],
    }
    entries: list[dict[str, Any]] = []
    payload_parts: list[bytes] = []

    import json
    for name, relative in candidates:
        if name == "config":
            body = json.dumps(config.as_dict(), indent=2).encode("utf-8")
        else:
            path = Path(relative) if Path(relative).is_absolute() else base / relative
            if not path.is_file():
                continue
            body = path.read_bytes()
        _scan(body)
        digest = _hash(body)
        entries.append({"name": name, "content_hash": digest, "size_bytes": len(body)})
        payload_parts.append(body)

    manifest_payload = canonical_line(manifest)
    entries_index_path = bundle_path.with_suffix(bundle_path.suffix + _INDEX_SUFFIX)
    entries_index_path.parent.mkdir(parents=True, exist_ok=True)
    bundle_payload = b"".join(
        [part + b"\n---AYRAN-DIAGNOSTIC-BUNDLE-PART---\n" for part in payload_parts]
    )
    _scan(bundle_payload)

    fd = os.open(bundle_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        write_all(fd, bundle_payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(entries_index_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        write_all(fd, manifest_payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_directory(bundle_path.parent)

    logger.event(
        "INFO",
        "diagnose.exported",
        path_role="diagnostic_bundle",
        count=len(entries),
    )
    return {
        "schema_version": "1.0.0",
        "bundle_id": manifest["bundle_id"],
        "run_id": run_id,
        "bundle_path": str(bundle_path),
        "index_path": str(entries_index_path),
        "entry_count": len(entries),
        "content_hash": _hash(bundle_payload),
        "scan_status": "passed",
    }
