"""Immutable evaluation result manifests. Errors create a new session, never an edit."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ayran.evaluation.errors import MANIFEST_IMMUTABLE, SESSION_NOT_FOUND, EvaluationError
from ayran.evaluation.models import EvaluationManifest
from ayran.evaluation.paths import session_dir, session_manifest_path
from ayran.graph.canonical import atomic_write, canonical_hash, canonical_line


def write_manifest(manifest: EvaluationManifest, *, results_root: Path | str | None = None) -> Path:
    path = session_manifest_path(manifest.session_id, results=results_root)
    if path.is_file():
        existing = json.loads(path.read_text(encoding="utf-8"))
        if existing.get("content_hash") != manifest.content_hash:
            raise EvaluationError(
                MANIFEST_IMMUTABLE,
                "evaluation session already exists with a different hash; create a new session",
            )
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = manifest.model_dump(mode="json")
    atomic_write(path, canonical_line(payload))
    return path


def load_manifest(session_id: str, *, results_root: Path | str | None = None) -> EvaluationManifest:
    path = session_manifest_path(session_id, results=results_root)
    if not path.is_file():
        raise EvaluationError(SESSION_NOT_FOUND, f"evaluation session {session_id} has no manifest")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise EvaluationError(SESSION_NOT_FOUND, "evaluation manifest is not an object")
    return EvaluationManifest.model_validate(payload)


def verify_manifest(session_id: str, *, results_root: Path | str | None = None) -> dict[str, Any]:
    manifest = load_manifest(session_id, results_root=results_root)
    unsigned = {
        "session_id": manifest.session_id,
        "created_at": manifest.created_at,
        "seeds": list(manifest.seeds),
        "arms": [run.result_hash for run in manifest.arms],
        "leakage": manifest.leakage.get("result_hash"),
        "gate": manifest.gate.model_dump(mode="json"),
        "parser": "1.0.0",
    }
    actual = canonical_hash(unsigned)
    if actual != manifest.content_hash:
        raise EvaluationError(MANIFEST_IMMUTABLE, "evaluation manifest hash does not match contents")
    return {
        "session_id": session_id,
        "path": str(session_dir(session_id, results=results_root)),
        "verified": True,
        "content_hash": manifest.content_hash,
        "release_ready": manifest.gate.release_ready,
    }
