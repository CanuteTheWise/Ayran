"""Prepare a per-session Target run so ``ayran service`` can bind."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ayran.api.token import create_token
from ayran.graph.canonical import (
    atomic_write,
    canonical_hash,
    canonical_line,
    strict_json_loads,
    utc_now,
)
from ayran.graph.errors import CONTRACT_INVALID, GraphError
from ayran.graph.ids import new_id
from ayran.graph.namespaces import require_ext4, target_stream
from ayran.graph.recovery import GraphStore
from ayran.policy.scope import ScopeManifest
from ayran.runtime.paths import default_state_root, run_root, runtime_root, socket_path


def prepare_session(
    *,
    cwd: Path,
    state_root: Path | None = None,
    allow_unsafe_filesystem: bool = False,
) -> dict[str, Any]:
    """Create stream, empty graph, token, and socket path for one Prime session."""

    resolved_cwd = cwd.expanduser().resolve(strict=False)
    resolved_state = (state_root or default_state_root()).expanduser().resolve(strict=False)
    require_ext4(resolved_state, allow_unsafe_filesystem=allow_unsafe_filesystem)
    run_id = new_id("run")
    identity = {
        "target_id": new_id("tgt"),
        "source_tree_hash": canonical_hash({"cwd": str(resolved_cwd)}),
        "scope_id": new_id("scp"),
    }
    target_key = canonical_hash({"cwd": str(resolved_cwd), "run_id": run_id})
    stream = target_stream(run_id, identity, target_key)
    base = run_root(resolved_state, run_id)
    base.mkdir(parents=True, exist_ok=True)
    (base / "stream.json").write_text(
        canonical_line(stream).decode("utf-8"),
        encoding="utf-8",
    )
    graph_root = base / "graph"
    store = GraphStore(graph_root, stream, allow_unsafe_filesystem=allow_unsafe_filesystem)
    store.close()
    runtime = runtime_root(resolved_state, run_id)
    runtime.mkdir(parents=True, exist_ok=True)
    token = create_token(runtime, run_id=run_id)
    sock = socket_path(resolved_state, run_id)
    return {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "state_root": str(resolved_state),
        "run_root": str(base),
        "socket": str(sock),
        "token_file": str(token),
        "cwd": str(resolved_cwd),
        "created_at": utc_now(),
    }


def bind_scope_value(payload: dict[str, Any], *, run_id: str, dest_root: Path) -> ScopeManifest:
    """Pin a validated scope object to ``run_id`` and write ``scope.json``."""

    bound = dict(payload)
    bound["run_id"] = run_id
    integrity = dict(bound.get("integrity") or {})
    integrity["algorithm"] = str(integrity.get("algorithm") or "sha256")
    integrity["canonicalization"] = str(integrity.get("canonicalization") or "rfc8785")
    excluded = integrity.get("excluded_fields") or ["integrity.content_hash"]
    integrity["excluded_fields"] = [str(item) for item in excluded]
    integrity["content_hash"] = "sha256:" + ("0" * 64)
    bound["integrity"] = integrity
    manifest = ScopeManifest(bound)
    dest_root.mkdir(parents=True, exist_ok=True)
    atomic_write(dest_root / "scope.json", canonical_line(manifest.value))
    return manifest


def bind_scope_to_run(source: Path, *, run_id: str, dest_root: Path) -> ScopeManifest:
    """Validate an operator scope template, pin it to ``run_id``, and write ``scope.json``."""

    payload = strict_json_loads(source.read_bytes())
    if not isinstance(payload, dict):
        raise GraphError(CONTRACT_INVALID, "scope manifest file must be a single JSON object.")
    return bind_scope_value(payload, run_id=run_id, dest_root=dest_root)


def start_engagement(
    *,
    cwd: Path,
    manifest: Path | None = None,
    roots: list[str] | None = None,
    state_root: Path | None = None,
    allow_unsafe_filesystem: bool = False,
) -> dict[str, Any]:
    """Prepare a session and bind a scope file or generated local-roots envelope."""

    if manifest is not None and roots:
        raise GraphError(
            CONTRACT_INVALID,
            "start accepts only one of --manifest or --roots.",
        )
    prepared = prepare_session(
        cwd=cwd,
        state_root=state_root,
        allow_unsafe_filesystem=allow_unsafe_filesystem,
    )
    dest = Path(prepared["run_root"])
    run_id = str(prepared["run_id"])
    if manifest is not None:
        bound = bind_scope_to_run(
            manifest.expanduser(),
            run_id=run_id,
            dest_root=dest,
        )
    else:
        from ayran.policy.local_scope import detect_local_roots, local_scope_manifest

        chosen = list(roots) if roots else detect_local_roots(cwd)
        bound = bind_scope_value(
            local_scope_manifest(chosen, run_id=run_id, cwd=cwd),
            run_id=run_id,
            dest_root=dest,
        )
    prepared["scope_id"] = bound.scope_id
    prepared["scope_hash"] = bound.hash
    prepared["scope_file"] = str(dest / "scope.json")
    prepared["included_roots"] = [item or "." for item in bound.included_roots]
    return prepared
