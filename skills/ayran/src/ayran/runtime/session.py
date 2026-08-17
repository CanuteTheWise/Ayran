"""Prepare a per-session Target run so ``ayran service`` can bind."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ayran.api.token import create_token
from ayran.graph.canonical import canonical_hash, canonical_line, utc_now
from ayran.graph.ids import new_id
from ayran.graph.namespaces import require_ext4, target_stream
from ayran.graph.recovery import GraphStore
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
