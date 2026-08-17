"""Recover one run: replay the journal and reconcile process/lease state."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ayran.artifacts.store import ArtifactStore
from ayran.graph.recovery import GraphStore
from ayran.process.supervisor import ProcessSupervisor
from ayran.runtime.logs import StructuredLogger
from ayran.runtime.paths import process_root, run_root
from ayran.runtime.servicerun import reconcile_processes, recover_lease


def recover_run(config: Any, run_id: str, state_root: Path | None) -> dict[str, Any]:
    base = run_root((state_root or Path(config.state_root)), run_id)
    logger = StructuredLogger(base / "logs" / "runtime.jsonl", run_id=run_id, component="ayran.recover")
    artifact_store = ArtifactStore(base / "artifacts", allow_unsafe_filesystem=True)
    supervisor = ProcessSupervisor(
        process_root((state_root or Path(config.state_root)), run_id),
        run_id=run_id,
        logger=logger,
        artifact_store=artifact_store,
    )

    # 1. Reclaim and re-enforce the graph lease if the old writer is absent.
    lease_reclaimed = recover_lease(base, run_id, logger)

    # 2. Replay and verify the journal (authoritative recovery; rebuild if the
    #    projection is stale).
    graph_root = base / "graph"
    stream_id = None
    stream_path = base / "stream.json"
    if stream_path.is_file():
        stream_id = json.loads(stream_path.read_text(encoding="utf-8"))
    replayed: dict[str, Any] = {}
    if stream_id and graph_root.is_dir():
        store = GraphStore(graph_root, stream_id, allow_unsafe_filesystem=True)
        replayed = store.replay()
        store.close()

    # 3. Reconcile process entries against live OS state.
    reconciled = reconcile_processes(
        process_root((state_root or Path(config.state_root)), run_id),
        run_id=run_id,
        supervisor=supervisor,
        logger=logger,
    )

    return {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "lease_reclaimed": lease_reclaimed,
        "graph_replay": replayed,
        "reconciled_processes": [entry.__dict__ for entry in reconciled],
    }
