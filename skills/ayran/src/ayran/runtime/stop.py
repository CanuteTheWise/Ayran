"""Stop one run through the process supervisor's termination protocol."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ayran.artifacts.store import ArtifactStore
from ayran.process.supervisor import ProcessSupervisor
from ayran.runtime.logs import StructuredLogger
from ayran.runtime.paths import artifacts_root, process_root, run_root


def stop_run(
    config: Any,
    run_id: str,
    state_root: Path | None,
    graceful: bool,
    force_after: int | None,
) -> dict[str, Any]:
    base = run_root((state_root or Path(config.state_root)), run_id)
    logger = StructuredLogger(base / "logs" / "runtime.jsonl", run_id=run_id, component="ayran.stop")
    artifact_store = ArtifactStore(artifacts_root((state_root or Path(config.state_root)), run_id), allow_unsafe_filesystem=True)
    supervisor = ProcessSupervisor(
        process_root((state_root or Path(config.state_root)), run_id),
        run_id=run_id,
        logger=logger,
        artifact_store=artifact_store,
    )
    # The CLI stop path reconciles any *recorded* process entries; new spawns
    # are not possible after the lease is reclaimed by the service entrypoint.
    from ayran.runtime.servicerun import _entry_from_record, _load_records

    stopped: list[dict[str, Any]] = []
    for record in _load_records(process_root((state_root or Path(config.state_root)), run_id)):
        if record.get("state") != "running":
            continue
        entry = _entry_from_record(record, run_id)
        try:
            entry.pid = record.get("pid")
            entry.pgid = record.get("pgid")
            if force_after is not None:
                entry.budget.graceful_stop_seconds = int(force_after)  # type: ignore[misc]
        except Exception:
            pass
        supervisor.terminate(entry, reason="operator_stop")
        # Append INSIDE the loop: with the append at function level, a run with
        # zero running records crashed (UnboundLocalError) and multi-record runs
        # reported only the last entry (found by the first real `ayran stop`
        # execution during R6 close-out).
        stopped.append(entry.identity_tuple())
    captured: dict[str, Any] | None = None
    graph_root = base / "graph"
    stream_path = base / "stream.json"
    if graph_root.is_dir() and stream_path.is_file():
        try:
            import json

            from ayran.graph.recovery import GraphStore
            from ayran.learning.capture import capture_run_outcomes

            stream = json.loads(stream_path.read_text(encoding="utf-8"))
            store = GraphStore(graph_root, stream, allow_unsafe_filesystem=True)
            try:
                captured = capture_run_outcomes(store, run_id=run_id)
            finally:
                store.close()
        except Exception:
            captured = None
    return {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "stopped_processes": stopped,
        "graceful": graceful,
        "force_after": force_after,
        "learning_capture": captured,
    }
