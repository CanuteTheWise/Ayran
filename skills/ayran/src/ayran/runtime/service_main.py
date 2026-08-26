"""Owner-local JSON-RPC ayrand service entrypoint: own socket, supervisor, run receipt."""
from __future__ import annotations

import contextlib
import json
import os
import signal
import sys
from pathlib import Path
from typing import Any

from ayran.api.server import AyranServer, PeerCredentials
from ayran.api.token import create_token
from ayran.artifacts.store import ArtifactStore
from ayran.bridge.handler import build_dispatcher
from ayran.config.models import EffectiveConfig
from ayran.graph.recovery import GraphStore
from ayran.process.supervisor import ProcessSupervisor
from ayran.runtime.logs import StructuredLogger
from ayran.runtime.paths import run_root, socket_path
from ayran.runtime.servicerun import reconcile_processes


def _run_receipt_path(base: Path) -> Path:
    return base / "run.json"


def _write_run_receipt(base: Path, receipt: dict[str, Any]) -> None:
    from ayran.graph.canonical import atomic_write, canonical_line

    atomic_write(_run_receipt_path(base), canonical_line(receipt))


def service_main(
    config: EffectiveConfig,
    *,
    run_id: str,
    state_root: Path | None,
    socket: Path | None,
    token_file: Path | None,
    idle_exit_secs: float | None = None,
) -> dict[str, Any]:
    resolved_state = state_root or Path(config.state_root)
    base = run_root(resolved_state, run_id)
    base.mkdir(parents=True, exist_ok=True)
    logger = StructuredLogger(
        base / "logs" / "runtime.jsonl", run_id=run_id, component="ayran.service"
    )
    artifact_store = ArtifactStore(base / "artifacts", allow_unsafe_filesystem=True)
    process_supervisor = ProcessSupervisor(
        base / "processes",
        run_id=run_id,
        logger=logger,
        artifact_store=artifact_store,
    )

    # Recover stale lease + reconcile process state first.
    socket_resolved = socket or socket_path(resolved_state, run_id)
    stream_path = base / "stream.json"
    if not stream_path.is_file():
        raise ValueError(f"service requires an existing stream identity at {stream_path}")
    stream = json.loads(stream_path.read_text(encoding="utf-8"))
    reconcile_processes(base / "processes", run_id=run_id, supervisor=process_supervisor, logger=logger)

    # Start/verify the graph store.
    store = GraphStore(base / "graph", stream, allow_unsafe_filesystem=True)
    replay_result = store.replay()
    receipt = {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "phase": replay_result.get("state", "replayed"),
        "graph_cursor": replay_result.get("cursor"),
        "budgets": {},
        "run_state": "running",
        "active_processes": [],
        "pending_approvals": [],
        "queued_hypotheses": [],
        "last_concrete_progress": replay_result.get("committed_at"),
    }
    _write_run_receipt(base, receipt)

    # Prepare and bind the run-scoped authentication boundary.
    if token_file is None:
        token_file = create_token(base / "runtime", run_id=run_id)
    expected = token_file.read_bytes()

    dispatcher = build_dispatcher(
        run_id=run_id,
        config=config,
        store=store,
        logger=logger,
        artifact_store=artifact_store,
        process_supervisor=process_supervisor,
        receipt=receipt,
        state_root=resolved_state,
        run_root=base,
        shutdown_callback=None,
    )

    def handler(method: str, params: dict[str, Any], credentials: PeerCredentials) -> Any:
        # Token already verified and popped by AyranServer.
        if method == "run.ping":
            return {
                "schema_version": "1.0.0",
                "run_id": run_id,
                "pid": os.getpid(),
                "peer_uid": credentials.uid,
                "graph_cursor": receipt["graph_cursor"],
            }
        return dispatcher.dispatch(method, params)

    server = AyranServer(
        socket_resolved,
        token=expected,
        logger=logger,
        handler=handler,
        run_id=run_id,
        idle_exit_secs=idle_exit_secs,
    )
    dispatcher.shutdown_callback = server.stop
    thread = server.start_background()

    def _shutdown(signum, frame):  # type: ignore[no-untyped-def]
        logger.event("INFO", "service.signalled", signal=signum)
        server.stop()
        with contextlib.suppress(Exception):
            store.close()
        _write_run_receipt(base, dict(receipt, run_state="stopped"))
        sys.exit(128 + signum)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    logger.event("INFO", "service.begin", run_state="running")
    while thread.is_alive():
        thread.join(timeout=1)
    return dict(receipt, run_state="stopped")
