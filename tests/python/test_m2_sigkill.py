"""M2 ext4 SIGKILL process-recovery tests."""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "skills" / "ayran" / "src"))

import pytest
from ayran.artifacts.store import ArtifactStore
from ayran.process.supervisor import ProcessBudget, ProcessSupervisor
from ayran.runtime.logs import StructuredLogger
from ayran.runtime.servicerun import reconcile_processes

pytestmark = pytest.mark.wsl_ext4


@pytest.mark.wsl_ext4
def test_supervisor_records_then_sigkill_then_reconcile(tmp_path: Path) -> None:
    """Spawn a sleeping process group, SIGKILL it, then reconcile."""
    root = tmp_path
    logger = StructuredLogger(root / "logs.jsonl", run_id="run_test", component="test")
    artifact_store = ArtifactStore(root / "artifacts", allow_unsafe_filesystem=True)
    supervisor = ProcessSupervisor(
        root / "process",
        run_id="run_test",
        logger=logger,
        artifact_store=artifact_store,
    )
    budget = ProcessBudget(wall_seconds=30, graceful_stop_seconds=1)
    entry = supervisor.spawn(
        ("/bin/sh", "-c", "sleep 5"),
        budget=budget,
        scope_hash="sha256:" + "0" * 64,
        actor={"kind": "test", "id": "sigkill"},
    )
    assert entry.pid is not None
    assert entry.pgid is not None
    assert entry.start_identity is not None
    import signal

    os.killpg(entry.pgid, getattr(signal, "SIGKILL", 9))  # type: ignore[attr-defined]
    time.sleep(0.1)
    reconciled = reconcile_processes(
        root / "process", run_id="run_test", supervisor=supervisor, logger=logger
    )
    match = [item for item in reconciled if item.process_uid == entry.process_uid]
    assert match
    assert match[0].final_state in {"exited", "signalled", "zombie_reaped"}
