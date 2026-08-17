"""Orphan process-group reaping after sidecar death during a tool run."""

from __future__ import annotations

import contextlib
import os
import signal
from typing import Any

from ayran.process.supervisor import ProcessSupervisor, TerminationKind


def reap_orphans(supervisor: ProcessSupervisor) -> dict[str, Any]:
    reaped: list[str] = []
    for entry in list(supervisor.reconcile()):
        stopped = supervisor.terminate(entry, reason="orphan-reap")
        reaped.append(stopped.process_uid)
    return {
        "reaped": reaped,
        "remaining": [item.process_uid for item in supervisor.reconcile()],
        "kind": TerminationKind.ZOMBIE_REAPED.value,
    }


def kill_sidecar_and_reap(supervisor: ProcessSupervisor, *, pid: int | None = None) -> dict[str, Any]:
    if pid is not None and hasattr(os, "kill"):
        with contextlib.suppress(OSError):
            os.kill(pid, getattr(signal, "SIGKILL", signal.SIGTERM))
    return reap_orphans(supervisor)
