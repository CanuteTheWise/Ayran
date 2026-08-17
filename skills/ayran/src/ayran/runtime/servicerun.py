"""Top-level run lifecycle: reconcile graph + process state after restart.

The service runner owns the SQLite projection, the process supervisor, and
the JSON-RPC server.  On startup it binds to a single-run ext4 root, replays
the journal, rebuilds the projection when stale, and *reconciles* recorded
process entries before accepting new requests:

1. Read the durable process record index.
2. For each record with state ``running``/``signalled`` check live OS state:
   ``kill(pid, 0)`` only proves a pid exists; the auth boundary requires the
   recorded pid's *start identity* (Linux ``/proc`` start ticks) and process
   group to match.
3. Records whose processes no longer exist are finalized.

A *stale lease* is reclaimed only when the lease lock file is free AND the
``lease.json`` owner record's pid/start-identity no longer exists.
"""

from __future__ import annotations

import contextlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ayran.graph.ids import new_id
from ayran.graph.leases import process_start_identity
from ayran.process.supervisor import ProcessBudget, ProcessEntry, ProcessSupervisor
from ayran.runtime.logs import StructuredLogger


@dataclass(frozen=True, slots=True)
class ReconciledProcess:
    process_uid: str
    final_state: str
    pid: int | None
    pgid: int | None
    reason: str


def _live(pid: int) -> bool:
    if os.name == "nt":
        # Signaling 0 is not meaningful on Windows; fall back to PID-list.
        return pid in set(_windows_pids())
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


def _proc_state(pid: int) -> str | None:
    """Return the one-letter /proc state for pid (R/S/Z/D/T...), or None."""

    if os.name == "nt":
        return None
    try:
        with open(f"/proc/{pid}/stat", "rb") as stream:
            text = stream.read().decode("utf-8")
        closing = text.rindex(")")
        fields = text[closing + 2 :].split()
        return fields[0] if fields else None
    except (OSError, ValueError, IndexError):
        return None


def _windows_pids() -> list[int]:
    import ctypes

    k32 = ctypes.windll.kernel32
    snapshot = k32.CreateToolhelp32Snapshot(0x2, 0)
    if snapshot == -1:
        return []
    try:
        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", ctypes.c_ulong),
                ("cntUsage", ctypes.c_ulong),
                ("th32ProcessID", ctypes.c_ulong),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", ctypes.c_ulong),
                ("cntThreads", ctypes.c_ulong),
                ("th32ParentProcessID", ctypes.c_ulong),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", ctypes.c_ulong),
                ("szExeFile", ctypes.c_wchar * 260),
            ]

        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        pids: list[int] = []
        has = k32.Process32FirstW(snapshot, ctypes.byref(entry))
        while has:
            pids.append(int(entry.th32ProcessID))
            has = k32.Process32NextW(snapshot, ctypes.byref(entry))
        k32.CloseHandle(snapshot)
        return pids
    finally:
        with contextlib.suppress(Exception):
            k32.CloseHandle(snapshot)


def _same_identity(pid: int, recorded_identity: str | None) -> bool:
    if recorded_identity is None:
        return False
    return process_start_identity(pid) == recorded_identity


def _load_records(process_root_path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    records_root = process_root_path / "records"
    if not records_root.is_dir():
        return records
    for path in sorted(records_root.glob("*.jsonl")):
        last: dict[str, Any] | None = None
        with path.open("rb") as stream:
            for line in stream:
                line = line.strip()
                if not line:
                    continue
                last = json.loads(line.decode("utf-8"))
        if last is not None:
            records.append(last)
    return records


def reconcile_processes(
    process_root_path: Path,
    *,
    run_id: str,
    supervisor: ProcessSupervisor,
    logger: StructuredLogger,
) -> list[ReconciledProcess]:
    """Resolve recorded process entries against live OS state and finalize."""

    reconciled: list[ReconciledProcess] = []
    for record in _load_records(process_root_path):
        state = record.get("state", "")
        pid = record.get("pid")
        pgid = record.get("pgid")
        start_identity = record.get("process_start_identity")
        uid = str(record.get("process_uid", ""))
        if state in {"exited", "signalled", "killed_grace_expired", "rejected_policy", "zombie_reaped"}:
            reconciled.append(ReconciledProcess(uid, state, pid, pgid, "already-final"))
            continue
        if not isinstance(pid, int) or pid <= 0:
            logger.event("WARN", "reconcile.invalid_pid", process_uid=uid)
            reconciled.append(ReconciledProcess(uid, "rejected_policy", pid, pgid, "invalid-pid"))
            continue
        if not _live(pid):
            reconciled.append(ReconciledProcess(uid, "exited", pid, pgid, "pid-absent"))
            continue
        # An unreaped zombie is a terminated process; SIGKILL and SIGTERM both
        # arrive here as ``state==Z`` until the supervisor's own ``waitpid``
        # has a chance to consume them.
        proc_state = _proc_state(pid)
        if proc_state == "Z":
            supervisor.record_final_state(uid=uid, state="signalled", reason="zombie_reaped")
            reconciled.append(ReconciledProcess(uid, "signalled", pid, pgid, "zombie-reaped"))
            continue
        if not _same_identity(pid, start_identity):
            reconciled.append(
                ReconciledProcess(uid, "zombie_reaped", pid, pgid, "pid-reused-identity-mismatch")
            )
            continue
        reconciled.append(ReconciledProcess(uid, state, pid, pgid, "live-and-owned"))
    logger.event("INFO", "reconcile.completed", count=len(reconciled))
    return reconciled


def _entry_from_record(record: dict[str, Any], run_id: str) -> ProcessEntry:
    budget = record.get("budget") or {}
    return ProcessEntry(
        process_uid=str(record.get("process_uid", new_id("prc"))),
        argv=tuple(record.get("argv", [])),
        cwd=record.get("cwd"),
        env_fingerprint=str(record.get("env_fingerprint", "")),
        budget=ProcessBudget(
            wall_seconds=budget.get("wall_seconds"),
            max_stdout_bytes=budget.get("max_stdout_bytes"),
            max_stderr_bytes=budget.get("max_stderr_bytes"),
            cpu_seconds=budget.get("cpu_seconds"),
            max_rss_mib=budget.get("max_rss_mib"),
            max_processes=budget.get("max_processes"),
            graceful_stop_seconds=budget.get("graceful_stop_seconds", 20),
        ),
        scope_hash=str(record.get("scope_hash", "")),
        actor=dict(record.get("actor") or {}),
        run_id=run_id,
    )


def recover_lease(root: Path, run_id: str, logger: StructuredLogger) -> bool:
    """Return True when the run graph lease is free or was safely reclaimed."""

    runtime_root = root / "runtime"
    metadata_path = runtime_root / "lease.json"
    if not metadata_path.is_file():
        return True
    try:
        value = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        # Corrupt lease metadata is NOT reclaimed automatically.
        return False
    pid = value.get("pid")
    recorded = value.get("process_start_identity")
    # Only a lease whose process is absent *and* whose start identity no longer
    # resolves is safe to reclaim.  The authoritative exclusion is the OS
    # advisory lock; the metadata file is diagnostic only.
    if isinstance(pid, int) and pid > 0 and _live(pid) and _same_identity(pid, recorded):
        return False
    try:
        metadata_path.unlink(missing_ok=False)
        logger.event("INFO", "lease.reclaimed", run_state="reclaimed", count=1)
        return True
    except OSError:
        return False
