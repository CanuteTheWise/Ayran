"""Process supervisor bound to operation/scope/budget identity.

Every external process is supervised as a dedicated process group.  The entry
key is a unique ``process_uid`` and the identity tuple is
``(pid, process_start_identity, process_group_id)`` so a pid-reused zombie
can never be reconciled as the original collaborator (??11.1).

SIGTERM first; after the configured grace period the whole process group is
SIGKILLed and a final non-blocking verify of group membership is performed.
"""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from ayran.artifacts.store import ArtifactStore
from ayran.graph.canonical import canonical_line, fsync_directory, utc_now
from ayran.graph.errors import CONTRACT_INVALID, GraphError
from ayran.graph.ids import new_id
from ayran.graph.leases import process_start_identity
from ayran.runtime.logs import StructuredLogger


class TerminationKind(StrEnum):
    RUNNING = "running"
    EXITED = "exited"
    SIGNALLED = "signalled"
    KILLED_GRACE_EXPIRED = "killed_grace_expired"
    ZOMBIE_REAPED = "zombie_reaped"
    REJECTED_POLICY = "rejected_policy"


@dataclass(frozen=True, slots=True)
class ProcessBudget:
    wall_seconds: int | None = None
    max_stdout_bytes: int | None = None
    max_stderr_bytes: int | None = None
    cpu_seconds: int | None = None
    max_rss_mib: int | None = None
    max_processes: int | None = None
    graceful_stop_seconds: int = 20


@dataclass(slots=True)
class ProcessEntry:
    process_uid: str
    argv: tuple[str, ...]
    cwd: str | None
    env_fingerprint: str
    budget: ProcessBudget
    scope_hash: str
    actor: dict[str, Any]
    run_id: str
    state: TerminationKind = TerminationKind.RUNNING
    pid: int | None = None
    pgid: int | None = None
    start_identity: str | None = None
    started_at: str | None = None
    ended_at: str | None = None
    exit_code: int | None = None
    signal: int | None = None
    terminated_by: str | None = None
    handle: subprocess.Popen[bytes] | None = field(default=None, repr=False, compare=False)
    stdout_artifact: str | None = None
    stderr_artifact: str | None = None
    stdout_digest: str | None = None
    stderr_digest: str | None = None

    def identity_tuple(self) -> dict[str, Any]:
        return {
            "process_uid": self.process_uid,
            "pid": self.pid,
            "pgid": self.pgid,
            "process_start_identity": self.start_identity,
            "state": self.state.value,
        }


def _env_fingerprint(env: Mapping[str, str]) -> str:
    import hashlib

    digest = hashlib.sha256()
    for key in sorted(env):
        value = env[key]
        digest.update(key.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(str(len(value)).encode("ascii"))
        digest.update(b"\x00")
    return "sha256:" + digest.hexdigest()


def _resolve_executable(argv0: str, allowed_binary_roots: tuple[Path, ...]) -> Path:
    if not argv0 or "\x00" in argv0:
        raise GraphError(CONTRACT_INVALID, "argv[0] is empty or contains NUL")
    candidate = Path(argv0)
    if not candidate.is_absolute():
        import shutil

        resolved = shutil.which(argv0)
        if resolved is None:
            raise GraphError(CONTRACT_INVALID, f"executable {argv0!r} was not found on PATH")
        candidate = Path(resolved)
    real = candidate.resolve(strict=True)
    for root in allowed_binary_roots:
        root_real = root.resolve(strict=True)
        if real == root_real or root_real in real.parents:
            return real
    raise GraphError(
        "PERMISSION",
        f"executable {argv0!r} resolves to {real}, which is outside the allowed binary roots",
        details={"argv0": argv0, "resolved": str(real)},
    )


def _validate_argv(argv: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    if not argv:
        raise GraphError(CONTRACT_INVALID, "argv must not be empty")
    out: list[str] = []
    for index, raw in enumerate(argv):
        if not isinstance(raw, str) or "\x00" in raw or "\r" in raw or "\n" in raw:
            raise GraphError(CONTRACT_INVALID, f"argv[{index}] is malformed")
        out.append(raw)
    return tuple(out)


class ProcessSupervisor:
    """Owns the lifecycle of all external processes bound to a run."""

    def __init__(
        self,
        process_root: Path,
        *,
        run_id: str,
        logger: StructuredLogger,
        artifact_store: ArtifactStore | None = None,
        allowed_binary_roots: tuple[Path, ...] = (Path("/usr/bin"), Path("/bin"), Path("/usr/local/bin")),
    ) -> None:
        self.process_root = process_root
        self.records = process_root / "records"
        self.records.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self.records.chmod(0o700)
        self.run_id = run_id
        self.logger = logger
        self.artifact_store = artifact_store
        self.allowed_binary_roots = allowed_binary_roots
        self._lock = threading.Lock()
        self._active: dict[str, ProcessEntry] = {}
        self._record_index = process_root / "index.jsonl"

    def _record(self, entry: ProcessEntry) -> None:
        record = {
            "schema_version": "1.0.0",
            "process_uid": entry.process_uid,
            "argv": list(entry.argv),
            "cwd": entry.cwd,
            "env_fingerprint": entry.env_fingerprint,
            "scope_hash": entry.scope_hash,
            "budget": {
                "wall_seconds": entry.budget.wall_seconds,
                "max_stdout_bytes": entry.budget.max_stdout_bytes,
                "max_stderr_bytes": entry.budget.max_stderr_bytes,
                "cpu_seconds": entry.budget.cpu_seconds,
                "max_rss_mib": entry.budget.max_rss_mib,
                "max_processes": entry.budget.max_processes,
                "graceful_stop_seconds": entry.budget.graceful_stop_seconds,
            },
            "actor": dict(entry.actor),
            "run_id": entry.run_id,
            "state": entry.state.value,
            "pid": entry.pid,
            "pgid": entry.pgid,
            "process_start_identity": entry.start_identity,
            "started_at": entry.started_at,
            "ended_at": entry.ended_at,
            "exit_code": entry.exit_code,
            "signal": entry.signal,
            "terminated_by": entry.terminated_by,
            "stdout_artifact": entry.stdout_artifact,
            "stderr_artifact": entry.stderr_artifact,
            "stdout_digest": entry.stdout_digest,
            "stderr_digest": entry.stderr_digest,
        }
        path = self.records / f"{entry.process_uid}.jsonl"
        line = canonical_line(record)
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o600)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
        index_line = canonical_line(
            {"process_uid": entry.process_uid, "state": entry.state.value, "pid": entry.pid, "pgid": entry.pgid}
        )
        ifd = os.open(
            self._record_index, os.O_CREAT | os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o600
        )
        try:
            os.write(ifd, index_line)
            os.fsync(ifd)
        finally:
            os.close(ifd)
        fsync_directory(self.records)

    def spawn(
        self,
        argv: tuple[str, ...] | list[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        budget: ProcessBudget,
        scope_hash: str,
        actor: dict[str, Any],
    ) -> ProcessEntry:
        """Resolve, scope-check, and supervise one external process."""

        argv = _validate_argv(argv)
        resolved = _resolve_executable(argv[0], self.allowed_binary_roots)
        if env is None:
            env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
        process_uid = new_id("prc")
        entry = ProcessEntry(
            process_uid=process_uid,
            argv=(str(resolved), *argv[1:]),
            cwd=str(cwd.resolve(strict=True)) if cwd else None,
            env_fingerprint=_env_fingerprint(env),
            budget=budget,
            scope_hash=scope_hash,
            actor=actor,
            run_id=self.run_id,
        )
        try:
            # start_new_session creates the dedicated process group.
            handle = subprocess.Popen(
                entry.argv,
                cwd=entry.cwd,
                env=dict(env),
                stdin=None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as error:
            entry.state = TerminationKind.REJECTED_POLICY
            entry.ended_at = utc_now()
            entry.terminated_by = f"spawn_error:{type(error).__name__}"
            self._record(entry)
            raise GraphError(
                "PERMISSION",
                f"failed to spawn {resolved}: {error}",
                details={"argv0": str(resolved)},
            ) from error
        entry.pid = handle.pid
        entry.handle = handle
        try:
            entry.pgid = getattr(os, "getpgid", lambda _pid: -1)(handle.pid)
            entry.start_identity = process_start_identity(handle.pid)
        except (OSError, PermissionError):
            entry.pgid = None
            entry.start_identity = None
        entry.started_at = utc_now()
        self._record(entry)
        with self._lock:
            self._active[entry.process_uid] = entry
        self.logger.event(
            "INFO",
            "process.spawned",
            process_uid=entry.process_uid,
            pid=entry.pid,
            pgid=entry.pgid,
        )
        return entry

    def _kill_group(self, entry: ProcessEntry, signum: int) -> None:
        if entry.pgid is None or entry.pid is None:
            return
        with contextlib.suppress(ProcessLookupError, PermissionError):
            getattr(os, "killpg", lambda *_args, **_kwargs: None)(entry.pgid, signum)

    def _verify_group_dead(self, entry: ProcessEntry) -> bool:
        if entry.pgid is None:
            return True
        try:
            getattr(os, "killpg", lambda *_args, **_kwargs: None)(entry.pgid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            # A PermissionError proves the group id is taken by a process owned
            # by someone else (different uid in the pid namespace).  We cannot
            # inspect its identity; treat it as "still alive".
            pass
        # pgid is live *now*.  WSL aggressively recycles small process-group
        # ids; any live member whose pgid matches but whose pid/start_time does
        # not match the recorded tuple is a different process and proves the
        # original group has already been reaped.
        if os.name == "nt":
            return True
        try:
            for pid_dir in filter(str.isdigit, os.listdir("/proc")):
                pid = int(pid_dir)
                if self._proc_matches(pid, entry.pgid, entry.pid, entry.start_identity):
                    return False
        except OSError:
            return False
        return True

    @staticmethod
    def _proc_matches(pid: int, pgid: int, entry_pid: int | None, entry_start: str | None) -> bool:
        try:
            with open(f"/proc/{pid}/stat", "rb") as stream:
                stat = stream.read().decode("utf-8")
            closing = stat.rindex(")")
            fields = stat[closing + 2 :].split()
            if len(fields) <= 5 or int(fields[4]) != pgid:
                return False
            if entry_pid is not None and pid != entry_pid:
                return False
            if entry_start is None:
                return True
            return fields[19] == entry_start
        except (OSError, ValueError, IndexError):
            return False

    def wait(
        self,
        entry: ProcessEntry,
        *,
        timeout: int | None = None,
        capture_limit: int = 1024 * 1024,
    ) -> ProcessEntry:
        """Wait for one entry, enforcing wall/output limits and the kill protocol."""

        if entry.handle is None or entry.pid is None:
            entry.state = TerminationKind.REJECTED_POLICY
            self._record(entry)
            return entry
        deadline = time.monotonic() + (timeout if timeout is not None else (entry.budget.wall_seconds or 3600))
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        stdout_size = 0
        stderr_size = 0
        assert entry.handle.stdout is not None
        assert entry.handle.stderr is not None
        stdout_stream = entry.handle.stdout
        stderr_stream = entry.handle.stderr

        def _drain() -> None:
            nonlocal stdout_size, stderr_size
            while True:
                chunk = stdout_stream.read(65536)
                if not chunk:
                    break
                stdout_size += len(chunk)
                stdout_chunks.append(chunk)
                if entry.budget.max_stdout_bytes is not None and stdout_size > entry.budget.max_stdout_bytes:
                    break
            while True:
                chunk = stderr_stream.read(65536)
                if not chunk:
                    break
                stderr_size += len(chunk)
                stderr_chunks.append(chunk)
                if entry.budget.max_stderr_bytes is not None and stderr_size > entry.budget.max_stderr_bytes:
                    break

        drain = threading.Thread(target=_drain, daemon=True)
        drain.start()
        killed = False
        while True:
            code = entry.handle.poll()
            if code is not None:
                entry.exit_code = code
                entry.ended_at = utc_now()
                if code < 0:
                    entry.state = TerminationKind.SIGNALLED
                    entry.signal = -code
                    entry.terminated_by = "signal"
                else:
                    entry.state = TerminationKind.EXITED
                break
            if time.monotonic() > deadline:
                # Stop-loss: SIGTERM, grace, SIGKILL, verify no group remains.
                entry.terminated_by = "wall_budget_exceeded"
                self._kill_group(entry, getattr(signal, "SIGTERM", 15))
                time.sleep(entry.budget.graceful_stop_seconds)
                if entry.handle.poll() is None:
                    self._kill_group(entry, getattr(signal, "SIGKILL", 9))
                    killed = True
                entry.handle.wait(timeout=5)
                entry.exit_code = entry.handle.returncode
                entry.ended_at = utc_now()
                entry.state = TerminationKind.KILLED_GRACE_EXPIRED if killed else TerminationKind.SIGNALLED
                entry.signal = (
                    entry.handle.returncode
                    if entry.handle.returncode is not None and entry.handle.returncode < 0
                    else None
                )
                break
            time.sleep(0.05)
        drain.join(timeout=5)

        if self.artifact_store is not None and stdout_chunks:
            stdout_record = self.artifact_store.store(b"".join(stdout_chunks), media_type="application/octet-stream")
            entry.stdout_artifact = stdout_record["artifact_id"]
            entry.stdout_digest = stdout_record["content_hash"]
        if self.artifact_store is not None and stderr_chunks:
            stderr_record = self.artifact_store.store(b"".join(stderr_chunks), media_type="application/octet-stream")
            entry.stderr_artifact = stderr_record["artifact_id"]
            entry.stderr_digest = stderr_record["content_hash"]
        if not self._verify_group_dead(entry):
            entry.state = TerminationKind.ZOMBIE_REAPED
            entry.terminated_by = entry.terminated_by or "grace_timeout_then_sigkill"
        self._record(entry)
        with self._lock:
            self._active.pop(entry.process_uid, None)
        self.logger.event(
            "INFO",
            "process.waited",
            process_uid=entry.process_uid,
            pid=entry.pid,
            pgid=entry.pgid,
            exit_code=entry.exit_code,
            signal=entry.signal,
            terminated_by=entry.terminated_by,
        )
        return entry

    def terminate(self, entry: ProcessEntry, *, reason: str) -> ProcessEntry:
        """Apply the stop-loss protocol on demand (SIGTERM ??? SIGKILL ??? verify)."""

        if entry.state != TerminationKind.RUNNING:
            return entry
        entry.terminated_by = reason
        self._kill_group(entry, getattr(signal, "SIGTERM", 15))
        deadline = time.monotonic() + entry.budget.graceful_stop_seconds
        if entry.handle is not None:
            while time.monotonic() < deadline:
                if entry.handle.poll() is not None:
                    break
                time.sleep(0.05)
            if entry.handle.poll() is None:
                self._kill_group(entry, getattr(signal, "SIGKILL", 9))
                entry.state = TerminationKind.KILLED_GRACE_EXPIRED
            else:
                code = entry.handle.returncode
                entry.state = TerminationKind.SIGNALLED if code is not None and code < 0 else TerminationKind.EXITED
            entry.exit_code = entry.handle.returncode
            entry.ended_at = utc_now()
        else:
            entry.state = TerminationKind.ZOMBIE_REAPED
        if not self._verify_group_dead(entry):
            entry.state = TerminationKind.ZOMBIE_REAPED
        self._record(entry)
        with self._lock:
            self._active.pop(entry.process_uid, None)
        return entry

    def reconcile(self) -> list[ProcessEntry]:
        """Return the entries the supervisor still considers active."""

        with self._lock:
            return list(self._active.values())

    def record_final_state(self, uid: str, state: str, *, reason: str) -> None:
        """Record a terminal state for a previously recorded process entry.

        This is used by the reconciler to finalize zombie-process records when
        the supervisor object no longer has the child handle in memory (for
        example after an external SIGKILL).
        """

        record = None
        path = self.records / f"{uid}.jsonl"
        if path.is_file():
            with path.open("rb") as stream:
                for line in stream:
                    line = line.strip()
                    if not line:
                        continue
                    record = json.loads(line.decode("utf-8"))
        if record is None:
            return
        record["state"] = state
        record["terminated_by"] = reason
        record["ended_at"] = utc_now()
        with self._record_index.open("ab") as stream:
            stream.write(canonical_line({**record, "process_uid": uid}))
            stream.flush()
            os.fsync(stream.fileno())
