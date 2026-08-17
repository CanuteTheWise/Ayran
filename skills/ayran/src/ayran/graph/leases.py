"""Kernel-enforced single-writer lease plus PID/start-time diagnostic metadata."""

from __future__ import annotations

import importlib
import json
import os
import socket
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, BinaryIO

from .canonical import atomic_write, canonical_line, fsync_directory, utc_now
from .errors import LEASE_HELD, GraphError
from .ids import new_id


def _boot_identity() -> str:
    path = Path("/proc/sys/kernel/random/boot_id")
    if path.is_file():
        return path.read_text(encoding="ascii").strip()
    return f"{socket.gethostname()}:{os.name}"


def _linux_start_ticks(pid: int) -> str | None:
    path = Path(f"/proc/{pid}/stat")
    try:
        text = path.read_text(encoding="ascii")
    except OSError:
        return None
    closing = text.rfind(")")
    fields = text[closing + 2 :].split()
    return fields[19] if len(fields) > 19 else None


def process_start_identity(pid: int) -> str | None:
    if os.name != "nt":
        return _linux_start_ticks(pid)
    if pid != os.getpid():
        return None
    return str(time.time_ns())


def _try_lock(stream: BinaryIO) -> bool:
    if os.name == "nt":
        msvcrt: Any = importlib.import_module("msvcrt")

        try:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False
    fcntl: Any = importlib.import_module("fcntl")

    try:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False


def _unlock(stream: BinaryIO) -> None:
    if os.name == "nt":
        msvcrt: Any = importlib.import_module("msvcrt")

        stream.seek(0)
        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        return
    fcntl: Any = importlib.import_module("fcntl")

    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


class WriterLease:
    """An advisory OS lock is authoritative; JSON is diagnostics, never exclusion."""

    def __init__(
        self,
        root: Path,
        stream_id: str,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.root = root
        self.stream_id = stream_id
        self.runtime = root / "runtime"
        self.lock_path = self.runtime / "writer.lock"
        self.metadata_path = self.runtime / "lease.json"
        self.lease_id = new_id("lea")
        self.fault_hook = fault_hook
        self._stream: BinaryIO | None = None

    def acquire(self) -> WriterLease:
        self.runtime.mkdir(parents=True, exist_ok=True)
        stream = self.lock_path.open("a+b")
        if self.lock_path.stat().st_size == 0:
            stream.write(b"0")
            stream.flush()
        if not _try_lock(stream):
            stream.close()
            details: dict[str, Any] = {"stream_id": self.stream_id}
            try:
                existing = json.loads(self.metadata_path.read_text(encoding="utf-8"))
                details["lease_id"] = existing.get("lease_id")
            except (OSError, json.JSONDecodeError):
                pass
            raise GraphError(LEASE_HELD, "Another writer holds this graph namespace.", details=details)
        self._stream = stream
        if self.fault_hook is not None:
            self.fault_hook("after_lease_lock")
        self._publish("acquired")
        return self

    def _publish(self, state: str) -> None:
        value = {
            "schema_version": "1.0.0",
            "lease_id": self.lease_id,
            "stream_id": self.stream_id,
            "pid": os.getpid(),
            "process_start_identity": process_start_identity(os.getpid()),
            "boot_identity": _boot_identity(),
            "namespace_root_hash": __import__("hashlib").sha256(
                str(self.root.resolve()).encode("utf-8")
            ).hexdigest(),
            "acquired_at": utc_now(),
            "heartbeat_at": utc_now(),
            "state": state,
        }
        atomic_write(self.metadata_path, canonical_line(value))

    def heartbeat(self) -> None:
        if self._stream is None:
            raise RuntimeError("lease is not held")
        self._publish("held")

    def release(self) -> None:
        stream, self._stream = self._stream, None
        if stream is None:
            return
        try:
            try:
                value = json.loads(self.metadata_path.read_text(encoding="utf-8"))
                if value.get("lease_id") == self.lease_id:
                    self.metadata_path.unlink(missing_ok=True)
                    fsync_directory(self.runtime)
            except (OSError, json.JSONDecodeError):
                pass
            _unlock(stream)
        finally:
            stream.close()

    def __enter__(self) -> WriterLease:
        return self.acquire()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()
