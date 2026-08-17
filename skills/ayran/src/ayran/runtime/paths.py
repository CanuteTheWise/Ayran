"""XDG-owned runtime path topology and deterministic socket/runtime directory options.

The authoritative state root must resolve to a WSL ext4 filesystem (the same
boundary M1 enforces with ``findmnt``).  This module only computes and binds
paths; it never creates persistent global configuration and never trusts
target-controlled directories.
"""

from __future__ import annotations

import os
from pathlib import Path


def default_state_root() -> Path:
    """Return the XDG state root used for authoritative durable runtime state."""

    value = os.environ.get("AYRAN_STATE_ROOT") or os.environ.get("XDG_STATE_HOME")
    if value:
        return Path(value) / "ayran" if os.environ.get("XDG_STATE_HOME") else Path(value)
    return Path.home() / ".local" / "state" / "ayran"


class SocketPathError(ValueError):
    """Raised when a caller-requested socket path violates a deterministic rule."""


def runtime_root(state_root: Path, run_id: str) -> Path:
    """Return the per-run runtime directory (sockets, heartbeats, pid files)."""

    return state_root / "runtime" / run_id


def validate_socket_path(path: Path, *, runtime_dir: Path) -> Path:
    """Resolve and validate a service socket path inside the run runtime directory.

    Deterministic rules:
    - must be absolute after resolution against ``runtime_dir``;
    - must live inside ``runtime_dir`` (no traversal outside the run root);
    - must not exceed the Linux UNIX-domain sun_path limit (107 usable chars);
    - basename must be non-empty and contain no NUL/CR/LF.
    """

    if not path.is_absolute():
        path = runtime_dir / path
    resolved = path.resolve(strict=False)
    base = runtime_dir.resolve(strict=True)
    if resolved.parent != base and base not in resolved.parents:
        raise SocketPathError(f"socket path escapes the run runtime directory: {resolved}")
    if len(str(resolved)) > 107:
        raise SocketPathError(
            f"socket path exceeds the UNIX sun_path limit ({len(str(resolved))} > 107): {resolved}"
        )
    name = resolved.name
    if not name or any(char in name for char in ("\x00", "\r", "\n")):
        raise SocketPathError(f"socket basename is invalid: {name!r}")
    return resolved


def socket_path(state_root: Path, run_id: str, *, name: str = "ayrand.sock") -> Path:
    """Return the default, deterministic ayrand socket path for one run."""

    runtime = runtime_root(state_root, run_id)
    return validate_socket_path(Path(name), runtime_dir=runtime)


def run_root(state_root: Path, run_id: str) -> Path:
    """Return the per-run authoritative state directory (graph/artifacts/processes)."""

    return state_root / "runs" / run_id


def artifacts_root(state_root: Path, run_id: str) -> Path:
    return run_root(state_root, run_id) / "artifacts"


def process_root(state_root: Path, run_id: str) -> Path:
    return run_root(state_root, run_id) / "processes"


def token_root(state_root: Path, run_id: str) -> Path:
    return runtime_root(state_root, run_id)

