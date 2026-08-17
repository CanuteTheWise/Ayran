"""UDS socket permission, restart survival, and shutdown cleanup checks."""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path
from typing import Any

from ayran.api.server import AyranServer
from ayran.runtime.logs import StructuredLogger


def socket_mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def assert_owner_only(path: Path) -> dict[str, Any]:
    mode = socket_mode(path)
    return {"path": str(path), "mode": oct(mode), "ok": mode == 0o600}


def bind_socket(path: Path, *, token: bytes, run_id: str, log_root: Path) -> AyranServer:
    logger = StructuredLogger(log_root / "ayrand.log", run_id=run_id, component="ayrand")
    server = AyranServer(
        path,
        token=token,
        logger=logger,
        handler=lambda method, params, peer: {"method": method, "ok": True},
        run_id=run_id,
    )
    server.start_background()
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if path.exists():
            return server
        time.sleep(0.02)
    raise FileNotFoundError(f"UDS socket did not appear at {path}")


def restart_socket(path: Path, *, token: bytes, run_id: str, log_root: Path) -> dict[str, Any]:
    first = bind_socket(path, token=token, run_id=run_id, log_root=log_root)
    first.stop()
    if path.exists():
        path.unlink()
    second = bind_socket(path, token=token, run_id=run_id, log_root=log_root)
    check = assert_owner_only(path)
    second.stop()
    cleaned = not path.exists()
    return {**check, "restarted": True, "cleaned": cleaned, "uid": os.getuid() if hasattr(os, "getuid") else 0}
