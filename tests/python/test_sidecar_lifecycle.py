"""Sidecar lifecycle regression drills for the 0.2.1 permanent fix.

Named after the six approved scenarios: healthy-reattach-no-rotation,
dead-service-takeover-rotates, stale-file-reclaimed,
refuse-if-live-server-owns-path, idle-watchdog-exits, SIGTERM-cleans-socket.
"""

from __future__ import annotations

import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from ayran.api.client import AyranClient
from ayran.api.server import AyranServer
from ayran.runtime.logs import StructuredLogger
from ayran.runtime.paths import runtime_root
from ayran.runtime.session import prepare_session, start_engagement

pytestmark = pytest.mark.wsl_ext4


def _logger(tmp_path: Path) -> StructuredLogger:
    return StructuredLogger(tmp_path / "logs" / "runtime.jsonl", run_id="run_test", component="test")


def _echo_handler(method: str, params: dict[str, Any], credentials: object) -> Any:
    del params, credentials
    return {"method": method}


def _make_server(
    tmp_path: Path,
    sock: Path,
    token: bytes,
    *,
    idle_exit_secs: float | None = None,
) -> AyranServer:
    return AyranServer(
        sock,
        token=token,
        logger=_logger(tmp_path),
        handler=_echo_handler,
        run_id="run_test",
        idle_exit_secs=idle_exit_secs,
    )


def _ping_ok(sock: Path, token: bytes, attempts: int = 40) -> bool:
    for _ in range(attempts):
        try:
            AyranClient(sock, token_bytes=token, timeout=1.0).call("run.ping")
            return True
        except Exception:
            time.sleep(0.05)
    return False


def _prepare_workspace(tmp_path: Path, short_state_root: Path) -> tuple[Path, Path, bytes]:
    ws = tmp_path / "ws"
    (ws / "src").mkdir(parents=True)
    prepared = prepare_session(
        cwd=ws,
        state_root=short_state_root,
        allow_unsafe_filesystem=True,
    )
    return ws, Path(prepared["socket"]), Path(prepared["token_file"]).read_bytes()


def _reattach(ws: Path, short_state_root: Path) -> dict[str, Any]:
    return start_engagement(
        cwd=ws,
        state_root=short_state_root,
        allow_unsafe_filesystem=True,
    )


# 1. healthy-reattach-no-rotation ---------------------------------------------


def test_healthy_reattach_no_rotation(tmp_path: Path, short_state_root: Path) -> None:
    ws, sock, token_v1 = _prepare_workspace(tmp_path, short_state_root)
    server = _make_server(tmp_path, sock, token_v1)
    server.start_background()
    try:
        assert _ping_ok(sock, token_v1)
        resumed = _reattach(ws, short_state_root)
        assert resumed["resumed"] is True
        assert resumed["reattached"] is True
        # No rotation: the file the live guard holds still matches disk.
        assert Path(resumed["token_file"]).read_bytes() == token_v1
        # The unchanged credentials authenticate against the SAME live guard.
        pong = AyranClient(sock, token_bytes=token_v1).call("run.ping")
        assert isinstance(pong, dict)
    finally:
        server.stop()


# 2. dead-service-takeover-rotates --------------------------------------------


def test_dead_service_takeover_rotates(tmp_path: Path, short_state_root: Path) -> None:
    ws, _sock, token_v1 = _prepare_workspace(tmp_path, short_state_root)
    first = _reattach(ws, short_state_root)
    assert Path(first["token_file"]).read_bytes() == token_v1
    # No live server answers the probe -> cleanup path rotates the bearer.
    second = _reattach(ws, short_state_root)
    assert second["reattached"] is False
    assert Path(second["token_file"]).read_bytes() != token_v1


# 3. stale-file-reclaimed -------------------------------------------------------


def test_stale_socket_file_reclaimed_by_bind(tmp_path: Path, short_state_root: Path) -> None:
    _ws, sock, token = _prepare_workspace(tmp_path, short_state_root)
    sock.write_bytes(b"stale landmine left behind by an ungraceful death")
    assert sock.exists()
    server = _make_server(tmp_path, sock, token)
    thread = server.start_background()
    try:
        assert _ping_ok(sock, token)
        assert thread.is_alive()
    finally:
        server.stop()
    assert not sock.exists()


# 4. refuse-if-live-server-owns-path -------------------------------------------


def test_refuse_if_live_server_owns_path(tmp_path: Path, short_state_root: Path) -> None:
    _ws, sock, token = _prepare_workspace(tmp_path, short_state_root)
    live = _make_server(tmp_path, sock, token)
    live.start_background()
    try:
        assert _ping_ok(sock, token)
        challenger = _make_server(tmp_path, sock, token)
        with pytest.raises(SystemExit, match="live server owns this socket path"):
            challenger._bind()
        # The legitimate owner is untouched by the refused takeover.
        assert AyranClient(sock, token_bytes=token).call("run.ping")
    finally:
        live.stop()


# 5. idle-watchdog-exits ---------------------------------------------------------


def test_idle_watchdog_exits_and_cleans_socket(tmp_path: Path, short_state_root: Path) -> None:
    _ws, sock, token = _prepare_workspace(tmp_path, short_state_root)
    server = _make_server(tmp_path, sock, token, idle_exit_secs=0.4)
    thread = server.start_background()
    assert _ping_ok(sock, token)
    deadline = time.monotonic() + 6.0
    while thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not thread.is_alive()
    assert not sock.exists()


def test_missing_idle_flag_disables_watchdog(tmp_path: Path, short_state_root: Path) -> None:
    _ws, sock, token = _prepare_workspace(tmp_path, short_state_root)
    server = _make_server(tmp_path, sock, token, idle_exit_secs=None)
    thread = server.start_background()
    try:
        assert _ping_ok(sock, token)
        time.sleep(0.8)
        assert thread.is_alive()
    finally:
        server.stop()


# 6. SIGTERM-cleans-socket ---------------------------------------------------------


def test_sigterm_cleans_socket(tmp_path: Path, short_state_root: Path) -> None:
    ws = tmp_path / "ws"
    (ws / "src").mkdir(parents=True)
    prepared = prepare_session(
        cwd=ws,
        state_root=short_state_root,
        allow_unsafe_filesystem=True,
    )
    argv = [
        sys.executable,
        "-m",
        "ayran.cli",
        "service",
        "--run",
        str(prepared["run_id"]),
        "--state-root",
        str(prepared["state_root"]),
        "--socket",
        str(prepared["socket"]),
        "--token-file",
        str(prepared["token_file"]),
        "--idle-exit-secs",
        "3600",
    ]
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    sock = Path(prepared["socket"])
    token = Path(prepared["token_file"]).read_bytes()
    try:
        assert _ping_ok(sock, token)
        proc.send_signal(signal.SIGTERM)
        rc = proc.wait(timeout=10)
        assert rc == 128 + int(signal.SIGTERM)
        assert not sock.exists()
        state_dir = Path(str(prepared["state_root"]))
        assert not (
            runtime_root(state_dir, str(prepared["run_id"])) / "ayrand.sock"
        ).exists()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
