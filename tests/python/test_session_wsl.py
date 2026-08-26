"""Session sidecar ping on WSL ext4."""

from __future__ import annotations

import contextlib
import subprocess
import sys
import time
from pathlib import Path

import pytest
from ayran.api.client import AyranClient
from ayran.runtime.session import prepare_session

pytestmark = pytest.mark.wsl_ext4


def test_prepared_service_answers_ping(tmp_path: Path, short_state_root: Path) -> None:
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    prepared = prepare_session(
        cwd=cwd,
        state_root=short_state_root,
        allow_unsafe_filesystem=True,
    )
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "ayran.cli",
            "service",
            "--run",
            prepared["run_id"],
            "--state-root",
            prepared["state_root"],
            "--socket",
            prepared["socket"],
            "--token-file",
            prepared["token_file"],
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        token = Path(prepared["token_file"]).read_bytes()
        sock = Path(prepared["socket"])
        client: AyranClient | None = None
        for _ in range(40):
            if sock.exists():
                try:
                    client = AyranClient(sock, token_bytes=token)
                    pong = client.call("run.ping")
                    assert pong["run_id"] == prepared["run_id"]
                    with contextlib.suppress(Exception):
                        client.call("run.shutdown")
                    break
                except Exception:
                    client = None
            time.sleep(0.15)
        else:
            raise AssertionError("sidecar did not answer run.ping")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
