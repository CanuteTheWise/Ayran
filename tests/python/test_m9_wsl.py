"""M9 WSL ext4: sockets, orphan cleanup, distribution install rehearsal."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from ayran.resilience.sockets import restart_socket
from m9_fixtures import ROOT

pytestmark = pytest.mark.wsl_ext4


@pytest.mark.skipif(os.name == "nt", reason="UDS SO_PEERCRED is a Linux boundary")
def test_socket_permissions_restart_and_cleanup(tmp_path: Path) -> None:
    path = tmp_path / "runtime" / "ayrand.sock"
    path.parent.mkdir(parents=True)
    result = restart_socket(
        path,
        token=b"token-token-token-token",
        run_id="run_01J00000000000000000000001",
        log_root=tmp_path,
    )
    assert result["ok"] is True
    assert result["restarted"] is True
    assert result["cleaned"] is True


def test_payload_enumerates_m9(tmp_path: Path) -> None:
    from scripts import stage_wsl

    files, identity = stage_wsl.enumerate_payload(ROOT, "layer")
    assert identity["milestone"] == "M9"
    assert files
    _ = tmp_path
