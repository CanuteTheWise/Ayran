"""Real subprocess SIGKILL recovery tests on an explicitly selected WSL ext4 root."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

WORKER = Path(__file__).with_name("graph_crash_worker.py")
SELECTED_ROOT = os.environ.get("AYRAN_WSL_EXT4_ROOT")
SIGKILL = getattr(signal, "SIGKILL", 9)

pytestmark = [
    pytest.mark.wsl_ext4,
    pytest.mark.resilience,
    pytest.mark.skipif(not SELECTED_ROOT, reason="AYRAN_WSL_EXT4_ROOT selects a safe ext4 base"),
]


@pytest.fixture
def crash_root() -> Iterator[Path]:
    assert SELECTED_ROOT is not None
    base = Path(SELECTED_ROOT).resolve(strict=True)
    probe = subprocess.run(
        ["findmnt", "--noheadings", "--output", "FSTYPE", "--target", str(base)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert probe.stdout.strip() == "ext4"
    root = Path(tempfile.mkdtemp(prefix="crash-", dir=base))
    try:
        yield root
    finally:
        resolved = root.resolve(strict=True)
        assert resolved.parent == base and resolved.name.startswith("crash-")
        shutil.rmtree(resolved)


def worker(root: Path, action: str, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(WORKER), action, "--root", str(root), *extra],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )


def kill_at(root: Path, action: str, point: str, *extra: str) -> None:
    ready = root / "fault.ready"
    ready.unlink(missing_ok=True)
    process = subprocess.Popen(
        [
            sys.executable,
            str(WORKER),
            action,
            "--root",
            str(root),
            "--fault",
            point,
            *extra,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 20
    while not ready.is_file() and time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(f"worker exited before {point}: {stdout}\n{stderr}")
        time.sleep(0.01)
    assert ready.read_text(encoding="utf-8") == point
    os.kill(process.pid, SIGKILL)
    process.wait(timeout=10)
    assert process.returncode == -SIGKILL
    ready.unlink(missing_ok=True)


@pytest.mark.parametrize(
    ("point", "durable_before_kill"),
    [
        ("after_lease_lock", False),
        ("after_segment_create", False),
        ("before_append", False),
        ("during_partial_write", False),
        ("after_complete_write", True),
        ("after_journal_fsync", True),
        ("after_sqlite_begin", True),
        ("after_applied_event", True),
        ("after_outbox", True),
        ("after_sqlite_commit", True),
        ("after_acknowledgement", True),
    ],
)
def test_sigkill_append_boundaries(
    crash_root: Path, point: str, durable_before_kill: bool
) -> None:
    kill_at(crash_root, "append", point)
    retry = json.loads(worker(crash_root, "append").stdout)
    report = json.loads(worker(crash_root, "verify").stdout)
    assert retry["idempotent_replay"] is durable_before_kill
    assert report["status"] == "ok"
    assert report["journal_cursor"] == report["projection_cursor"] == 1


@pytest.mark.parametrize(
    "point",
    [
        "after_manifest_temp_fsync",
        "after_manifest_rename",
        "after_manifest_directory_fsync",
    ],
)
def test_sigkill_segment_manifest_rotation(crash_root: Path, point: str) -> None:
    kill_at(crash_root, "append", point, "--max-segment-events", "1")
    retry = json.loads(
        worker(crash_root, "append", "--max-segment-events", "1").stdout
    )
    report = json.loads(worker(crash_root, "verify").stdout)
    assert retry["idempotent_replay"] is True
    assert report["status"] == "ok"
    assert report["journal_cursor"] == 1


@pytest.mark.parametrize(
    "point",
    [
        "during_projection_rebuild",
        "after_projection_pointer_temp_fsync",
        "after_projection_pointer_rename",
        "after_projection_pointer_directory_fsync",
    ],
)
def test_sigkill_rebuild_pointer_boundaries(crash_root: Path, point: str) -> None:
    worker(crash_root, "append")
    kill_at(crash_root, "rebuild", point)
    report = json.loads(worker(crash_root, "verify").stdout)
    rebuilt = json.loads(worker(crash_root, "rebuild").stdout)
    assert report["status"] == "ok"
    assert rebuilt["cursor"] == 1


@pytest.mark.parametrize(
    "point",
    [
        "after_checkpoint_temp_fsync",
        "after_checkpoint_rename",
        "after_checkpoint_directory_fsync",
    ],
)
def test_sigkill_checkpoint_boundaries(crash_root: Path, point: str) -> None:
    worker(crash_root, "append")
    kill_at(crash_root, "checkpoint", point)
    report = json.loads(worker(crash_root, "verify").stdout)
    assert report["status"] == "ok"
    assert report["journal_cursor"] == 1


@pytest.mark.parametrize(
    "point",
    [
        "after_global_pointer_temp_fsync",
        "after_global_pointer_rename",
        "after_global_pointer_directory_fsync",
    ],
)
def test_sigkill_global_release_pointer_boundaries(crash_root: Path, point: str) -> None:
    kill_at(crash_root, "global", point)
    release = crash_root / "releases" / "rel_01K00000000000000000000001"
    assert release.is_dir()
    current = crash_root / "current.json"
    if current.is_file():
        assert json.loads(current.read_text(encoding="utf-8"))["release_id"] == release.name


def test_sigkill_releases_kernel_writer_lease(crash_root: Path) -> None:
    kill_at(crash_root, "append", "after_lease_lock")
    result = json.loads(worker(crash_root, "append").stdout)
    assert result["last_seq"] == 1
    assert not (crash_root / "runtime" / "lease.json").exists()
