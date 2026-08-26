from __future__ import annotations

import contextlib
import os
import shutil
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "skills" / "ayran" / "src"))


@pytest.fixture
def short_state_root() -> Iterator[Path]:
    """Keep ``.../runtime/<run_id>/ayrand.sock`` under the 107-byte sun_path limit."""

    base = Path("/tmp/t") if os.name != "nt" else Path.home() / "t"
    base.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix="s", dir=base))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
        with contextlib.suppress(OSError):
            base.rmdir()


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip wsl_ext4 tests automatically on Windows, where UDS SO_PEERCRED is unavailable."""

    if sys.platform != "win32" and Path("/proc").exists():
        return
    skip = pytest.mark.skip(reason="wsl_ext4 requires Linux UDS SO_PEERCRED on ext4")
    for item in items:
        if item.get_closest_marker("wsl_ext4") is not None:
            item.add_marker(skip)
