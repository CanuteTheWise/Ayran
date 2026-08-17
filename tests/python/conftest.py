from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "skills" / "ayran" / "src"))


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip wsl_ext4 tests automatically on Windows, where UDS SO_PEERCRED is unavailable."""

    if sys.platform != "win32" and Path("/proc").exists():
        return
    skip = pytest.mark.skip(reason="wsl_ext4 requires Linux UDS SO_PEERCRED on ext4")
    for item in items:
        if item.get_closest_marker("wsl_ext4") is not None:
            item.add_marker(skip)
