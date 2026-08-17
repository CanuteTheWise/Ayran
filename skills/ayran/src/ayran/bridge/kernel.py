"""Detect whether Prime is using Ayran's managed kernel or a custom interpreter.

This module never installs, upgrades, or mutates a Python environment. It only
records facts the extension can log.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


def _probe_import(python: str, module: str) -> bool:
    try:
        result = subprocess.run(
            [python, "-c", f"import {module}"],
            check=False,
            capture_output=True,
            timeout=8,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def detect_kernel() -> dict[str, Any]:
    """Return managed-vs-custom kernel facts without mutating the environment."""

    override = os.environ.get("PRIME_AGENT_KERNEL_PYTHON")
    home = Path.home()
    managed_candidates = [
        home / ".prime" / "agent" / "kernel-venv" / "bin" / "python",
        home / ".prime" / "agent" / "kernel-venv" / "Scripts" / "python.exe",
    ]
    managed_python: str | None = None
    for candidate in managed_candidates:
        if candidate.is_file():
            managed_python = str(candidate)
            break

    selected = override or managed_python or shutil.which("python3") or shutil.which("python")
    managed = False
    if managed_python is not None:
        managed = override is None or Path(override) == Path(managed_python)
    ayran_importable = _probe_import(selected, "ayran") if selected else False
    ipykernel_importable = _probe_import(selected, "ipykernel") if selected else False
    warning: str | None = None
    if not managed:
        warning = (
            "Python kernel is not Ayran-managed. Ayran will not install or modify "
            "this interpreter. Sidecar reachability is required to continue."
        )
    return {
        "schema_version": "1.0.0",
        "managed": managed,
        "python": selected,
        "override_set": override is not None,
        "ayran_importable": ayran_importable,
        "ipykernel_importable": ipykernel_importable,
        "warning": warning,
    }
