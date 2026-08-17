from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_generated_contracts_are_current() -> None:
    subprocess.run(
        [sys.executable, "scripts/generate_contracts.py", "--check"], cwd=ROOT, check=True
    )
