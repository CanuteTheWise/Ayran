"""Shared M7 knowledge-tree copies and CLI helpers."""

from __future__ import annotations

import io
import json
import shutil
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

from ayran.cli import main as cli_main
from ayran.graph.namespaces import TargetNamespace
from ayran.graph.recovery import GraphStore
from m5_fixtures import RUN_ID, TARGET_IDENTITY, TARGET_KEY

ROOT = Path(__file__).resolve().parents[2]
AUTHORED_KNOWLEDGE = ROOT / "knowledge"


def copy_knowledge(tmp_path: Path, name: str = "knowledge") -> Path:
    dest = tmp_path / name
    shutil.copytree(
        AUTHORED_KNOWLEDGE,
        dest,
        ignore=shutil.ignore_patterns("releases", "staging", "quarantine", "current.json"),
    )
    return dest


def open_store(tmp_path: Path) -> GraphStore:
    namespace = TargetNamespace(
        tmp_path / "graph",
        RUN_ID,
        TARGET_IDENTITY,
        TARGET_KEY,
        allow_unsafe_filesystem=True,
    )
    return GraphStore(namespace.root, namespace.stream, allow_unsafe_filesystem=True)


def invoke(argv: list[str]) -> tuple[int, str]:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = cli_main(argv)
    return code, buffer.getvalue()


def payload(output: str) -> dict[str, Any]:
    parsed = json.loads(output)
    assert isinstance(parsed, dict)
    return parsed
