"""Held-out evaluation targets. Contamination is enforced before any launch."""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ayran.evaluation.partitions import enforce_at_harness_start
from ayran.knowledge.models import KnowledgeRecord
from ayran.tools.yaml_lite import load_yaml

DEFAULT_TASK_TEXT = (
    "Audit the Solidity sources in this workspace. Record every hypothesis you form "
    "through the available recording interface, gather evidence in-scope, and finish "
    "with your findings."
)


class TargetGroundTruth(BaseModel):
    model_config = ConfigDict(extra="forbid")
    root_cause_family: str
    severity: float
    notes: str = ""


class TargetManifest(BaseModel):
    """Held-out target: workspace plus planted root-cause answer key."""

    model_config = ConfigDict(extra="forbid")
    target_id: str
    workspace_path: str
    ground_truth: list[TargetGroundTruth] = Field(default_factory=list)
    revision_or_commit: str
    held_out: bool = True
    task_text: str = DEFAULT_TASK_TEXT

    def workspace(self, relative_to: Path | None = None) -> Path:
        path = Path(self.workspace_path)
        if path.is_absolute():
            return path
        base = relative_to if relative_to is not None else Path.cwd()
        return (base / path).resolve()


def load_target_manifest(path: Path | str) -> TargetManifest:
    location = Path(path)
    text = location.read_text(encoding="utf-8")
    payload: Any = load_yaml(text) if location.suffix.lower() in {".yaml", ".yml"} else json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError(f"target manifest {location} is not an object")
    manifest = TargetManifest.model_validate(payload)
    if not manifest.held_out:
        raise ValueError(f"target {manifest.target_id} is not marked held_out")
    return manifest


def load_target_dir(root: Path | str) -> list[TargetManifest]:
    directory = Path(root)
    if directory.is_file():
        return [load_target_manifest(directory)]
    found: list[TargetManifest] = []
    for path in sorted(directory.rglob("*")):
        if path.name in {"target.json", "target.yaml", "target.yml"}:
            found.append(load_target_manifest(path))
    return found


def select_targets(
    candidates: Sequence[TargetManifest] | Sequence[Path | str],
    cards: Iterable[KnowledgeRecord],
) -> list[TargetManifest]:
    """Load candidates, enforce the contamination gate, return only survivors.

    The gate runs before this function returns a list the runner may launch.
    A collision raises ``ContaminationViolation`` (zero launches).
    """

    loaded: list[TargetManifest] = []
    for item in candidates:
        if isinstance(item, TargetManifest):
            loaded.append(item)
        else:
            path = Path(item)
            loaded.extend(load_target_dir(path) if path.is_dir() else [load_target_manifest(path)])
    names = [item.target_id for item in loaded]
    names.extend(item.workspace_path for item in loaded)
    enforce_at_harness_start(cards, names)
    return [item for item in loaded if item.held_out]
